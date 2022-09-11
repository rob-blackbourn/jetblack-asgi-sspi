"""Middleware for SSPI using spnego"""

import base64
from datetime import datetime, timedelta
import logging
import socket
from typing import (
    List,
    Literal,
    Optional,
    Tuple,
    TypedDict,
    cast
)

from asgi_typing import (
    Scope,
    HTTPScope,
    ASGIReceiveCallable,
    ASGISendCallable,
    ASGIHTTPReceiveCallable,
    ASGIHTTPSendCallable,
    ASGI3Application
)
from bareutils import header, response_code
import spnego

from .session_manager import SessionManager, Session

LOGGER = logging.getLogger(__name__)


class SSPIDetails(TypedDict):
    """The details available from SPNEGO"""
    client_principal: str
    negotiated_protocol: str
    protocol: str
    spn: str


class SSPISession(Session):
    """The data to store for a session"""
    server_auth: spnego.ContextProxy
    status: Optional[Literal['requested', 'accepted', 'rejected']]
    sspi: Optional[SSPIDetails]


class SPNEGOSessionManager(SessionManager[SSPISession]):
    """The session manager implementation for SPNEGO"""

    def __init__(
            self,
            session_duration: timedelta,
            hostname: str,
            service: str,
            protocol: str
    ) -> None:
        super().__init__(session_duration)
        self.hostname = hostname
        self.service = service
        self.protocol = protocol

    def create_session(self, expiry: datetime) -> SSPISession:
        server_auth = spnego.server(
            hostname=self.hostname,
            service=self.service,
            protocol=self.protocol.lower()
        )

        session: SSPISession = {
            'server_auth': server_auth,
            'expiry': expiry,
            'status': None,
            'sspi': None
        }

        return session


class SPNEGOMiddleware:
    """ASGI middleware for authenticating with SSPI using SPNEGO

    Authentication data is stored in the scope `"extensions"` property under
    `"sspi"`.
    """

    def __init__(
            self,
            app: ASGI3Application,
            *,
            protocol: Literal[b'Negotiate', b'NTLM'] = b'Negotiate',
            service: str = 'HTTP',
            hostname: Optional[str] = None,
            session_duration: timedelta = timedelta(hours=1),
            forbid_unauthenticated: bool = True
    ) -> None:
        """Initialise the SPNEGO middleware.

        Args:
            app (ASGI3Application): The AGI application.
            protocol (Literal[b&#39;Negotiate&#39;, b&#39;NTLM&#39;], optional):
                The protocol. Defaults to b'Negotiate'.
            service (str, optional): The service. Defaults to 'HTTP'.
            hostname (Optional[str], optional): The hostname. Defaults to None.
            session_duration (timedelta, optional): The duration of a session
                before re-authentication is performed. Defaults to
                `timedelta(hours=1)`.
            forbid_unauthenticated (bool, optional): If true, 403 (Forbidden) is
                sent if authentication fails. If false the request is handled,
                but no authentication details are added. Defaults to True.
        """
        self._app = app
        self.protocol = protocol
        self.forbid_unauthenticated = forbid_unauthenticated

        if hostname is None:
            hostname = socket.gethostname()

        self._session_manager = SPNEGOSessionManager(
            session_duration,
            hostname,
            service,
            self.protocol.decode('ascii')
        )

    async def _send_response(
            self,
            send: ASGIHTTPSendCallable,
            status: int,
            headers: List[Tuple[bytes, bytes]],
            body: bytes
    ) -> None:
        await send({
            'type': 'http.response.start',
            'status': status,
            'headers': [
                (b'content-type', b'text/plain'),
                (b'content-length', str(len(body)).encode('ascii')),
                *headers
            ]
        })
        await send({
            'type': 'http.response.body',
            'body': body,
            'more_body': False
        })

    async def _send_forbidden(self, send: ASGIHTTPSendCallable) -> None:
        await self._send_response(
            send,
            response_code.FORBIDDEN,
            [],
            b'Forbidden'
        )

    async def _handle_accepted(
            self,
            session: SSPISession,
            scope: HTTPScope,
            receive: ASGIHTTPReceiveCallable,
            send: ASGIHTTPSendCallable
    ) -> None:
        scope['extensions']['sspi'] = session['sspi']  # type: ignore
        await self._app(
            cast(Scope, scope),
            cast(ASGIReceiveCallable, receive),
            cast(ASGISendCallable, send)
        )

    async def _request_authentication(
            self,
            session: SSPISession,
            headers: List[Tuple[bytes, bytes]],
            scope: HTTPScope,
            send: ASGIHTTPSendCallable
    ) -> None:
        LOGGER.debug(
            "Requesting authentication for client %s using %s",
            scope['client'],
            self.protocol
        )

        # To request authentication a message with status 401 (Unauthorized)
        # is sent with the "www-authenticate" header set to the desired
        # protocol (e.g. Negotiate or NTLM). The client will then respond with
        # a message containing the "authorization" header. This header will
        # return the auth-scheme that the client has chosen, and a token.
        await self._send_response(
            send,
            response_code.UNAUTHORIZED,
            [
                (b'www-authenticate', self.protocol),
                *headers
            ],
            b'Unauthenticated'
        )
        session['status'] = 'requested'

    async def _authenticate(
            self,
            authorization: Optional[bytes],
            session: SSPISession,
            scope: HTTPScope,
            receive: ASGIHTTPReceiveCallable,
            send: ASGIHTTPSendCallable
    ) -> None:
        # The authentication handshake involves an exchange of tokens.

        if not authorization:
            raise RuntimeError("Missing 'authorization' header")

        # Feed the client token into the authenticator. This is a two step
        # process.
        in_token = base64.b64decode(authorization[len(self.protocol)+1:])
        server_auth = session['server_auth']
        buf = server_auth.step(in_token)

        if server_auth.complete:
            # This is the second step. The handshake has succeeded and the
            # request can be passed on to the downstream handlers.
            LOGGER.debug(
                "Authentication succeeded for client %s using %s as user %s",
                scope['client'],
                self.protocol,
                server_auth.client_principal
            )
            session['status'] = 'accepted'
            session['sspi'] = {
                'client_principal': server_auth.client_principal,
                'protocol': server_auth.protocol,
                'negotiated_protocol': server_auth.negotiated_protocol,
                'spn': server_auth.spn
            }
            await self._handle_accepted(session, scope, receive, send)
            return

        if buf:
            # This is the first step. The client has sent an acceptable token
            # and the server responds with its own as another 401 response.
            LOGGER.debug(
                "Sending challenge for client %s using %s",
                scope['client'],
                self.protocol
            )
            out_token = self.protocol + b" " + base64.b64encode(buf)
            body = b'Unauthorized'
            await self._send_response(
                send,
                response_code.UNAUTHORIZED,
                [
                    (b'www-authenticate', out_token),
                    (b'content-type', b'text/plain'),
                    (b'content-length', str(len(body)).encode('ascii'))
                ],
                body
            )
            return

        raise RuntimeError("Handshake failed")

    async def _handle_requested(
            self,
            session: SSPISession,
            scope: HTTPScope,
            receive: ASGIHTTPReceiveCallable,
            send: ASGIHTTPSendCallable
    ) -> None:
        authorization = header.find(b'authorization', scope['headers'])
        try:
            await self._authenticate(
                authorization,
                session,
                scope,
                receive,
                send
            )
        except:  # pylint: disable=bare-except
            LOGGER.exception(
                "Failed to authenticate for client %s using %s",
                scope['client'],
                self.protocol
            )
            session['status'] = 'rejected'
            await self._handle_rejected(session, scope, receive, send)

    async def _handle_rejected(
            self,
            session: SSPISession,
            scope: HTTPScope,
            receive: ASGIHTTPReceiveCallable,
            send: ASGIHTTPSendCallable
    ) -> None:
        if self.forbid_unauthenticated:
            await self._send_forbidden(send)
        else:
            await self._handle_accepted(session, scope, receive, send)

    async def _send_internal_server_error(
            self,
            scope: HTTPScope,
            send: ASGIHTTPSendCallable
    ) -> None:
        LOGGER.debug(
            "Failed to handle message for client %s",
            scope['client']
        )
        body = b'Internal Server Error'
        await self._send_response(
            send,
            response_code.INTERNAL_SERVER_ERROR,
            [
                (b'content-type', b'text/plain'),
                (b'content-length', str(len(body)).encode('ascii'))
            ],
            body
        )

    async def _process_http(
            self,
            scope: HTTPScope,
            receive: ASGIHTTPReceiveCallable,
            send: ASGIHTTPSendCallable
    ) -> None:
        try:
            session, headers = self._session_manager.get_session(scope)

            if session['status'] is None:
                await self._request_authentication(session, headers, scope, send)
            elif session['status'] == 'requested':
                await self._handle_requested(session, scope, receive, send)
            elif session['status'] == 'accepted':
                await self._handle_accepted(session, scope, receive, send)
            elif session['status'] == 'rejected':
                await self._handle_rejected(session, scope, receive, send)
            else:
                raise RuntimeError("Unhandled session status")

        except:  # pylint: disable=bare-except
            LOGGER.exception("Failed to authenticate")
            await self._send_internal_server_error(scope, send)

    async def __call__(
            self,
            scope: Scope,
            receive: ASGIReceiveCallable,
            send: ASGISendCallable
    ) -> None:
        if scope['type'] == 'http':
            # Only use for the http connect event.
            await self._process_http(
                cast(HTTPScope, scope),
                cast(ASGIHTTPReceiveCallable, receive),
                cast(ASGIHTTPSendCallable, send)
            )
        else:
            await self._app(scope, receive, send)
