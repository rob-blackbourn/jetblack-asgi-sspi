"""Session Manager"""

from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta, timezone
import logging
import secrets
from typing import (
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    TypeVar,
    TypedDict,
    cast
)

from asgi_typing import (
    HTTPScope,
)
from bareutils import encode_set_cookie, header

LOGGER = logging.getLogger(__name__)


class Session(TypedDict):
    """The base session"""
    expiry: datetime


T = TypeVar('T', bound=Session)


class SessionManager(Generic[T], metaclass=ABCMeta):
    """The base class for session managers

    This is a cookie based session manager. When a client connects the cookie
    headers are checked to see if they contain a session cookie.

    If the session cookie doesn't exist a set-cookie header is added to the
    response headers containing a unique value to use as a session key. This
    cookie will then be sent by the client in all subsequent requests.

    If the session cookie is found the value of the cookie is used to access
    a session cache.
    """

    def __init__(self, session_duration: timedelta) -> None:
        """Initialize the session manager.

        Args:
            session_duration (timedelta): The time after which a session
                will expire.
        """
        self.session_duration = session_duration

        self._sessions: Dict[bytes, T] = {}
        # The name of the cookie is only relevant for the life of the session
        # manager.
        self._session_cookie_name = secrets.token_urlsafe().encode('ascii')

    def _get_session_key_from_cookie(
        self,
        scope: HTTPScope
    ) -> Optional[bytes]:
        cookies = header.cookie(scope['headers'])
        session_cookie = cookies.get(
            self._session_cookie_name,
            [None]  # type: ignore
        )
        return next(iter(session_cookie))

    def _make_new_session_key(self) -> bytes:
        return secrets.token_hex(32).encode('ascii')

    @abstractmethod
    def create_session(self, expiry: datetime) -> T:
        """Create the session data.

        Args:
            expiry (datetime): The session expiry time.

        Returns:
            T: The session data.
        """

    def _make_session(self, now: datetime) -> Tuple[T, bytes]:
        """Make a new session.

        Args:
            now (datetime): The current time in UTC.

        Returns:
            Tuple[T, bytes]: The session data and the set-cookie value.
        """
        session_key = self._make_new_session_key()
        expiry = now + self.session_duration

        session = self.create_session(expiry)
        self._sessions[session_key] = session

        set_cookie = encode_set_cookie(
            self._session_cookie_name,
            session_key,
            expires=expiry
        )

        return session, set_cookie

    def _expire_sessions(self, now: datetime) -> None:
        """Delete all expired sessions.

        Args:
            now (datetime): The current time in UTC.
        """
        expired_session_keys = [
            key
            for key, session in self._sessions.items()
            if cast(Session, session)['expiry'] < now
        ]
        for key in expired_session_keys:
            del self._sessions[key]

    def get_session(
            self,
            scope: HTTPScope
    ) -> Tuple[T, List[Tuple[bytes, bytes]]]:
        """Get an existing session, or create a new one.

        Args:
            scope (HTTPScope): The ASGI HTTP scope.

        Returns:
            Tuple[T, List[Tuple[bytes, bytes]]]: The session and an headers to
                send to maintain the session.
        """
        now = datetime.now(timezone.utc)

        self._expire_sessions(now)

        session_key = self._get_session_key_from_cookie(scope)
        headers: List[Tuple[bytes, bytes]] = []

        session = (
            self._sessions.get(session_key)
            if session_key is not None
            else None
        )
        if session is None:
            session, set_cookie = self._make_session(now)
            headers.append((b'set-cookie', set_cookie))

        return session, headers
