"""Example using the SPNEGO middleware"""

import asyncio
import logging
from typing import cast, Optional

from bareasgi import Application, HttpRequest, HttpResponse
from bareutils import text_writer
from hypercorn import Config
from hypercorn.asyncio import serve

from jetblack_asgi_sspi.spnego_middleware import SPNEGOMiddleware, SSPIDetails


async def http_request_callback(request: HttpRequest) -> HttpResponse:
    extensions = request.scope['extensions'] or {}
    sspi_details = cast(Optional[SSPIDetails], extensions.get('sspi'))
    client_principal = (
        sspi_details['client_principal']
        if sspi_details is not None
        else 'unknown'
    )
    return HttpResponse(
        200,
        [(b'content-type', b'text/plain')],
        text_writer(f"Authenticated as '{client_principal}'")
    )


async def main_async():
    app = Application()
    app.http_router.add({'GET'}, '/', http_request_callback)

    wrapped_app = SPNEGOMiddleware(
        app,
        protocol=b'NTLM',  # NTLM or Negotiate
        forbid_unauthenticated=True
    )

    config = Config()
    config.bind = ['localhost:9023']
    await serve(wrapped_app, config)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main_async())
