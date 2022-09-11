# jetblack-asgi-sspi

ASGI middleware for SSPI authentication on Windows.

This is not specific to a particular ASGI framework or server.

## Installation

Install from the pie store.

```
pip install bareasgi-sspi
```

## Usage

The following program uses the
[Hypercorn](https://pgjones.gitlab.io/hypercorn/)
ASGI server, and the
[bareASGI](https://github.com/rob-blackbourn/bareASGI)
ASGI framework.

```python
import asyncio
import logging

from bareasgi import Application, HttpRequest, HttpResponse
from bareutils import text_writer
from hypercorn import Config
from hypercorn.asyncio import serve

from jetblack_asgi_sspi.spnego_middleware import SPNEGOMiddleware, SSPIDetails

# A callback to display the results of the SSPI middleware.
async def http_request_callback(request: HttpRequest) -> HttpResponse:
    # Get the details from scope['extensions']['sspi']. Note if
    # authentication failed this might be absent or empty.
    extensions = request.scope.get('extensions', {})
    sspi_details = extensions.get('sspi', {})
    client_principal = sspi_details.get('client_principal', 'unknown')

    message = f"Authenticated as '{client_principal}'"

    return HttpResponse(
        200,
        [(b'content-type', b'text/plain')],
        text_writer(message)
    )

async def main_async():
    # Make the ASGI application.
    app = Application()
    app.http_router.add({'GET'}, '/', http_request_callback)

    # Wrap the application with the middleware.
    wrapped_app = SPNEGOMiddleware(
        app,
        protocol=b'NTLM',  # NTLM or Negotiate
        forbid_unauthenticated=True
    )

    # Start the ASGI server.
    config = Config()
    config.bind = ['localhost:9023']
    await serve(wrapped_app, config)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main_async())
```

### Arguments

The `SPNEGOMiddleware` wraps the ASGI application. The first and only
positional argument is the ASGI application. Optional arguments include:

* `protocol` (`bytes`): Either `b"Negotiate"` or `b"NTLM"`.
* `service` (`str`): The SPN service. Defaults to `"HTTP"`.
* `hostname` (`str`, optional): The hostname. Defaults to `gethostname`.
* `service_principal` (`str`, optional): The service principal.
* `session_duration` (`timedelta`, optional): The duration of a session. Defaults to 1 hour.
* `forbid_unauthenticated` (`bool`): If true, and authentication fails, send 403 (Forbidden). Otherwise handle the request unauthenticated.

If `service_principal` if specified, it supersedes `service` and `hostname`.

### Results

If the authentication is successful the SSPI details are added to the
`"extensions"` property of the ASGI scope under the property `"sspi"`.
The following properties are set:

* `"client_principal"` (`str`): The username of the client.
* `"negotiated_protocol"` (`str`): The negotiated protocol.
* `"protocol"` (`str`): The requested protocol.
* `"spn"` (`str`): The SPN of the server.
