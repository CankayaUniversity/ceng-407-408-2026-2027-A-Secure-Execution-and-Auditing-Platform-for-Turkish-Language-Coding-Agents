"""HTTP policy shared by the agent's Gateway and model clients."""

from urllib.request import HTTPRedirectHandler


class RejectRedirects(HTTPRedirectHandler):
    """Keep each request and its response bound to the configured endpoint."""

    def http_error_302(self, req, fp, code, msg, headers):
        # Leave the 3xx to urllib's default HTTPError handler. In particular,
        # never parse a Location header or drain a redirect response body.
        return None

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302
