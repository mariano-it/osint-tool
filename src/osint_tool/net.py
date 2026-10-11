"""Cliente HTTP mínimo (stdlib) con límites de tamaño y User-Agent propio."""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "osint-tool/0.1 (reconocimiento pasivo; uso autorizado)"


class HttpError(RuntimeError):
    """Fallo de red (DNS, timeout, TLS...), distinto de un status 4xx/5xx."""


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]  # claves en minúsculas
    set_cookies: list[str] = field(default_factory=list)
    body: bytes = b""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def fetch(
    url: str,
    timeout: float = 10.0,
    max_bytes: int = 2_000_000,
    follow_redirects: bool = True,
) -> Response:
    handlers = [] if follow_redirects else [_NoRedirect()]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:  # 3xx sin seguir, 4xx, 5xx
        resp = exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise HttpError(f"{url}: {exc}") from exc

    try:
        body = resp.read(max_bytes)
    except OSError as exc:
        raise HttpError(f"{url}: {exc}") from exc
    finally:
        resp.close()

    msg = resp.headers
    return Response(
        url=resp.geturl() if hasattr(resp, "geturl") else url,
        status=resp.status if hasattr(resp, "status") else resp.code,
        headers={k.lower(): v for k, v in msg.items()},
        set_cookies=msg.get_all("Set-Cookie") or [],
        body=body,
    )
