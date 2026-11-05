"""Start the public site: python -m mainsite.serve

Like the decoy, it never trusts X-Forwarded-For (proxy_headers=False): the Tor/VPN check
must use the real TCP peer address, or anyone could bypass the block with one header.
"""

from __future__ import annotations

import os

import uvicorn


def build_config(**overrides) -> uvicorn.Config:
    kw = dict(host=os.environ.get("MAIN_SITE_HOST", "127.0.0.1"),
              port=int(os.environ.get("MAIN_SITE_PORT", "8088")),
              proxy_headers=False, forwarded_allow_ips="", server_header=False, date_header=True,
              access_log=False, limit_concurrency=200, timeout_keep_alive=5, h11_max_incomplete_event_size=16 * 1024)
    kw.update(overrides)
    return uvicorn.Config("mainsite.app:create_app", factory=True, **kw)


def main() -> None:
    try:
        uvicorn.Server(build_config()).run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
