#!/usr/bin/env python3
"""Read-only checks against a live store the maintainer owns and agreed to have checked.

Usage: python3 live_check.py <base-url> [--store-root <dir>] [--cafile <ca.pem>]

Only GET requests, on a fixed list of paths, redirects not followed except one hop on the
admin and checkout paths. Certificates are always verified; --cafile trusts an extra certificate
authority, such as the mkcert CA of a local store. Prints JSON with status codes and
whether a response looks like the real file; never response bodies.
"""

import argparse
import hashlib
import re
import http.client
import json
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT_SECONDS = 10
USER_AGENT = "store-security-check (read-only)"
# path -> (text that proves the response is the real file, whether that file is an HTML page)
PROBES = {
    ".git/HEAD": ("ref:", False),
    ".git/config": ("[core]", False),
    "app/etc/env.php": ("<?php", False),
    "app/etc/env.php.bak": ("<?php", False),
    "app/etc/config.php": ("<?php", False),
    "composer.json": ('"require"', False),
    "composer.lock": ('"packages"', False),
    "auth.json": ('"http-basic"', False),
    ".env": ("=", False),
    ".user.ini": ("=", False),
    "dump.sql": ("CREATE TABLE", False),
    "backup.sql": ("CREATE TABLE", False),
    "var/log/system.log": ("main.", False),
    "var/log/exception.log": ("main.", False),
    "magento_version": ("Magento/", False),
    "phpinfo.php": ("PHP Version", True),
    "info.php": ("PHP Version", True),
    "adminer.php": ("Adminer", True),
    "setup/": ("Setup", True),
}
REDIRECTS = (301, 302, 303, 307, 308)
GUESSABLE_ADMIN_PATHS = ("admin", "backend")
# A store answers a missing file with 404 (or 410). When no probe got one, a WAF, a bot challenge (202, 405)
# or a block page served as 200 answered instead, and "nothing exposed" proves nothing
NOT_FOUND_STATUSES = (404, 410)
ADMIN_LOGIN_MARKER = "login[username]"
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "content-security-policy-report-only", "x-frame-options", "x-content-type-options")
DISCLOSING_HEADERS = ("server", "x-powered-by", "x-magento-cache-debug", "x-magento-tags", "x-magento-debug")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *arguments, **keywords):
        return None


class Client:
    def __init__(self, cafile: str | None):
        context = ssl.create_default_context(cafile=cafile)
        self.opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))
        self.errors: list[dict] = []
        # Paths reported by label only: the real admin path never goes into the output
        self.hidden_paths: dict[str, str] = {}

    def get(self, url: str) -> tuple[int | None, dict, str]:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with self.opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                return response.status, lower_keys(response.headers), response.read(65536).decode(errors="ignore")
        except urllib.error.HTTPError as error:
            return error.code, lower_keys(error.headers), ""
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError, ValueError) as error:
            path = urllib.parse.urlparse(url).path
            segments = path.strip("/").split("/")
            label = next((name for secret, name in self.hidden_paths.items() if secret in segments), path)
            self.errors.append({"url_path": label, "error": str(getattr(error, "reason", error))})
            return None, {}, ""


def lower_keys(headers) -> dict:
    return {key.lower(): value for key, value in headers.items()} if headers else {}


def fingerprint(body: str) -> str:
    return hashlib.sha256(body.encode()).hexdigest()


def looks_like_html(body: str) -> bool:
    return body.lstrip()[:15].lower().startswith(("<!doctype", "<html"))


def same_origin(base: str, location: str) -> str | None:
    target = urllib.parse.urljoin(base, location)
    origin = urllib.parse.urlparse(base)
    parsed = urllib.parse.urlparse(target)
    return target if (parsed.scheme, parsed.netloc) == (origin.scheme, origin.netloc) else None


def get_with_hop(client: Client, url: str) -> tuple[int | None, dict, str, bool]:
    """GET, following at most one redirect, and only on the same origin."""
    status, headers, body = client.get(url)
    location = headers.get("location") if status in REDIRECTS else None
    hop = same_origin(url, location) if location else None
    if hop:
        status, headers, body = client.get(hop)
    return status, headers, body, bool(hop)


def check_admin(client: Client, base: str, path: str) -> dict:
    status, _, body, redirected = get_with_hop(client, base + path.strip("/") + "/")
    return {"status": status, "login_form_public": status == 200 and ADMIN_LOGIN_MARKER in body, "redirected": redirected}


def admin_path_from(store_root: str) -> str | None:
    """The admin path read from env.php, so it never appears on a command line or in the transcript."""
    try:
        source = open(f"{store_root.rstrip('/')}/app/etc/env.php", encoding="utf-8", errors="ignore").read()
    except OSError:
        return None
    match = re.search(r"'frontName'\s*=>\s*'([^']+)'", source)
    return match.group(1) if match else None


def same_host(base: str, target: str) -> bool:
    """Same host, give or take a leading www.: anything else is a site the maintainer didn't name."""
    hosts = [(urllib.parse.urlparse(url).hostname or "").removeprefix("www.") for url in (base, target)]
    return hosts[0] == hosts[1] != ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only checks against a live store you run.")
    parser.add_argument("base_url")
    parser.add_argument("--store-root", help="the store's root, to check the real admin path; reported as configured_admin_path, never by name")
    parser.add_argument("--cafile", help="extra certificate authority to trust, e.g. a local mkcert rootCA.pem")
    options = parser.parse_args()

    base = options.base_url.rstrip("/") + "/"
    if urllib.parse.urlparse(base).scheme not in ("http", "https") or not urllib.parse.urlparse(base).netloc:
        sys.exit("The base URL must look like https://store.example")
    try:
        client = Client(options.cafile)
    except (OSError, ssl.SSLError) as error:
        sys.exit(f"Can't read the CA file: {error}")
    # Hidden before the first request: /admin may redirect to the real path, and a failed hop is reported
    admin_path = admin_path_from(options.store_root) if options.store_root else None
    if admin_path:
        for segment in admin_path.strip("/").split("/"):
            client.hidden_paths[segment] = "configured_admin_path"

    status, headers, _ = client.get(base)
    if status is None:
        print(json.dumps({"base_url": base, "reachable": False, "errors": client.errors}, indent=2))
        sys.exit(1)
    if status in REDIRECTS:
        # Checking the redirect's host would report nothing exposed on a store we never reached
        target = urllib.parse.urljoin(base, headers.get("location", ""))
        same_site = same_host(base, target)
        print(json.dumps({"base_url": base, "reachable": True, "homepage_redirects_to": target, "same_site": same_site,
                          "downgrades_to_http": base.startswith("https://") and target.startswith("http://"),
                          "note": "Run again with the URL the store redirects to." if same_site
                          else "Another host: ask the maintainer whether they run it before checking it."}, indent=2))
        sys.exit(2)

    soft_404_status, _, soft_404_body = client.get(base + f"store-security-{secrets.token_hex(6)}")
    soft_404 = fingerprint(soft_404_body) if soft_404_status == 200 else None
    catch_all_body = soft_404_body if soft_404_status == 200 else ""

    statuses, exposed = {}, []
    for path, (marker, is_html) in PROBES.items():
        probe_status, _, body = client.get(base + path)
        statuses[path] = probe_status
        # A marker the catch-all page also contains proves nothing on a store that answers 200 to everything
        real = marker in body and marker not in catch_all_body and fingerprint(body) != soft_404 and (is_html or not looks_like_html(body))
        if probe_status == 200 and real:
            exposed.append(path)

    admin = {name: check_admin(client, base, name) for name in GUESSABLE_ADMIN_PATHS}
    if admin_path:
        admin["configured_admin_path"] = check_admin(client, base, admin_path)
    # Payment pages are where CSP matters most (PCI DSS 6.4.3): an empty cart redirects to the cart page
    checkout_status, checkout_headers, _, checkout_redirected = get_with_hop(client, base + "checkout/")
    # A file proven exposed stays Critical: only an empty result can be inconclusive
    blocked = not exposed and not any(code in NOT_FOUND_STATUSES for code in [soft_404_status, *statuses.values()])

    plain_http = None
    if base.startswith("https://"):
        http_status, http_headers, _ = client.get("http://" + base[len("https://"):])
        plain_http = {"checked": http_status is not None, "status": http_status,
                      "redirects_to_https": (http_headers.get("location") or "").startswith("https://")}

    print(json.dumps({
        "base_url": base,
        "reachable": True,
        "homepage_status": status,
        "soft_404": soft_404 is not None,
        "exposed": exposed,
        "inconclusive": "no probe got a plain 404 (WAF, bot challenge or block page): nothing exposed is not proven" if blocked else None,
        # 200 here with nothing in exposed: PHP ran the file, so the web root is the store root, not pub/
        "app_etc_reachable": statuses["app/etc/env.php"] == 200 or statuses["app/etc/config.php"] == 200,
        "statuses": statuses,
        "admin": admin,
        "security_headers": {name: headers.get(name) for name in SECURITY_HEADERS},
        "checkout_status": checkout_status,
        # An empty cart sends /checkout/ to the cart page: its headers aren't the payment page's
        "checkout_redirected": checkout_redirected,
        "checkout_security_headers": {name: checkout_headers.get(name) for name in SECURITY_HEADERS},
        "disclosing_headers": {name: headers[name] for name in DISCLOSING_HEADERS if name in headers},
        "plain_http": plain_http,
        "errors": client.errors,
    }, indent=2))


if __name__ == "__main__":
    main()
