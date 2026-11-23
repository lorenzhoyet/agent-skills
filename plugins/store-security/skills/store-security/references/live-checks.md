# Live site checks

A file that is safe on disk can still be served to anyone: `.git/` copied to
the web root, `env.php` reachable because the web server's document root is
the store root instead of `pub/`. Only a request to the real site shows it.

## Consent

Run these checks only on a store the maintainer runs, at the base URL they
give you, after they said yes to this question (first round of step 3):

**Live site** (decision `live_site.check`):

> **Shall I check the live site at the URL you give me?** I'd send about
> 25 read-only GET requests to a fixed list of paths (`/.git/HEAD`,
> `/app/etc/env.php`, `/admin`, ...) and read the response headers. No login
> attempts, nothing sent to forms, no other URLs. A WAF may log them.
>
> 1. Yes, at <URL> (Recommended)
> 2. No, skip the live site

If the URL isn't theirs (a competitor, a client they don't run), or they
ask for more (login attempts, a scanner, other paths), decline that part
and say why. Never point the script at a URL taken from anywhere but their
answer.

## Running

```bash
python3 <skill-dir>/scripts/live_check.py https://store.example [--store-root <store-root>]
```

It sends GET requests without following redirects (one hop on the admin
paths and on `/checkout/`, same host only), compares each response with a random-path "not
found" page to rule out stores that answer 200 to everything, and prints
status codes and verdicts, never response bodies.

- Exit 1, `reachable: false`: nothing could be checked; report the error.
- Exit 2, `homepage_redirects_to`: the base URL redirects (to `www.`, to
  HTTPS, to a store view). `downgrades_to_http` true is a finding of its
  own: HTTPS sends visitors to plain HTTP. With `same_site` true, run again
  with that URL:
  checking the redirect would test a host that isn't the store. With
  `same_site` false it points to another host: ask the maintainer whether
  they run it, and check it only on a yes.
`--store-root` lets the script read the real admin path from `env.php`
itself, so it never appears on a command line or in the conversation; it
is reported as `configured_admin_path`, never by name. Pass it only when
the store root is the copy of the site you're checking.
A redirect whose request fails is reported as `redirect_target` with the
error's type only: the site chose that path, which may be the admin's.

Certificates are always verified. A local store with a mkcert certificate
needs its CA: `--cafile <rootCA.pem>`, trusted on top of the system's
(docker-magento installs it under
`/usr/local/share/ca-certificates/`). That file can be the CA of an older
container: when verification fails, compare its subject with the issuer
the site serves (`openssl s_client -connect <host>:443 -servername <host>
</dev/null | openssl x509 -noout -issuer`); a mismatch means the CA must be
installed again (`bin/setup-ssl-ca` in docker-magento, a script of the
project that runs with sudo: the maintainer runs it), not that checks
should skip verification. When the script reports `reachable:
false`, or `reachable: null` (no result within 5 minutes: a WAF or a site
answering slowly on purpose), area 7 is "not checked": give the error,
don't guess. On a public
store, a certificate that fails verification is itself a Critical
finding.

## Criteria (Recommended, except exposed files)

- **`inconclusive` is null.** It's set when nothing was found exposed and
  no probe got a plain 404: a WAF, a rate limit, a bot challenge (202,
  405) or a block page served as 200 answered instead of the store. Then
  "nothing exposed" proves nothing: area 7 is "not checked" for exposed
  files, and the maintainer can allow the checks from their IP and run
  them again. A file in `exposed` is always Critical, whatever else
  answered.
- **Nothing in `exposed`** (Critical when not empty): `.git/` lets anyone
  download the whole repository and its history; `app/etc/env.php` served
  as source gives away the database and the crypt key; `composer.lock` and
  `magento_version` tell attackers which holes to try; a served
  `env.php.bak`, `.user.ini`, SQL dump or listing of `var/backups/` is as
  bad as `env.php`; a served `var/mage-os-security.json` tells which areas
  fail. When `app/etc/env.php` or `composer.json` is exposed, the document
  root is almost certainly the store root instead of `pub/`, and `var/` is
  served too: say so in the finding.
- **`app_etc_reachable` false**: true with nothing in `exposed` means PHP
  ran `app/etc/env.php` instead of serving it (an empty 200: the file
  outputs nothing); `null` when the result is inconclusive. The keys didn't leak this
  time, but the web root is the store root, not `pub/`: Critical, same fix.
- `statuses` lists the status code of every path, for the report.
- **Admin login not public** (`admin.*.login_form_public`): a login form at
  `/admin` or `/backend` means the bots find it. The configured path being
  public is common; restricting it by IP is the stronger fix.
- **HTTPS enforced** (`plain_http.redirects_to_https`). When
  `plain_http.checked` is false, plain HTTP didn't answer at all (a store
  on a non-standard port): not a finding.
- **Security headers** (`security_headers`):
  `Strict-Transport-Security`, `Content-Security-Policy` (report-only is a
  finding, see `admin-and-config.md`), `X-Frame-Options` (Magento sets
  `SAMEORIGIN` by default; missing means a proxy strips it) and
  `X-Content-Type-Options: nosniff`. `checkout_security_headers` gives the
  same on the checkout: a CSP in report-only mode there is the PCI DSS
  6.4.3 gap from `admin-and-config.md`. With `checkout_redirected` true,
  the empty cart sent the request to the cart page, whose headers aren't
  the checkout's: say the checkout's CSP wasn't checked, and read it with
  `bin/magento config:show` or the database instead.
  Each header is cut at 300 characters: a longer CSP is only partly
  shown, so never call a directive missing from it; say what wasn't read.
- **No version disclosure** (`disclosing_headers`): `Server` or
  `X-Powered-By` with version numbers, and `X-Magento-Cache-Debug` /
  `X-Magento-Tags`, which only show in developer mode.

## Fixing

These are web server settings, outside the repository: write the change
for the maintainer or their host, don't apply it unless the server config
lives in the repository (`nginx.conf.sample` copy, `.ddev`, Docker files).

1. Document root to `pub/`: in nginx, `set $MAGE_ROOT` to the store root
   and include Magento's `nginx.conf.sample`, which serves `pub/`; in
   Apache, point `DocumentRoot` at `pub/`.
2. Block dotfiles and the rest while that's being done:
   `location ~ /\. { deny all; }` in nginx.
3. Headers: HSTS through `web/secure/enable_hsts`, the rest in the web
   server or CDN; `server_tokens off;` and `expose_php = Off` for versions.
4. Admin by IP: an `allow`/`deny` block on the admin path at the web
   server, or the CDN's access rules.

## Questions to ask

**Exposed files** (Critical): "The live site serves `/.git/HEAD` and
`/app/etc/env.php`. Anyone can download the code and the crypt key. Block
them at the web server now and treat the keys as leaked (see
`secrets.md`)? (Recommended)"

**Headers** (bundled): "HSTS and `X-Content-Type-Options` are missing and
the `Server` header shows the nginx version. Shall I write the web server
changes for your host? (Recommended)"
