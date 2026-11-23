# Admin and configuration

The admin is where an attacker with a stolen password does the most damage:
they can add a skimmer through a CMS block in two minutes. These settings
make a stolen or guessed password much less useful.

Read values with `bin/magento config:show <path>`. Two traps:

- **Empty output** means the value isn't stored, so the default from the
  declaring module's `etc/config.xml` applies. The defaults are given below.
- **"The path doesn't exist"** means either the module declaring it is
  disabled (2FA paths while `Magento_TwoFactorAuth` is off) or the path has
  no admin field (the CSP modes). Read those in the database instead:
  `SELECT path, scope, scope_id, value FROM core_config_data WHERE path LIKE 'csp/mode/%';`
  and fall back to the default when there's no row.

Stores that dump config to files keep some values in `app/etc/config.php`
or `env.php` (`modules.dumped_config_paths`); those win over the database.
`config:show` reads them too. Never open `env.php` to read one: the
secrets are in the same file.

## Admin criteria (Recommended; 2FA off is Critical)

- **Two-factor authentication on** (`modules.two_factor_auth`): the
  `Magento_TwoFactorAuth` module enabled, with at least one provider
  configured (`twofactorauth/general/force_providers`). Disabling it is the
  most common shortcut and the most expensive one. `modules.module_entries_odd`
  lists modules set twice in `config.php` (the last one counts, as in PHP),
  or to anything else than `0` or `1`, whose state is then `null`, unknown:
  Magento writes neither, so each is a finding. `modules.modules_key_repeated`
  true means `config.php` has two `'modules'` keys: PHP keeps the second,
  which the audit doesn't follow, so every module state is `null`. Read
  `config.php` then: 2FA and CSP are "not checked" until it's rewritten
  with one `'modules'` array.
- **Admin URL not guessable** (`env.admin_path_guessable`): not `admin`,
  `backend` or similar. It doesn't stop a determined attacker, but it stops
  the bots that try passwords on `/admin` all day. Better still: the admin
  reachable only from known IPs or a VPN, at the web server.
- **Lockout**: `admin/security/lockout_failures` set (default 6) and
  `admin/security/lockout_threshold` in minutes (default 30).
- **Sessions**: `admin/security/session_lifetime` at most 3600 seconds
  (default 900); `admin/security/admin_account_sharing` 0 (default), so one
  login can't be used from two places at once.
- **Passwords**: `admin/security/password_is_forced` 1 and
  `admin/security/password_lifetime` set (defaults 1 and 90 days).
- **Captcha on the admin login**: `admin/captcha/enable` 1 (default).
- **Form keys**: `admin/security/use_form_key` 1 (CSRF protection). Never 0.

## Configuration criteria (Recommended)

- **Production mode** (`env.mage_mode`): developer mode shows stack traces
  with paths and queries to visitors and is slower. No `MAGE_MODE` at all
  (`null`) means the `default` mode, which isn't production either.
- **CSP enforced**: `csp/mode/storefront/report_only` and
  `csp/mode/admin/report_only` 0 (default 1, report-only). In report-only
  mode, a skimmer's script loads and is merely reported. Since 2.4.7
  checkout pages enforce CSP by default; the rest of the storefront
  doesn't.
- **HTTPS everywhere**: `web/secure/use_in_frontend` and
  `web/secure/use_in_adminhtml` 1, `web/secure/base_url` on `https://`,
  `web/secure/enable_hsts` 1.
- **Cookies**: `web/cookie/cookie_httponly` 1.
- **No debug output**: `dev/debug/template_hints_storefront` and
  `dev/debug/template_hints_admin` 0.
- **Guest API access off unless needed**: `webapi/webapisecurity/allow_insecure`
  0, so anonymous REST calls can't read store configuration and catalog
  data meant for logged-in clients.
- **Payment-page scripts under control** (PCI DSS 4.0.1, 6.4.3 and 11.6.1,
  required since April 2025 for any store whose pages load the payment
  form):
  - every script on the checkout is authorized and inventoried: CSP in
    restrict mode on checkout (the default since 2.4.7) is the
    authorization, and the store's `csp_whitelist.xml` files are the
    inventory; each entry needs a reason the merchant can give;
  - each script's integrity is checked: 2.4.7 and later add Subresource
    Integrity hashes to the payment pages' scripts (`Magento_Csp`); on
    older versions, say it's missing. The hashes are computed at deploy
    time from the files on the server: they catch a script changed at a
    CDN or in transit, not one changed on a server that's already
    compromised, nor inline code injected through the database;
  - a change to the payment page's scripts or security headers is detected
    and alerted on at least weekly (11.6.1). Magento doesn't do this: a
    CSP report endpoint (`csp/mode/storefront/report_uri`) someone reads,
    or a monitoring service. Ask what they use; "nothing" is a finding.
  A store whose payment form is entirely the provider's (hosted page or
  iframe) fills in SAQ A: since January 2025 SAQ A no longer lists 6.4.3
  and 11.6.1, but asks the merchant to confirm their site isn't
  susceptible to script attacks that could reach the payment form. These
  checks are how they can confirm it, so they stay recommended. The ASV
  scan (11.3.2) is a different check, from outside.
- **Version not advertised**: `Magento_Version` disabled
  (`modules.version_module`), which serves `/magento_version` to anyone
  and helps bots pick stores with known holes.

## Fixing

1. Config values: `bin/magento config:set <path> <value>`, then
   `bin/magento cache:clean config`. If the store dumps config to files,
   add `--lock-config` or `--lock-env` to match where the path is, and say
   so. `config:set` refuses paths without an admin
   field, like the CSP modes: set those in the `system` section of
   `app/etc/config.php` (`'system' => ['default' => ['csp' => ['mode' =>
   ['storefront' => ['report_only' => 0]]]]]`), or in the `etc/config.xml`
   of a store module, and say which you chose.
2. 2FA: `bin/magento module:enable Magento_TwoFactorAuth`,
   `setup:upgrade`, then configure a provider
   (`bin/magento config:set twofactorauth/general/force_providers google`).
   Every admin user sets it up at next login: tell them before.
3. Admin URL: `bin/magento setup:config:set --backend-frontname=<name>`.
   Bookmarks and any integration calling the admin URL break: needs
   decision. Never write the new name in the scorecard or a commit message.
4. Production mode: `bin/magento deploy:mode:set production`. It compiles
   DI and static content, takes minutes and is a deploy: needs decision on
   a live store.
5. CSP restrict: turn it on in staging first and browse checkout, the cart
   and the pages with third-party widgets; add what's legitimately blocked
   to a `csp_whitelist.xml` in a store module before turning it on in
   production. Needs decision.
6. `Magento_Version`: `bin/magento module:disable Magento_Version`,
   `setup:upgrade`.

## Questions to ask

**2FA off** (decision `admin.two_factor_auth`):

> **Two-factor authentication is disabled.** A single leaked admin password
> is enough to add a skimmer to checkout. Every admin user will set up an
> authenticator app at their next login.
>
> 1. Turn it on, with Google Authenticator as provider (Recommended)
> 2. Skip for now

**Guessable admin URL** (decision `admin.custom_path`): "The admin is at
`/admin`, where bots try passwords all day. Move it to a random path?
Bookmarks will need updating." with "Move it, and restrict it by IP at the
web server too (Recommended)", "Move it only", "Skip for now".

**CSP report-only** (decision `configuration.csp_restrict`): "CSP only
reports blocked scripts on the storefront, so an injected skimmer still
runs. Switch to restrict mode after testing on staging? (Recommended)"

**Small settings** (auto-fixable, one bundled question): lockout, session
lifetime, captcha, template hints, guest API access, `Magento_Version`.
