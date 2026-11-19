# Secrets in git

`app/etc/env.php` holds the database password and the crypt key, which
decrypts every encrypted value in the admin (payment gateway keys, API
tokens). `auth.json` holds the Composer keys for repo.magento.com or private
repositories. Anyone with a copy of the repository, a former agency, a
leaked CI cache, a public fork, has them.

## Criteria (Critical)

- No sensitive file is tracked (`git.tracked_sensitive_files`): `env.php`,
  `auth.json`, `.env`, database dumps, private keys.
- None was ever committed (`git.sensitive_files_in_history`): deleting a
  file in a later commit leaves it in every clone.
- No secret pattern in the history (`git.secret_patterns_in_history`: crypt
  key, database password, repo.magento.com keys, private keys, cloud and
  payment API keys). The report gives commits and files, never values. To
  look at a hit, `python3 <skill-dir>/scripts/audit.py --show <store-root>
  <file> <commit>` prints the file's key names with every value masked,
  multi-line values included. Never `git show`, `git log -p` or a shell
  pipe of your own: a value on two lines or with an escaped quote gets
  through a `sed`.
- `.gitignore` covers them (`git.not_ignored`): `app/etc/env.php`,
  `auth.json`, `.env`, `var/`, `generated/`, `pub/media/`, `pub/static/`.
  Backups count too: `env.php.bak`, `.env.local`, `*.sql.gz`, an archive at
  the root.
- `git.errors` is empty and `is_git_repository` isn't `null`: otherwise the
  history wasn't read, and the area is "not checked".
  `app/etc/config.php` *should* be committed: it lists modules, no secrets.

## Fixing

1. **Stop tracking now** (auto-fixable): add the entries from
   `assets/gitignore` to `.gitignore`, then `git rm --cached <file>`. The
   file stays on disk. This doesn't remove it from history.
2. **Rotate what leaked** (needs decision): a secret that reached git is
   compromised, whatever happens to the history next. The maintainer types
   every new secret themselves: you never see, choose or write one.
   - Database password: they change it on the database server, then in
     `env.php`.
   - Composer keys: they regenerate them in the Magento Marketplace account
     (or the private repository) and update `auth.json`.
   - Crypt key: a leaked key lets anyone decrypt the stored payment and API
     credentials, the admins' 2FA secrets and, as in CosmicSting
     (APSB24-40), forge admin API tokens. Treat it as a possible
     compromise: check area 3 first, admin users and `oauth_token`
     especially. The steps below follow Mage-OS 4.0's code
     (`module-encryption-key`); on another version, check what
     `bin/magento list encryption` offers and Adobe's guide for it before
     relying on them. `bin/magento` runs store code: only once area 3 found
     nothing. The maintainer runs every step in their own terminal; you
     never see a key. In this order:
     1. Database and `env.php` backup, kept off the server.
     2. New key: `bin/magento encryption:key:change`. It only adds a new key
        at the end of `crypt/key` in `env.php`; nothing is re-encrypted yet,
        and the old key still decrypts everything.
     3. Re-encrypt: `bin/magento encryption:data:re-encrypt` runs every
        re-encryptor registered (`encryption:data:list-re-encryptors` lists
        them; on Mage-OS 4.0, `core_config_data` and the card data in
        `sales_order_payment`). Everything else stays on the old key: the
        admins' 2FA secrets (`tfa_user_config`) and every third-party
        module's encrypted columns. Re-enter those values in the admin (a
        payment module's keys), or re-encrypt them column by column, for
        instance with the commands of `gene/module-encryption-key-manager`.
        Reset 2FA for every admin (`bin/magento security:tfa:reset <user>
        <provider>`): the attacker could decrypt their secrets, and each
        admin enrolls again with the new key.
     4. Old key out, last: every encrypted value starts with the number of
        its key (`0:3:...` for the first line of `crypt/key`), so the old
        line must never be deleted: the new key would move up to its number
        and nothing re-encrypted would decrypt any more. The maintainer
        replaces the old line's value in place with a random value of the
        same form (`base64` and 32 random bytes in base64), which
        `gene/module-encryption-key-manager` also does with its invalidate
        command. Anything still on the old key becomes unreadable: only
        once step 3 is done and checked.
     5. Tokens and sessions: admin and customer API tokens are JWTs signed
        with the newest key only (`SecretBasedJwksFactory`), so those signed
        with the old key stop working at step 2. Integrations' OAuth tokens
        (`oauth_token`) don't depend on the key: reauthorize every
        integration (System > Extensions > Integrations) and remove the
        ones nobody knows. Log every admin out by clearing the session
        storage (`var/session/` or the Redis session database; customers
        are logged out too).
     6. New admin passwords for every admin user, at next login.
     7. New keys at the payment providers and every API the admin stored a
        key for: whoever had the old crypt key could already decrypt them.
   - Any other API key found: revoke it at the provider.
3. **Rewrite history** (needs decision, last): `git filter-repo --invert-paths
   --path app/etc/env.php` (and the others) removes them from every commit,
   but it rewrites all commit IDs: every clone and fork must be re-cloned,
   and it changes nothing for copies already made. Only after rotation, and
   only if the maintainer controls every copy. Make a mirror backup first
   (`git clone --mirror <store-root> <backup>`): `filter-repo` also drops
   the `origin` remote, so say how to add it back. Never push the result
   yourself.

## Questions to ask

**Committed secrets** (decision `secrets.rotate_crypt_key`):

> **`app/etc/env.php` is in git since commit 4b10cbd, with the crypt key and
> the database password.** Anyone with a copy of the repository can decrypt
> the payment credentials stored in the admin. Removing the file from git
> doesn't change that: the keys must be replaced.
>
> 1. Stop tracking it now and rotate the crypt key, database password and
>    payment keys, in that order (Recommended)
> 2. Stop tracking it now, rotate later
> 3. Skip for now

**History rewrite** (decision `secrets.rewrite_history`), only after
rotation: "Remove env.php and auth.json from the whole history too? Every
clone will need to be re-cloned." with "Leave the history, the keys are
rotated (Recommended)" when the repository has outside copies.
