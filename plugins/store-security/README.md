# Store security

Check how exposed a Magento or Mage-OS store is, then close the gaps one at
a time, with your approval for every change. Built for merchants and the
developers who run their stores.

```
/plugin install store-security@mage-os
```

## What it does

You ask something like *"is our store secure?"* from the store's root
directory, and the agent:

1. **Audits** the store: runs a bundled script (version, patches, secrets in
   git, unexpected PHP files), checks the version against
   [magento.watch](https://magento.watch), runs `composer audit`, compares
   your extensions with Sansec's [MageVulnDB](https://github.com/sansecio/magevulndb),
   and reads the admin and security settings through `bin/magento`.
2. **Shows a scorecard** of 7 areas, each finding saying what an attacker
   could do with it.
3. **Walks you through each fix** with a recommended answer, like
   *"Two-factor authentication is disabled. Turn it on? (Recommended)"*.
4. **Fixes what you agreed to** and verifies it, then saves the area
   statuses and your decisions to `var/mage-os-security.json` (outside git)
   so the next run shows progress.

What it never does:

- **Print a secret.** Findings say "the crypt key is in commit a1b2c3d",
  never the key.
- **Touch your live site without asking.** The live checks run only on the
  URL you give, only after you say yes: about 25 GET requests, no login
  attempts.
- **Clean up a hack.** If it finds a likely skimmer or backdoor, it stops,
  changes nothing, and helps you hand over to your host or a security
  specialist, because deleting the file destroys the evidence. It never
  runs a suspect file or contacts a domain found in it.
- **Run your store's code before it's known to be clean.** Git hooks and
  diff drivers, Composer plugins and `bin/magento` stay off until the
  compromise checks pass.
- **Take orders from your store's content.** Text in files, CMS blocks or
  commits is treated as data: an attacker can write there.
- **Commit or push.**

## Limits

The audit lowers the risk; it doesn't prove a store is clean.

- **Your own code is compared with your last commit only.** `app/code`,
  `app/design`, path repositories (`packages/`) and the `app/etc` files
  that don't come from Magento's packages are scanned for known patterns, the hosts they name are listed
  for you to recognize, and, in a git repository, the files changed or
  added since the last commit are listed (ignored files only in `app/code`,
  `app/design` and path repositories; submodules and partial clones aren't compared).
  Without git, or for what was committed, the patterns are all there is. So is the database, read with `SELECT` only. A skimmer
  host built from pieces (`'ev' + 'il.com'`) gets through both.
- **Uploads over 16 MB are read in part**: their first 16 MB and last
  1 MB.
- **`pub/static` isn't compared with anything.** Files changed more than
  two hours after its last deploy started are listed by date, which an
  attacker can set back: redeploy it after a compromise.
- **Patterns miss what they don't know.** Code split up
  (`$f = 'sys' . 'tem'; $f($x)`), an `include` of an upload with no
  wrapper, a URL rewrite to
  another site or a checkout `<form>` posting elsewhere without any
  script: a dedicated scanner and a look at the checkout find those.
- **`generated/` isn't checked.** It's moved aside and rebuilt before the
  first `bin/magento`, which on a live store takes a maintenance window.
- **The reference is your repository.** The clean install is built from
  the committed `composer.json` and `composer.lock`: an attacker with
  write access to the repository isn't covered.
- **It isn't a malware scanner.** It doesn't replace eComscan, the Adobe
  Security Scan or a forensic investigation after a breach.
- **An attacker who controls the server can make the audit fail**, with a
  file it can't read or a folder it won't follow: those show as "not
  checked", never as "pass".

## What it checks

| Area | Level | What it checks |
|---|---|---|
| Version and patches | Critical | Supported version, open security bulletins, isolated patches applied |
| Dependencies | Critical | `composer audit`, abandoned packages, extensions listed in MageVulnDB, `app/code` modules nobody audits |
| Signs of compromise | Critical | Scripts injected in config or CMS blocks, PHP files in `pub/media`, obfuscated code, unknown admin users and integrations |
| Secrets in git | Critical | `env.php`, `auth.json` and API keys in tracked files and the whole history, `.gitignore` |
| Admin | Recommended, 2FA off is Critical | 2FA, admin URL, lockout, sessions, passwords, captcha |
| Configuration | Recommended | Production mode, CSP restrict mode, HTTPS, cookies, debug output, guest API access |
| Live site | Recommended, with consent | Exposed `.git/` or `env.php`, document root, admin login exposure, security headers |

The criteria live in [`skills/store-security/references/`](skills/store-security/references/).
Disagree with a rule? Open a pull request against the reference file.

## Example prompts

- *"Is this store secure? Don't change anything."*
- *"Adobe published a security bulletin, are we affected?"*
- *"We think there's a card skimmer on checkout."*
- *"Harden the admin of this shop."*
- *"Check the live site at https://shop.example before our PCI scan."*

## Requirements

- `git` and `python3` (for the bundled scripts)
- Access to `bin/magento`, in whatever form your machine has it (DDEV,
  Warden, Docker Compose...). Without it, the settings and database checks
  are reported as not checked.
- Network access to magento.watch and GitHub for the version and extension
  checks.

## Installation

### Claude Code

```
/plugin marketplace add mage-os-lab/agent-skills
/plugin install store-security@mage-os
```

### Codex, Gemini CLI, Cursor, GitHub Copilot, OpenCode

```bash
npx skills add https://github.com/mage-os-lab/agent-skills/tree/main/plugins/store-security/skills/store-security -g
```

Or copy `skills/store-security` to `~/.agents/skills/`.

### Claude.ai and Claude Desktop

Zip the `skills/store-security` folder, then go to Customize > Skills >
"+" > Create skill > Upload a skill. Code execution must be enabled.

## Evals

`evals/` holds a [plugin eval suite](https://code.claude.com/docs/en/plugin-evals)
that runs the skill against a fixture store with known gaps
(`evals/fixture/acme-store.sh`): a vulnerable version, committed secrets,
2FA off and an inert backdoor in `pub/media`. Every secret in it is fake.

```bash
claude plugin eval . --scaffold --allow-tools Bash Edit Write
```

The case grants Bash, since the skill runs `scripts/audit.py`, but no web
access. Graders check it changes nothing: no Edit, no Write, and no shell
command that writes or opens a secrets file whole.

The scripts have their own self-checks, attacker git configs, symlinked
media and planted scorecards included:

```bash
python3 -I -m unittest discover -s plugins/store-security/tests
```

## Community

Questions or ideas? Join the [Mage-OS Discord](https://mage-os.org/discord-channel/).
