# Security reviews of the store-security skill

The skill is checked by rounds of independent review: an agent playing a
Magento security expert audits the whole plugin, then the findings are
fixed. This file keeps what a new session needs to run the next round
without the previous conversation.

## Running a round

Start a new session in the repository and ask for a review with the prompt
below, in a background subagent. Then fix every defect it reports, add a
test for each fix, run the tests, replay the reviewer's proofs of concept,
and add the round to the history at the end of this file.

```text
Tu es un expert en cybersécurité spécialisé Magento / Mage-OS et forensic de
boutiques e-commerce compromises (Magecart, skimmers, backdoors PHP,
webshells, persistance en base). Fais un contre-audit indépendant et
sceptique du skill `store-security`, dans `plugins/store-security/`.

Lis d'abord `plugins/store-security/docs/security-reviews.md` : l'état
actuel, les limites déjà acceptées (ne les remonte pas comme défauts) et
les correctifs du dernier tour, à vérifier en priorité (contournements,
régressions, faux positifs, plantages, lenteurs). Cherche aussi ce qui a été
raté partout.

Périmètre : tout le plugin (SKILL.md, references/, assets/, scripts/audit.py,
scripts/live_check.py, tests/, README.md, evals/).

Priorités : 1. faux négatifs ; 2. sûreté de l'agent (destruction, fuite de
secrets, action en prod sans accord, exécution de code du dépôt audité,
prompt injection via fichiers, noms, base, HTTP, JSON) ; 3. robustesse face
à une boutique contrôlée par l'attaquant ; 4. live_check.py ; 5. cohérence
doc ↔ code et exactitude SQL (MariaDB, MySQL 8) ; 6. coût et bruit sur une
vraie installation Mage-OS (lecture seule ; demande son chemin), y compris
avec un gros app/code simulé.

Règles : lecture seule sur le dépôt et sur la boutique ; fixtures et PoC
dans le scratchpad de la session uniquement. Lance les tests
(`python3 -m unittest discover -s plugins/store-security/tests`) et
reproduis tes constats : [E] reproduit, [T] théorique. Docker possible sans
réseau (`--network none`), conteneurs supprimés ensuite. Pas d'accès réseau
vers des tiers, pas de vraie boutique en ligne. Distingue « défaut » (à
corriger, avec un scénario concret) et « limite inhérente » (à documenter).

Rapport en français, concis : verdict (prêt à commiter ou non) ; tableau de
validation des correctifs du dernier tour (point, FIXED / PARTIAL / KO, une
ligne) ; nouveaux constats Critique / Élevé / Moyen / Faible avec
fichier:ligne, scénario, impact, correctif minimal, défaut ou limite ; ce
qui est solide ; ce que tu n'as pas pu vérifier ; où s'arrêter.
```

## Accepted limits

These are inherent to the approach and documented in the README and the
references. A review shouldn't report them again as defects, only a way
around them that the documentation doesn't cover.

- **Patterns:** they never stop a determined attacker. Out of reach on
  purpose:
  - code built from pieces or read through variables (`$f = 'sys'.'tem'`) ;
  - `require $_SERVER['HTTP_X']` and `include 'php://input'` ;
  - `<?php` hidden with rot13, iconv or zlib and read through
    `php://filter` ;
  - a `<? ` without a closing `?>` under `short_open_tag` ;
  - a skimmer host built from pieces, in code or in the database ;
  - octal and short IPs (`0300.0250.0.1`, `127.1`).
- **History:** committed images, videos, PDFs and fonts aren't searched
  for secret patterns (as text, they make each search time out).
- **Comparison with the last commit:** a backdoor that was committed isn't
  covered. Neither are:
  - submodules ;
  - ignored files outside `app/code`, `app/design` and the store root's PHP ;
  - files over 16 MB ;
  - partial clones, refused rather than read.

  Git LFS files and `ident` expansion always show as different.
- **`pub/static`:** files are dated against `deployed_version.txt`, with a
  two-hour window. A date set back, a `touch` of that file, a change made
  within the window and `_cache/merged/` all get through. Switching to the
  ctime would flag every rsync deploy.
- **Uploads over 16 MB:** only their first 16 MB and last 1 MB are read.
- **Short tags in `pub/static`:** not looked for there, since Hyvä's
  `zxcvbn.js` ships `<?= ... ?>` and static deploy copies it. `<?php`, phar
  stubs and base64 still are, and the static files are dated against the
  deploy.
- **`$P` in the database:** it looks for code, not hosts. A `<link href>`
  or `<img src>` to an outside host in a CMS block gets through; only
  `core_config_data` lists its hosts.
- **`live_check` headers:** each is cut at 300 characters, so a long CSP
  is only partly read.
- **No independent reference:** the store's own code has no clean copy to
  compare with. The reference is the repository or `--compare`, and the
  skill is not a malware scanner: a pass lowers the risk, it doesn't prove
  the store is clean.

## History

Rounds 1 to 14 weren't recorded in this file. Their fixes are in the
commits and the tests. The main ones:
- the git hardening (`GIT_SAFE_OPTIONS`, no filters, no hooks, no
  fsmonitor) ;
- the sanitized names in the JSON output ;
- the bounded, linear regexes ;
- `open_regular` (no FIFOs or devices) ;
- the `$P` SQL pattern ;
- `live_check` restricted to GET requests, on the same origin.

### Round 14

Fixed:
- **`pub/static`:** the reference became `deployed_version.txt` plus a
  two-hour window, so `requirejs-config.js` and the bundles are
  candidates again.
- **Speed:** the PHP tag pattern lost `IGNORECASE` (a 140 times
  slowdown), and the include-wrapper check became linear
  (`include_before`).
- **Backslashes:** `\` is read as `/` in every host extractor.
- **Webshells:** more primitives are flagged (`eval` with comments before
  its parenthesis, `$_SERVER[..](`, `include $_FILES`), and so is PHP in
  the images of `app/` and `lib/`.
- **Archives:** any archive under another name than an archive's is
  flagged.
- **`.htaccess`:** `[H=…php]` and `Options +Includes` are flagged.
- **Double quotes:** keys in double quotes are read in `env.php`, by both
  scripts.
- **Comparison with git HEAD:** added (`git.compared_with_head`).

### Round 15

The verdict was "not ready", because of the new comparison with git HEAD.
Every finding was fixed:

| Finding | Severity | Fix |
|---|---|---|
| C1. A partial clone's lazy fetch runs `remote.*.uploadpack` from `.git/config` | Critical | `GIT_NO_LAZY_FETCH=1` on every git call; no object read when `extensions.partialClone` or `remote.*.promisor` is set (git before 2.44); same in SKILL.md |
| E1. A store in a folder of its repository is compared with nothing, silently | High | No `--full-tree`; `files_compared` added (0 means not checked) |
| E2. A staged, uncommitted file is invisible | High | `ls-files --cached` paths missing from HEAD count as untracked |
| E3. A file hidden by an attacker's `.gitignore`, `info/exclude` or `core.excludesFile` | High | `ignored_files` for `app/code`, `app/design` and the store root's PHP |
| E4. PHP at the store root is flagged nowhere | High | Root files go into the HEAD comparison; `unexpected_php.store_root_php` added |
| M1. Submodules are skipped silently | Medium | Listed in `not_compared` |
| M2. A short tag holding a `<` (`<?=1<2?…?>`) gets through | Medium | The run accepts `<` when no `?` follows it |
| M3. A bzip2 archive under an image name | Medium | `BZh` magic, `.bz2` and `.tbz2` suffixes |
| F1. A CRLF checkout is a false positive | Low | Hashed again with LF; `line_endings_converted` removed |
| F2. `?` in `app_etc_base_url_hosts` isn't documented | Low | Documented as a finding |
| F3. `core.worktree` points elsewhere | Low | Refused when the toplevel doesn't contain the store root |
| F4. The README promised every change since the last commit | Low | The README and `compromise.md` list the gaps |
| `include $GLOBALS['_GET'][…]` gets through | Limit | Detected anyway: it costs one pattern |

The reviewer found these solid:
- `-c core.fsmonitor=` stops the fsmonitor ;
- a tampered untracked cache hides nothing ;
- `assume-unchanged` and `skip-worktree` change nothing, since the audit
  hashes files itself ;
- the names coming from git are sanitized.

Not checked:
- git before 2.44 ;
- the SQL on MariaDB and MySQL 8 (replayed in round 14 only) ;
- the noise of LFS and of a real Composer `.gitignore` ;
- `git log -G` on a long history.

The reviewer's advice: stop after this round. Each new pattern only moves
the next way around it. The real guarantees are `--compare`, the
comparison with the last commit and the SQL queries.

### Round 16

The verdict was "not ready", because of a false positive that stopped
every audit of a deployed Mage-OS. Every defect was fixed:

| Finding | Severity | Fix |
|---|---|---|
| É1. HugeRTE's codesample plugin in `pub/static` is "PHP code in an upload" | High | `<?=` must not be followed by `>` (a PHP syntax error); `__HALT_COMPILER` needs its `()`, since Prism's keyword list, the actual hit, holds the bare word |
| M1. `git replace` swaps HEAD's tree (and `HEAD:composer.lock`) without changing its id | Medium | `GIT_NO_REPLACE_OBJECTS=1` on every git call and in SKILL.md; `replace_refs_or_grafts` flags them |
| M2. Path repositories (`packages/*`) are neither compared with HEAD nor scanned | Medium | The HEAD comparison covers everything tracked outside `vendor/`, `var/`, `generated/`, `pub/media/`, `pub/static/` and `node_modules/`; the folders composer.json's path repositories name are scanned like `app/code` |
| M3. A zip appended to a JPEG runs through `zip://` | Medium | `appended_zip`: the end record in the last 64 KB, and the central directory it points back to |
| F1. `--compare` reads `HEAD:composer.json` from the repository root | Low | `HEAD:./composer.json`, in the code and the references |
| F2. `auth.json.sample` is a "sensitive file" | Low | `.sample`, `.example` and `.dist` excluded, as for `.env` |
| F3. `--show <commit>` runs `rev-parse` on a partial clone | Low | Refused |
| F4. `$P` misses `<link href>` and `<img src>` | Limit | Documented |
| F5. `live_check` cuts headers at 300 characters | Limit | Documented |

The reviewer found these solid:
- no repository command runs, and assume-unchanged, skip-worktree and the
  index don't fool the comparison ;
- the regexes stay linear (at most 2.4 s on a 16 MB adversarial file) ;
- no false positive in obfuscation, hosts or server config on the real
  install, nor on 30,000 copies of `Installer.php` ;
- the cost: 14 s and 40 MB on the real install, 450 s on 2 GB of
  committed `app/code`, 56 s on 20,000 commits.

Not checked:
- MySQL 8 and git before 2.44 ;
- a real multi-theme `pub/static` ;
- Git LFS, an agency's `.gitignore`, `phar://` on a tar ;
- the noise of the wider HEAD comparison on a real repository (the local
  install has no commit).

The reviewer's advice: stop after this round. A round 17 should only check
these fixes.

### Round 17

A validation round of the round 16 fixes. The verdict was "not ready",
because of another false positive that stopped the audit of every
deployed Hyvä store. Fixed:

| Finding | Severity | Fix |
|---|---|---|
| É1. Hyvä's `zxcvbn.js` holds `<?= $escaper->escapeJs() ?>`, copied into `pub/static` | High | Short tags aren't looked for in `pub/static` (`PHP_OPEN_TAG_STATIC`); documented as a limit |
| M1. `appended_zip` misses a fake end record in the comment, a gap before the end record, and zip64 | Medium | Every end record in the last 64 KB is tried: a zip64 locator before it, or the central directory at its absolute or its relative offset |
| M2. A `composer.json` with `"repositories": 5`, or nested 100,000 deep, crashes the whole audit | Medium | Types checked, `RecursionError` caught |
| F1. Grafts hide a commit from the history scan | Low | `GIT_GRAFT_FILE=/dev/null` in the code and in SKILL.md; grafts read from `--git-common-dir` |
| F3. 40,000 path repositories go past ARG_MAX | Low | Only folders that exist |
| F4. `composer.json` or `composer.lock` as a FIFO hangs the audit | Low | Read through `read_small` |
| F5. `--show <commit>` reads the path from the repository root | Low | `<commit>:./<file>` |
| F2. Hyvä's `web/tailwind/node_modules` floods `ignored_files` | Low | Not fixed: the count is given, and 200 names are listed |
| F6. Secret patterns match `setup/` tests and `lib/web/*.min.js` in the history | Low | Not fixed: noise, not a miss |

The reviewer found these solid: phars (native, gzip, GIF polyglot, tar)
and malicious short tags still found; no false positive on Luma or
HugeRTE; the wider HEAD comparison is quiet and cheap on the real
install committed with `.gitignore.sample` (0.4 s); 13.7 s and 40 MB for
the whole audit.

Not checked: a real Hyvä `setup:static-content:deploy` (simulated),
`phar://` on the `appended_zip` bypasses, MySQL 8, git before 2.44, Git
LFS, Hyvä Checkout.

### Round 18

A validation round of the round 17 fixes, all confirmed but F4 (partial,
see M3). The verdict was "not ready", because of two silent passes. Every
finding was fixed:

| Finding | Severity | Fix |
|---|---|---|
| É1. The history scan is blinded by `.git/shallow` (or a `clone --depth 1`), a forged `commit-graph`, a `-diff` attribute or `core.bigFileThreshold` | High | `-c core.commitGraph=false -c core.bigFileThreshold=512m` on every git call, `--text` on `git log`, in the code and SKILL.md; a shallow repository is in `git.errors` |
| É2. Each list stops at 50 findings with no total: a backdoor after 50 legacy hits isn't listed | High | `findings_over_limit` gives each cut list's total; area 3 is "partial" then |
| M1. `config.php`'s 2FA and CSP read as on when a comment or a double-quoted duplicate turns them off | Medium | Comments out first, both quotes, the last key wins, any truthy value enables; `modules.module_entries_odd` lists duplicates and values other than 0 or 1 |
| M2. `var/view_preprocessed/`, the minified templates Magento includes, isn't read | Medium | Scanned like `app/design` (broad pattern, JavaScript, hosts); emptied during containment |
| M3. `patches.json` or the scorecard as a FIFO hangs the audit; `/dev/zero` fills the memory | Medium | Read through `read_small` |
| F1. `enabled_third_party_modules` has no bound (20,001 names, one of 2,118 characters) | Low | `shown_names(…, 500)` and a count |
| F2. IPs as one integer, in hexadecimal or `[IPv6]` aren't listed | Low | Listed in the code; documented for the SQL `hosts` (`scripts` above 0 without a host is a finding) |
| F3. `compromise.md` says path packages are audited like `app/code` when only their `vendor/` copy is there | Low | Documented |
| F4. `assets/gitignore` ignores `auth.json.sample` | Low | `!` exceptions, as for `.env` |
| F5. `live-checks.md` leaves out the hop on `/checkout/` | Low | Documented |

The reviewer found these solid: no false positive on the real Mage-OS 4.0
install (13.7 s, 40 MB; 15 s with `var/view_preprocessed`, 611 files, no
new hit); 162,730 committed files in 99 s; `ls-tree HEAD` not fooled by a
forged commit-graph; the SQL `hosts` and `$P` on MariaDB 11;
`live_check.py` read through without a defect; `--show` keeps values
masked.

Not checked: MySQL 8, git before 2.44, a real Hyvä static deploy, Magento
actually rendering a tampered minified template, `phar://` on a zip with
data before it, `live_check` against a hostile server.

The reviewer's advice: a round 19 should only check these fixes.

### Round 19

A validation round of the round 18 fixes. The shallow detection, `read_small`,
the bounded module list, the new IP forms and the `.gitignore` exceptions
held; the rest was partial. The verdict was "not ready", because the
history scan could still be blinded. Every finding was fixed:

| Finding | Severity | Fix |
|---|---|---|
| É1. `log.showRoot=false`, `log.diffMerges=off` and `diff.relative=true` hide the root commit, an evil merge, or what's outside the store's folder from the history scan | High | `-c log.showRoot=true -c log.diffMerges=separate -c diff.relative=false` on every git call and in SKILL.md |
| M1. A second `'modules'` key in `config.php` (PHP keeps it) leaves 2FA and CSP read as on; `-0`, `[]`, `!1` guessed as on | Medium | `modules_key_repeated` sets every state to `null`; a value other than 0 or 1 is `null` too; the doc no longer claims the audit reads as PHP does |
| M2. Minified core templates in `var/view_preprocessed` (`eval(grid)`, 25 vendor hosts) are false positives once `minify_html` is on | Medium | Each copy counts only for the matches and hosts its original doesn't hold |
| M3. `--text` makes `log -G` time out on gigabytes of committed media | Medium | Images, videos, PDFs and fonts left out of the secret search; documented as a limit |
| F1. Capped lists without a total (`lock_*`, `--compare`, symlinks, `not_compared`) | Low | A `_count` beside each |
| F2. A tracked `.env` at the repository's root is missed when the store is a folder of it | Low | `ls-files --full-name -- :/` |
| F3. `extra.patches-file` absolute or with `../` opens any path | Low | Refused; `open_regular` checks the type before opening |
| F4. Octal and short IPs aren't listed; `[09]` passes for an IPv6 host | Low | Documented as a limit; brackets need a `:` |

The reviewer found these solid: the shallow detection (linked worktree, a
forged `shallow`), refs/replace and grafts, `color.ui=always`, the linear
host regex, `read_small` against FIFOs and `/dev/zero`, `live_check.py`;
the real install unchanged (14 s, 40 MB, no hit). With the originals in
place, every vendor template minified gives no hit and no host (1 s).

Not checked: MySQL 8, git before 2.32 (no `log.diffMerges`, `-m` stays
"separate") and 2.44, Magento's real minifier, `live_check` against a
hostile server, Hyvä Checkout.

The reviewer's advice: stop after this round; a round 20 would only
replay these proofs of concept.

### Round 20

A validation round of the round 19 fixes: `log.showRoot`, `diffMerges`,
`diff.relative`, the media exclusions, `ls-files :/`, `patches-file` and
the IPv6 brackets held; the `modules` reading, the minified copies and the
`_count`s were partial. The verdict was "not ready", because the history
scan could still be blinded. Every finding was fixed:

| Finding | Severity | Fix |
|---|---|---|
| É1. `i18n.logOutputEncoding=UTF-16` writes `commit %h` in UTF-16: the history scan finds nothing, with no error | High | `-c i18n.logOutputEncoding=UTF-8` on every git call and in SKILL.md; the reviewer's 31 other config keys found nothing more |
| M1. `'Magento_TwoFactorAuth' => 1 -1` (PHP reads 0) or a second key spelled `"Magento_TwoFactor\x41uth"` leave 2FA read as on | Medium | The value is read up to `,`, `]` or `)` and must be exactly 0 or 1; a double-quoted key holding `\` or `$` sets every state to `null` |
| M2. A webshell in a minified core template passes when its original holds an `eval(` of its own | Medium | Matches counted against the original's (`Counter`), not looked up in a set |
| M3. A 16 MB `composer.json` (60,000 repositories) makes a 27 MB report, the signs of compromise past the cut | Medium | Its lists stop at 100, with a `_count` each |
| F1. A failed redirect on `/admin` printed its path, the site's words (or the real admin path), and urllib's error quoting it | Low | Reported as `redirect_target` with the error's type only |
| F2. `app_code_modules`, `root_folders_not_scanned`, `module_entries_odd`, `tracked_sensitive_files` and `sensitive_files_in_history` cut with no total | Low | A `_count` beside each |
| F3. No `--no-pager` in SKILL.md's git command: `core.pager` runs in a terminal | Low | `git --no-pager` |

The reviewer found these solid: a sparse index hides no untracked file;
the SQL `hosts` and `$P` on MariaDB 12.3; no false positive on the real
install (22.6 s warm, 40 MB); `--show` keeps values masked; the scorecard
filter.

Not checked: MySQL 8, git before 2.32 and 2.44, Magento's real minifier,
a real Hyvä static deploy, a large `app/code` (measured in round 16).

The reviewer's advice: a round 21 should only replay these proofs of
concept. The config keys that blind `git log` come back every round: an
allowlist (`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, only the
useful local keys) would close the family; it's left for a later decision.
