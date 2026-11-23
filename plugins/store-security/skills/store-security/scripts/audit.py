#!/usr/bin/env python3
"""Collect offline security signals about a Magento 2 / Mage-OS store for the store-security audit.

Usage: python3 audit.py <store-root>
       python3 audit.py --show <store-root> <file> [<commit>]

Prints JSON. Never prints a secret: env.php and git history are reported as facts
("crypt key committed in a1b2c3d"), not values. Every finding is a lead to verify.
--show prints the key names of a secrets file, on disk or in a commit, with every value
masked: the way to look at a hit without reading the file.

Runs none of the store's code: git is called with the repository's hooks, fsmonitor,
textconv and external diff drivers turned off, since its .git/config may be the attacker's.
"""

import bisect
import collections
import functools
import difflib
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import urllib.parse
from datetime import date
from pathlib import Path

SCORECARD_FILE = Path("var") / "mage-os-security.json"
PRODUCT_PACKAGES = (
    "magento/product-enterprise-edition",
    "mage-os/product-community-edition", "magento/product-community-edition",
    "mage-os/magento2-base", "magento/magento2-base",
)
KNOWN_PACKAGE_HOSTS = (
    "repo.packagist.org", "packagist.org", "api.github.com", "codeload.github.com", "github.com",
    "gitlab.com", "bitbucket.org", "repo.magento.com", "repo.mage-os.org", "mirror.mage-os.org",
)
# The core's vendors ship from their own repository or their own GitHub organisation, nowhere else
OFFICIAL_SOURCES = {"magento": ("repo.magento.com", "mirror.mage-os.org"), "mage-os": ("repo.mage-os.org",)}
GITHUB_HOSTS = {"github.com", "api.github.com", "codeload.github.com"}
GUESSABLE_ADMIN_PATHS = {"admin", "backend", "admin_1", "adminhtml", "magento", "manager", "administrator"}
SENSITIVE_PATHS = ["app/etc/env.php", "auth.json", ".env", "var/", "generated/", "pub/media/", "pub/static/"]
# .env and auth.json as .example / .dist / .sample hold no secrets and are meant to be committed
NEVER_TRACKED = re.compile(
    r"(^|/)(app/etc/env\.php(\.[^/]+)?|auth\.json(\.(?!example$|dist$|sample$)[^/]+)?|\.env(\.(?!example$|dist$|sample$)[^/]+)?"
    r"|[^/]+\.(sql|sql\.(gz|bz2|xz|zip)|dump|pem|key|p12|pfx)|id_(rsa|ecdsa|ed25519))$"
    r"|^[^/]+\.(tar|tar\.gz|tgz|zip)$"
    # Editor and admin copies of env.php: env.php~, env.backup.php, env.old.php
    r"|(^|/)app/etc/env[^/]*\.php[^/]*$|(^|/)app/etc/[^/]*env\.php[^/]*$"
    # direnv files and file backups, which hold env.php
    r"|(^|/)\.envrc$|(^|/)var/backups/"
)
# POSIX extended regexes for git log -G ([[:space:]], not \s: macOS git has no \s); they only
# select commits, the matched text is never printed
SECRET_PATTERNS = {
    # 2.4.7+ keys are "base64" + base64, so + / = are part of them
    "magento_crypt_key": r"['\"]key['\"][[:space:]]*=>[[:space:]]*['\"][0-9A-Za-z+/=:_]{32,}",
    "db_password": r"['\"]password['\"][[:space:]]*=>[[:space:]]*['\"][^'\"]{4,}",
    "env_file_secret": r"(PASS|PWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|pass|pwd|secret|token|api_key|private_key)[A-Za-z_]*=[^[:space:]]{4,}",
    "repo_magento_auth": r'"username"[[:space:]]*:[[:space:]]*"[0-9a-f]{32}"',
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "stripe_live_key": r"sk_live_[0-9a-zA-Z]{20,}",
    "github_token": r"gh[pousr]_[0-9A-Za-z]{36}",
}
# Strict patterns only: vendor/ is scanned with these too, and legitimate libraries use eval($code)
OBFUSCATION_STRICT = (
    r"eval\s*\([\s@\\(]*(?:['\"]\?>['\"]\s*\.\s*)?[\s@\\(]*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|strrev)\s*\("
    r"|(assert|eval|system|exec|passthru|shell_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)"
    r"|\$_(GET|POST|REQUEST|COOKIE)\s*(?:\[[^]\n]{0,200}\]\s*){1,5}\("
    r"|base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"
    r"|call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"
)
# PHP function names ignore case: EVAL(BASE64_DECODE(...)) runs too
# eval with comments between the name and its parenthesis runs too: eval/**/(, eval//x\n(
OBFUSCATION = re.compile(OBFUSCATION_STRICT + r"|create_function\s*\(|(?<![\w>:$.])eval\s*(?:(?:/\*(?s:.){0,200}?\*/|//[^\n]{0,200}\n|#[^\n]{0,200}\n)\s*)*\("
                         r"|(\\x[0-9a-fA-F]{2}){8,}|\$_(SERVER|FILES)\s*(?:\[[^]\n]{0,200}\]\s*){1,5}\(", re.IGNORECASE)
# What an include must not read: a request value (strict, vendor/ too), or a wrapper that unpacks an upload (broad).
# Found first, then an include looked for before it on its line: a regex from each include would be quadratic
INCLUDED_REQUEST = re.compile(r"\$(?:_|GLOBALS\s*\[\s*['\"]_)(GET|POST|REQUEST|COOKIE|FILES)\b")
INCLUDED_WRAPPER = re.compile(r"(?:phar|compress\.zlib|zip|data)://|php://filter", re.IGNORECASE)
INCLUDE_WORD = re.compile(r"\b(include|require)(_once)?\b", re.IGNORECASE)
OBFUSCATION_VENDOR = re.compile(OBFUSCATION_STRICT, re.IGNORECASE)
# Markup that runs script, in a config value: env.php and config.php's 'system' part win over the database
CONFIG_VALUE_SCRIPT = re.compile(r"<\s*(script|iframe|object|embed)\b|<meta[^>]{0,500}http-equiv|srcdoc|(?<![\w-])on[a-z]+\s*=|javascript:|\\u003c|&lt;\s*script", re.IGNORECASE)
# Where a script or a request goes, in the store's own code (vendor/ is compared with a clean install instead):
# the host only, JSON's https:\/\/ included. Right after a quote, a backtick, (, = or an XML tag: a link in a comment runs nothing
EXTERNAL_HOST = re.compile(
    r"[\"'`(=>]\s*(?:https?:|wss?:)?[\\/]{2,4}((?:(?:[^\W_]|-)+\.)+(?:[^\W\d_]{2,24}|xn--[a-z0-9-]{1,59})|[0-9]{1,3}(?:\.[0-9]{1,3}){3}"
    # IPs a browser reads too: one integer, hexadecimal parts, IPv6 in brackets
    r"|[0-9]{8,10}|0x[0-9a-f]{1,8}(?:\.(?:0x[0-9a-f]{1,8}|[0-9]{1,3})){0,3}|\[[0-9a-f.]{0,40}:[0-9a-f:.]{1,44}\])(?![^\W_]|-)",
    re.IGNORECASE)
# XML namespaces, never fetched, and names reserved for examples and tests
IGNORED_HOSTS = re.compile(r"(?:.*\.)?(?:w3\.org|example\.(?:com|net|org)|localhost)|.*\.(?:test|example|invalid|localhost)"
                           r"|.*\.(?:jpe?g|png|gif|svg|webp|css|js|php|html?)")
# A module's PHP tests: listed last, since app/code's PSR-0 autoloader still loads one a di.xml names
TEST_FOLDER = re.compile(r"app/code/[^/]+/[^/]+/Test/.*\.php")
# Front-end files first: that's where a skimmer loads from or sends to
HOST_SUFFIXES = (".php", ".phtml", ".html", ".js", ".xml", ".json")
FRONT_END_SUFFIXES = {".phtml", ".html", ".js", ".xml"}
MAX_HOSTS = 300
MAX_HOSTS_KEPT = 5000
# Skimmer tells in JavaScript: decoded-then-run code, a raw WebSocket out, long hex escapes
JS_SKIMMER = re.compile(
    r"eval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\("
    r"|new\s+Function\s*\(\s*atob\s*\("
    r"|new\s+WebSocket\s*\(\s*['\"`]wss?://"
    r"|(\\x[0-9a-fA-F]{2}){40,}"
)
# In the store's own app/: a decoded payload or a beacon out is rare enough to read every hit (none in the core or Hyvä)
JS_SKIMMER_APP = re.compile(JS_SKIMMER.pattern + r"|\batob\s*\(|\bsendBeacon\s*\(")
# Words each pattern needs: a file without any of them is skipped before the (much slower) regex runs
TRIGGERS = {
    "strict": ("eval", "$_"),
    "broad": ("eval", "$_", "create_function", "\\x"),
    "javascript": ("eval", "Function", "WebSocket", "\\x"),
    "javascript_app": ("eval", "Function", "WebSocket", "\\x", "atob", "sendBeacon"),
}
# x.php.jpg runs as PHP under mod_mime's AddHandler; .phps shows the source
PHP_EXTENSION = re.compile(r"\.(php\d?|pht|phtml|phar|inc|phps)$|\.(php\d?|pht|phtml|phar)\.[^./]+$", re.IGNORECASE)
# <?php, a short <?= or <? tag followed by printable code (random bytes in an image hold "<?=$" about once a GB),
# a phar stub (__HALT_COMPILER(), not the bare word a syntax highlighter lists), or <?php in base64 at each of its three alignments (read through php://filter)
PHP_LONG_TAG = rb"<\?[pP][hH][pP]\s|__[hH][aA][lL][tT]_[cC][oO][mM][pP][iI][lL][eE][rR]\s*\(\s*\)|PD9waHA|Dw/cGhw|8P3BocC"
PHP_OPEN_TAG = re.compile(PHP_LONG_TAG + rb"|<\?(?:=(?!>)|\s)(?:[\x09-\x0d\x20-\x3b\x3d-\x7e]|<(?!\?)){4,500}?\?>"
                          rb"|<\?=(?!>)(?:[\x09-\x0d\x20-\x3b\x3d-\x7e]|<(?!\?)){12}")
# pub/static copies themes' web/ files, and Hyva's zxcvbn.js holds <?= $escaper->escapeJs() ?>: short tags aren't looked for there
PHP_OPEN_TAG_STATIC = re.compile(PHP_LONG_TAG)
# An upload that is a zip or gzip under another name: phar:// and compress.zlib:// run the PHP packed inside
ARCHIVE_SUFFIXES = {".zip", ".gz", ".tgz", ".jar", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub", ".apk", ".svgz", ".bz2", ".tbz2"}
IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif"}
ARCHIVE_MAGIC = (b"PK\x03\x04", b"\x1f\x8b", b"BZh")
# A zip's end record sits in its last 64 KB (its comment's maximum) plus 22 bytes
ZIP_END_SEARCH_BYTES = 65557
# A handler or type naming PHP makes the server run it (Magento's own "AddHandler cgi-script .php" in
# pub/media does the opposite); engine on re-enables PHP where Magento turns it off
SERVER_CONFIG_RISK = re.compile(
    r"auto_(prepend|append)_file|(AddType|AddHandler|SetHandler|ForceType)\s+[\"']?\S*(php|x-httpd|proxy:fcgi|proxy:unix|fcgid-script)"
    r"|php_(admin_)?(flag|value)\s+engine\s+(1|on)\b|php_admin_value"
    # A directive starts its line: anchored, so a line of repeats is read once
    r"|^\s*Options\s[^\n#]{0,500}?(?<![-\w])\+?(ExecCGI|All|Includes)\b"
    r"|^\s*RewriteRule\s[^\n#]{0,500}?\[[^]\n]{0,200}?\b[HT]=[^]\n]{0,100}?php", re.IGNORECASE)
# Magento ships these two, with memory and execution limits
SHIPPED_USER_INI = {".user.ini", "pub/.user.ini"}
# env.php and config.php are "return [...];" and nothing else: they run on every request and every command
APP_ETC_CONFIG = {"app/etc/env.php", "app/etc/config.php", "app/etc/vendor_path.php"}
# app/autoload.php loads vendor/ from the folder this file returns: anything else loads another vendor/
# PHP keywords ignore case, a Linux path doesn't: './VENDOR' is another folder
VENDOR_PATH_RETURN = re.compile(r"\s*(?i:<\?php)\s+(?:(?i:declare)\s*\(\s*(?i:strict_types)\s*=\s*1\s*\)\s*;\s*)?(?i:return)\s*'(?:\./)?vendor/?'\s*;\s*")
# Files in app/etc that come from neither magento2-base's map nor the store's own config: an added *di.xml is read
APP_ETC_KNOWN = {"env.php", "config.php", "vendor_path.php", "hyva-themes.json"}
# #[ opens a PHP 8 attribute, code to the end of the line; a string or comment never closed ends with the file, so an
# unclosed quote can't make the match quadratic
STRINGS_AND_COMMENTS = re.compile(r"'(?:\\.|[^'\\])*(?:'|\\?\Z)|\"(?:\\.|[^\"\\])*(?:\"|\\?\Z)|//(?:[^\r\n?]|\?(?!>))*|#(?!\[)(?:[^\r\n?]|\?(?!>))*|/\*.*?(?:\*/|\Z)", re.DOTALL)
# What an env.php or config.php may hold once strings and comments are out; anything left is code, whatever it
# looks like (('system')('id'), print, a call on an array item)
CONFIG_ALLOWED = re.compile(
    r"<\?php\b|\breturn\b|\barray\s*\(|\bgetenv\s*\(\s*\)|\bdeclare\s*\(\s*strict_types\s*=\s*1\s*\)"
    r"|\\?Magento\\Framework(?:\\\w+)+::[A-Za-z_]\w*|(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])|\b(?:true|false|null)\b|=>|[\[\]),;]", re.IGNORECASE)
DOUBLE_QUOTED_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]|u\{|[0-7])")
BASE_URL_KEY = re.compile(r"(['\"])base_(?:static_|media_|link_)?url\1")
BASE_URL_VALUE = re.compile(r"\s*=>\s*(['\"])([^'\"]{0,300})\1")
# An include runs PHP wherever it sits in the file: uploads are read whole, in chunks, up to this size, then their end
MEDIA_READ_MAX_BYTES = 16 * 1024 * 1024
MEDIA_CHUNK_BYTES = 1024 * 1024
# Longer than the longest tag match, so one cut between two chunks is still found
MEDIA_OVERLAP_BYTES = 512
SCAN_FILE_MAX_BYTES = 2 * 1024 * 1024
# Code is read up to this size: a backdoor padded past 2 MB is still read (the patterns are bounded, so it stays fast)
CODE_FILE_MAX_BYTES = 16 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 120
# The repository's own config can run commands (hooks, fsmonitor, textconv, external diff, the signature
# verifier behind log.showSignature): turn them off. A forged commit-graph cuts a commit's parents, and
# core.bigFileThreshold makes files binary to log -G: read the commits themselves, at git's default threshold.
# log.showRoot, log.diffMerges and diff.relative would hide the root commit, merges, or what's outside the store's folder;
# i18n.logOutputEncoding (UTF-16) would turn log's "commit " lines into bytes nothing matches
GIT_SAFE_OPTIONS = (
    "-c", "i18n.logOutputEncoding=UTF-8", "-c", "core.commitGraph=false", "-c", "core.bigFileThreshold=512m", "-c", "log.showRoot=true",
    "-c", "log.diffMerges=separate", "-c", "diff.relative=false", "-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null", "-c", "core.quotePath=false", "-c", "diff.external=", "-c", "core.pager=cat",
    "-c", "log.showSignature=false", "-c", "gpg.program=false", "-c", "gpg.ssh.program=false", "-c", "gpg.x509.program=false",
)
# --text: a "-diff" attribute (.git/info/attributes, core.attributesFile) would hide a file from log -G
GIT_SAFE_LOG = ("--no-textconv", "--no-ext-diff", "--no-show-signature", "--text")
# Read as text, committed images and videos make every log -G run past its timeout: they hold no secret to find
BINARY_SUFFIXES = ("jpg", "jpeg", "png", "gif", "webp", "avif", "ico", "bmp", "tif", "tiff", "psd", "mp4", "webm", "mov", "avi",
                   "mp3", "wav", "ogg", "pdf", "woff", "woff2", "ttf", "otf", "eot")
SECRET_SEARCH_PATHSPECS = (":/", *(f":(top,exclude,glob,icase)**/*.{suffix}" for suffix in BINARY_SUFFIXES))
# English messages, so a refusal is recognized whatever the machine's language
# GIT_NO_LAZY_FETCH: a partial clone would fetch a missing object with the repository's own commands
# (remote.*.uploadpack, core.sshCommand, a credential helper); git before 2.44 ignores it, see lazy_fetch_possible.
# GIT_NO_REPLACE_OBJECTS, GIT_GRAFT_FILE: refs/replace and info/grafts would swap HEAD's tree, or hide a commit from
# the history, without changing any id
GIT_ENVIRONMENT = {**os.environ, "LC_ALL": "C", "LANGUAGE": "C", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
                   "GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": os.devnull}
# Commands that read objects, which a partial clone may lack
GIT_OBJECT_READERS = {"log", "show", "ls-tree", "cat-file", "rev-list"}
# Deployer, Capistrano and most hosts link these to a shared folder
TOP_SYMLINKS_FOLLOWED = {"pub/media", "pub/static", "app/etc"}
# Kernel and device files: reading them can block or consume them
SYSTEM_FOLDERS = ("/proc", "/sys", "/dev", "/run", "/boot")
# bin/ holds bin/magento, PHP without an extension, run by cron and by the agent
SCANNED_FOLDERS = ("app", "bin", "dev", "generated", "lib", "phpserver", "pub", "setup", "vendor")
# Root folders left out on purpose: logs and caches, git's own, front-end tooling
UNSCANNED_ROOT_FOLDERS = {"var", ".git", "node_modules"}
# Except the minified templates (dev/template/minify_html), which Magento includes instead of the originals
PREPROCESSED_FOLDER = "var/view_preprocessed"
PREPROCESSED_STATIC = PREPROCESSED_FOLDER + "/pub/static/"
# php.ini in a folder applies to it under suPHP and CGI, like .user.ini under PHP-FPM
SERVER_FILES = (".htaccess", ".user.ini", "php.ini")
HITS_PER_CHECK = 50
# How long a static content deploy may run after writing deployed_version.txt
STATIC_DEPLOY_WINDOW_SECONDS = 2 * 3600
# A link's target goes out only as a plain path: a folder name is text the attacker chose
SHOWN_PATH = r"[\w./@+-]{1,300}"
# What Magento ships under pub/, outside media and static; a custom error skin adds its own .phtml
SHIPPED_PUB_PHP = re.compile(
    r"pub/(index|get|static|health_check|cron)\.php"
    r"|pub/errors/(404|503|noCache|processor|processorFactory|report)\.php|pub/errors/[^/]+/[^/]+\.phtml"
)
# A secrets-file line that names a key; the value after it is never printed. Keys must be quoted
# (PHP, JSON) or, in .env files only, shell names: the second line of a rotated crypt key is bare
# base64, whose = padding would otherwise pass for "name = value"
KEY_LINE = re.compile(r"""^\s*((['"])[^'"]{1,80}\2)\s*(=>|:)""")
ENV_KEY_LINE = re.compile(r"^\s*((?:export\s+)?[A-Za-z_][A-Za-z0-9_]{0,80})\s*(=)")
# Decision key -> the choices SKILL.md allows: anything else in the scorecard is dropped
DECISION_CHOICES = {
    "patches.upgrade": {"upgrade", "isolated_patches", "declined"},
    "dependencies.update": {"accepted", "declined"},
    "secrets.rotate_crypt_key": {"accepted", "declined"},
    "secrets.rewrite_history": {"accepted", "declined"},
    "admin.two_factor_auth": {"accepted", "declined"},
    "admin.custom_path": {"accepted", "declined"},
    "configuration.csp_restrict": {"accepted", "declined"},
    "live_site.check": {"accepted", "declined"},
}
# Decisions that always come back. 2FA is among them: a stolen admin password is how most skimmers get in,
# and PCI DSS 8.4 requires MFA for admin access
CRITICAL_DECISIONS = {"patches.upgrade", "dependencies.update", "secrets.rotate_crypt_key", "admin.two_factor_auth"}
# A Critical decision put off comes back after this many days at most, whatever the file says
CRITICAL_MAX_DELAY_DAYS = 90
ISO_DATE = r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
VERSION = r"[0-9][0-9A-Za-z.+-]{0,30}"
# No spaces: a URL can't carry a sentence
URL = r"[\w.:/@*~%+=&-]{1,200}"
AREA_KEYS = {"version_and_patches", "dependencies", "compromise", "secrets", "admin", "configuration", "live_site"}
AREA_STATUSES = {"pass", "partial", "fail", "not_checked"}


def shown_name(path: str) -> str:
    """A file name as it goes out: the attacker chose it, so path characters only, each part cut short."""
    return "/".join(re.sub(r"[^\w.@+:~-]", "?", part)[:80] for part in path.split("/"))


def shown_names(paths, limit: int) -> list[str]:
    return [shown_name(path) for path in sorted(paths)[:limit]]


@functools.cache
def lazy_fetch_possible(root: Path) -> bool:
    """A partial clone: no object is read from it, whatever git's version."""
    result = run_git(root, "config", "--get-regexp", r"^(extensions\.partialclone|remote\..*\.promisor)$")
    return result is None or result.returncode not in (0, 1) or bool(result.stdout.strip())


def run_git(root: Path, *arguments: str) -> subprocess.CompletedProcess | None:
    if arguments[0] in GIT_OBJECT_READERS and lazy_fetch_possible(root):
        return None
    try:
        return subprocess.run(["git", *GIT_SAFE_OPTIONS, "-C", str(root), *arguments], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=GIT_TIMEOUT_SECONDS, stdin=subprocess.DEVNULL, env=GIT_ENVIRONMENT)
    except (OSError, subprocess.TimeoutExpired):
        return None


def git(root: Path, *arguments: str, ok_codes: tuple = (0,)) -> str | None:
    result = run_git(root, *arguments)
    return result.stdout if result is not None and result.returncode in ok_codes else None


def read_version(root: Path) -> dict:
    lock = root / "composer.lock"
    if not lock.exists():
        return {"composer_lock": False}
    packages = {package["name"]: package for package in json.loads(read_small(lock, CODE_FILE_MAX_BYTES) or "").get("packages", [])}
    composer = root / "composer.json"
    direct = set(json.loads(read_small(composer, CODE_FILE_MAX_BYTES) or "").get("require", {})) if composer.exists() else set()
    product = next((name for name in PRODUCT_PACKAGES if name in packages), None)
    distribution = None
    if product:
        distribution = "adobe-commerce" if "enterprise" in product else "mage-os" if product.startswith("mage-os/") else "magento"
    return {
        "composer_lock": True,
        **unexpected_lock_hosts(root, packages.values()),
        # Installed from a folder on the server: the store's own code, like app/code, not in any comparison
        "lock_path_packages": sorted(plain(name) for name, package in packages.items()
                                     if isinstance(package.get("dist"), dict) and package["dist"].get("type") == "path")[:50],
        "lock_path_packages_count": sum(1 for package in packages.values() if isinstance(package.get("dist"), dict) and package["dist"].get("type") == "path"),
        "distribution": distribution,
        "product_package": product,
        "version": plain(str(packages[product].get("version", "")).lstrip("v"), VERSION) if product else None,
        "quality_patches_installed": "magento/quality-patches" in packages,
        "composer_patches_installed": "cweagans/composer-patches" in packages,
        # Abandoned packages the core pulls in are the core's problem: only direct requirements are the store's
        "abandoned_direct_requirements": sorted(plain(name) for name, package in packages.items() if package.get("abandoned") and name in direct),
        "abandoned_through_core_or_extensions": len([name for name, package in packages.items() if package.get("abandoned") and name not in direct]),
        "package_count": len(packages),
    }


def plain(text, pattern: str = r"[a-z0-9_.-]{1,100}(/[a-z0-9_.-]{1,100})?") -> str:
    """A package name or host from composer.lock, or "?": the lock is attacker-writable, no free text gets out."""
    return text if isinstance(text, str) and re.fullmatch(pattern, text) else "?"


def github_owner(url: str) -> str | None:
    parsed = urllib.parse.urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.hostname not in GITHUB_HOSTS or not parts:
        return None
    return (parts[1] if parts[0] == "repos" and len(parts) > 1 else parts[0]).lower()


def unexpected_lock_hosts(root: Path, packages) -> dict:
    """Packages composer.lock downloads from where they shouldn't: a lock and a vendor/ altered together pass a
    clean-install comparison. Core vendors must come from their own repository or GitHub organisation; other
    packages from a public registry or a repository composer.json declares, and a GitHub download from the
    owner of the package's source."""
    composer = root / "composer.json"
    repositories = json.loads(read_small(composer, CODE_FILE_MAX_BYTES) or "").get("repositories", []) if composer.exists() else []
    repositories = repositories.values() if isinstance(repositories, dict) else repositories if isinstance(repositories, list) else []
    known = set(KNOWN_PACKAGE_HOSTS)
    for entry in repositories:
        try:
            known.add(urllib.parse.urlparse(str(entry.get("url", ""))).hostname if isinstance(entry, dict) else None)
        except ValueError:
            pass
    # A path or SSH repository has no host: it mustn't make every host-less URL (file://, /var/tmp/x.zip) pass
    known.discard(None)
    found = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = plain(package.get("name"))
        vendor = name.split("/")[0]
        owners = {}
        for kind in ("dist", "source"):
            entry = package.get(kind) if isinstance(package.get(kind), dict) else {}
            if entry.get("type") == "path" or not entry.get("url"):
                continue
            # One unparsable URL is a finding, not a reason to drop the whole check
            try:
                parsed = urllib.parse.urlparse(str(entry["url"]))
                host, owners[kind] = parsed.hostname, github_owner(str(entry["url"]))
            except ValueError:
                found.append({"package": name, kind: "unparsable URL"})
                continue
            # The client resolves /magento/../attacker/ to /attacker/: the owner read here wouldn't be the real one
            if ".." in urllib.parse.unquote(parsed.path).split("/"):
                found.append({"package": name, kind: "URL with ../"})
                continue
            allowed = host in OFFICIAL_SOURCES[vendor] or owners[kind] == vendor if vendor in OFFICIAL_SOURCES else host in known
            if not allowed:
                found.append({"package": name, kind: plain(host) if host else "no host"})
        if owners.get("dist") and owners.get("source") and owners["dist"] != owners["source"]:
            found.append({"package": name, "dist": f"github.com/{plain(owners['dist'])}", "source": f"github.com/{plain(owners['source'])}"})
    return {"lock_unexpected_hosts": found[:50], "lock_unexpected_hosts_count": len(found)}


def read_composer_patches(root: Path) -> dict:
    composer = root / "composer.json"
    if not composer.exists():
        return {}
    extra = json.loads(read_small(composer, CODE_FILE_MAX_BYTES) or "").get("extra", {})
    patches = dict(extra.get("patches", {})) if isinstance(extra, dict) else {}
    # composer-patches v1 names the file in extra.patches-file; v2 reads patches.json by default
    patches_file = (extra.get("patches-file") if isinstance(extra, dict) else None) or "patches.json"
    if not isinstance(patches_file, str) or Path(patches_file).is_absolute() or ".." in Path(patches_file).parts:
        raise ValueError("extra.patches-file points outside the store")
    if (root / patches_file).exists():
        source = read_small(root / patches_file, CODE_FILE_MAX_BYTES)
        if source is None:
            raise ValueError("the patch list isn't a regular file under 16 MB")
        patches.update(json.loads(source).get("patches", {}))
    # How many patches each package gets, not their descriptions: free text the attacker can write
    return {plain(package): len(entries) if isinstance(entries, (dict, list)) else 1 for package, entries in patches.items()}


def mask_url(url: str) -> str:
    """Repository URLs can carry credentials (https://user:token@host, ?access_token=): drop both."""
    return re.sub(r"(?<=://)[^/@]+@", "***@", url.split("?", 1)[0].split("#", 1)[0])


def read_composer_config(root: Path) -> dict:
    """Where Composer fetches code from and which plugins may run: both are ways in for an attacker."""
    composer = root / "composer.json"
    if not composer.exists():
        return {}
    data = json.loads(read_small(composer, CODE_FILE_MAX_BYTES) or "")
    repositories = data.get("repositories", [])
    repositories = repositories.values() if isinstance(repositories, dict) else repositories
    config = data.get("config", {}) if isinstance(data.get("config"), dict) else {}
    allow_plugins = config.get("allow-plugins")
    repositories = [entry for entry in repositories if isinstance(entry, dict)]
    insecure = [entry for entry in repositories if str(entry.get("url", "")).startswith("http://")]
    plugins = sorted(name for name, allowed in allow_plugins.items() if allowed) if isinstance(allow_plugins, dict) else []
    scripts = sorted(data["scripts"]) if isinstance(data.get("scripts"), dict) else []
    # Capped: a composer.json the attacker wrote would bury the rest of the report
    return {
        "repositories": [{"type": plain(entry.get("type"), r"[a-z-]{1,20}"), "url": plain(mask_url(str(entry.get("url", ""))), URL)}
                         for entry in repositories[:100]],
        "repositories_count": len(repositories),
        "insecure_repositories": [plain(mask_url(str(entry.get("url", ""))), URL) for entry in insecure[:100]],
        "insecure_repositories_count": len(insecure),
        "secure_http_disabled": config.get("secure-http") is False,
        "allow_plugins": "all" if allow_plugins is True else [plain(name, r"[a-z0-9_.*/-]{1,100}") for name in plugins[:100]] if isinstance(allow_plugins, dict) else None,
        "allow_plugins_count": len(plugins),
        # composer audit obeys these: run it in the clean folder, from the committed composer.json
        "audit_ignored_advisories": len(config["audit"].get("ignore") or []) if isinstance(config.get("audit"), dict) else 0,
        "audit_abandoned": plain(config["audit"].get("abandoned"), r"[a-z]{1,10}") if isinstance(config.get("audit"), dict) and config["audit"].get("abandoned") else None,
        "scripts": [plain(name, r"[\w:.-]{1,60}") for name in scripts[:100]],
        "scripts_count": len(scripts),
    }


def list_app_code_modules(root: Path) -> list[str]:
    base = root / "app" / "code"
    return [f"{vendor.name}_{module.name}" for vendor in base.iterdir() if vendor.is_dir() for module in vendor.iterdir() if module.is_dir()] if base.is_dir() else []


def php_string(source: str, key: str) -> str | None:
    found = re.findall(rf"""(['"]){re.escape(key)}\1\s*=>\s*(['"])([^'"]*)\2""", PHP_COMMENTS.sub(lambda match: match.group(1) or "", source))
    return found[-1][2] if found else None


def open_regular(path: Path):
    """The open file and its stat, or None and the stat: opened without blocking, then checked, so a FIFO or
    /dev/zero behind the name, or swapped in after the walk, can't hang the audit."""
    # Checked before opening too: opening some devices does something
    if not stat.S_ISREG(os.stat(path).st_mode):
        return None, os.stat(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        return None, info
    return os.fdopen(descriptor, "rb"), info


def read_small(path: Path, limit: int = SCAN_FILE_MAX_BYTES) -> str | None:
    """A regular file under the size cap, or None."""
    try:
        handle, info = open_regular(path)
        if handle is None:
            return None
        with handle:
            return None if info.st_size > limit else handle.read().decode(errors="ignore")
    except OSError:
        return None


def read_env(root: Path) -> dict:
    """Facts about env.php, never its secret values."""
    env = root / "app" / "etc" / "env.php"
    if not env.exists():
        return {"present": False}
    source = read_small(env)
    if source is None:
        return {"present": True, "error": "not a regular file under 2 MB: not read"}
    front_name = php_string(source, "frontName")
    return {
        "present": True,
        "mage_mode": plain(php_string(source, "MAGE_MODE"), r"[a-z]{1,20}") if php_string(source, "MAGE_MODE") else None,
        "admin_path_guessable": (front_name or "admin").lower() in GUESSABLE_ADMIN_PATHS,
        "admin_path_length": len(front_name) if front_name else None,
        "x_frame_options": plain(php_string(source, "x-frame-options"), r"[A-Za-z-]{1,20}") if php_string(source, "x-frame-options") else None,
        "has_crypt_key": "'crypt'" in source,
    }


def dumped_config_sections(root: Path) -> list[str]:
    """Config sections kept in files (app:config:dump), which win over the database: only the 'system' part counts."""
    sections = set()
    for name in ("config.php", "env.php"):
        path = root / "app" / "etc" / name
        source = read_small(path) or ""
        start = source.find("'system'")
        if start >= 0:
            sections |= set(re.findall(r"'(csp|admin|web|dev|twofactorauth|webapi|design|payment|checkout|sales|customer|google|cms|general|catalog|oauth|system)'\s*=>", source[start:]))
    return sorted(sections)


def read_enabled_modules(root: Path) -> dict:
    config = root / "app" / "etc" / "config.php"
    if not config.exists():
        return {"present": False}
    source = read_small(config)
    if source is None:
        return {"present": True, "error": "not a regular file under 2 MB: not read"}
    # Comments out, strings kept: a commented-out "=> 1" mustn't pass for the value PHP reads
    code = STRINGS_AND_COMMENTS.sub(lambda match: match.group() if match.group()[0] in "'\"" else " ", source)
    starts = list(re.finditer(r"(['\"])modules\1\s*=>", code))
    region = code[starts[0].start():] if starts else ""
    entries = [(quote, name, value.strip()) for quote, name, value in re.findall(r"(['\"])([A-Z]\w*_\w+)\1\s*=>\s*([^,\]\)]+)", region)]
    # PHP keeps the last of two equal keys; a value Magento never writes (-0, 1 -1, [], an expression) is unknown, not guessed
    state = {name: True if value == "1" else False if value == "0" else None for _, name, value in entries}
    # Two 'modules' keys: PHP keeps the second array, which this doesn't follow; "Magento_TwoFactor\x41uth" is a key this
    # doesn't read either
    repeated = len(starts) > 1
    if repeated or re.search(r'"[^"]*[\\$][^"]*"\s*=>', region):
        state = dict.fromkeys(state)
    names = collections.Counter(name for _, name, _ in entries)
    odd = {name for _, name, value in entries if names[name] > 1 or value not in ("0", "1")}
    return {
        "present": True,
        "two_factor_auth": state.get("Magento_TwoFactorAuth"),
        "csp": state.get("Magento_Csp"),
        "captcha": state.get("Magento_Captcha"),
        "admin_adobe_ims": state.get("Magento_AdminAdobeIms"),
        "version_module": state.get("Magento_Version"),
        # Unknown states included: a module that may be enabled
        "enabled_third_party_modules": shown_names([name for name, enabled in state.items() if enabled is not False and not name.startswith(("Magento_", "MageOS_"))], 500),
        "enabled_third_party_modules_count": sum(1 for name, enabled in state.items() if enabled is not False and not name.startswith(("Magento_", "MageOS_"))),
        "modules_key_repeated": repeated,
        # Set twice, or to something else than 0 or 1: Magento never writes either
        "module_entries_odd": shown_names(odd, 50),
        "module_entries_odd_count": len(odd),
        "dumped_config_paths": dumped_config_sections(root),
    }


# Everything the last commit tracks is the store's own code, which no clean install has, except what Composer,
# Magento and uploads write (path repositories, .ddev and the store root's files included)
HEAD_NOT_COMPARED = ("vendor/", "var/", "generated/", "pub/media/", "pub/static/", "node_modules/")
HEAD_PATHSPECS = (".", *(f":(exclude){prefix.rstrip('/')}" for prefix in HEAD_NOT_COMPARED))
# Where nothing is ignored on purpose: an ignored file there is hidden from the comparison
HEAD_NEVER_IGNORED = ("app/code", "app/design", ":(glob)*.php", ":(glob)*.phtml")


def head_compared(path: str) -> bool:
    return not path.startswith(HEAD_NOT_COMPARED) and path != "app/etc/env.php"


@functools.cache
def path_repository_folders(root: Path) -> tuple[str, ...]:
    """Root folders that composer.json's path repositories install from (packages/* and the like)."""
    try:
        data = json.loads(read_small(root / "composer.json", CODE_FILE_MAX_BYTES) or "{}")
    except (ValueError, RecursionError):
        return ()
    repositories = data.get("repositories") if isinstance(data, dict) else None
    repositories = list(repositories.values()) if isinstance(repositories, dict) else repositories if isinstance(repositories, list) else []
    folders = set()
    for repository in repositories:
        url = repository.get("url") if isinstance(repository, dict) and repository.get("type") == "path" else None
        top = url.replace("\\", "/").removeprefix("./").split("/", 1)[0] if isinstance(url, str) else ""
        if re.fullmatch(r"[\w.-]+", top) and top not in ("..", ".") and top not in SCANNED_FOLDERS and top not in UNSCANNED_ROOT_FOLDERS \
                and (root / top).is_dir():
            folders.add(top)
    return tuple(sorted(folders))


def git_paths(root: Path, *arguments: str) -> list[str] | None:
    output = git(root, *arguments)
    return None if output is None else [path for path in output.split("\0") if path]


def head_differences(root: Path) -> dict:
    """Tracked files of the store's own code that differ from HEAD or are gone, and the files there HEAD doesn't have.
    The hash is git's (sha1 or sha256 of "blob <size>\\0" + content), computed here: git status would run the
    repository's filters. Paths are relative to the store root, which can be a folder of the repository."""
    top = git(root, "rev-parse", "--show-toplevel")
    # core.worktree can point git at another folder than the one audited
    if top is None or not root.resolve().is_relative_to(Path(top.strip()).resolve()):
        return {"error": "the repository's work tree isn't the store: not compared"}
    tree = git(root, "ls-tree", "-r", "-z", "HEAD")
    if tree is None:
        return {"error": "no commit to compare with, or a partial clone: not compared"}
    differ, missing, not_compared, in_head = [], [], [], set()
    for entry in tree.split("\0"):
        meta, _, path = entry.partition("\t")
        fields = meta.split()
        if len(fields) != 3 or not head_compared(path):
            continue
        in_head.add(path)
        mode, kind, expected = fields
        full = root / path
        if kind != "blob":
            # A submodule: its files are another repository's
            not_compared.append(path)
            continue
        try:
            if mode == "120000":
                data = os.readlink(full).encode() if full.is_symlink() else None
            else:
                handle, info = open_regular(full)
                data = None
                if handle is not None:
                    with handle:
                        if info.st_size > CODE_FILE_MAX_BYTES:
                            not_compared.append(path)
                            continue
                        data = handle.read()
        except FileNotFoundError:
            missing.append(path)
            continue
        except OSError:
            not_compared.append(path)
            continue

        def digest(content: bytes) -> str:
            return hashlib.new("sha1" if len(expected) == 40 else "sha256", b"blob %d\0" % len(content) + content).hexdigest()
        # A checkout with eol=crlf or core.autocrlf writes CRLF where the commit has LF
        if data is None or (digest(data) != expected and (b"\r\n" not in data or digest(data.replace(b"\r\n", b"\n")) != expected)):
            differ.append(path)
    staged = git_paths(root, "ls-files", "-z", "--cached", "--", *HEAD_PATHSPECS)
    untracked = git_paths(root, "ls-files", "-z", "--others", "--exclude-standard", "--", *HEAD_PATHSPECS)
    ignored = git_paths(root, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--", *HEAD_NEVER_IGNORED,
                        *path_repository_folders(root))
    if staged is None or untracked is None or ignored is None:
        return {"error": "git ls-files failed or timed out: not compared"}
    added = sorted({path for path in staged if path not in in_head} | set(untracked))
    added = [path for path in added if head_compared(path)]
    ignored = [path for path in ignored if head_compared(path)]
    return {
        "files_compared": len(in_head),
        "files_differ": shown_names(differ, 200), "files_differ_count": len(differ),
        "files_missing": shown_names(missing, 50), "files_missing_count": len(missing),
        "untracked_files": shown_names(added, 200), "untracked_files_count": len(added),
        "ignored_files": shown_names(ignored, 200), "ignored_files_count": len(ignored),
        "not_compared": shown_names(not_compared, 50), "not_compared_count": len(not_compared),
        # git replace and grafts make the history lie; this comparison ignores them, but someone put them there
        "replace_refs_or_grafts": bool(git(root, "for-each-ref", "--count=1", "refs/replace/"))
        # --git-path would answer GIT_GRAFT_FILE, which is /dev/null here
        or (root / (git(root, "rev-parse", "--git-common-dir") or "").strip() / "info" / "grafts").is_file(),
    }


def read_git(root: Path) -> dict:
    probe = run_git(root, "rev-parse", "--is-inside-work-tree")
    if probe is None:
        return {"is_git_repository": None, "error": "git missing or timed out: secrets in git not checked"}
    if probe.returncode != 0:
        if "dubious ownership" in probe.stderr or "safe.directory" in probe.stderr:
            # Not bypassed with safe.directory: that check exists so a stranger's .git/config can't run code
            return {"is_git_repository": None, "error": "git refuses the repository (dubious ownership): run as its owner"}
        if "not a git repository" in probe.stderr:
            return {"is_git_repository": False}
        return {"is_git_repository": None, "error": "git rev-parse failed: secrets in git not checked"}
    errors = []
    if lazy_fetch_possible(root):
        errors.append("partial clone: git would fetch missing objects with the repository's own commands, history not read")
    # A clone --depth 1, or a .git/shallow the attacker wrote: the commits before it aren't read
    if (git(root, "rev-parse", "--is-shallow-repository") or "").strip() == "true":
        errors.append("shallow clone: history incomplete, secrets in older commits not checked")

    def lines(*arguments: str, ok_codes: tuple = (0,)) -> list[str]:
        output = git(root, *arguments, ok_codes=ok_codes)
        if output is None:
            errors.append(f"git {arguments[0]} failed or timed out")
        return (output or "").splitlines()

    # The whole repository, when the store is one of its folders
    tracked = [path for line in lines("ls-files", "-z", "--full-name", "--", ":/") for path in line.split("\0") if path]
    # A filter's command runs on git status, diff and add in the working tree; no -c option turns them all
    # off, since each has its own name: the agent avoids those commands while one is set
    # The repository's own config, worktree config and its includes; a global filter (git-lfs) is the user's own
    scoped = git(root, "config", "--show-scope", "--includes", "--get-regexp", r"^filter\.", ok_codes=(0, 1))
    if scoped is not None:
        filters = [line.split("\t", 1)[1] for line in scoped.splitlines() if "\t" in line and line.split("\t", 1)[0] in ("local", "worktree")]
    else:
        # git before 2.26 has no --show-scope; worktree config needs extensions.worktreeConfig, read from .git/config
        filters = lines("config", "--local", "--includes", "--get-regexp", r"^filter\.", ok_codes=(0, 1))
        filters += (git(root, "config", "--worktree", "--get-regexp", r"^filter\.", ok_codes=(0, 1)) or "").splitlines()
    # check-ignore exits 1 when none of the paths is ignored, and refuses "pub/media/" when pub/media is a
    # symlink: ask about the link itself then
    queried = {path.rstrip("/") if (root / path.rstrip("/")).is_symlink() else path: path for path in SENSITIVE_PATHS}
    ignored = {queried.get(path, path) for path in lines("check-ignore", "--no-index", *queried, ok_codes=(0, 1))}
    # --no-renames: a renamed secrets file shows as added under its new name too
    ever_added = lines("log", "--all", "--reflog", "-m", "--diff-filter=A", "--no-renames", "--name-only", "--format=", *GIT_SAFE_LOG)
    history = {}
    for name, pattern in SECRET_PATTERNS.items():
        output = git(root, "log", "--all", "--reflog", "-m", "-G", pattern, "--format=commit %h", "--name-only", *GIT_SAFE_LOG,
                     "--", *SECRET_SEARCH_PATHSPECS)
        if output is None:
            history[name] = {"error": "git log failed or timed out"}
            continue
        commits, files, current = [], set(), None
        for line in output.splitlines():
            if line.startswith("commit "):
                current = line[len("commit "):]
                # -m lists a merge once per parent
                if not commits or commits[-1] != current:
                    commits.append(current)
            elif line and current:
                files.add(line)
        if commits:
            history[name] = {"commits": commits[:10], "commit_count": len(commits), "files": shown_names(files, 10)}
    tracked_sensitive = [path for path in tracked if NEVER_TRACKED.search(path)]
    sensitive_in_history = {path for path in ever_added if NEVER_TRACKED.search(path)}
    return {
        "is_git_repository": True,
        "tracked_sensitive_files": shown_names(tracked_sensitive, 100),
        "tracked_sensitive_files_count": len(tracked_sensitive),
        "sensitive_files_in_history": shown_names(sensitive_in_history, 100),
        "sensitive_files_in_history_count": len(sensitive_in_history),
        "not_ignored": [path for path in SENSITIVE_PATHS if path not in ignored],
        "secret_patterns_in_history": history,
        "filters_configured": sorted({plain(line.split(".")[1] if line.count(".") > 1 else "", r"[\w-]{1,40}") for line in filters}),
        "compared_with_head": safely(head_differences, root),
        "errors": errors,
    }


def ascii_host(host: str) -> str:
    """A host as it goes out: an Unicode name in its xn-- form, so a look-alike shows as what it is."""
    if host.startswith("["):
        return plain(host.lower(), r"\[[0-9a-f:.]{2,45}\]")
    try:
        return plain(host.lower().encode("idna").decode("ascii"))
    except UnicodeError:
        return "?"


def url_host(url: str) -> str:
    """The host of a base URL, "{{placeholder}}" for Magento's own placeholders, "?" for anything else."""
    if url.startswith("{{"):
        return "{{placeholder}}"
    try:
        # A browser reads \ as / in an http(s) URL: https:\/\/evil or https:\\evil goes to evil
        return plain((urllib.parse.urlsplit(url.replace("\\/", "/").replace("\\", "/")).hostname or "").lower())
    except ValueError:
        return "?"


def include_before(source: str, pattern: re.Pattern) -> int | None:
    """Where an include or require reads what pattern matches, on the same line and at most 200 characters before."""
    for match in pattern.finditer(source):
        start = max(source.rfind("\n", 0, match.start()) + 1, match.start() - 200)
        if INCLUDE_WORD.search(source, start, match.start()):
            return match.start()
    return None


def refused_target(target: Path, root: Path) -> str | None:
    """Why a symlinked folder's target isn't walked: the whole disk, the store's own parents, the kernel's files."""
    if target == Path("/") or root.is_relative_to(target):
        return "points to / or to a parent of the store"
    if any(target == Path(system) or target.is_relative_to(system) for system in SYSTEM_FOLDERS):
        return "points to a system folder"
    return None


def hosts_in(source: str) -> set[str]:
    return {ascii_host(match.group(1)) for match in EXTERNAL_HOST.finditer(source)}


def new_match(pattern: re.Pattern, source: str, original: str | None) -> re.Match | None:
    """The first match, or with an original, the first one past those the original holds (spaces aside: minifying drops them)."""
    if original is None:
        return pattern.search(source)
    # Counted: a second eval( in a copy whose original holds one is new
    known = collections.Counter(re.sub(r"\s+", "", match.group()) for match in pattern.finditer(original))
    for match in pattern.finditer(source):
        text = re.sub(r"\s+", "", match.group())
        if known[text] <= 0:
            return match
        known[text] -= 1
    return None


def appended_zip(handle, size: int) -> bool:
    """A zip after an image (zip:// reads it from the end): any end record in the last 64 KB that a zip64 locator
    precedes, or whose central directory sits where it says (absolute offset) or right before it (relative)."""
    start = max(0, size - ZIP_END_SEARCH_BYTES)
    handle.seek(start)
    tail = handle.read(ZIP_END_SEARCH_BYTES)
    found, end = False, tail.find(b"PK\x05\x06")
    while not found and 0 <= end <= len(tail) - 22:
        directory_size = int.from_bytes(tail[end + 12:end + 16], "little")
        directory_offset = int.from_bytes(tail[end + 16:end + 20], "little")
        found = tail[max(0, end - 20):end - 16] == b"PK\x06\x07"
        for offset in (directory_offset, start + end - directory_size):
            if not found and 0 <= offset < start + end:
                handle.seek(offset)
                found = handle.read(4) == b"PK\x01\x02"
        end = tail.find(b"PK\x05\x06", end + 1)
    handle.seek(0)
    return found


class StoreScan:
    """One walk over the store's code and uploads, every check applied to each file as it goes by: nothing but
    the findings is kept, so a million uploads don't fill the memory."""

    def __init__(self, root: Path):
        self.root = root
        self.folders = SCANNED_FOLDERS + path_repository_folders(root)
        self.own_code = ("app/code/", "app/design/", PREPROCESSED_FOLDER + "/", *(f"{folder}/" for folder in path_repository_folders(root)))
        self.hits: dict[str, list[str]] = {name: [] for name in (
            "store_root_php", "pub_root_php", "pub_unexpected_php", "media_or_static_php", "php_code_in_media_files", "app_etc_code",
            "archives_under_other_names", "app_etc_script_values", "unexpected_user_ini_files", "risky_directives",
            "static_files_changed_after_deploy",
            "php", "core_copies_and_generated_php", "vendor_php", "javascript",
        )}
        self.hosts: dict[str, list] = {}
        self.hosts_dropped = 0
        self.symlinked_outside: set[str] = set()
        self.base_url_hosts: set[str] = set()
        self.partly_read: set[str] = set()
        self.static_deployed_at: float | None = None
        self.static_changed = 0
        self.followed_symlinks: dict[str, str] = {}
        self.refused_symlinks: dict[str, str] = {}
        self.symlinked_files: set[str] = set()
        self.symlinked_folders: set[str] = set()
        self.unreadable: set[str] = set()
        self.skipped_large: set[str] = set()
        self.unscanned_root_folders: set[str] = set()
        self.hit_counts: collections.Counter = collections.Counter()

    def add(self, category: str, value: str) -> None:
        self.hit_counts[category] += 1
        if len(self.hits[category]) < HITS_PER_CHECK:
            self.hits[category].append(shown_name(value))

    def run(self) -> None:
        for path in sorted(self.root.iterdir()) if self.root.is_dir() else []:
            if path.is_symlink():
                (self.symlinked_folders if path.is_dir() else self.symlinked_files).add(path.name)
            elif path.is_dir() and path.name not in self.folders and path.name not in UNSCANNED_ROOT_FOLDERS:
                self.unscanned_root_folders.add(path.name)
            elif path.is_file() and (PHP_EXTENSION.search(path.name) or path.name in SERVER_FILES):
                self.check(path, path.name)
        try:
            self.static_deployed_at = (self.root / "pub" / "static" / "deployed_version.txt").stat().st_mtime
        except OSError:
            self.static_deployed_at = None
        for base in self.folders + (PREPROCESSED_FOLDER,):
            self.walk(self.root / base, base)

    def scanned(self, target: Path) -> bool:
        return target.is_relative_to(self.root) and target.relative_to(self.root).parts[:1] in [(name,) for name in self.folders]

    def walk(self, start: Path, label: str) -> None:
        pending = [(start, label)]
        while pending:
            directory, shown = pending.pop()
            if directory.is_symlink():
                if shown not in TOP_SYMLINKS_FOLLOWED or not directory.is_dir():
                    self.symlinked_folders.add(shown)
                    continue
                target = directory.resolve()
                refusal = refused_target(target, self.root)
                if refusal:
                    self.refused_symlinks[shown] = refusal
                    continue
                self.followed_symlinks[shown] = plain(str(target), SHOWN_PATH)
                directory = target
            try:
                entries = list(os.scandir(directory))
            except OSError:
                if directory.exists():
                    self.unreadable.add(shown)
                continue
            for entry in entries:
                child = f"{shown}/{entry.name}"
                try:
                    if entry.is_symlink():
                        if child in TOP_SYMLINKS_FOLLOWED:
                            pending.append((Path(entry.path), child))
                        elif child in APP_ETC_CONFIG and entry.is_file():
                            # Deployer shares env.php from shared/ behind a link: read it, only line numbers get out
                            target = Path(entry.path).resolve()
                            if refusal := refused_target(target, self.root):
                                self.refused_symlinks[child] = refusal
                            else:
                                self.followed_symlinks[child] = plain(str(target), SHOWN_PATH)
                                self.check(Path(entry.path), child)
                        elif entry.is_dir():
                            self.symlinked_folders.add(child)
                        elif PHP_EXTENSION.search(entry.name) or entry.name in SERVER_FILES:
                            self.symlinked_files.add(child)
                        elif not self.scanned(Path(entry.path).resolve()):
                            # A template or script served from outside the scanned folders: not scanned, not in any comparison
                            self.symlinked_outside.add(child)
                    elif entry.is_dir(follow_symlinks=False):
                        pending.append((Path(entry.path), child))
                    elif entry.is_file(follow_symlinks=False):
                        self.check(Path(entry.path), child)
                except OSError:
                    self.unreadable.add(child)

    def read(self, path: Path, shown: str, limit: int = SCAN_FILE_MAX_BYTES) -> str | None:
        try:
            handle, info = open_regular(path)
            if handle is None:
                self.unreadable.add(shown)
                return None
            with handle:
                if info.st_size > limit:
                    self.skipped_large.add(shown)
                    return None
                return handle.read(limit + 1).decode(errors="ignore")
        except OSError:
            self.unreadable.add(shown)
            return None

    def has_php_code(self, path: Path, shown: str, pattern: re.Pattern = PHP_OPEN_TAG) -> bool:
        """PHP anywhere in an upload, read in overlapping chunks: whole up to 16 MB, then only its last chunk."""
        try:
            handle, info = open_regular(path)
            if handle is None:
                self.unreadable.add(shown)
                return False
            size = info.st_size
            with handle:
                archive_name = path.suffix.lower() in ARCHIVE_SUFFIXES
                appended = not archive_name and appended_zip(handle, size)
                previous, read = b"", 0
                while read < MEDIA_READ_MAX_BYTES and (chunk := handle.read(MEDIA_CHUNK_BYTES)):
                    if not read and not archive_name and (appended or chunk.startswith(ARCHIVE_MAGIC)):
                        self.add("archives_under_other_names", shown)
                    if pattern.search(previous + chunk):
                        return True
                    previous, read = chunk[-MEDIA_OVERLAP_BYTES:], read + len(chunk)
                if size > read:
                    self.partly_read.add(shown)
                    handle.seek(max(read, size - MEDIA_CHUNK_BYTES))
                    return bool(pattern.search(handle.read(MEDIA_CHUNK_BYTES)))
        except OSError:
            self.unreadable.add(shown)
        return False

    def add_hosts(self, source: str, shown: str, original: str | None = None) -> None:
        rank = 2 if TEST_FOLDER.fullmatch(shown) else 0 if Path(shown).suffix in FRONT_END_SUFFIXES else 1
        known = hosts_in(original) if original is not None else set()
        for host in hosts_in(source) - known:
            if IGNORED_HOSTS.fullmatch(host):
                continue
            if host not in self.hosts and len(self.hosts) >= MAX_HOSTS_KEPT:
                self.hosts_dropped += 1
                continue
            entry = self.hosts.setdefault(host, [rank, set()])
            entry[0] = min(entry[0], rank)
            if len(entry[1]) < 5:
                entry[1].add(shown_name(shown))

    def static_report(self) -> dict:
        """pub/static files changed after a deploy's length past deployed_version.txt, which setup:static-content:deploy
        writes as it starts: requirejs-config.js and the bundles, written last, included."""
        if self.static_deployed_at is None:
            return {"static_files_changed_after_deploy": None}
        return {"static_files_changed_after_deploy": sorted(self.hits["static_files_changed_after_deploy"]),
                "static_files_changed_after_deploy_count": self.static_changed}

    def hosts_report(self) -> dict:
        ranked = sorted(self.hosts.items(), key=lambda item: (item[1][0], item[0]))
        return {
            "external_hosts_in_code": {host: sorted(files) for host, (_, files) in ranked[:MAX_HOSTS]},
            "external_hosts_dropped": self.hosts_dropped + max(0, len(ranked) - MAX_HOSTS),
        }

    def check(self, path: Path, shown: str) -> None:
        top = shown.split("/", 1)[0]
        is_php = bool(PHP_EXTENSION.search(path.name)) or top == "bin"
        in_media = shown.startswith("pub/media/")
        in_static = shown.startswith("pub/static/")
        if in_static and self.static_deployed_at is not None and not shown.startswith("pub/static/_cache/"):
            try:
                if path.stat().st_mtime > self.static_deployed_at + STATIC_DEPLOY_WINDOW_SECONDS:
                    self.static_changed += 1
                    self.add("static_files_changed_after_deploy", shown)
            except OSError:
                pass
        # Served when the web root is the store root; Magento ships no PHP there but a coding-standard config
        if "/" not in shown and is_php and shown != ".php-cs-fixer.dist.php":
            self.add("store_root_php", shown)
        if in_media or in_static:
            if is_php:
                self.add("media_or_static_php", shown)
            elif path.name not in SERVER_FILES and self.has_php_code(path, shown, PHP_OPEN_TAG_STATIC if in_static else PHP_OPEN_TAG):
                # PHP code inside an image or any other upload: harmless alone, a backdoor once included
                self.add("php_code_in_media_files", shown)
        elif top in ("app", "lib") and path.suffix.lower() in IMAGE_SUFFIXES and self.has_php_code(path, shown):
            self.add("php_code_in_media_files", shown)
        elif top == "pub" and is_php and not SHIPPED_PUB_PHP.fullmatch(shown):
            # Under Apache every .php under pub/ runs, not only those at its root
            self.add("pub_root_php" if shown.count("/") == 1 else "pub_unexpected_php", shown)
        if path.name in SERVER_FILES and (top == "pub" or "/" not in shown):
            if path.name in (".user.ini", "php.ini") and shown not in SHIPPED_USER_INI:
                self.add("unexpected_user_ini_files", shown)
            # Apache joins a line ending in \ to the next one: the directive is read whole, at its first line
            first, joined = 1, ""
            for number, line in enumerate((self.read(path, shown) or "").splitlines() + [""], start=1):
                if line.endswith("\\"):
                    joined, first = joined + line[:-1], first if joined else number
                    continue
                line, first, joined = joined + line, first if joined else number, ""
                if SERVER_CONFIG_RISK.search(line) and not line.lstrip().startswith("#"):
                    self.add("risky_directives", f"{shown}:{first}")
        php_pattern = None
        if is_php and not in_static:
            php_pattern = ("vendor_php", OBFUSCATION_VENDOR, "strict") if top == "vendor" else \
                ("core_copies_and_generated_php", OBFUSCATION_VENDOR, "strict") if top in ("generated", "setup", "dev", "phpserver") else ("php", OBFUSCATION, "broad")
        if shown in APP_ETC_CONFIG:
            self.config_code(path, shown)
        # Themes installed with Composer keep their templates and JavaScript outside any view/ folder
        js = path.suffix in (".js", ".html", ".phtml") and (top in ("app", "pub", "lib", "vendor", "var") or shown.startswith(self.own_code))
        hosts = (path.suffix in HOST_SUFFIXES and (shown.startswith(self.own_code) or (top == "pub" and not (in_media or in_static)))) \
            or (in_media and path.suffix.lower() in (".js", ".html", ".htm", ".svg"))
        if php_pattern or js or hosts:
            source = self.read(path, shown, CODE_FILE_MAX_BYTES)
            if source is None:
                return
            # A minified template counts only for what its original (vendor/, app/design...) doesn't already have
            original = None
            if shown.startswith(PREPROCESSED_STATIC):
                original_path = self.root / shown[len(PREPROCESSED_STATIC):]
                original = (read_small(original_path, CODE_FILE_MAX_BYTES) or "") if not original_path.is_symlink() else ""
            if hosts:
                self.add_hosts(source, shown, original)
            js_pattern = ("javascript", JS_SKIMMER_APP, "javascript_app") if top == "app" else ("javascript", JS_SKIMMER, "javascript")
            for category, pattern, triggers in ([php_pattern] if php_pattern else []) + ([js_pattern] if js else []):
                # PHP triggers are matched case-insensitively, like the patterns; JavaScript is case-sensitive
                haystack = source if triggers.startswith("javascript") else source.lower()
                if not any(word in haystack for word in TRIGGERS[triggers]):
                    continue
                match = new_match(pattern, source, original)
                if match:
                    self.add(category, f"{shown}:{source.count(chr(10), 0, match.start()) + 1}")
            if php_pattern:
                position = include_before(source, INCLUDED_REQUEST) if "$_" in source or "$GLOBALS" in source else None
                if position is None and php_pattern[2] == "broad" and "://" in source:
                    position = include_before(source, INCLUDED_WRAPPER)
                if position is not None:
                    self.add(php_pattern[0], f"{shown}:{source.count(chr(10), 0, position) + 1}")

    def config_code(self, path: Path, shown: str) -> None:
        source = self.read(path, shown)
        if source is None:
            return
        # Strings and comments out, line breaks kept: only line numbers get out, never a value
        code = STRINGS_AND_COMMENTS.sub(lambda match: "\n" * match.group().count("\n"), source)
        lines = {number for number, line in enumerate(code.splitlines(), start=1)
                 if CONFIG_ALLOWED.sub("", line).strip()}
        # A ?> left once comments end at it is code, so is "{$x}" inside a double-quoted string
        newlines = [found.start() for found in re.finditer("\n", source)]
        for match in STRINGS_AND_COMMENTS.finditer(source):
            value, number = match.group(), bisect.bisect_left(newlines, match.start()) + 1
            if value.startswith('"') and "$" in value:
                lines.add(number)
            # A head include or a payment field set with config:set --lock-env: a skimmer the database queries don't see.
            # "\x3cscript" is <script to PHP: an escape in double quotes hides anything
            if value[:1] in ("'", '"') and (CONFIG_VALUE_SCRIPT.search(value) or JS_SKIMMER.search(value)
                                            or (value[0] == '"' and DOUBLE_QUOTED_ESCAPE.search(value))):
                self.add("app_etc_script_values", f"{shown}:{number}")
            # Every script the store serves loads from its base URLs: another host serves all of them
            if BASE_URL_KEY.fullmatch(value):
                url = BASE_URL_VALUE.match(source, match.end())
                self.base_url_hosts.add(url_host(url.group(2)) if url else "?")
        if not re.match(r"\s*<\?php\s+(declare\s*\(\s*strict_types\s*=\s*1\s*\)\s*;\s*)?return\b", code, re.IGNORECASE):
            lines.add(1)
        # The whole file, comments out: PHP stops at the first return, so a second one proves nothing
        if shown == "app/etc/vendor_path.php" and not VENDOR_PATH_RETURN.fullmatch(STRINGS_AND_COMMENTS.sub(
                lambda match: match.group() if match.group().startswith("'") else "\n" * match.group().count("\n"), source)):
            lines.add(1)
        for number in sorted(lines):
            self.add("app_etc_code", f"{shown}:{number}")

    def report(self) -> dict:
        hits = {name: sorted(values) for name, values in self.hits.items()}
        return {
            "unexpected_php": {
                "pub_directory": (self.root / "pub").is_dir(),
                **{name: hits[name] for name in ("store_root_php", "pub_root_php", "pub_unexpected_php", "media_or_static_php", "php_code_in_media_files",
                                               "archives_under_other_names", "app_etc_code")},
            },
            # Line numbers of strings in env.php and config.php holding markup or script: values never get out
            "app_etc_script_values": hits["app_etc_script_values"],
            # The hosts of the base URLs kept in env.php and config.php: the store serves every script from them
            "app_etc_base_url_hosts": sorted(self.base_url_hosts),
            # Every host the store's own code (app/code, app/design, pub/ outside uploads) loads from or sends to,
            # front-end files' first
            **self.hosts_report(),
            # Files in pub/static newer than its last deploy: what a skimmer added there survives until the next one
            **self.static_report(),
            "server_config": {name: hits[name] for name in ("unexpected_user_ini_files", "risky_directives")},
            "obfuscated_code": {name: hits[name] for name in ("php", "core_copies_and_generated_php", "vendor_php", "javascript")},
            # Lists cut at HITS_PER_CHECK: the total of each, the rest unlisted (a backdoor among them included)
            "findings_over_limit": {name: count for name, count in sorted(self.hit_counts.items()) if count > HITS_PER_CHECK},
            "files_not_checked": {
                "followed_symlinked_folders": {shown_name(name): target for name, target in self.followed_symlinks.items()},
                "root_folders_not_scanned": shown_names(self.unscanned_root_folders, HITS_PER_CHECK),
                "root_folders_not_scanned_count": len(self.unscanned_root_folders),
                "refused_symlinked_folders": {shown_name(name): reason for name, reason in self.refused_symlinks.items()},
                "symlinked_php_or_server_files": shown_names(self.symlinked_files, HITS_PER_CHECK),
                "symlinked_php_or_server_files_count": len(self.symlinked_files),
                "symlinked_files_not_scanned": shown_names(self.symlinked_outside, HITS_PER_CHECK),
                "symlinked_files_not_scanned_count": len(self.symlinked_outside),
                "symlinked_folders_not_followed": shown_names(self.symlinked_folders, HITS_PER_CHECK),
                "symlinked_folders_not_followed_count": len(self.symlinked_folders),
                "unreadable": shown_names(self.unreadable, HITS_PER_CHECK),
                "unreadable_count": len(self.unreadable),
                "skipped_large_files": shown_names(self.skipped_large, HITS_PER_CHECK),
                "skipped_large_count": len(self.skipped_large),
                # Uploads over 16 MB: only their first 16 MB and last 1 MB were read
                "media_files_partly_read": shown_names(self.partly_read, HITS_PER_CHECK),
                "media_files_partly_read_count": len(self.partly_read),
            },
        }


def closing_quote(text: str, quote: str, backslash_escapes: bool) -> int | None:
    """Index of the quote that closes a string starting just before text, or None if it stays open."""
    index = 0
    while index < len(text):
        if backslash_escapes and text[index] == "\\":
            index += 2
            continue
        if text[index] == quote:
            return index
        index += 1
    return None


def masked_env_keys(source: str) -> list[str]:
    """A .env as the shell reads it: a quote opens a string only at the start of a value, so a stray quote
    inside a bare value changes nothing. Double quotes take backslash escapes, single quotes don't."""
    shown, quote = [], None
    for number, line in enumerate(source.splitlines(), start=1):
        if quote:
            if closing_quote(line, quote, quote == '"') is not None:
                quote = None
            continue
        match = ENV_KEY_LINE.match(line)
        if not match:
            continue
        shown.append(f"{number}: {match.group(1)} = ***")
        value = line[match.end():].lstrip()
        if value[:1] in ("'", '"') and closing_quote(value[1:], value[0], value[0] == '"') is None:
            quote = value[0]
    if quote:
        shown.append("(a quote never closes: some keys may be missing)")
    return shown


def masked_keys(source: str, env_style: bool) -> list[str]:
    """Key names with every value masked. Quotes are followed over the whole file, the way PHP or JSON reads
    them (backslashes in pairs, comments skipped), so a line inside a multi-line value (a rotated crypt key,
    a PEM) is never taken for a key. Anything this can't follow (a PHP heredoc) stops the output there."""
    if env_style:
        return masked_env_keys(source)
    shown, quote, block_comment = [], None, False
    for number, line in enumerate(source.splitlines(), start=1):
        if quote is None and not block_comment:
            match = KEY_LINE.match(line)
            if match:
                shown.append(f"{number}: {match.group(1)} {match.group(match.lastindex)} ***")
        index = 0
        while index < len(line):
            character, following = line[index], line[index + 1:index + 2]
            if block_comment:
                if character == "*" and following == "/":
                    block_comment, index = False, index + 1
            elif quote:
                if character == "\\":
                    index += 1
                elif character == quote:
                    quote = None
            elif character in ("'", '"'):
                quote = character
            elif (character == "#" and following != "[") or (character == "/" and following == "/"):
                break
            elif character == "/" and following == "*":
                block_comment, index = True, index + 1
            elif line.startswith("<<<", index) or line.startswith("?>", index):
                # A heredoc, or HTML after the closing tag: nothing this follows, so nothing more is shown
                shown.append(f"{number}: (nothing shown from here on)")
                return shown
            index += 1
    if quote:
        shown.append("(a quote never closes: some keys may be missing)")
    return shown


def show_masked(root: Path, file: str, commit: str | None) -> None:
    if commit:
        if not re.fullmatch(r"[0-9a-fA-F]{4,40}", commit) or file.startswith(("-", "/")) or ".." in Path(file).parts:
            sys.exit("The commit must be a hash and the file a path inside the store")
        if lazy_fetch_possible(root):
            sys.exit("A partial clone: its commits aren't read, git would fetch missing objects with the repository's own commands")
        resolved = (git(root, "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}") or "").strip()
        # A branch or tag named like a hash would win over the commit: refuse rather than show another file
        if not resolved.startswith(commit.lower()):
            sys.exit(f"{commit} isn't a commit of this repository, or a branch or tag has that name")
        source = git(root, "show", *GIT_SAFE_LOG, f"{resolved}:./{file}")
        if source is None:
            sys.exit(f"{file} isn't in commit {commit}")
    else:
        path = (root / file).resolve()
        linked_config = os.path.normpath(file) in APP_ETC_CONFIG and refused_target(path, root) is None
        if not (path.is_relative_to(root) or linked_config):
            sys.exit(f"{file} isn't a file of the store")
        source = read_small(path)
        if source is None:
            sys.exit(f"{file} isn't a regular file under 2 MB")
    print("\n".join(masked_keys(source, Path(file).name.startswith(".env"))))


def is_decision_due(key: str, decision: dict, today: date) -> bool:
    ask_again = decision.get("ask_again", "next_run")
    if ask_again in ("next_run", "next_upgrade"):
        return True
    if ask_again == "never":
        # A Critical decision always comes back: a "never" planted in the file would silence it for good
        return key in CRITICAL_DECISIONS
    try:
        when = date.fromisoformat(ask_again)
    except (ValueError, TypeError):
        return True
    if key in CRITICAL_DECISIONS and (when - today).days > CRITICAL_MAX_DELAY_DAYS:
        return True
    return when <= today


def clean_decision(key: str, value) -> dict | None:
    """A decision with only allowed values: the scorecard is attacker-writable, so no free text gets through."""
    if key not in DECISION_CHOICES or not isinstance(value, dict) or value.get("choice") not in DECISION_CHOICES[key]:
        return None
    decision = {"choice": value["choice"]}
    ask_again = value.get("ask_again", "next_run")
    if ask_again in ("next_run", "next_upgrade", "never") or (isinstance(ask_again, str) and re.fullmatch(ISO_DATE, ask_again)):
        decision["ask_again"] = ask_again
    else:
        decision["ask_again"] = "next_run"
    for field, pattern in (("date", ISO_DATE), ("version_at_decision", r"[0-9][0-9A-Za-z.+-]{0,30}")):
        if isinstance(value.get(field), str) and re.fullmatch(pattern, value[field]):
            decision[field] = value[field]
    return decision


def read_previous_run(root: Path, version: str | None) -> dict | None:
    scorecard = root / SCORECARD_FILE
    if not scorecard.exists():
        return None
    try:
        data = json.loads(read_small(scorecard) or "")
    except (ValueError, OSError, RecursionError):
        data = None
    if not isinstance(data, dict):
        return {"error": f"{SCORECARD_FILE} is unreadable or not a JSON object: start a fresh scorecard"}
    # Anyone with write access to var/ can edit this file: only known keys and well-formed values go back
    # to the agent, never free text such as the reason
    raw = data.get("decisions") if isinstance(data.get("decisions"), dict) else {}
    decisions = {key: decision for key, value in raw.items() if (decision := clean_decision(key, value))}
    areas = data.get("areas") if isinstance(data.get("areas"), dict) else {}
    today = date.today()

    def due(key: str, decision: dict) -> bool:
        if decision.get("ask_again") == "next_upgrade":
            if decision.get("version_at_decision") != version or version is None:
                return True
            if key in CRITICAL_DECISIONS:
                # A store that never upgrades would otherwise never be asked again
                try:
                    days = (today - date.fromisoformat(decision.get("date", ""))).days
                except (ValueError, TypeError):
                    return True
                # A date in the future would hold it off for good
                return not 0 <= days <= CRITICAL_MAX_DELAY_DAYS
            return False
        return is_decision_due(key, decision, today)

    def well_formed(value, pattern: str) -> str | None:
        return value if isinstance(value, str) and re.fullmatch(pattern, value) else None

    return {
        "checked_at": well_formed(data.get("checked_at"), ISO_DATE),
        "version_at_check": well_formed(data.get("version"), r"[0-9][0-9A-Za-z.+-]{0,30}"),
        "areas": {key: value for key, value in areas.items() if key in AREA_KEYS and value in AREA_STATUSES},
        "note": "Written by an earlier run, editable by anyone with write access to var/: progress only, re-check every area",
        "decisions_due": {key: value for key, value in decisions.items() if due(key, value)},
        "decisions_waiting": {key: value for key, value in decisions.items() if not due(key, value)},
    }


def file_digest(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def tree_files(base: Path) -> dict[str, Path]:
    """Relative path -> file, without following symlinks (reported apart: a path repository's module)."""
    files = {}
    for directory, folders, names in os.walk(base):
        names = names + [folder for folder in folders if (Path(directory) / folder).is_symlink()]
        for name in names:
            path = Path(directory) / name
            files[str(path.relative_to(base))] = path
    return files


AUTOLOADER_SUFFIX = re.compile(r"\b(ComposerAutoloaderInit|ComposerStaticInit)\w+")
# Random per dump, and the root package's own version and commit: the only parts two installs of one lock differ by
APCU_PREFIX = re.compile(r"(setApcuPrefix\()'[^'\\]*'")
ROOT_VERSION = re.compile(r"^(\s*'(?:pretty_version|version|reference)' => )(?:'[^'\\]*'|(?i:null))(,)$")
PHP_STRING = r"'(?:[^'\\]|\\.)*(?:'|\\?\Z)"
PHP_COMMENTS = re.compile(rf"({PHP_STRING})|/\*.*?(?:\*/|\Z)|//(?:[^\r\n?]|\?(?!>))*|#(?!\[)(?:[^\r\n?]|\?(?!>))*", re.DOTALL)
# An optimized classmap (-o) also lists the store's own classes, which a clean install doesn't have: only at the
# path PSR-0 and PSR-4 would load them from anyway
OWN_CLASS = re.compile(r"\s*'((?:[^'\\]|\\\\)+)' => (?:__DIR__ \. '/\.\./\.\.' \. |\$baseDir \. )'/((app/code|generated/code|lib/internal|setup/src)/[^']+)\.php',")
# Class names Magento's code generator writes to generated/code
GENERATED_SUFFIX = re.compile(r"(Interceptor|Factory|Proxy|ProxyDeferred|Remote|Extension|ExtensionInterface|SearchResults|Mapper|Persistor|Repository|Converter|Logger)$")
# Folders the store's autoloader reads core namespaces from before vendor/: Composer never puts a file there
CORE_SHADOW_FOLDERS = ("app/code/Magento", "lib/internal/Magento", "app/code/MageOS")


def vendor_prefixes(vendor: Path) -> tuple[str, ...]:
    """PSR-4 and PSR-0 prefixes the clean install loads from vendor/: a store class under one shadows a package's."""
    prefixes = []
    for name in ("autoload_psr4.php", "autoload_namespaces.php"):
        path = vendor / "composer" / name
        for key, paths in re.findall(r"^\s*'((?:[^'\\]|\\\\)*)' => array\((.*)\),$", path.read_text(errors="ignore") if path.is_file() else "", re.MULTILINE):
            if "$vendorDir" in paths:
                prefixes.append(key.replace("\\\\", "\\"))
    return tuple(prefix for prefix in prefixes if prefix)


def own_class_line(line: str, clean_keys: set[str], store_keys: collections.Counter, vendor_owned: tuple[str, ...]) -> bool:
    """An optimized classmap's entry for one of the store's own classes, at the path PSR-0 or PSR-4 gives it: a class
    the clean install doesn't have, listed once, under no namespace vendor/ provides (generated/code: generated
    class names only)."""
    match = OWN_CLASS.fullmatch(line)
    if not match or ".." in match.group(2).split("/") or match.group(1) in clean_keys or store_keys[match.group(1)] != 1:
        return False
    name = match.group(1).replace("\\\\", "\\")
    if match.group(3) == "generated/code":
        if not GENERATED_SUFFIX.search(name):
            return False
    elif name.startswith(vendor_owned):
        return False
    path = name.replace("\\", "/")
    return match.group(2)[len(match.group(3)) + 1:] in (path, path.replace("_", "/"))


def autoloader_lines(path: Path) -> list[str]:
    text = path.read_text(errors="ignore")
    root = re.search(r"'root' => array\(\s*'name' => ('[^'\\]*')", text)
    # The root package's version and commit, in its two blocks of installed.php only: every other package's are compared
    starts = ("'root' => array(",) + ((f"{root.group(1)} => array(",) if root else ())
    lines, closing = [], None
    for line in text.splitlines():
        line = APCU_PREFIX.sub(r"\1X", AUTOLOADER_SUFFIX.sub(r"\1", line))
        if closing is None and line.strip() in starts:
            closing = line[:len(line) - len(line.lstrip())] + "),"
        elif closing is not None:
            if line == closing:
                closing = None
            else:
                line = ROOT_VERSION.sub(r"\1X\2", line)
        lines.append(line)
    return lines


def unexpected_autoloader_lines(store_file: Path, clean_file: Path, vendor_owned: tuple[str, ...] = (), optimized: bool = False) -> list[int]:
    """Store lines (1-based) where a generated Composer file isn't the clean one, line for line: a check removed
    counts as much as a line added. Only the suffix, the APCu prefix, the root's version and the store's own
    classes in an optimized classmap are set aside."""
    store_lines, clean = autoloader_lines(store_file), autoloader_lines(clean_file)
    key = re.compile(r"\s*'((?:[^'\\]|\\\\)+)' => ")
    clean_keys = {match.group(1) for line in clean if (match := key.match(line))}
    store_keys = collections.Counter(match.group(1) for line in store_lines if (match := key.match(line)))
    # Only with -o on both sides: without it, the store's classmap has no business listing its own classes
    store = [(number, line) for number, line in enumerate(store_lines, start=1)
             if not (optimized and own_class_line(line, clean_keys, store_keys, vendor_owned))]
    if [line for _, line in store] == clean:
        return []
    matcher = difflib.SequenceMatcher(None, [line for _, line in store], clean, autojunk=False)
    found = set()
    for tag, first, last, _, _ in matcher.get_opcodes():
        if tag != "equal":
            # A deletion has no store line of its own: point at the line after it
            found.update(store[index][0] for index in range(first, max(last, first + 1)) if index < len(store))
    return sorted(found) or [len(store_file.read_text(errors="ignore").splitlines())]


def autoload_options(vendor: Path) -> dict:
    """How the store's autoloader was dumped: the clean install must use the same options, or every line differs."""
    def read(name: str) -> str:
        path = vendor / "composer" / name
        return path.read_text(errors="ignore") if path.is_file() else ""
    real, installed, classmap = read("autoload_real.php"), read("installed.php"), read("autoload_classmap.php")
    prefixes = re.findall(r"^\s*'((?:[^'\\]|\\\\)+\\\\)' => ", read("autoload_psr4.php"), re.MULTILINE)
    psr4_classes = sum(1 for key in re.findall(r"^\s*'((?:[^'\\]|\\\\)+)' => ", classmap, re.MULTILINE) if key.startswith(tuple(prefixes)))
    dev = re.search(r"'root' => array\s*\((?:(?!\n    \),).)*?'dev' => (true|false)", installed, re.DOTALL)
    return {
        # -o puts every PSR-4 class in the classmap; without it only a few packages' classmaps are there
        "optimize_autoloader": psr4_classes > 100,
        "classmap_authoritative": "setClassMapAuthoritative(true)" in real,
        "apcu_autoloader": "setApcuPrefix(" in real,
        "dev": None if not dev else dev.group(1) == "true",
    }


def autoload_files(vendor: Path) -> set[str]:
    """Every file Composer includes on every request, literal paths too: Composer 2 reads autoload_static.php's
    $files, older autoloaders autoload_files.php."""
    entries = set()
    for name, start in (("autoload_static.php", r"\$files\s*="), ("autoload_files.php", r"\breturn\b")):
        source = vendor / "composer" / name
        # Comments out first: a "/* ); */" would end the array early
        text = PHP_COMMENTS.sub(lambda match: match.group(1) or "", source.read_text(errors="ignore")) if source.is_file() else ""
        parts = re.split(start + r"\s*(?:array\s*\(|\[)", text, maxsplit=1)
        block = re.split(r"[)\]]\s*;", parts[1], maxsplit=1)[0] if len(parts) == 2 else ""
        entries |= {f"{name}: {value[:200]}" for value in re.findall(r"=>\s*(.+?),?[ \t]*$", block, re.MULTILINE)}
    return entries


def compare_with_clean(store: Path, clean: Path) -> dict:
    """The store's vendor/ and the root files magento2-base puts in place, against a clean install of the same
    composer.lock (composer install --no-plugins --no-scripts in an empty folder)."""
    if not (clean / "vendor").is_dir():
        sys.exit(f"{clean} has no vendor/: install the store's composer.lock there first")
    store_files, clean_files = tree_files(store / "vendor"), tree_files(clean / "vendor")
    # The committed patch list, not the server's: a planted patches.json would pass tampered files off as patched
    patched = set(read_composer_patches(clean))
    differ, only_store, patched_differ, composer_differ, symlinked, not_regular = [], [], [], [], [], []
    autoloader_lines, metadata_differ = {}, []
    vendor_owned = vendor_prefixes(clean / "vendor")
    optimized = autoload_options(store / "vendor")["optimize_autoloader"] and autoload_options(clean / "vendor")["optimize_autoloader"]
    for relative, path in store_files.items():
        expected = clean / "vendor" / relative
        # vendor/composer/ and vendor/autoload.php are the autoloader: it runs first, on every request and command
        # Composer's own packages (composer/pcre, composer/ca-bundle...) are ordinary packages, compared byte for byte
        bucket = composer_differ if (relative.startswith("composer/") and relative.count("/") == 1) or relative == "autoload.php" else \
            patched_differ if "/".join(Path(relative).parts[:2]) in patched else differ
        if path.is_symlink():
            # A symlink where the clean install has a real file or folder replaces core code
            (bucket if expected.exists() and not expected.is_symlink() else symlinked).append(relative)
        elif not path.is_file():
            # A FIFO would block the read
            not_regular.append(relative)
        elif relative not in clean_files:
            (composer_differ if bucket is composer_differ else only_store).append(relative)
        elif file_digest(path) == file_digest(clean_files[relative]):
            continue
        elif relative == "composer/installed.json":
            # Data Composer reads, never runs: dev flags, the root's commit, composer-patches' patches_applied
            metadata_differ.append(relative)
        elif bucket is composer_differ and relative.endswith(".php"):
            if found := unexpected_autoloader_lines(path, clean_files[relative], vendor_owned, optimized):
                composer_differ.append(relative)
                autoloader_lines[relative] = found[:20]
        else:
            bucket.append(relative)
    only_clean = sorted(set(clean_files) - set(store_files))
    # magento2-base's extra.map says which store file comes from which file of the package
    # Adobe Commerce adds magento2-ee-base, with a map of its own
    bases = [clean / "vendor" / name for name in ("mage-os/magento2-base", "magento/magento2-base", "magento/magento2-ee-base")
             if (clean / "vendor" / name).is_dir()]
    root_differ, root_missing, map_refused, destinations, mapped_files, mapped_folders = [], [], [], set(), set(), set()
    for base in bases:
        mapping = json.loads(read_small((base / "composer.json"), CODE_FILE_MAX_BYTES) or "").get("extra", {}).get("map", [])
        for entry in mapping if isinstance(mapping, list) else []:
            if not (isinstance(entry, list) and len(entry) == 2 and all(isinstance(part, str) for part in entry)) \
                    or any(Path(part).is_absolute() or ".." in Path(part).parts for part in entry):
                map_refused.append(plain(str(entry)[:100].replace(" ", ""), r"[\w./,'\[\]-]{1,100}"))
                continue
            origin, target = base / entry[0], store / entry[1]
            destinations.add(entry[1].strip("/"))
            pairs = [(origin, target)] if origin.is_file() else [
                (origin / relative, target / relative) for relative in tree_files(origin)] if origin.is_dir() else []
            for wanted, actual in pairs:
                shown = str(actual.relative_to(store))
                mapped_files.add(shown)
                if not actual.exists():
                    root_missing.append(shown)
                elif not actual.is_file() or file_digest(actual) != file_digest(wanted):
                    root_differ.append(shown)
            if origin.is_dir() and target.is_dir() and not entry[1].startswith(("generated", "pub/media")):
                mapped_folders.add(entry[1].strip("/"))
    # A file added in a core folder runs like the core's own; generated/ and uploads change by nature. Against every
    # base's files at once: ee-base maps files into magento2-base's folders
    root_only_store = sorted({f"{folder}/{relative}" for folder in mapped_folders for relative in tree_files(store / folder)} - mapped_files)
    # The root autoloader reads Magento\ and Magento\Framework\ from these before vendor/: a class there replaces the core's
    shadowing = sorted(str(path.relative_to(store)) for folder in CORE_SHADOW_FOLDERS for path in tree_files(store / folder).values())
    # The object manager reads every app/etc/*di.xml and */di.xml: a preference there swaps any class
    app_etc_unknown = sorted(f"app/etc/{relative}" for relative in tree_files(store / "app" / "etc")
                             if relative not in APP_ETC_KNOWN and f"app/etc/{relative}" not in destinations)
    # generated/code holds the code generator's classes only, and runs at the first bin/magento
    generated_odd = sorted(f"generated/code/{relative}" for relative in tree_files(store / "generated" / "code")
                           if not (relative.endswith(".php") and GENERATED_SUFFIX.search(relative[:-4])))
    # The reference is only as good as the composer.json and composer.lock it was built from: the server's copies
    # can be the attacker's
    committed = {}
    patches_file = (json.loads(read_small((store / "composer.json"), CODE_FILE_MAX_BYTES) or "").get("extra") or {}).get("patches-file", "patches.json") \
        if (store / "composer.json").is_file() else "patches.json"
    inside = isinstance(patches_file, str) and not Path(patches_file).is_absolute() and ".." not in Path(patches_file).parts
    for name in ("composer.json", "composer.lock") + ((patches_file,) if inside and (store / patches_file).is_file() else ()):
        in_git, copy = git(store, "show", *GIT_SAFE_LOG, f"HEAD:./{name}"), clean / name
        committed[name] = None if in_git is None or not copy.is_file() else in_git == copy.read_text(errors="ignore")
    return {
        "clean_built_from_committed": committed,
        "vendor_files_differ": shown_names(differ, 200),
        "vendor_files_differ_count": len(differ),
        "vendor_files_only_in_store": shown_names(only_store, 200),
        "vendor_files_only_in_store_count": len(only_store),
        "vendor_files_missing_from_store": shown_names(only_clean, 200),
        "vendor_files_missing_from_store_count": len(only_clean),
        "store_autoload_options": autoload_options(store / "vendor"),
        "clean_autoload_options": autoload_options(clean / "vendor"),
        "store_autoloader_suffix": plain(next(iter(re.findall(r"ComposerAutoloaderInit(\w+)::", (store / "vendor" / "autoload.php").read_text(errors="ignore"))), None)
                                         if (store / "vendor" / "autoload.php").is_file() else None, r"\w{1,64}"),
        "composer_autoloader_files_differ": shown_names(composer_differ, 200),
        "composer_autoloader_files_differ_count": len(composer_differ),
        "composer_autoloader_unexpected_lines": {shown_name(name): lines for name, lines in autoloader_lines.items()},
        "composer_metadata_differ": shown_names(metadata_differ, 50),
        "patches_differ_from_committed": set(read_composer_patches(store)) != patched,
        "autoload_files_only_in_store": [plain(entry.replace(" ", ""), r"[\w$./':-]{1,240}") for entry in sorted(autoload_files(store / "vendor") - autoload_files(clean / "vendor"))],
        # Patched packages differ on purpose: check each file against its patch
        "patched_packages_files_differ": shown_names(patched_differ, 200),
        "patched_packages_files_differ_count": len(patched_differ),
        "vendor_symlinks_not_compared": shown_names(symlinked, 50),
        "vendor_not_regular_files": shown_names(not_regular, 50),
        "magento2_base_found": bool(bases),
        "root_files_differ": shown_names(root_differ, 200),
        "root_files_differ_count": len(root_differ),
        "root_files_missing": shown_names(root_missing, 50),
        "root_files_missing_count": len(root_missing),
        "root_files_only_in_store": shown_names(root_only_store, 200),
        "root_files_only_in_store_count": len(root_only_store),
        "core_namespace_files_outside_vendor": shown_names(shadowing, 200),
        "core_namespace_files_outside_vendor_count": len(shadowing),
        "app_etc_files_unknown": shown_names(app_etc_unknown, 100),
        "app_etc_files_unknown_count": len(app_etc_unknown),
        "generated_code_files_not_generated_names": shown_names(generated_odd, 200),
        "generated_code_files_not_generated_names_count": len(generated_odd),
        "map_entries_refused": map_refused,
        "not_compared": ["generated/ (moved aside and kept before the first bin/magento, then rebuilt by setup:di:compile)",
                         "app/code, app/design and app/etc (the store's own code and config), except the files magento2-base's map lists"],
    }


def safely(reader, *arguments):
    """A broken composer.json, composer.lock or scorecard becomes an error in the report, not a crash."""
    try:
        return reader(*arguments)
    except (ValueError, OSError, AttributeError, TypeError, KeyError, RecursionError) as error:
        return {"error": f"{reader.__name__}: {type(error).__name__}, this part wasn't checked"}


def main() -> None:
    if len(sys.argv) in (4, 5) and sys.argv[1] == "--show":
        show_masked(Path(sys.argv[2]).resolve(), sys.argv[3], sys.argv[4] if len(sys.argv) == 5 else None)
        return
    if len(sys.argv) == 4 and sys.argv[1] == "--compare":
        print(json.dumps(safely(compare_with_clean, Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve()), indent=2))
        return
    if len(sys.argv) != 2:
        sys.exit("Usage: audit.py <store-root> | --show <store-root> <file> [<commit>] | --compare <store-root> <clean-root>")
    root = Path(sys.argv[1]).resolve()
    if not (root / "app" / "etc").is_dir():
        sys.exit(f"{root} has no app/etc: run this from the store root, not a module")
    version = safely(read_version, root)
    scan = StoreScan(root)
    scan.run()
    app_code = safely(list_app_code_modules, root)
    report = {
        "root": str(root),
        "previous_run": safely(read_previous_run, root, version.get("version")),
        "version": version,
        "composer_patches": safely(read_composer_patches, root),
        "composer_config": safely(read_composer_config, root),
        "app_code_modules": shown_names(app_code, 500) if isinstance(app_code, list) else app_code,
        "app_code_modules_count": len(app_code) if isinstance(app_code, list) else None,
        "env": safely(read_env, root),
        "modules": safely(read_enabled_modules, root),
        "git": safely(read_git, root),
        **scan.report(),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
