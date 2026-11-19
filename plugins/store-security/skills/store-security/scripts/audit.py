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

import json
import os
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

SCORECARD_FILE = Path("var") / "mage-os-security.json"
PRODUCT_PACKAGES = (
    "magento/product-enterprise-edition",
    "mage-os/product-community-edition", "magento/product-community-edition",
    "mage-os/magento2-base", "magento/magento2-base",
)
GUESSABLE_ADMIN_PATHS = {"admin", "backend", "admin_1", "adminhtml", "magento", "manager", "administrator"}
SENSITIVE_PATHS = ["app/etc/env.php", "auth.json", ".env", "var/", "generated/", "pub/media/", "pub/static/"]
# .env.example / .env.dist / .env.sample hold no secrets and are meant to be committed
NEVER_TRACKED = re.compile(
    r"(^|/)(app/etc/env\.php(\.[^/]+)?|auth\.json(\.[^/]+)?|\.env(\.(?!example$|dist$|sample$)[^/]+)?"
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
    r"eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|strrev)\s*\("
    r"|(assert|eval|system|exec|passthru|shell_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)"
    r"|\$_(GET|POST|REQUEST|COOKIE)\s*\[[^]]*\]\s*\("
    r"|base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"
)
# PHP function names ignore case: EVAL(BASE64_DECODE(...)) runs too
OBFUSCATION = re.compile(OBFUSCATION_STRICT + r"|create_function\s*\(|(?<![\w>:$])eval\s*\(\s*\$|(\\x[0-9a-fA-F]{2}){8,}", re.IGNORECASE)
OBFUSCATION_VENDOR = re.compile(OBFUSCATION_STRICT, re.IGNORECASE)
# Skimmer tells in JavaScript: decoded-then-run code, a raw WebSocket out, long hex escapes
JS_SKIMMER = re.compile(
    r"eval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\("
    r"|new\s+Function\s*\(\s*atob\s*\("
    r"|new\s+WebSocket\s*\(\s*['\"`]wss?://"
    r"|(\\x[0-9a-fA-F]{2}){40,}"
)
# Words each pattern needs: a file without any of them is skipped before the (much slower) regex runs
TRIGGERS = {
    "strict": ("eval", "$_"),
    "broad": ("eval", "$_", "create_function", "\\x"),
    "javascript": ("eval", "Function", "WebSocket", "\\x"),
}
PHP_EXTENSION = re.compile(r"\.(php\d?|pht|phtml|phar|inc)$", re.IGNORECASE)
# <?php, or a short <?= followed by a variable, a backtick, @ or a function that runs code: a bare <?= turns
# up by chance in binary images
PHP_OPEN_TAG = re.compile(rb"<\?php|<\?=\s*([$`@]|(system|eval|exec|passthru|shell_exec|assert|include|require|popen|proc_open)\b)", re.IGNORECASE)
# A handler or type naming PHP makes the server run it (Magento's own "AddHandler cgi-script .php" in
# pub/media does the opposite); engine on re-enables PHP where Magento turns it off
SERVER_CONFIG_RISK = re.compile(
    r"auto_(prepend|append)_file|(AddType|AddHandler|SetHandler|ForceType)\s+[\"']?\S*(php|x-httpd|proxy:fcgi|proxy:unix|fcgid-script)"
    r"|php_(admin_)?(flag|value)\s+engine\s+(1|on)\b|php_admin_value|Options\s+[^\n#]*\+ExecCGI", re.IGNORECASE)
# Magento ships these two, with memory and execution limits
SHIPPED_USER_INI = {".user.ini", "pub/.user.ini"}
MEDIA_SNIFF_BYTES = 64 * 1024
SCAN_FILE_MAX_BYTES = 2 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 120
# The repository's own config can run commands (hooks, fsmonitor, textconv, external diff, the signature
# verifier behind log.showSignature): turn them off
GIT_SAFE_OPTIONS = (
    "-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null", "-c", "diff.external=", "-c", "core.pager=cat",
    "-c", "log.showSignature=false", "-c", "gpg.program=false", "-c", "gpg.ssh.program=false", "-c", "gpg.x509.program=false",
)
GIT_SAFE_LOG = ("--no-textconv", "--no-ext-diff", "--no-show-signature")
# English messages, so a refusal is recognized whatever the machine's language
GIT_ENVIRONMENT = {**os.environ, "LC_ALL": "C", "LANGUAGE": "C", "GIT_TERMINAL_PROMPT": "0"}
# Deployer, Capistrano and most hosts link these to a shared folder
TOP_SYMLINKS_FOLLOWED = {"pub/media", "pub/static", "app/etc"}
# Kernel and device files: reading them can block or consume them
SYSTEM_FOLDERS = ("/proc", "/sys", "/dev", "/run", "/boot")
# bin/ holds bin/magento, PHP without an extension, run by cron and by the agent
SCANNED_FOLDERS = ("app", "bin", "generated", "lib", "pub", "setup", "vendor")
SERVER_FILES = (".htaccess", ".user.ini")
HITS_PER_CHECK = 50
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
CRITICAL_DECISIONS = {"patches.upgrade", "dependencies.update", "secrets.rotate_crypt_key"}
# A Critical decision put off comes back after this many days at most, whatever the file says
CRITICAL_MAX_DELAY_DAYS = 90
ISO_DATE = r"\d{4}-\d{2}-\d{2}"
AREA_KEYS = {"version_and_patches", "dependencies", "compromise", "secrets", "admin", "configuration", "live_site"}
AREA_STATUSES = {"pass", "partial", "fail", "not_checked"}


def run_git(root: Path, *arguments: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["git", *GIT_SAFE_OPTIONS, "-C", str(root), *arguments], capture_output=True, text=True,
                              timeout=GIT_TIMEOUT_SECONDS, stdin=subprocess.DEVNULL, env=GIT_ENVIRONMENT)
    except (OSError, subprocess.TimeoutExpired):
        return None


def git(root: Path, *arguments: str, ok_codes: tuple = (0,)) -> str | None:
    result = run_git(root, *arguments)
    return result.stdout if result is not None and result.returncode in ok_codes else None


def read_version(root: Path) -> dict:
    lock = root / "composer.lock"
    if not lock.exists():
        return {"composer_lock": False}
    packages = {package["name"]: package for package in json.loads(lock.read_text()).get("packages", [])}
    composer = root / "composer.json"
    direct = set(json.loads(composer.read_text()).get("require", {})) if composer.exists() else set()
    product = next((name for name in PRODUCT_PACKAGES if name in packages), None)
    distribution = None
    if product:
        distribution = "adobe-commerce" if "enterprise" in product else "mage-os" if product.startswith("mage-os/") else "magento"
    return {
        "composer_lock": True,
        "distribution": distribution,
        "product_package": product,
        "version": packages[product]["version"].lstrip("v") if product else None,
        "quality_patches_installed": "magento/quality-patches" in packages,
        "composer_patches_installed": "cweagans/composer-patches" in packages,
        # Abandoned packages the core pulls in are the core's problem: only direct requirements are the store's
        "abandoned_direct_requirements": sorted(name for name, package in packages.items() if package.get("abandoned") and name in direct),
        "abandoned_through_core_or_extensions": len([name for name, package in packages.items() if package.get("abandoned") and name not in direct]),
        "package_count": len(packages),
    }


def read_composer_patches(root: Path) -> dict:
    composer = root / "composer.json"
    if not composer.exists():
        return {}
    extra = json.loads(composer.read_text()).get("extra", {})
    patches = dict(extra.get("patches", {})) if isinstance(extra, dict) else {}
    # composer-patches v1 names the file in extra.patches-file; v2 reads patches.json by default
    patches_file = (extra.get("patches-file") if isinstance(extra, dict) else None) or "patches.json"
    if (root / patches_file).exists():
        patches.update(json.loads((root / patches_file).read_text()).get("patches", {}))
    return {package: list(entries) if isinstance(entries, dict) else entries for package, entries in patches.items()}


def mask_url(url: str) -> str:
    """Repository URLs can carry credentials (https://user:token@host, ?access_token=): drop both."""
    return re.sub(r"(?<=://)[^/@]+@", "***@", url.split("?", 1)[0].split("#", 1)[0])


def read_composer_config(root: Path) -> dict:
    """Where Composer fetches code from and which plugins may run: both are ways in for an attacker."""
    composer = root / "composer.json"
    if not composer.exists():
        return {}
    data = json.loads(composer.read_text())
    repositories = data.get("repositories", [])
    repositories = repositories.values() if isinstance(repositories, dict) else repositories
    config = data.get("config", {}) if isinstance(data.get("config"), dict) else {}
    allow_plugins = config.get("allow-plugins")
    return {
        "repositories": [{"type": entry.get("type"), "url": mask_url(str(entry.get("url", "")))} for entry in repositories if isinstance(entry, dict)],
        "insecure_repositories": [mask_url(str(entry.get("url", ""))) for entry in repositories if isinstance(entry, dict) and str(entry.get("url", "")).startswith("http://")],
        "secure_http_disabled": config.get("secure-http") is False,
        "allow_plugins": "all" if allow_plugins is True else sorted(name for name, allowed in allow_plugins.items() if allowed) if isinstance(allow_plugins, dict) else None,
        "scripts": sorted(data.get("scripts", {})) if isinstance(data.get("scripts"), dict) else [],
    }


def list_app_code_modules(root: Path) -> list[str]:
    base = root / "app" / "code"
    return sorted(f"{vendor.name}_{module.name}" for vendor in base.iterdir() if vendor.is_dir() for module in vendor.iterdir() if module.is_dir()) if base.is_dir() else []


def php_string(source: str, key: str) -> str | None:
    match = re.search(rf"'{re.escape(key)}'\s*=>\s*'([^']*)'", source)
    return match.group(1) if match else None


def read_env(root: Path) -> dict:
    """Facts about env.php, never its secret values."""
    env = root / "app" / "etc" / "env.php"
    if not env.exists():
        return {"present": False}
    source = env.read_text(errors="ignore")
    front_name = php_string(source, "frontName")
    return {
        "present": True,
        "mage_mode": php_string(source, "MAGE_MODE"),
        "admin_path_guessable": (front_name or "admin").lower() in GUESSABLE_ADMIN_PATHS,
        "admin_path_length": len(front_name) if front_name else None,
        "x_frame_options": php_string(source, "x-frame-options"),
        "has_crypt_key": "'crypt'" in source,
    }


def dumped_config_sections(root: Path) -> list[str]:
    """Config sections kept in files (app:config:dump), which win over the database: only the 'system' part counts."""
    sections = set()
    for name in ("config.php", "env.php"):
        path = root / "app" / "etc" / name
        source = path.read_text(errors="ignore") if path.exists() else ""
        start = source.find("'system'")
        if start >= 0:
            sections |= set(re.findall(r"'(csp|admin|web|dev|twofactorauth|webapi)'\s*=>", source[start:]))
    return sorted(sections)


def read_enabled_modules(root: Path) -> dict:
    config = root / "app" / "etc" / "config.php"
    if not config.exists():
        return {"present": False}
    source = config.read_text(errors="ignore")
    modules = source[source.find("'modules'"):] if "'modules'" in source else ""
    state = {name: value == "1" for name, value in re.findall(r"'([A-Z]\w*_\w+)'\s*=>\s*(\d)", modules)}
    return {
        "present": True,
        "two_factor_auth": state.get("Magento_TwoFactorAuth"),
        "csp": state.get("Magento_Csp"),
        "captcha": state.get("Magento_Captcha"),
        "admin_adobe_ims": state.get("Magento_AdminAdobeIms"),
        "version_module": state.get("Magento_Version"),
        "enabled_third_party_modules": sorted(name for name, enabled in state.items() if enabled and not name.startswith(("Magento_", "MageOS_"))),
        "dumped_config_paths": dumped_config_sections(root),
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

    def lines(*arguments: str, ok_codes: tuple = (0,)) -> list[str]:
        output = git(root, *arguments, ok_codes=ok_codes)
        if output is None:
            errors.append(f"git {arguments[0]} failed or timed out")
        return (output or "").splitlines()

    tracked = lines("ls-files")
    # check-ignore exits 1 when none of the paths is ignored, and refuses "pub/media/" when pub/media is a
    # symlink: ask about the link itself then
    queried = {path.rstrip("/") if (root / path.rstrip("/")).is_symlink() else path: path for path in SENSITIVE_PATHS}
    ignored = {queried.get(path, path) for path in lines("check-ignore", "--no-index", *queried, ok_codes=(0, 1))}
    # --no-renames: a renamed secrets file shows as added under its new name too
    ever_added = lines("log", "--all", "--diff-filter=A", "--no-renames", "--name-only", "--format=", *GIT_SAFE_LOG)
    history = {}
    for name, pattern in SECRET_PATTERNS.items():
        output = git(root, "log", "--all", "-G", pattern, "--format=commit %h", "--name-only", *GIT_SAFE_LOG)
        if output is None:
            history[name] = {"error": "git log failed or timed out"}
            continue
        commits, files, current = [], set(), None
        for line in output.splitlines():
            if line.startswith("commit "):
                current = line[len("commit "):]
                commits.append(current)
            elif line and current:
                files.add(line)
        if commits:
            history[name] = {"commits": commits[:10], "commit_count": len(commits), "files": sorted(files)[:10]}
    return {
        "is_git_repository": True,
        "tracked_sensitive_files": sorted(path for path in tracked if NEVER_TRACKED.search(path)),
        "sensitive_files_in_history": sorted({path for path in ever_added if NEVER_TRACKED.search(path)}),
        "not_ignored": [path for path in SENSITIVE_PATHS if path not in ignored],
        "secret_patterns_in_history": history,
        "errors": errors,
    }


def refused_target(target: Path, root: Path) -> str | None:
    """Why a symlinked folder's target isn't walked: the whole disk, the store's own parents, the kernel's files."""
    if target == Path("/") or root.is_relative_to(target):
        return "points to / or to a parent of the store"
    if any(target == Path(system) or target.is_relative_to(system) for system in SYSTEM_FOLDERS):
        return "points to a system folder"
    return None


class StoreScan:
    """One walk over the store's code and uploads, every check applied to each file as it goes by: nothing but
    the findings is kept, so a million uploads don't fill the memory."""

    def __init__(self, root: Path):
        self.root = root
        self.hits: dict[str, list[str]] = {name: [] for name in (
            "pub_root_php", "pub_unexpected_php", "media_or_static_php", "php_code_in_media_files",
            "unexpected_user_ini_files", "risky_directives",
            "php", "generated_and_setup_php", "vendor_php", "javascript",
        )}
        self.followed_symlinks: dict[str, str] = {}
        self.refused_symlinks: dict[str, str] = {}
        self.symlinked_files: set[str] = set()
        self.symlinked_folders: set[str] = set()
        self.unreadable: set[str] = set()
        self.skipped_large: set[str] = set()
        self.media_partly_read = 0

    def add(self, category: str, value: str) -> None:
        if len(self.hits[category]) < HITS_PER_CHECK:
            self.hits[category].append(value)

    def run(self) -> None:
        for path in sorted(self.root.iterdir()) if self.root.is_dir() else []:
            if path.is_file() and not path.is_symlink() and (PHP_EXTENSION.search(path.name) or path.name in SERVER_FILES):
                self.check(path, path.name)
        for base in SCANNED_FOLDERS:
            self.walk(self.root / base, base)

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
                self.followed_symlinks[shown] = str(target)
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
                        elif entry.is_dir():
                            self.symlinked_folders.add(child)
                        elif PHP_EXTENSION.search(entry.name) or entry.name in SERVER_FILES:
                            self.symlinked_files.add(child)
                    elif entry.is_dir(follow_symlinks=False):
                        pending.append((Path(entry.path), child))
                    elif entry.is_file(follow_symlinks=False):
                        self.check(Path(entry.path), child)
                except OSError:
                    self.unreadable.add(child)

    def read(self, path: Path, shown: str) -> str | None:
        try:
            if path.stat().st_size > SCAN_FILE_MAX_BYTES:
                self.skipped_large.add(shown)
                return None
            return path.read_text(errors="ignore")
        except OSError:
            self.unreadable.add(shown)
            return None

    def read_ends(self, path: Path, shown: str) -> bytes | None:
        """First and last 64 KB: where code hidden in an upload sits, without reading big files whole."""
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                if size <= 2 * MEDIA_SNIFF_BYTES:
                    return handle.read()
                self.media_partly_read += 1
                head = handle.read(MEDIA_SNIFF_BYTES)
                handle.seek(size - MEDIA_SNIFF_BYTES)
                return head + b"\n" + handle.read(MEDIA_SNIFF_BYTES)
        except OSError:
            self.unreadable.add(shown)
            return None

    def check(self, path: Path, shown: str) -> None:
        top = shown.split("/", 1)[0]
        is_php = bool(PHP_EXTENSION.search(path.name)) or top == "bin"
        in_media = shown.startswith("pub/media/")
        in_static = shown.startswith("pub/static/")
        if in_media or in_static:
            if is_php:
                self.add("media_or_static_php", shown)
            elif in_media and path.name not in SERVER_FILES:
                content = self.read_ends(path, shown)
                if content is not None and PHP_OPEN_TAG.search(content):
                    # PHP code inside an image or any other upload: harmless alone, a backdoor once included
                    self.add("php_code_in_media_files", shown)
        elif top == "pub" and is_php and not SHIPPED_PUB_PHP.fullmatch(shown):
            # Under Apache every .php under pub/ runs, not only those at its root
            self.add("pub_root_php" if shown.count("/") == 1 else "pub_unexpected_php", shown)
        if path.name in SERVER_FILES and (top == "pub" or "/" not in shown):
            if path.name == ".user.ini" and shown not in SHIPPED_USER_INI:
                self.add("unexpected_user_ini_files", shown)
            for number, line in enumerate((self.read(path, shown) or "").splitlines(), start=1):
                if SERVER_CONFIG_RISK.search(line) and not line.lstrip().startswith("#"):
                    self.add("risky_directives", f"{shown}:{number}")
        php_pattern = None
        if is_php and not in_static:
            php_pattern = ("vendor_php", OBFUSCATION_VENDOR, "strict") if top == "vendor" else \
                ("generated_and_setup_php", OBFUSCATION_VENDOR, "strict") if top in ("generated", "setup") else ("php", OBFUSCATION, "broad")
        js = path.suffix in (".js", ".html", ".phtml") and (top in ("app", "pub") or shown.startswith("lib/web/"))
        if php_pattern or js:
            source = self.read(path, shown)
            if source is None:
                return
            for category, pattern, triggers in ([php_pattern] if php_pattern else []) + ([("javascript", JS_SKIMMER, "javascript")] if js else []):
                # PHP triggers are matched case-insensitively, like the patterns; JavaScript is case-sensitive
                haystack = source if triggers == "javascript" else source.lower()
                if not any(word in haystack for word in TRIGGERS[triggers]):
                    continue
                match = pattern.search(source)
                if match:
                    self.add(category, f"{shown}:{source.count(chr(10), 0, match.start()) + 1}")

    def report(self) -> dict:
        hits = {name: sorted(values) for name, values in self.hits.items()}
        return {
            "unexpected_php": {
                "pub_directory": (self.root / "pub").is_dir(),
                **{name: hits[name] for name in ("pub_root_php", "pub_unexpected_php", "media_or_static_php", "php_code_in_media_files")},
            },
            "server_config": {name: hits[name] for name in ("unexpected_user_ini_files", "risky_directives")},
            "obfuscated_code": {name: hits[name] for name in ("php", "generated_and_setup_php", "vendor_php", "javascript")},
            "files_not_checked": {
                "followed_symlinked_folders": self.followed_symlinks,
                "refused_symlinked_folders": self.refused_symlinks,
                "symlinked_php_or_server_files": sorted(self.symlinked_files)[:HITS_PER_CHECK],
                "symlinked_folders_not_followed": sorted(self.symlinked_folders)[:HITS_PER_CHECK],
                "unreadable": sorted(self.unreadable)[:HITS_PER_CHECK],
                "unreadable_count": len(self.unreadable),
                "skipped_large_files": sorted(self.skipped_large)[:HITS_PER_CHECK],
                "skipped_large_count": len(self.skipped_large),
                # Uploads over 128 KB: only their first and last 64 KB were read
                "media_files_partly_read": self.media_partly_read,
            },
        }


def masked_keys(source: str, env_style: bool) -> list[str]:
    """Key names with every value masked. Quotes are followed over the whole file, the way PHP, JSON or a .env
    reads them (backslashes in pairs, comments skipped), so a line inside a multi-line value (a rotated crypt
    key, a PEM) is never taken for a key. Anything this can't follow (a PHP heredoc) stops the output there."""
    key_line = ENV_KEY_LINE if env_style else KEY_LINE
    shown, quote, block_comment = [], None, False
    for number, line in enumerate(source.splitlines(), start=1):
        if quote is None and not block_comment:
            match = key_line.match(line)
            if match:
                shown.append(f"{number}: {match.group(1)} {match.group(match.lastindex)} ***")
        index = 0
        while index < len(line):
            character, following = line[index], line[index + 1:index + 2]
            if block_comment:
                if character == "*" and following == "/":
                    block_comment, index = False, index + 1
            elif quote:
                # In a .env single-quoted value a backslash is plain text; everywhere else it escapes one character
                if character == "\\" and not (env_style and quote == "'"):
                    index += 1
                elif character == quote:
                    quote = None
            elif character in ("'", '"'):
                quote = character
            elif character == "#" and (not env_style or index == 0 or line[index - 1].isspace()):
                break
            elif not env_style and character == "/" and following == "/":
                break
            elif not env_style and character == "/" and following == "*":
                block_comment, index = True, index + 1
            elif not env_style and line.startswith("<<<", index):
                shown.append(f"{number}: (heredoc: nothing shown from here on)")
                return shown
            index += 1
    if quote:
        shown.append("(a quote never closes: some keys may be missing)")
    return shown


def show_masked(root: Path, file: str, commit: str | None) -> None:
    if commit:
        if not re.fullmatch(r"[0-9a-fA-F]{4,40}", commit) or file.startswith(("-", "/")) or ".." in Path(file).parts:
            sys.exit("The commit must be a hash and the file a path inside the store")
        resolved = (git(root, "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}") or "").strip()
        # A branch or tag named like a hash would win over the commit: refuse rather than show another file
        if not resolved.startswith(commit.lower()):
            sys.exit(f"{commit} isn't a commit of this repository, or a branch or tag has that name")
        source = git(root, "show", *GIT_SAFE_LOG, f"{resolved}:{file}")
        if source is None:
            sys.exit(f"{file} isn't in commit {commit}")
    else:
        path = (root / file).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            sys.exit(f"{file} isn't a file of the store")
        source = path.read_text(errors="ignore")
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
        data = json.loads(scorecard.read_text())
    except (ValueError, OSError):
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
            return decision.get("version_at_decision") != version
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


def main() -> None:
    if len(sys.argv) in (4, 5) and sys.argv[1] == "--show":
        show_masked(Path(sys.argv[2]).resolve(), sys.argv[3], sys.argv[4] if len(sys.argv) == 5 else None)
        return
    if len(sys.argv) != 2:
        sys.exit("Usage: audit.py <store-root> | audit.py --show <store-root> <file> [<commit>]")
    root = Path(sys.argv[1]).resolve()
    if not (root / "app" / "etc").is_dir():
        sys.exit(f"{root} has no app/etc: run this from the store root, not a module")
    version = read_version(root)
    scan = StoreScan(root)
    scan.run()
    report = {
        "root": str(root),
        "previous_run": read_previous_run(root, version.get("version")),
        "version": version,
        "composer_patches": read_composer_patches(root),
        "composer_config": read_composer_config(root),
        "app_code_modules": list_app_code_modules(root),
        "env": read_env(root),
        "modules": read_enabled_modules(root),
        "git": read_git(root),
        **scan.report(),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
