from __future__ import annotations

import ipaddress
import re
import shlex
from pathlib import Path
from urllib.parse import urlparse

from .models import ScopeDocument


NETWORK_TOOLS = {
    "curl", "wget", "http", "httpx", "nmap", "masscan", "nuclei", "ffuf", "gobuster",
    "feroxbuster", "nikto", "sqlmap", "subfinder", "amass", "dnsx", "naabu", "katana",
    "gau", "waybackurls", "hydra", "medusa", "netcat", "nc", "ssh", "scp",
    # Methodology tools (recon/genpentest/hermes): URL-addressing scanners
    "arjun", "xsstrike", "openredirex", "whatweb", "ssrfmap", "rustscan", "puredns",
    "sublist3r", "assetfinder", "bsqli", "dalfox", "getjs", "jsluice",
}
DESTRUCTIVE_PATTERNS = [
    re.compile(r"(^|\s)rm\s+(-[^\s]*r[^\s]*f|-rf|-fr)\b"),
    re.compile(r"(^|\s)rm\s+(?:-[^\s]*\s)*(?:/root|/etc|/usr|/bin|/sbin|/boot|/lib|/var|/opt|/proc|/sys)(?:/|\s|$)"),
    re.compile(r"(^|\s)(mkfs|shutdown|reboot|poweroff)\b"),
    re.compile(r"(^|\s)dd\s+.*\bof=/dev/"),
    re.compile(r">\s*/dev/(sd|nvme|disk)"),
]
PROTECTED_CONTROL_FILES = (".hacker-harness/scope.yaml", ".hacker-harness/settings.json", ".hacker-harness/settings.local.json", ".hacker-harness/mcp.json", ".hacker-harness/config.yaml", ".hacker-harness/apis.yaml", ".hacker-harness/state.db", ".hacker-harness/history", ".hacker-harness/SYSTEM.md")
TARGET_RE = re.compile(r"https?://[^\s'\"]+|\b(?<![\w@])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Final labels that are file extensions, not TLDs (cookies.txt, Register.asp, out.html).
FILE_EXTENSION_TLDS = {
    "txt", "log", "md", "markdown", "html", "htm", "asp", "aspx", "php", "jsp", "js", "mjs", "cjs",
    "ts", "jsx", "tsx", "css", "scss", "sass", "json", "xml", "yml", "yaml", "toml", "ini", "cfg",
    "conf", "csv", "tsv", "xls", "xlsx", "doc", "docx", "pdf", "ppt", "pptx", "png", "jpg", "jpeg",
    "gif", "svg", "webp", "ico", "bmp", "tif", "tiff", "avif", "zip", "tar", "gz", "tgz", "bz2",
    "xz", "7z", "rar", "deb", "rpm", "exe", "msi", "dll", "so", "dylib", "py", "pyc", "rb", "go",
    "rs", "java", "class", "jar", "war", "c", "h", "cpp", "hpp", "cs", "sh", "bash", "zsh", "bat",
    "ps1", "sql", "db", "sqlite", "sqlite3", "lock", "pid", "tmp", "bak", "old", "swp", "map",
    "pem", "key", "crt", "csr", "p12", "pfx", "der", "cer", "jks", "env", "git", "nvmrc",
}


def _quote_mask(command: str) -> list[bool]:
    """True for characters inside single/double quotes (with double-quote escapes)."""
    mask = [False] * len(command)
    quote: str | None = None
    index = 0
    while index < len(command):
        ch = command[index]
        if quote:
            mask[index] = True
            if ch == "\\" and quote == '"' and index + 1 < len(command) and command[index + 1] in {'"', "\\", "$"}:
                index += 1
                if index < len(command):
                    mask[index] = True
            elif ch == quote:
                quote = None
        else:
            if ch in {'"', "'"}:
                quote = ch
                mask[index] = True
        index += 1
    return mask


def _extract_targets(command: str) -> list[str]:
    """Pull candidate targets out of a command, ignoring file names, email domains,
    quoted data, and uppercase tech names (e.g. ASP.NET). URL-form targets are
    authoritative everywhere, including inside quotes."""
    targets: list[str] = []
    mask = _quote_mask(command)
    for match in TARGET_RE.finditer(command):
        raw = match.group(0)
        start, end = match.span()
        if "://" in raw:
            targets.append(raw)
            continue
        if any(mask[start:end]):
            continue
        if raw != raw.lower():
            continue
        label = raw.rsplit(".", 1)[-1].lower()
        if label in FILE_EXTENSION_TLDS:
            continue
        targets.append(raw)
    return targets


class ScopeError(PermissionError):
    pass


def _hostname(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or value).strip("[]").lower().rstrip(".")


def _matches(target: str, rule: str) -> bool:
    host = _hostname(target)
    raw_rule = rule.strip().lower()
    rule_host = _hostname(raw_rule.lstrip("*."))
    try:
        ip = ipaddress.ip_address(host)
        try:
            return ip in ipaddress.ip_network(raw_rule, strict=False)
        except ValueError:
            return ip == ipaddress.ip_address(rule_host)
    except ValueError:
        if raw_rule.startswith("*."):
            return host.endswith("." + rule_host) and host != rule_host
        return host == rule_host


def target_allowed(target: str, scope: ScopeDocument) -> bool:
    if not scope.is_active():
        return False
    if any(_matches(target, item.value) for item in scope.excluded):
        return False
    return any(_matches(target, item.value) for item in scope.targets)


def validate_command(command: str, scope: ScopeDocument, extra_domains: tuple[str, ...] = ()) -> None:
    if any(path in command for path in PROTECTED_CONTROL_FILES):
        raise ScopeError("commands may not modify or access harness control files; edit them directly as the operator")
    if any(pattern.search(command) for pattern in DESTRUCTIVE_PATTERNS):
        raise ScopeError("destructive command pattern is blocked")
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        raise ScopeError(f"invalid shell syntax: {exc}") from exc
    executables = {Path(token).name.lower() for token in tokens if Path(token).name.lower() in NETWORK_TOOLS}
    if not executables:
        return
    targets = _extract_targets(command)
    if not targets:
        raise ScopeError(f"network tool(s) {sorted(executables)} require an explicit in-scope target")
    denied = [target for target in targets if not target_allowed(target, scope) and not any(_matches(target, item) or _matches(target, "*." + item.lstrip("*.")) for item in extra_domains)]
    if denied:
        raise ScopeError(f"target is not in active authorization scope: {', '.join(denied)}")
