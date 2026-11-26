"""Deterministic misconfiguration checks for Cisco IOS configurations.

Each rule inspects the parsed configuration and returns zero or more findings.
The rules are intentionally simple and explainable: they are the baseline that
the AI review in audit_agent.py builds on, and they keep working with no API
access at all.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    line: int | None  # 1-based line number, or None when something is missing
    evidence: str
    fix: str
    source: str = "rule"


@dataclass
class Block:
    """A top-level config line plus the indented lines that belong to it."""

    header: str
    line: int
    children: list[tuple[int, str]] = field(default_factory=list)

    def child_lines(self) -> list[str]:
        return [text for _, text in self.children]


def parse_blocks(text: str) -> list[Block]:
    blocks: list[Block] = []
    current: Block | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("!"):
            current = None
            continue
        if line[0] in (" ", "\t") and current is not None:
            current.children.append((number, stripped))
        else:
            current = Block(header=stripped, line=number)
            blocks.append(current)
    return blocks


def _headers(blocks: list[Block], pattern: str) -> list[Block]:
    regex = re.compile(pattern, re.IGNORECASE)
    return [b for b in blocks if regex.search(b.header)]


def _has(blocks: list[Block], pattern: str) -> bool:
    return bool(_headers(blocks, pattern))


def _missing(rule_id: str, severity: str, title: str, fix: str) -> Finding:
    return Finding(rule_id, severity, title, None, "(not present in configuration)", fix)


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------

def check_enable_password(blocks: list[Block]) -> list[Finding]:
    findings = []
    for b in _headers(blocks, r"^enable password\b"):
        findings.append(Finding(
            "IOS-001", "high",
            "Privileged password stored with 'enable password'",
            b.line, b.header,
            "no enable password\nenable algorithm-type scrypt secret <strong-password>",
        ))
    if not _has(blocks, r"^enable (secret|password)\b"):
        findings.append(_missing(
            "IOS-002", "medium", "No enable secret configured",
            "enable algorithm-type scrypt secret <strong-password>",
        ))
    return findings


def check_user_passwords(blocks: list[Block]) -> list[Finding]:
    findings = []
    for b in _headers(blocks, r"^username \S+ .*\bpassword\b"):
        findings.append(Finding(
            "IOS-003", "high",
            "Local user defined with 'password' instead of 'secret'",
            b.line, b.header,
            "username <name> privilege 15 algorithm-type scrypt secret <strong-password>",
        ))
    return findings


def check_type7(blocks: list[Block]) -> list[Finding]:
    findings = []
    regex = re.compile(r"\b(password|key) 7 \S+", re.IGNORECASE)
    for b in blocks:
        for number, text in [(b.line, b.header)] + b.children:
            if regex.search(text):
                findings.append(Finding(
                    "IOS-004", "medium",
                    "Type 7 (reversible) password in configuration",
                    number, text,
                    "Replace with a type 8/9 secret, or type 6 (AES) for keys that must be recoverable.",
                ))
    return findings


def check_password_encryption(blocks: list[Block]) -> list[Finding]:
    if _has(blocks, r"^service password-encryption$"):
        return []
    return [_missing(
        "IOS-005", "low", "'service password-encryption' is not enabled",
        "service password-encryption",
    )]


# --------------------------------------------------------------------------
# Management plane
# --------------------------------------------------------------------------

def check_vty(blocks: list[Block]) -> list[Finding]:
    findings = []
    for b in _headers(blocks, r"^line vty\b"):
        children = b.child_lines()
        transport = [c for c in children if c.startswith("transport input")]
        if not transport:
            findings.append(Finding(
                "IOS-006", "high",
                "VTY lines do not restrict the transport protocol (Telnet may be allowed)",
                b.line, b.header,
                f"{b.header}\n transport input ssh",
            ))
        for number, text in b.children:
            if text.startswith("transport input") and re.search(r"\b(telnet|all)\b", text):
                findings.append(Finding(
                    "IOS-006", "high",
                    "Telnet is allowed on VTY lines",
                    number, text,
                    f"{b.header}\n transport input ssh",
                ))
        if not any(c.startswith("access-class") for c in children):
            findings.append(Finding(
                "IOS-007", "medium",
                "VTY lines have no access-class restricting source addresses",
                b.line, b.header,
                "ip access-list standard MGMT-ONLY\n permit <management-subnet> <wildcard>\n"
                f"{b.header}\n access-class MGMT-ONLY in",
            ))
    return findings


def check_exec_timeout(blocks: list[Block]) -> list[Finding]:
    findings = []
    for b in _headers(blocks, r"^line (con|vty|aux)\b"):
        for number, text in b.children:
            if re.match(r"exec-timeout 0( 0)?$", text):
                findings.append(Finding(
                    "IOS-008", "medium",
                    f"Idle sessions never time out on '{b.header}'",
                    number, text,
                    f"{b.header}\n exec-timeout 10 0",
                ))
    return findings


def check_console_auth(blocks: list[Block]) -> list[Finding]:
    """Console must authenticate, and must not depend only on a remote AAA server."""
    findings = []
    aaa_enabled = _has(blocks, r"^aaa new-model$")
    for b in _headers(blocks, r"^line con 0$"):
        children = b.child_lines()
        if aaa_enabled:
            match = next(
                (re.match(r"login authentication (\S+)", c) for c in children
                 if c.startswith("login authentication")),
                None,
            )
            list_name = match.group(1) if match else "default"
            method_line = next(
                (h for h in _headers(blocks, rf"^aaa authentication login {re.escape(list_name)}\b")),
                None,
            )
            if method_line is not None:
                methods = method_line.header.split()[4:]
                if not any(m in ("local", "local-case") for m in methods):
                    findings.append(Finding(
                        "IOS-009", "medium",
                        "Console authentication has no local fallback (lockout risk if the AAA server is down)",
                        method_line.line, method_line.header,
                        "aaa authentication login CONSOLE local\nline con 0\n login authentication CONSOLE",
                    ))
        else:
            has_login_local = "login local" in children
            has_line_password = "login" in children and any(c.startswith("password") for c in children)
            if not (has_login_local or has_line_password):
                findings.append(Finding(
                    "IOS-010", "medium",
                    "Console line has no authentication",
                    b.line, b.header,
                    "line con 0\n login local",
                ))
    return findings


def check_aaa(blocks: list[Block]) -> list[Finding]:
    if _has(blocks, r"^aaa new-model$"):
        return []
    return [_missing(
        "IOS-011", "medium", "AAA is not enabled ('aaa new-model' missing)",
        "aaa new-model\naaa authentication login default local",
    )]


def check_ssh(blocks: list[Block]) -> list[Finding]:
    findings = []
    for b in _headers(blocks, r"^ip ssh version 1$"):
        findings.append(Finding(
            "IOS-012", "high", "SSH version 1 is enabled", b.line, b.header, "ip ssh version 2",
        ))
    if not _has(blocks, r"^ip ssh version 2$") and not _has(blocks, r"^ip ssh version 1$"):
        findings.append(_missing(
            "IOS-013", "medium", "SSH version 2 is not enforced", "ip ssh version 2",
        ))
    return findings


def check_http(blocks: list[Block]) -> list[Finding]:
    return [
        Finding(
            "IOS-014", "medium", "Unencrypted HTTP management server is enabled",
            b.line, b.header, "no ip http server",
        )
        for b in _headers(blocks, r"^ip http server$")
    ]


def check_snmp(blocks: list[Block]) -> list[Finding]:
    findings = []
    regex = re.compile(r"^snmp-server community (\S+)(.*)$", re.IGNORECASE)
    for b in blocks:
        match = regex.match(b.header)
        if not match:
            continue
        community, rest = match.group(1), match.group(2).split()
        problems, severity = [], "medium"
        if community.lower() in ("public", "private"):
            problems.append("default community string")
            severity = "high"
        if "RW" in [r.upper() for r in rest]:
            problems.append("read-write access")
            severity = "high"
        has_acl = bool(rest) and rest[-1].upper() not in ("RO", "RW")
        if not has_acl:
            problems.append("no ACL restricting who can query")
        if problems:
            findings.append(Finding(
                "IOS-015", severity,
                "Weak SNMP v1/v2c community: " + ", ".join(problems),
                b.line, b.header,
                "no snmp-server community <string>\n"
                "snmp-server group NMS v3 priv\n"
                "snmp-server user <user> NMS v3 auth sha <auth-pass> priv aes 128 <priv-pass>",
            ))
    return findings


def check_legacy_services(blocks: list[Block]) -> list[Finding]:
    findings = []
    pattern = r"^(service (tcp-small-servers|udp-small-servers|finger)|ip source-route|ip finger)$"
    for b in _headers(blocks, pattern):
        findings.append(Finding(
            "IOS-016", "medium", "Legacy or unnecessary service is enabled",
            b.line, b.header, f"no {b.header}",
        ))
    return findings


# --------------------------------------------------------------------------
# Visibility
# --------------------------------------------------------------------------

def check_logging(blocks: list[Block]) -> list[Finding]:
    if _has(blocks, r"^logging (host )?\d{1,3}(\.\d{1,3}){3}"):
        return []
    return [_missing(
        "IOS-017", "medium", "No remote syslog server configured",
        "logging host <syslog-or-siem-ip>\nlogging trap informational",
    )]


def check_ntp(blocks: list[Block]) -> list[Finding]:
    if _has(blocks, r"^ntp server\b"):
        return []
    return [_missing(
        "IOS-018", "low", "No NTP server configured (log timestamps will not be reliable)",
        "ntp server <ntp-ip>",
    )]


def check_banner(blocks: list[Block]) -> list[Finding]:
    if _has(blocks, r"^banner (login|motd)\b"):
        return []
    return [_missing(
        "IOS-019", "low", "No login banner configured",
        "banner login ^Authorized access only. Activity is monitored.^",
    )]


# --------------------------------------------------------------------------
# Traffic filtering
# --------------------------------------------------------------------------

def check_permit_any(blocks: list[Block]) -> list[Finding]:
    findings = []
    regex = re.compile(r"\bpermit ip any any\b", re.IGNORECASE)
    for b in blocks:
        is_acl_block = b.header.lower().startswith("ip access-list")
        candidates = [(b.line, b.header)] if b.header.lower().startswith("access-list") else []
        if is_acl_block:
            candidates += b.children
        for number, text in candidates:
            if regex.search(text):
                findings.append(Finding(
                    "IOS-020", "high",
                    "ACL entry permits all IP traffic ('permit ip any any')",
                    number, text,
                    "Replace with explicit permits for the required sources, destinations and ports, "
                    "then end the ACL with 'deny ip any any log'.",
                ))
    return findings


ALL_RULES = [
    check_enable_password,
    check_user_passwords,
    check_type7,
    check_password_encryption,
    check_vty,
    check_exec_timeout,
    check_console_auth,
    check_aaa,
    check_ssh,
    check_http,
    check_snmp,
    check_legacy_services,
    check_logging,
    check_ntp,
    check_banner,
    check_permit_any,
]


def run_rules(text: str) -> list[Finding]:
    blocks = parse_blocks(text)
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(blocks))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.line or 0, f.rule_id))
    return findings
