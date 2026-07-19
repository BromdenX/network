#!/usr/bin/env python3
"""Validate canonical routing sources and generate all client rule files."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = (
    ROOT / "AutoProxy.list",
    ROOT / "MyRules.sgmodule",
    ROOT / "ToDirect.yaml",
    ROOT / "ToProxy.yaml",
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
KEYWORD_RE = re.compile(r"^[a-z0-9._-]+$")

CONFIG_KEYS = {
    "direct_exact",
    "proxy_exact",
    "proxy_keyword",
    "direct_cidr",
    "proxy_cidr",
    "reject_exact",
    "reject_suffix",
    "autoproxy_proxy_suffix",
    "openclash_direct_suffix",
    "openclash_proxy_suffix",
    "openclash_direct_exclude_suffix",
    "openclash_proxy_exclude_suffix",
}

DOMAIN_CONFIG_KEYS = {
    "direct_exact",
    "proxy_exact",
    "reject_exact",
    "reject_suffix",
    "autoproxy_proxy_suffix",
    "openclash_direct_suffix",
    "openclash_proxy_suffix",
    "openclash_direct_exclude_suffix",
    "openclash_proxy_exclude_suffix",
}


class RulesError(ValueError):
    pass


def normalize_domain(value: str, source: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise RulesError(f"{source}: invalid domain: {value!r}")
    return domain


def load_domain_file(path: Path) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        domain = normalize_domain(stripped, f"{path.name}:{number}")
        if domain in seen:
            print(f"warning: {path.name}:{number}: duplicate ignored: {domain}")
            continue
        seen.add(domain)
        values.append(domain)
    if not values:
        raise RulesError(f"{path.name}: no domains found")
    return sorted(values)


def load_simple_yaml(path: Path) -> dict[str, list[str]]:
    """Parse the intentionally small top-level-list YAML subset used here."""
    result = {key: [] for key in CONFIG_KEYS}
    current: str | None = None
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw.startswith(" ") and stripped.endswith(":"):
            current = stripped[:-1]
            if current not in CONFIG_KEYS:
                raise RulesError(f"{path.name}:{number}: unknown key: {current}")
            continue
        if raw.startswith("  - ") and current:
            value = raw[4:].strip()
            if not value:
                raise RulesError(f"{path.name}:{number}: empty list item")
            result[current].append(value)
            continue
        raise RulesError(f"{path.name}:{number}: unsupported YAML syntax")

    for key, values in result.items():
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            if key in DOMAIN_CONFIG_KEYS:
                item = normalize_domain(value, f"{path.name}:{key}")
            elif key.endswith("_cidr"):
                try:
                    item = str(ipaddress.ip_network(value, strict=True))
                except ValueError as exc:
                    raise RulesError(f"{path.name}:{key}: invalid CIDR {value!r}: {exc}") from exc
            elif key == "proxy_keyword":
                item = value.strip().lower()
                if not KEYWORD_RE.fullmatch(item):
                    raise RulesError(f"{path.name}:{key}: invalid keyword: {value!r}")
            else:
                raise RulesError(f"{path.name}: no validator for key: {key}")
            if item in seen:
                print(f"warning: {path.name}:{key}: duplicate ignored: {item}")
                continue
            seen.add(item)
            normalized.append(item)
        result[key] = sorted(normalized)
    return result


def is_suffix_match(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def validate_policy_conflicts(
    direct_suffix: list[str], proxy_suffix: list[str], config: dict[str, list[str]]
) -> None:
    conflicts: list[str] = []
    for direct in direct_suffix:
        for proxy in proxy_suffix:
            if is_suffix_match(direct, proxy) or is_suffix_match(proxy, direct):
                conflicts.append(f"DIRECT {direct} <-> PROXY {proxy}")
    exact_overlap = set(config["direct_exact"]) & set(config["proxy_exact"])
    conflicts.extend(f"exact domain has both policies: {item}" for item in sorted(exact_overlap))

    direct_networks = [ipaddress.ip_network(item) for item in config["direct_cidr"]]
    proxy_networks = [ipaddress.ip_network(item) for item in config["proxy_cidr"]]
    for direct in direct_networks:
        for proxy in proxy_networks:
            if direct.version == proxy.version and direct.overlaps(proxy):
                conflicts.append(f"DIRECT CIDR {direct} <-> PROXY CIDR {proxy}")

    if conflicts:
        detail = "\n  - ".join(conflicts)
        raise RulesError(f"routing policy conflicts found:\n  - {detail}")


def validate_openclash_conflicts(
    direct_exact: list[str],
    direct_suffix: list[str],
    proxy_exact: list[str],
    proxy_suffix: list[str],
    proxy_keyword: list[str],
) -> None:
    """Forbid cross-provider matches because provider order is external."""
    conflicts: set[str] = set()
    direct_domains = set(direct_exact) | set(direct_suffix)
    proxy_domains = set(proxy_exact) | set(proxy_suffix)
    for direct in direct_domains:
        for proxy in proxy_domains:
            if is_suffix_match(direct, proxy) or is_suffix_match(proxy, direct):
                conflicts.add(f"DIRECT {direct} <-> PROXY {proxy}")
        for keyword in proxy_keyword:
            if keyword in direct:
                conflicts.add(f"DIRECT {direct} <-> PROXY keyword {keyword}")
    if conflicts:
        detail = "\n  - ".join(sorted(conflicts))
        raise RulesError(
            "OpenClash cross-provider conflicts found; add an explicit "
            f"compatibility exclusion:\n  - {detail}"
        )


def generated_header(prefix: str) -> list[str]:
    return [
        f"{prefix} AUTO-GENERATED FILE - DO NOT EDIT",
        f"{prefix} Edit Raw_Direct.txt, Raw_Proxy.txt, or config/special_rules.yaml",
        f"{prefix} Generated by scripts/generate_rules.py",
    ]


def render_autoproxy(proxy_suffix: list[str], config: dict[str, list[str]]) -> str:
    proxy_domains = set(proxy_suffix)
    proxy_domains.update(config["proxy_exact"])
    proxy_domains.update(config["autoproxy_proxy_suffix"])

    direct_exceptions = {
        host
        for host in config["direct_exact"]
        if any(is_suffix_match(host, suffix) for suffix in proxy_domains)
    }

    lines = ["! MyFavorite", "! ZeroOmega Rules", *generated_header("!"), ""]
    if direct_exceptions:
        lines.append("! Direct exceptions inside proxied parent domains")
        lines.extend(f"@@||{domain}^" for domain in sorted(direct_exceptions))
        lines.append("")
    lines.append("! Proxy domains")
    lines.extend(f"||{domain}^" for domain in sorted(proxy_domains))
    return "\n".join(lines) + "\n"


def render_shadowrocket(
    direct_suffix: list[str], proxy_suffix: list[str], config: dict[str, list[str]]
) -> str:
    lines = [
        "#!name=MyRules",
        "#!desc=Shadowrocket Rules (auto-generated)",
        "#!category=自定义",
        "",
        *generated_header("#"),
        "",
        "[Rule]",
        "# Reject rules take priority over broader routing rules",
    ]
    lines.extend(f"DOMAIN,{item},REJECT" for item in config["reject_exact"])
    lines.extend(f"DOMAIN-SUFFIX,{item},REJECT" for item in config["reject_suffix"])

    lines.extend(["", "# Exact-domain exceptions take priority over suffix rules"])
    lines.extend(f"DOMAIN,{item},DIRECT" for item in config["direct_exact"])
    lines.extend(f"DOMAIN,{item},PROXY" for item in config["proxy_exact"])

    lines.extend(["", "# Keyword proxy rules"])
    lines.extend(f"DOMAIN-KEYWORD,{item},PROXY" for item in config["proxy_keyword"])

    lines.extend(["", "# Domain suffix rules"])
    lines.extend(f"DOMAIN-SUFFIX,{item},DIRECT" for item in direct_suffix)
    lines.extend(f"DOMAIN-SUFFIX,{item},PROXY" for item in proxy_suffix)

    lines.extend(["", "# CIDR rules"])
    lines.extend(f"IP-CIDR,{item},DIRECT,no-resolve" for item in config["direct_cidr"])
    lines.extend(f"IP-CIDR,{item},PROXY,no-resolve" for item in config["proxy_cidr"])
    return "\n".join(lines) + "\n"


def render_openclash(
    name: str,
    exact: list[str],
    suffix: list[str],
    keyword: list[str],
    cidr: list[str],
) -> str:
    lines = [
        f"# NAME: {name}",
        "# DESC: OpenClash Rules",
        *generated_header("#"),
        "",
        "payload:",
    ]
    lines.extend(f"  - DOMAIN,{item}" for item in exact)
    lines.extend(f"  - DOMAIN-KEYWORD,{item}" for item in keyword)
    lines.extend(f"  - DOMAIN-SUFFIX,{item}" for item in suffix)
    lines.extend(f"  - IP-CIDR,{item},no-resolve" for item in cidr)
    return "\n".join(lines) + "\n"


def build_outputs() -> dict[Path, str]:
    direct_suffix = load_domain_file(ROOT / "Raw_Direct.txt")
    proxy_suffix = load_domain_file(ROOT / "Raw_Proxy.txt")
    config = load_simple_yaml(ROOT / "config" / "special_rules.yaml")
    validate_policy_conflicts(direct_suffix, proxy_suffix, config)

    openclash_direct_suffix = sorted(
        (set(direct_suffix) - set(config["openclash_direct_exclude_suffix"]))
        | set(config["openclash_direct_suffix"])
    )
    openclash_proxy_suffix = sorted(
        (set(proxy_suffix) - set(config["openclash_proxy_exclude_suffix"]))
        | set(config["openclash_proxy_suffix"])
    )
    validate_openclash_conflicts(
        config["direct_exact"],
        openclash_direct_suffix,
        config["proxy_exact"],
        openclash_proxy_suffix,
        config["proxy_keyword"],
    )

    outputs = {
        ROOT / "AutoProxy.list": render_autoproxy(proxy_suffix, config),
        ROOT / "MyRules.sgmodule": render_shadowrocket(
            direct_suffix, proxy_suffix, config
        ),
        ROOT / "ToDirect.yaml": render_openclash(
            "ToDirect",
            config["direct_exact"],
            openclash_direct_suffix,
            [],
            config["direct_cidr"],
        ),
        ROOT / "ToProxy.yaml": render_openclash(
            "ToProxy",
            config["proxy_exact"],
            openclash_proxy_suffix,
            config["proxy_keyword"],
            config["proxy_cidr"],
        ),
    }

    print(
        "validated: "
        f"{len(direct_suffix)} direct suffixes, "
        f"{len(proxy_suffix)} proxy suffixes, "
        f"{len(config['direct_cidr']) + len(config['proxy_cidr'])} CIDRs"
    )
    skipped = len(config["direct_cidr"]) + len(config["proxy_cidr"])
    if config["proxy_keyword"]:
        skipped += len(config["proxy_keyword"])
    if skipped:
        print(
            "notice: AutoProxy.list intentionally skips "
            f"{len(config['direct_cidr']) + len(config['proxy_cidr'])} CIDRs and "
            f"{len(config['proxy_keyword'])} keyword rules"
        )
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate sources and fail if generated files are not current",
    )
    args = parser.parse_args()

    try:
        outputs = build_outputs()
    except (OSError, RulesError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    stale: list[str] = []
    for path, content in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == content:
            continue
        if args.check:
            stale.append(path.name)
        else:
            with path.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            print(f"generated: {path.name}")

    if stale:
        print("error: generated files are stale: " + ", ".join(stale), file=sys.stderr)
        print("run: python3 scripts/generate_rules.py", file=sys.stderr)
        return 1
    if args.check:
        print("check passed: all generated files are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
