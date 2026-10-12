#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""session-token-hygiene — audit session/token policy declarations.

Checks TTL ceilings, refresh-vs-access consistency, rotation, scope
wildcards and duplicate names in a JSON token policy. Graded findings
(WARN/FAIL); FAIL findings exit non-zero. Pure stdlib.
"""
import argparse
import json
import sys

KINDS = ("access", "refresh", "api_key")
DEFAULT_ACCESS_WARN = 3600
DEFAULT_ACCESS_FAIL = 86400
DEFAULT_REFRESH_FAIL = 90 * 86400


class HygieneError(Exception):
    """Recoverable input error surfaced as exit 2."""


def _is_number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def check_policy(policy, max_access_warn=DEFAULT_ACCESS_WARN,
                 max_access_fail=DEFAULT_ACCESS_FAIL,
                 max_refresh_fail=DEFAULT_REFRESH_FAIL):
    """Return list of findings for a policy dict:
    {"tokens": [{name, kind, ttl_seconds, refreshable, scopes, rotate_on_use}]}"""
    findings = []
    if not isinstance(policy, dict):
        raise HygieneError("policy must be a JSON object")
    tokens = policy.get("tokens")
    if tokens is None:
        raise HygieneError("policy missing 'tokens' list")
    if not isinstance(tokens, list):
        raise HygieneError("'tokens' must be a list")
    names = {}
    refresh_tokens = []
    access_tokens = []
    for i, tok in enumerate(tokens):
        if not isinstance(tok, dict):
            findings.append(("F", "H000", i, None, "token entry %d is not an object" % i))
            continue
        name = tok.get("name")
        kind = tok.get("kind")
        ttl = tok.get("ttl_seconds")
        scopes = tok.get("scopes", [])
        refreshable = tok.get("refreshable", False)
        rotate = tok.get("rotate_on_use", False)
        if not isinstance(name, str) or not name.strip():
            findings.append(("F", "H011", i, None, "token entry %d missing non-empty 'name'" % i))
            name = "<unnamed:%d>" % i
        if name in names:
            findings.append(("F", "H007", i, name, "duplicate token name %r" % name))
        names[name] = True
        if kind not in KINDS:
            findings.append(("F", "H009", i, name, "unknown kind %r (expected %s)" % (kind, "/".join(KINDS))))
            continue
        if not _is_number(ttl):
            findings.append(("F", "H001", i, name, "missing or non-numeric ttl_seconds"))
            continue
        if ttl <= 0:
            findings.append(("F", "H010", i, name, "ttl_seconds must be positive, got %s" % ttl))
            continue
        if kind == "access":
            access_tokens.append((name, ttl))
            if ttl > max_access_fail:
                findings.append(("F", "H002", i, name,
                                 "access ttl %ss exceeds fail ceiling %ss" % (ttl, max_access_fail)))
            elif ttl > max_access_warn:
                findings.append(("W", "H002", i, name,
                                 "access ttl %ss exceeds warn ceiling %ss" % (ttl, max_access_warn)))
            if refreshable and not rotate:
                findings.append(("W", "H008", i, name,
                                 "refreshable access token without rotate_on_use"))
        elif kind == "refresh":
            refresh_tokens.append((name, ttl))
            if ttl > max_refresh_fail:
                findings.append(("F", "H004", i, name,
                                 "refresh ttl %ss exceeds %ss ceiling" % (ttl, max_refresh_fail)))
            if ttl <= 60:
                findings.append(("W", "H012", i, name,
                                 "refresh ttl %ss suspiciously short" % ttl))
        else:  # api_key
            if ttl is None or ttl <= 0:
                findings.append(("F", "H005", i, name, "api_key without positive ttl"))
            elif ttl > max_refresh_fail:
                findings.append(("W", "H005", i, name,
                                 "api_key ttl %ss very long; plan rotation" % ttl))
        if isinstance(scopes, list):
            if "*" in scopes:
                findings.append(("F", "H006", i, name, "wildcard scope '*'"))
            dup_scopes = {s for s in scopes if isinstance(s, str) and scopes.count(s) > 1}
            if dup_scopes:
                findings.append(("W", "H013", i, name,
                                 "duplicate scopes: %s" % ", ".join(sorted(dup_scopes))))
        else:
            findings.append(("F", "H014", i, name, "scopes must be a list"))
    for rname, rtl in refresh_tokens:
        paired = [at for at in access_tokens if at[0] == rname.replace("refresh", "access")]
        if paired and rtl <= paired[0][1]:
            findings.append(("F", "H003", i, rname,
                             "refresh ttl %ss <= access ttl %ss for pair %s/%s"
                             % (rtl, paired[0][1], paired[0][0], rname)))
    return findings


def summarize(findings):
    fails = sum(1 for f in findings if f[0] == "F")
    warns = sum(1 for f in findings if f[0] == "W")
    return {"fails": fails, "warns": warns, "tokens_checked": None}


def _cmd_check(args):
    with open(args.policy, "r", encoding="utf-8") as fh:
        policy = json.load(fh)
    findings = check_policy(policy,
                            max_access_warn=args.max_access_warn,
                            max_access_fail=args.max_access_fail,
                            max_refresh_fail=args.max_refresh_fail)
    sev = {"F": "fail", "W": "warn"}
    payload = {
        "summary": {"fails": sum(1 for f in findings if f[0] == "F"),
                    "warns": sum(1 for f in findings if f[0] == "W"),
                    "tokens_checked": len(policy.get("tokens", [])) if isinstance(policy.get("tokens"), list) else 0},
        "findings": [dict(severity=sev[f[0]], code=f[1], index=f[2], token=f[3], message=f[4])
                     for f in findings],
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for f in payload["findings"]:
            print("%s %s token=%s: %s" % (f["severity"].upper(), f["code"], f["token"], f["message"]))
        print("summary: %d fail(s), %d warn(s), %d token(s) checked"
              % (payload["summary"]["fails"], payload["summary"]["warns"],
                 payload["summary"]["tokens_checked"]))
    return 1 if payload["summary"]["fails"] else 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="session-token-hygiene",
        description="Audit session/token policy JSON for TTL, refresh, rotation "
                    "and scope hygiene issues.")
    sub = parser.add_subparsers(dest="cmd")
    p = sub.add_parser("check", help="check a policy JSON file")
    p.add_argument("policy", help="token policy JSON file")
    p.add_argument("--max-access-warn", type=int, default=DEFAULT_ACCESS_WARN)
    p.add_argument("--max-access-fail", type=int, default=DEFAULT_ACCESS_FAIL)
    p.add_argument("--max-refresh-fail", type=int, default=DEFAULT_REFRESH_FAIL)
    p.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.cmd != "check":
        parser.print_help()
        return 2
    try:
        return _cmd_check(args)
    except (HygieneError, OSError, json.JSONDecodeError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
