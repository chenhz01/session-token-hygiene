# -*- coding: utf-8 -*-
"""self_test for session-token-hygiene — inherits scaffold-v2 defenses D1-D4."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")  # D3
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import session_token_hygiene as mod  # noqa: E402


def run_cli(argv):  # D1
    buf_out, buf_err = io.StringIO(), io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            rc = mod.main(argv)
            code = 0 if rc is None else rc
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except Exception as e:  # noqa: BLE001
        code = 1
        buf_err.write(repr(e))
    return code, buf_out.getvalue(), buf_err.getvalue()


CASES = []


def case(name, cat):
    def deco(fn):
        CASES.append((name, cat, fn))
        return fn
    return deco


TMP = tempfile.mkdtemp(prefix="sth_selftest_")


def write_json(name, obj):
    p = os.path.join(TMP, name)
    with open(p, "w", encoding="utf-8", newline="") as fh:  # D3
        json.dump(obj, fh, ensure_ascii=False)
    return p


def tok(name, kind, ttl, **kw):
    d = {"name": name, "kind": kind, "ttl_seconds": ttl}
    d.update(kw)
    return d


def codes(findings):
    return [f[1] for f in findings]


def sev(findings):
    return [f[0] for f in findings]


# ------------------------------------------------------------------ [A] functional

@case("A01_clean_policy_no_findings", "A")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 600), tok("r", "refresh", 86400)]})
    assert f == []

@case("A02_access_warn_over_1h", "A")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 7200)]})
    assert codes(f) == ["H002"] and sev(f) == ["W"]

@case("A03_access_fail_over_24h", "A")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 100000)]})
    assert codes(f) == ["H002"] and sev(f) == ["F"]

@case("A04_refresh_over_90d_fail", "A")
def t():
    f = mod.check_policy({"tokens": [tok("r", "refresh", 100 * 86400)]})
    assert codes(f) == ["H004"]

@case("A05_missing_ttl_H001", "A")
def t():
    f = mod.check_policy({"tokens": [{"name": "a", "kind": "access"}]})
    assert codes(f) == ["H001"]

@case("A06_unknown_kind_H009", "A")
def t():
    f = mod.check_policy({"tokens": [tok("x", "bearer", 60)]})
    assert codes(f) == ["H009"]

@case("A07_wildcard_scope_H006", "A")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 60, scopes=["*"])]})
    assert codes(f) == ["H006"]

@case("A08_duplicate_names_H007", "A")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 60), tok("a", "access", 60)]})
    assert "H007" in codes(f)

@case("A09_refresh_shorter_than_access_H003", "A")
def t():
    f = mod.check_policy({"tokens": [tok("access1", "access", 3600), tok("refresh1", "refresh", 60)]})
    assert "H003" in codes(f)

@case("A10_refresh_short_warn_H012", "A")
def t():
    f = mod.check_policy({"tokens": [tok("r", "refresh", 30)]})
    assert "H012" in codes(f)

@case("A11_api_key_long_ttl_warn", "A")
def t():
    f = mod.check_policy({"tokens": [tok("k", "api_key", 100 * 86400)]})
    assert "H005" in codes(f) and sev(f) == ["W"]

@case("A12_refreshable_without_rotation_H008", "A")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 60, refreshable=True)]})
    assert "H008" in codes(f)

@case("A13_refreshable_with_rotation_clean", "A")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 60, refreshable=True, rotate_on_use=True)]})
    assert f == []

@case("A14_duplicate_scopes_H013", "A")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 60, scopes=["read", "read"])]})
    assert "H013" in codes(f)

@case("A15_scopes_not_list_H014", "A")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 60, scopes="read")]})
    assert "H014" in codes(f)

@case("A16_ttl_zero_H010", "A")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 0)]})
    assert codes(f) == ["H010"]

@case("A17_ttl_negative_H010", "A")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", -5)]})
    assert "H010" in codes(f)

@case("A18_custom_ceilings_respected", "A")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 7200)]}, max_access_warn=100, max_access_fail=5000)
    assert sev(f) == ["F"]

@case("A19_cli_clean_exit0", "A")
def t():
    p = write_json("a19.json", {"tokens": [tok("a", "access", 600)]})
    code, out, _ = run_cli(["check", p])
    assert code == 0 and "0 fail" in out

@case("A20_cli_fail_exit1", "A")
def t():
    p = write_json("a20.json", {"tokens": [tok("a", "access", 60, scopes=["*"])]})
    code, out, _ = run_cli(["check", p])
    assert code == 1 and "H006" in out

@case("A21_cli_json_summary", "A")
def t():
    p = write_json("a21.json", {"tokens": [tok("a", "access", 60, scopes=["*"])]})
    code, out, _ = run_cli(["check", p, "--json"])
    data = json.loads(out)
    assert data["summary"]["fails"] == 1 and data["summary"]["tokens_checked"] == 1

@case("A22_summary_counts_fails_warns", "A")
def t():
    s = mod.summarize([("F", "H006", 0, "a", "m"), ("W", "H002", 0, "a", "m")])
    assert s["fails"] == 1 and s["warns"] == 1

@case("A23_mixed_kinds_all_checked", "A")
def t():
    pol = {"tokens": [tok("a", "access", 600), tok("r", "refresh", 86400), tok("k", "api_key", 2592000)]}
    assert mod.check_policy(pol) == []

@case("A24_name_missing_H011", "A")
def t():
    f = mod.check_policy({"tokens": [{"kind": "access", "ttl_seconds": 60}]})
    assert "H011" in codes(f)

# ------------------------------------------------------------------ [B] exception / CLI contract

@case("B01_cli_no_subcommand_exit2", "B")
def t():
    assert run_cli([])[0] == 2

@case("B02_cli_unknown_subcommand_exit2", "B")
def t():
    assert run_cli(["audit", "x.json"])[0] == 2

@case("B03_missing_file_exit2", "B")
def t():
    code, _, err = run_cli(["check", os.path.join(TMP, "ghost.json")])
    assert code == 2 and "error" in err

@case("B04_bad_json_exit2", "B")
def t():
    p = os.path.join(TMP, "b04.json")
    with open(p, "w", encoding="utf-8", newline="") as fh:
        fh.write("{oops")
    assert run_cli(["check", p])[0] == 2

@case("B05_policy_not_object_exit2", "B")
def t():
    p = write_json("b05.json", [1, 2])
    code, _, err = run_cli(["check", p])
    assert code == 2 and "object" in err

@case("B06_missing_tokens_key_exit2", "B")
def t():
    p = write_json("b06.json", {"nothing": 1})
    code, _, err = run_cli(["check", p])
    assert code == 2 and "tokens" in err

@case("B07_tokens_not_list_exit2", "B")
def t():
    p = write_json("b07.json", {"tokens": {"a": 1}})
    code, _, err = run_cli(["check", p])
    assert code == 2 and "list" in err

@case("B08_token_entry_not_object", "B")
def t():
    f = mod.check_policy({"tokens": ["string"]})
    assert codes(f) == ["F000"] or "H000" in codes(f)

@case("B09_ttl_string_rejected_H001", "B")
def t():
    f = mod.check_policy({"tokens": [{"name": "a", "kind": "access", "ttl_seconds": "600"}]})
    assert "H001" in codes(f)

@case("B10_ttl_bool_rejected_H001", "B")
def t():
    f = mod.check_policy({"tokens": [{"name": "a", "kind": "access", "ttl_seconds": True}]})
    assert "H001" in codes(f)

@case("B11_kind_case_sensitive", "B")
def t():
    f = mod.check_policy({"tokens": [tok("a", "Access", 60)]})
    assert "H009" in codes(f)

@case("B12_warn_ceiling_override_cli", "B")
def t():
    p = write_json("b12.json", {"tokens": [tok("a", "access", 60)]})
    code, out, _ = run_cli(["check", p, "--max-access-warn", "10"])
    assert code == 0 and "warn" in out.lower()

@case("B13_bad_max_access_warn_type", "B")
def t():
    p = write_json("b13.json", {"tokens": []})
    assert run_cli(["check", p, "--max-access-warn", "abc"])[0] == 2

@case("B14_empty_tokens_list_clean", "B")
def t():
    assert mod.check_policy({"tokens": []}) == []

@case("B15_findings_index_tracks_position", "B")
def t():
    f = mod.check_policy({"tokens": [tok("ok", "access", 60), tok("bad", "access", 999999)]})
    assert f[0][2] == 1

@case("B16_help_mentions_policy", "B")
def t():
    code, out, _ = run_cli(["--help"])
    assert code == 0 and "token" in out

@case("B17_multiple_fails_aggregated", "B")
def t():
    pol = {"tokens": [tok("a", "access", 60, scopes=["*"]), tok("b", "access", 999999)]}
    s = mod.summarize(mod.check_policy(pol))
    assert s["fails"] == 2

@case("B18_unicode_token_names", "B")
def t():
    f = mod.check_policy({"tokens": [tok("访问令牌", "access", 999999)]})
    assert f[0][3] == "访问令牌"

@case("B19_refresh_pair_requires_name_pattern", "B")
def t():
    f = mod.check_policy({"tokens": [tok("access_x", "access", 3600), tok("refresh_x", "refresh", 100)]})
    assert "H003" in codes(f)

@case("B20_unnamed_token_gets_placeholder", "B")
def t():
    f = mod.check_policy({"tokens": [{"kind": "access", "ttl_seconds": 999999}]})
    assert any(x[3] and str(x[3]).startswith("<unnamed") for x in f)

# ------------------------------------------------------------------ [C] extreme edge

@case("C01_ttl_float_accepted", "C")
def t():
    assert mod.check_policy({"tokens": [tok("a", "access", 600.5)]}) == []

@case("C02_ttl_huge_float_warns_not_crash", "C")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 1e18)]})
    assert f and sev(f) == ["F"]

@case("C03_many_tokens_bulk", "C")
def t():
    pol = {"tokens": [tok("t%d" % i, "access", 60) for i in range(3000)]}
    import time
    t0 = __import__("time").perf_counter()
    assert mod.check_policy(pol) == []
    assert __import__("time").perf_counter() - t0 < 3

@case("C04_crlf_json_file", "C")
def t():
    p = os.path.join(TMP, "c04.json")
    with open(p, "w", encoding="utf-8", newline="\r\n") as fh:
        json.dump({"tokens": [tok("a", "access", 60)]}, fh)
    assert run_cli(["check", p])[0] == 0

@case("C05_unicode_scope_names", "C")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 60, scopes=["読み取り", "読み取り"])]})
    assert "H013" in codes(f)

@case("C06_emoji_token_name", "C")
def t():
    f = mod.check_policy({"tokens": [tok("🔑-key", "access", 999999)]})
    assert f[0][3] == "🔑-key"

@case("C07_empty_name_rejected", "C")
def t():
    f = mod.check_policy({"tokens": [tok("   ", "access", 60)]})
    assert "H011" in codes(f)

@case("C08_refresh_exactly_90d_ok", "C")
def t():
    assert mod.check_policy({"tokens": [tok("r", "refresh", 90 * 86400)]}) == []

@case("C09_refresh_just_over_90d_fails", "C")
def t():
    f = mod.check_policy({"tokens": [tok("r", "refresh", 90 * 86400 + 1)]})
    assert "H004" in codes(f)

@case("C10_access_exactly_24h_warns", "C")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 86400)]})
    assert codes(f) == ["H002"] and sev(f) == ["W"]  # at fail ceiling but still over warn

@case("C11_access_exactly_1h_ok", "C")
def t():
    assert mod.check_policy({"tokens": [tok("a", "access", 3600)]}) == []

@case("C12_wildcard_in_longer_string_not_flagged", "C")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 60, scopes=["read:*"])]})
    assert "H006" not in codes(f)

@case("C13_empty_scopes_ok", "C")
def t():
    assert mod.check_policy({"tokens": [tok("a", "access", 60, scopes=[])]}) == []

@case("C14_pair_name_match_requires_refresh_substring", "C")
def t():
    f = mod.check_policy({"tokens": [tok("access1", "access", 3600), tok("refresh1", "refresh", 3600)]})
    assert "H003" in codes(f)

@case("C15_non_empty_scopes_implied", "C")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 60)]})
    assert f == []  # scopes optional

@case("C16_json_output_uses_ascii_false", "C")
def t():
    p = write_json("c16.json", {"tokens": [tok("令牌", "access", 999999)]})
    code, out, _ = run_cli(["check", p, "--json"])
    assert code == 1 and "令牌" in out

@case("C17_boolean_scopes_flagged", "C")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 60, scopes=True)]})
    assert "H014" in codes(f)

@case("C18_ttl_scientific_notation", "C")
def t():
    f = mod.check_policy({"tokens": [tok("a", "access", 1e3)]})
    assert f == []  # 1000 > warn 3600? no, 1000 <= 3600 but > 3600? 1000 <= 3600 so clean

@case("C19_duplicate_name_after_rename_clean", "C")
def t():
    pol = {"tokens": [tok("a1", "access", 60), tok("a2", "access", 60)]}
    assert mod.check_policy(pol) == []

@case("C20_policy_with_bom_file", "C")
def t():
    p = os.path.join(TMP, "c20.json")
    with open(p, "w", encoding="utf-8-sig", newline="") as fh:
        json.dump({"tokens": [tok("a", "access", 60)]}, fh)
    code, _, err = run_cli(["check", p])
    assert code in (0, 2)  # tolerated either way, must not crash

class TestAll(unittest.TestCase):
    pass


def _build():
    for i, (name, cat, fn) in enumerate(CASES):
        def make(f):
            def m(self):
                f()
            return m
        slug = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in name)
        setattr(TestAll, "test_%s_%03d_%s" % (cat, i, slug), make(fn))
_build()


class TestMeta(unittest.TestCase):
    def test_case_count_ge_60(self):
        self.assertGreaterEqual(len(CASES), 60)

    def test_categories_present(self):
        self.assertEqual({c for _, c, _ in CASES}, {"A", "B", "C"})


if __name__ == "__main__":
    r = unittest.TextTestRunner(verbosity=0).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules["__main__"]))
    total, fails = r.testsRun, len(r.failures) + len(r.errors)
    print("SUMMARY: PASS %d/%d" % (total - fails, total))  # D4
    sys.exit(0 if fails == 0 else 1)
