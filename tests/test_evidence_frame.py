"""evidence_frame: a limitation of observation never becomes a fact about the thing observed. Table-driven over the framing rules."""
import dataclasses
import sys
import unicodedata
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from change_passport import evidence_frame as EF  # noqa: E402

AT = "2026-10-27T12:00:00+00:00"
LISTING = ["a.md", "b.md"]


def http(status, body=None, headers=None):
    return EF.observe_http("/things", status, body if body is not None else LISTING, headers or {}, "every thing", expect=list, at=AT, evidence=("R1",))


has = lambda item: (lambda v: item in v)                    # a presence claim: true because of something seen


class Rules(unittest.TestCase):
    def test_framing_table(self):
        more = {"link": '<https://x/things?page=2>; rel="next"'}
        cases = [  # name, observation, test, state, status, reason
            ("1 complete read, item present", http(200), has("a.md"), "KNOWN_TRUE", "COMPLETE", None),
            ("2 complete read, item absent", http(200), has("z.md"), "KNOWN_FALSE", "COMPLETE", None),
            ("2b complete read, empty collection", http(200, []), has("z.md"), "KNOWN_FALSE", "COMPLETE", None),
            ("3 permission failure", http(403, {"message": "Forbidden"}), has("z.md"), "UNKNOWN", "FAILED", "PERMISSION_DENIED"),
            ("3b unauthenticated", http(401, {}), has("z.md"), "UNKNOWN", "FAILED", "PERMISSION_DENIED"),
            ("4 rate limit, primary", http(403, {"message": "API rate limit exceeded"}, {"x-ratelimit-remaining": "0"}), has("z.md"), "UNKNOWN", "FAILED", "RATE_LIMITED"),
            ("4b rate limit, 429", http(429, {}), has("z.md"), "UNKNOWN", "FAILED", "RATE_LIMITED"),
            ("5 server failure", http(503, {}), has("z.md"), "UNKNOWN", "FAILED", "SOURCE_UNAVAILABLE"),
            ("5b no response at all", http(None, b""), has("z.md"), "UNKNOWN", "FAILED", "SOURCE_UNAVAILABLE"),
            ("5c 200 with the wrong shape", http(200, {"oops": 1}), has("z.md"), "UNKNOWN", "FAILED", "SOURCE_UNAVAILABLE"),
            ("6 partial read, item absent", http(200, LISTING, more), has("z.md"), "UNKNOWN", "PARTIAL", "PARTIAL_SCOPE"),
            ("6b partial read, item present", http(200, LISTING, more), has("a.md"), "KNOWN_TRUE", "PARTIAL", None),
            ("not attempted", EF.not_attempted("/things", "every thing"), has("z.md"), "UNKNOWN", "NOT_ATTEMPTED", "NOT_OBSERVED"),
            ("value cannot settle it", http(200), lambda v: None, "UNKNOWN", "COMPLETE", "UNSUPPORTED_INFERENCE"),
            ("404 where 404 is the answer", EF.observe_http("/file", 404, {}, {}, "one file", absent=True), lambda v: v is not EF.ABSENT,
             "KNOWN_FALSE", "COMPLETE", None),
            ("404 anywhere else", EF.observe_http("/thing", 404, {}, {}, "one thing"), lambda v: True, "UNKNOWN", "FAILED", "NOT_OBSERVED"),
        ]
        for name, obs, test, state, status, reason in cases:
            with self.subTest(name):
                f = EF.frame("the claim", obs, test)
                self.assertEqual((f.state, f.status, f.reason), (state, status, reason))
                if obs.status != "COMPLETE":
                    self.assertNotEqual(f.state, "KNOWN_FALSE")                        # rule 1: absence needs a complete read

    def test_a_failed_read_has_no_value_empty_or_otherwise(self):
        for status in (403, 429, 500, None):
            with self.subTest(status), self.assertRaises(EF.Unread):
                http(status, {}).value
        f = EF.frame("the claim", http(500, {}), has("z.md"))
        self.assertIsNone(f.observed)                                                  # not [], not {}, not False
        self.assertEqual(f.to_dict()["observation_status"], "FAILED")                  # and the status says why it is empty
        self.assertEqual(EF.frame("the claim", http(200, []), has("z.md"), show=list).observed, [])   # a real empty result stays distinguishable

    def test_observations_cannot_be_built_inconsistent(self):
        with self.assertRaises(ValueError):
            EF.Observation("/x", "COMPLETE", "s", reason="PERMISSION_DENIED")
        with self.assertRaises(ValueError):
            EF.Observation("/x", "FAILED", "s")
        with self.assertRaises(ValueError):
            EF.Observation("/x", "SOMEWHAT", "s")

    def test_7_stale_observations(self):
        now = datetime(2026, 10, 27, 13, 0, tzinfo=timezone.utc)
        f = EF.frame("the claim", http(200), has("a.md"), now=now, max_age=timedelta(minutes=30))
        self.assertEqual((f.state, f.reason), ("UNKNOWN", "STALE_OBSERVATION"))
        fresh = EF.frame("the claim", http(200), has("a.md"), now=now, max_age=timedelta(hours=2))
        self.assertEqual(fresh.state, "KNOWN_TRUE")
        undated = EF.observed("/things", LISTING, "every thing")
        self.assertEqual(EF.frame("the claim", undated, has("a.md"), now=now, max_age=timedelta(hours=2)).reason, "STALE_OBSERVATION")

    def test_8_unicode_normalization_is_not_a_missing_file(self):
        """The Crows Feet tombstone case: an index row spelled NFD, the file on disk spelled NFC. Raw comparison called 13 present files missing."""
        nfc = "Séance Results Log.md"
        nfd = unicodedata.normalize("NFD", nfc)
        disk = EF.observed("os.listdir(03 - Essence Notes)", [nfc, "Other.md"], "one folder, every name")
        self.assertNotIn(nfd, disk.value)                                              # what the indexer did: 'not in' => tombstone
        f = EF.present("the note is on disk", disk, nfd)
        self.assertEqual((f.state, f.reason), ("UNKNOWN", "NORMALIZATION_MISMATCH"))  # not KNOWN_FALSE
        self.assertIn("missing", f.does_not_permit)
        same_file = lambda a, b: unicodedata.normalize("NFC", a) == unicodedata.normalize("NFC", b)   # e.g. same inode or same content hash
        self.assertEqual(EF.present("the note is on disk", disk, nfd, same=same_file).state, "KNOWN_TRUE")
        self.assertEqual(EF.present("the note is on disk", disk, nfc).state, "KNOWN_TRUE")
        self.assertEqual(EF.present("the note is on disk", disk, "Gone.md").state, "KNOWN_FALSE")
        partial = EF.observed("os.listdir(...)", [nfc], "first page only", partial=True)
        self.assertEqual(EF.present("the note is on disk", partial, "Gone.md").reason, "PARTIAL_SCOPE")

    def test_11_severity_is_not_part_of_a_frame(self):
        self.assertFalse({f.name for f in dataclasses.fields(EF.Frame)} & {"severity", "severity_if_confirmed"})

    def test_12_a_broad_claim_needs_all_its_scope(self):
        flag = EF.frame("protected", EF.observed("/branch", {"protected": False}, "branch data"), lambda v: v["protected"])
        self.assertEqual(flag.state, "KNOWN_FALSE")
        broad = EF.derive("something stops a direct push", {"branch protection": flag}, needs=("branch protection", "rulesets"))
        self.assertEqual((broad.state, broad.reason), ("UNKNOWN", "UNSUPPORTED_INFERENCE"))   # protected=false alone proves nothing about rulesets
        rules = EF.frame("a ruleset applies", EF.observed("/rules", [], "rules"), lambda v: bool(v))
        both = EF.derive("something stops a direct push", {"branch protection": flag, "rulesets": rules}, needs=("branch protection", "rulesets"))
        self.assertEqual(both.state, "KNOWN_FALSE")
        failed = EF.frame("a ruleset applies", http(503, {}), lambda v: bool(v))
        open_ = EF.derive("something stops a direct push", {"branch protection": flag, "rulesets": failed}, needs=("branch protection", "rulesets"))
        self.assertEqual((open_.state, open_.reason), ("UNKNOWN", "SOURCE_UNAVAILABLE"))
        self.assertIn(flag.permits, open_.permits)                                     # the narrower fact is still what may be said

    def test_derive_truth_tables(self):
        T, F_, U = (EF.frame("p", EF.observed("/s", 1, "s"), lambda v: x) for x in (True, False, None))
        for mode, parts, want in [("any", (T, F_), "KNOWN_TRUE"), ("any", (F_, F_), "KNOWN_FALSE"), ("any", (F_, U), "UNKNOWN"), ("any", (T, U), "KNOWN_TRUE"),
                                  ("all", (T, T), "KNOWN_TRUE"), ("all", (T, F_), "KNOWN_FALSE"), ("all", (T, U), "UNKNOWN"), ("all", (F_, U), "KNOWN_FALSE")]:
            with self.subTest(mode=mode, parts=[p.state for p in parts]):
                self.assertEqual(EF.derive("c", {"a": parts[0], "b": parts[1]}, needs=("a", "b"), mode=mode).state, want)

    def test_all_explanations_match_the_truth_state(self):
        for answer, state, text in ((True, EF.KNOWN_TRUE, "All requirements hold"),
                                    (False, EF.KNOWN_FALSE, "Not so: All requirements hold")):
            with self.subTest(answer=answer):
                part = EF.frame("One requirement holds", EF.observed("/s", answer, "s"), lambda v: v)
                result = EF.derive("All requirements hold", {"a": part}, needs=("a",), mode="all")
                self.assertEqual((result.state, result.permits), (state, text))
                explicit = EF.derive("All requirements hold", {"a": part}, needs=("a",), mode="all",
                                     says_true="All confirmed", says_false="A requirement failed")
                self.assertEqual(explicit.permits, "All confirmed" if answer else "A requirement failed")

    def test_conflicting_observations_stay_unknown_without_a_recorded_rule(self):
        yes = EF.frame("enabled", EF.observed("/a", True, "a"), lambda v: v)
        no = EF.frame("enabled", EF.observed("/b", False, "b"), lambda v: v)
        f = EF.agree("enabled", [yes, no])
        self.assertEqual((f.state, f.reason), ("UNKNOWN", "CONFLICTING_OBSERVATIONS"))
        win = EF.agree("enabled", [yes, no], precedence=("/b", "the settings endpoint is authoritative for its own settings"))
        self.assertEqual(win.state, "KNOWN_FALSE")
        self.assertIn("takes precedence", win.permits)
        self.assertEqual(EF.agree("enabled", [yes, EF.frame("enabled", http(500, {}), lambda v: v)]).state, "KNOWN_TRUE")   # unknown is not a vote

    def test_the_record_is_stable(self):
        d = EF.frame("the claim", http(200), has("a.md"), show=list).to_dict()
        self.assertEqual(list(d), ["claim", "state", "observation_status", "reason", "source", "observed_value", "scope_inspected", "observed_at",
                                   "evidence", "limitation", "permits", "does_not_permit", "resolve"])
        self.assertEqual((d["source"], d["scope_inspected"], d["observed_at"], d["evidence"]), ("/things", "every thing", AT, ["R1"]))


if __name__ == "__main__":
    unittest.main()
