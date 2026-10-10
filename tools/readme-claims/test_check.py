"""Tests for tools/readme-claims/check.py (stdlib unittest; run: python3 tools/readme-claims/test_check.py)."""
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check  # noqa: E402


def make_repo(files):
    root = tempfile.mkdtemp(prefix="readme-claims-")
    for rel, body in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(body))
    return root


FIXTURE = {
    "internal/foo/foo_test.go": """\
        package foo

        import "testing"

        func TestFooWorks(t *testing.T) {}
        func FuzzFoo(f *testing.F) {}
        """,
    "python/tests/test_bar.py": """\
        def test_bar_ok():
            pass

        class TestGroup:
            def test_inside(self):
                pass
        """,
    "docs/benchmark.md": """\
        # Bench

        ## Current numbers (2026-10-09, after Track B3)

        | a | b |
        |---|---|

        ## Cloud lab: unverified
        """,
}


def run(readme, extra=None):
    files = dict(FIXTURE)
    files["README.md"] = readme
    if extra:
        files.update(extra)
    root = make_repo(files)
    return check.check_file(os.path.join(root, "README.md"), root)


class TriggerTests(unittest.TestCase):
    def test_unmarked_number_fails(self):
        res = run("Recall is 100% on the lab.\n")
        self.assertEqual(len(res.unlinked), 1)
        self.assertIn("100%", res.unlinked[0].text)

    def test_unmarked_superlative_fails(self):
        for word in ("every", "all", "only", "fastest", "complete"):
            with self.subTest(word=word):
                res = run(f"It handles {word} cloud.\n")
                self.assertEqual(len(res.unlinked), 1, word)

    def test_superlative_is_whole_word(self):
        res = run("A smallish tally of incomplete-ish words: install, ball, everyone.\n")
        self.assertEqual(res.unlinked, [])

    def test_read_only_is_a_term_not_a_superlative(self):
        self.assertEqual(run("The scan uses a read-only role.\n").unlinked, [])
        self.assertEqual(len(run("The scan is the only read-only role.\n").unlinked), 1)

    def test_plain_sentence_passes(self):
        res = run("nimbus reads findings and draws paths.\n")
        self.assertEqual(res.unlinked, [])
        self.assertEqual(res.bad_refs, [])

    def test_code_is_ignored(self):
        readme = "Run `cloud-posture paths --limit 0` to see them.\n\n```sh\nmake build  # all 100 things\n```\n"
        res = run(readme)
        self.assertEqual(res.unlinked, [])

    def test_dates_versions_and_standards_are_not_claims(self):
        readme = "Measured 2026-10-09 on v0.2.0 under Apache-2.0 with SHA-256 checksums and OCSF 1.6, see §8 and Phase 1.\n"
        res = run(readme)
        self.assertEqual(res.unlinked, [])

    def test_link_urls_are_ignored_but_text_is_checked(self):
        res = run("See [the bench](docs/benchmark.md#current-numbers-2026-10-09-after-track-b3).\n")
        self.assertEqual(res.unlinked, [])
        res = run("See [all 12 paths](docs/x.md).\n")
        self.assertEqual(len(res.unlinked), 1)


class MarkerTests(unittest.TestCase):
    def test_go_test_marker_resolves(self):
        res = run("Recall is 100% on the lab. <!-- claim: TestFooWorks -->\n")
        self.assertEqual(res.unlinked, [])
        self.assertEqual(res.bad_refs, [])
        self.assertEqual(len(res.claims), 1)

    def test_go_test_with_dir_prefix(self):
        res = run("Fuzzed 1 parser. <!-- claim: internal/foo/FuzzFoo -->\n")
        self.assertEqual(res.bad_refs, [])
        res = run("Fuzzed 1 parser. <!-- claim: internal/other/FuzzFoo -->\n")
        self.assertEqual(len(res.bad_refs), 1)

    def test_missing_go_test_is_a_bad_ref(self):
        res = run("Recall is 100%. <!-- claim: TestDoesNotExist -->\n")
        self.assertEqual(res.unlinked, [])
        self.assertEqual(len(res.bad_refs), 1)
        self.assertIn("TestDoesNotExist", res.bad_refs[0].ref)

    def test_pytest_node_ids(self):
        ok = "Has 1 check. <!-- claim: python/tests/test_bar.py::test_bar_ok -->\n"
        self.assertEqual(run(ok).bad_refs, [])
        ok_cls = "Has 1 check. <!-- claim: python/tests/test_bar.py::TestGroup::test_inside -->\n"
        self.assertEqual(run(ok_cls).bad_refs, [])
        ok_param = "Has 1 check. <!-- claim: python/tests/test_bar.py::test_bar_ok[case-1] -->\n"
        self.assertEqual(run(ok_param).bad_refs, [])
        bad = "Has 1 check. <!-- claim: python/tests/test_bar.py::test_missing -->\n"
        self.assertEqual(len(run(bad).bad_refs), 1)
        bad_file = "Has 1 check. <!-- claim: python/tests/test_nope.py::test_bar_ok -->\n"
        self.assertEqual(len(run(bad_file).bad_refs), 1)

    def test_doc_section_refs(self):
        ok = "Recall 100%. <!-- claim: docs/benchmark.md#current-numbers-2026-10-09-after-track-b3 -->\n"
        self.assertEqual(run(ok).bad_refs, [])
        ok2 = "Not 1 live run. <!-- claim: docs/benchmark.md#cloud-lab-unverified -->\n"
        self.assertEqual(run(ok2).bad_refs, [])
        bad = "Recall 100%. <!-- claim: docs/benchmark.md#no-such-section -->\n"
        self.assertEqual(len(run(bad).bad_refs), 1)
        bad_file = "Recall 100%. <!-- claim: docs/missing.md#x -->\n"
        self.assertEqual(len(run(bad_file).bad_refs), 1)

    def test_multiple_refs_all_must_resolve(self):
        res = run("All 3 hold. <!-- claim: TestFooWorks, TestNope -->\n")
        self.assertEqual(len(res.bad_refs), 1)
        res = run("All 3 hold. <!-- claim: TestFooWorks, python/tests/test_bar.py::test_bar_ok -->\n")
        self.assertEqual(res.bad_refs, [])

    def test_unknown_ref_kind_is_bad(self):
        res = run("All 3 hold. <!-- claim: trust me -->\n")
        self.assertTrue(res.bad_refs)

    def test_empty_marker_is_bad(self):
        res = run("All 3 hold. <!-- claim: -->\n")
        self.assertTrue(res.bad_refs or res.unlinked)

    def test_marker_on_last_line_covers_wrapped_paragraph(self):
        readme = "The engine found 12 of 12 labelled paths\nand reported zero false positives. <!-- claim: TestFooWorks -->\n"
        res = run(readme)
        self.assertEqual(res.unlinked, [])

    def test_marker_does_not_leak_to_next_paragraph(self):
        readme = "Found 12 paths. <!-- claim: TestFooWorks -->\n\nScans all clouds.\n"
        res = run(readme)
        self.assertEqual(len(res.unlinked), 1)
        self.assertIn("all clouds", res.unlinked[0].text)

    def test_list_items_are_separate_units(self):
        readme = "- covers 3 clouds <!-- claim: TestFooWorks -->\n- covers all clouds\n"
        res = run(readme)
        self.assertEqual(len(res.unlinked), 1)

    def test_table_rows_need_markers(self):
        readme = "| id | value |\n|---|---|\n| P01 | 10.00 |\n"
        res = run(readme)
        self.assertEqual(len(res.unlinked), 1)

    def test_row_marker_inside_last_cell(self):
        readme = "| cap | evidence |\n|---|---|\n| covers 3 clouds | `TestFooWorks` <!-- claim: TestFooWorks --> |\n| all clouds | none |\n"
        res = run(readme)
        self.assertEqual(len(res.unlinked), 1)
        self.assertIn("all clouds", res.unlinked[0].text)
        self.assertEqual(len(res.claims), 1)

    def test_marker_text_inside_inline_code_is_not_a_marker(self):
        readme = "Each claim carries a `<!-- claim: ... -->` marker; all 3 kinds resolve. <!-- claim: TestFooWorks -->\n"
        res = run(readme)
        self.assertEqual(res.bad_refs, [])
        self.assertEqual(res.unlinked, [])
        self.assertEqual(res.claims[0].refs, ["TestFooWorks"])

    def test_paragraph_marker_must_trail(self):
        res = run("Found 12 paths <!-- claim: TestFooWorks --> and more text here.\n")
        self.assertEqual(len(res.unlinked), 1)

    def test_claim_table_marker_covers_table(self):
        readme = (
            "<!-- claim-table: docs/benchmark.md#current-numbers-2026-10-09-after-track-b3 -->\n"
            "| id | value |\n|---|---|\n| P01 | 10.00 |\n| P02 | 7.60 |\n\nAfter the table, all 5 things.\n"
        )
        res = run(readme)
        self.assertEqual(len(res.unlinked), 1)
        self.assertIn("all 5", res.unlinked[0].text)
        self.assertEqual(res.bad_refs, [])

    def test_claim_table_marker_bad_ref(self):
        readme = "<!-- claim-table: docs/benchmark.md#nope -->\n| a |\n|---|\n| 1 |\n"
        res = run(readme)
        self.assertEqual(len(res.bad_refs), 1)

    def test_headings_are_checked(self):
        res = run("## The fastest scanner\n")
        self.assertEqual(len(res.unlinked), 1)


class CLITests(unittest.TestCase):
    def test_exit_codes_and_list(self):
        root = make_repo(dict(FIXTURE, **{"README.md": "Found 12 paths. <!-- claim: TestFooWorks -->\n"}))
        script = os.path.join(HERE, "check.py")
        ok = subprocess.run([sys.executable, script, "--root", root, "--list", os.path.join(root, "README.md")],
                            capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("TestFooWorks", ok.stdout)
        with open(os.path.join(root, "README.md"), "w") as fh:
            fh.write("Found all 12 paths.\n")
        bad = subprocess.run([sys.executable, script, "--root", root, os.path.join(root, "README.md")],
                             capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("README.md:1", bad.stdout + bad.stderr)


class RepoReadmeTest(unittest.TestCase):
    """The real README must pass: every numeric/superlative sentence links to a resolvable reference."""

    def test_repo_readme_passes(self):
        root = os.path.abspath(os.path.join(HERE, "..", ".."))
        res = check.check_file(os.path.join(root, "README.md"), root)
        msgs = [f"{u.line}: {u.text}" for u in res.unlinked] + [f"{b.line}: bad ref {b.ref} ({b.why})" for b in res.bad_refs]
        self.assertEqual(msgs, [], "\n".join(msgs))


if __name__ == "__main__":
    unittest.main()
