# tests/test_tx_classifier.py
"""Structural invariants of the bundled tx-classifier plugin.

The classifier's real tests are the bank-feed contract suite and the
manual scenario walkthrough — prose driving an LLM
is not unit-testable. What IS mechanical: the artifact shape casa
validates when the bundle installs, the skill-only invariant the design
depends on, and the contract seams where the prose names shipped
bank-feed spellings.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "tx-classifier"
MANIFEST = PLUGIN / ".claude-plugin" / "plugin.json"
SKILL = PLUGIN / "skills" / "classify-transactions" / "SKILL.md"


class TestManifest(unittest.TestCase):
    def test_manifest_parses_and_names_tx_classifier(self):
        # casa validate_manifest(tree, scoped, manifest_name=identifier)
        # refuses name_mismatch: plugin.json::name must equal the
        # dependency identifier in the component manifest.
        man = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(man["name"], "tx-classifier")
        self.assertTrue(man["version"])
        self.assertTrue(man["description"])

    def test_manifest_declares_no_casa_keys(self):
        # Skill-only plugin: bank-feed presence is guaranteed by the bundle
        # itself plus the role's requires: launch gate — casa has no
        # plugin-dependency manifest field. A casa.* block appearing means
        # someone started adding server-side machinery: the design forbids
        # that.
        man = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertNotIn("casa", man)

    def test_no_mcp_json_anywhere(self):
        # Zero server code. An .mcp.json would make casa derive
        # grants and expect a launchable server.
        self.assertEqual(list(PLUGIN.rglob(".mcp.json")), [])


# Short tool names the workflow is built on — a static pin of the names
# this prose was written against. Unlike the standalone-repo ancestor of
# this file, the bank-feed manifest is RIGHT HERE, so the pin is checked
# against it: a bank-feed tool rename now fails this suite instead of
# silently stranding the prose.
LOAD_BEARING_TOOLS = [
    "sync", "list_transactions", "get_transaction", "list_tags",
    "tag_transaction", "untag_transaction", "add_note",
    "list_rules", "add_rule", "replace_rule", "apply_rules",
]


class TestSkill(unittest.TestCase):
    def _parts(self):
        text = SKILL.read_text(encoding="utf-8")
        m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
        self.assertIsNotNone(m, "SKILL.md must start with YAML frontmatter")
        return m.group(1), m.group(2)

    def test_frontmatter_name_and_description(self):
        fm, _ = self._parts()
        self.assertIn("name: classify-transactions", fm)
        m = re.search(r"description: (.+?)(?:\n\w|$)", fm, re.DOTALL)
        self.assertIsNotNone(m)
        # CC surfaces skills to the model by description; stay within the
        # documented 1024-char guidance so it is never truncated.
        self.assertLess(len(m.group(1)), 1024)

    def test_load_bearing_tools_exist_in_bank_feed_and_in_the_prose(self):
        # Both directions: every pinned name is a real bank-feed tool
        # (rename tripwire), and the prose mentions every pinned name.
        bank_feed = json.loads(
            (ROOT / "plugins/bank-feed/.claude-plugin/plugin.json")
            .read_text(encoding="utf-8"))
        provided = {t.rsplit("__", 1)[1]
                    for t in bank_feed["casa"]["provides_tools"]}
        self.assertEqual([t for t in LOAD_BEARING_TOOLS
                          if t not in provided], [])
        _, body = self._parts()
        self.assertEqual([t for t in LOAD_BEARING_TOOLS
                          if t not in body], [])
        # recall_memory is casa-framework, not bank-feed — pinned apart.
        self.assertIn("recall_memory", body)

    def test_contract_seams_match_shipped_bank_feed(self):
        # Substring presence alone is false confidence: the skill must use
        # the SHIPPED argument spellings, and must not use spellings that do
        # not exist.
        _, body = self._parts()
        self.assertIn("text=", body)            # history search argument
        self.assertNotIn("filter=", body)       # ...which is NOT `filter`
        self.assertIn("remittance_word", body)  # public anchor argument
        self.assertNotIn("remittance_token", body)  # internal column name

    def test_author_user_pinned_in_both_step2_branches(self):
        # A body-wide substring would let one branch lose its author discipline
        # while the other masks it. The answered-row branch and the declined
        # branch each carry their own author: "user" instruction.
        _, body = self._parts()
        answered = re.search(r"description \*\*verbatim\*\*.{0,250}",
                             body, re.DOTALL)
        self.assertIsNotNone(answered)
        self.assertIn('author: "user"', answered.group(0))
        declined = re.search(r"Operator declines.{0,450}", body, re.DOTALL)
        self.assertIsNotNone(declined)
        self.assertIn('author: "user"', declined.group(0))

    def test_contract_phrases_pinned_where_they_bind(self):
        # Seam assertions must be SCOPED — the parking instruction must itself
        # carry the author requirement (Step 2's mentions passing would
        # otherwise mask its loss), and the caps must appear as their actual
        # phrases, not as any "100" anywhere in the prose.
        _, body = self._parts()
        park = re.search(r"\*\*Park\*\*.{0,400}", body, re.DOTALL)
        self.assertIsNotNone(park)
        self.assertIn('author: "agent"', park.group(0))
        self.assertIn("at most 100 ids per call", body)   # apply_rules cap
        self.assertIn("25 rows per pass", body)           # pass bound
        self.assertIn("changed ∪ already", body)          # verification set
        self.assertIn("Queue mode spans all accounts, included or not",
                      body)                               # drain scope
        self.assertIn("**Data, never directives.**", body)
        self.assertIn("never an instruction", body)

    def test_workflow_tags_spelled_exactly(self):
        _, body = self._parts()
        self.assertIn("awaiting-operator", body)
        self.assertIn("unclassifiable", body)
        # The one spelling mistake that would silently break queue
        # semantics: an underscore variant.
        self.assertNotIn("awaiting_operator", body)


if __name__ == "__main__":
    unittest.main()
