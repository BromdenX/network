import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "generate_rules", ROOT / "scripts" / "generate_rules.py"
)
assert SPEC and SPEC.loader
generate_rules = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generate_rules)


class GenerateRulesTests(unittest.TestCase):
    def setUp(self):
        self.outputs = generate_rules.build_outputs()

    def test_checked_in_outputs_are_current(self):
        for path, expected in self.outputs.items():
            self.assertEqual(path.read_text(encoding="utf-8"), expected, path.name)

    def test_generated_rule_lines_are_unique(self):
        ignored_prefixes = ("#", "!", "payload:", "[Rule]")
        for path, content in self.outputs.items():
            rules = [
                line.strip()
                for line in content.splitlines()
                if line.strip() and not line.startswith(ignored_prefixes)
            ]
            self.assertEqual(len(rules), len(set(rules)), path.name)

    def test_cidr_is_only_emitted_to_supported_targets(self):
        direct_cidr = "43.175.103.3/32"
        self.assertNotIn(direct_cidr, self.outputs[ROOT / "AutoProxy.list"])
        self.assertIn(direct_cidr, self.outputs[ROOT / "MyRules.sgmodule"])
        self.assertIn(direct_cidr, self.outputs[ROOT / "ToDirect.yaml"])
        self.assertNotIn(direct_cidr, self.outputs[ROOT / "ToProxy.yaml"])

    def test_specific_exceptions_precede_parent_suffixes(self):
        shadowrocket = self.outputs[ROOT / "MyRules.sgmodule"]
        cases = (
            (
                "DOMAIN,social-cdn.gposts.net,DIRECT",
                "DOMAIN-SUFFIX,gposts.net,PROXY",
            ),
            (
                "DOMAIN,amp-api-edge.apps.apple.com,PROXY",
                "DOMAIN-SUFFIX,apple.com,DIRECT",
            ),
            (
                "DOMAIN,sydney.bing.com,PROXY",
                "DOMAIN-SUFFIX,bing.com,DIRECT",
            ),
            (
                "DOMAIN-SUFFIX,metrics.icloud.com,REJECT",
                "DOMAIN-SUFFIX,icloud.com,DIRECT",
            ),
        )
        for specific, parent in cases:
            self.assertLess(shadowrocket.index(specific), shadowrocket.index(parent))

    def test_openclash_does_not_depend_on_provider_order(self):
        direct = self.outputs[ROOT / "ToDirect.yaml"]
        proxy = self.outputs[ROOT / "ToProxy.yaml"]
        self.assertNotIn("DOMAIN-SUFFIX,apple.com\n", direct)
        self.assertNotIn("DOMAIN-SUFFIX,bing.com\n", direct)
        self.assertNotIn("DOMAIN-SUFFIX,gposts.net\n", proxy)
        self.assertIn("DOMAIN,push.apple.com\n", direct)
        self.assertIn("DOMAIN,amp-api-edge.apps.apple.com\n", proxy)
        self.assertIn("DOMAIN,sydney.bing.com\n", proxy)

    def test_suffix_conflict_is_rejected(self):
        config = {key: [] for key in generate_rules.CONFIG_KEYS}
        with self.assertRaises(generate_rules.RulesError):
            generate_rules.validate_policy_conflicts(
                ["example.com"], ["api.example.com"], config
            )

    def test_openclash_cross_provider_conflict_is_rejected(self):
        with self.assertRaises(generate_rules.RulesError):
            generate_rules.validate_openclash_conflicts(
                [], ["example.com"], ["api.example.com"], [], []
            )


if __name__ == "__main__":
    unittest.main()
