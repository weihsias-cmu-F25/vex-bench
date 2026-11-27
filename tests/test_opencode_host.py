import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evaluate.agents.base import RunContext
from evaluate.agents.opencode_host import OpenCodeHostAgent


class OpenCodeHostTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.home = self.root / "opencode"
        binary = self.home / "node_modules/.bin/opencode"
        binary.parent.mkdir(parents=True)
        binary.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os\n"
            "from pathlib import Path\n"
            "message = '|'.join([str(Path.cwd()), os.environ['PWD'], "
            "Path('fact.txt').read_text().strip(), str(Path('escape').exists())])\n"
            "print(json.dumps({'type': 'text', 'part': {'text': message}}))\n"
        )
        binary.chmod(0o755)
        database = self.home / "data/opencode/opencode.db"
        database.parent.mkdir(parents=True)
        database.touch()
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "fact.txt").write_text("cedar\n")
        (self.source / "escape").symlink_to(database)

    def test_run_uses_disposable_copy_and_denies_external_tools(self):
        agent = OpenCodeHostAgent("gpt-6.2-sol")
        with patch.dict(os.environ, {"VEX_OPENCODE_HOME": str(self.home)}):
            result = agent.run("test", RunContext(cwd=self.source, language="python"))
        cwd, pwd, fact, escape = agent.extract_text(result.raw_output).split("|")
        self.assertEqual(Path(cwd).resolve(), Path(pwd).resolve())
        self.assertNotEqual(Path(cwd), self.source)
        self.assertEqual((fact, escape), ("cedar", "False"))
        self.assertFalse(Path(cwd).exists())
        policy = json.loads((self.home / "config/opencode/opencode.json").read_text())
        self.assertEqual(
            {rule["action"] for rule in policy["permissions"]},
            {
                "external_directory",
                "shell",
                "edit",
                "execute",
                "subagent",
                "websearch",
                "webfetch",
                "question",
            },
        )
        self.assertEqual(
            [rule for rule in policy["permissions"] if rule["effect"] == "allow"],
            [{"action": "shell", "resource": "shasum -a 256 *", "effect": "allow"}],
        )

    def test_unexpected_policy_is_rejected(self):
        policy = self.home / "config/opencode/opencode.json"
        policy.parent.mkdir(parents=True)
        policy.write_text("{}")
        with patch.dict(os.environ, {"VEX_OPENCODE_HOME": str(self.home)}):
            with self.assertRaisesRegex(RuntimeError, "Unexpected OpenCode policy"):
                OpenCodeHostAgent("gpt-6.2-sol").run(
                    "test", RunContext(cwd=self.source, language="python")
                )

    def test_error_event_is_reported_when_stderr_is_empty(self):
        binary = self.home / "node_modules/.bin/opencode"
        binary.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "print(json.dumps({'type': 'error', "
            "'error': {'type': 'provider.chatgpt-limit', 'message': 'Usage limit reached'}}))\n"
            "sys.exit(1)\n"
        )
        with patch.dict(os.environ, {"VEX_OPENCODE_HOME": str(self.home)}):
            with self.assertRaisesRegex(RuntimeError, "Usage limit reached"):
                OpenCodeHostAgent("gpt-6.2-sol").run(
                    "test", RunContext(cwd=self.source, language="python")
                )


if __name__ == "__main__":
    unittest.main()
