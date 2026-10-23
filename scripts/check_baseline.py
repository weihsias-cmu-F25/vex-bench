"""Read-only prerequisites report. Does not inspect credential values or call a model."""

import json
import shutil
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
docker = shutil.which("docker")
daemon = False
detail = "Docker command unavailable"
if docker:
    try:
        result = subprocess.run(
            [docker, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        daemon = result.returncode == 0
        detail = result.stdout.strip() if daemon else result.stderr.strip()
    except subprocess.TimeoutExpired:
        detail = "Docker info timed out"
config_paths = ["env/opencode/opencode.env", "env/opencode/opencode.json"]
report = {
    "docker_command_present": bool(docker),
    "docker_daemon_available": daemon,
    "docker_detail": detail,
    "opencode_configuration_files_present": {p: (root / p).is_file() for p in config_paths},
    "baseline_run": False,
    "credential_values_inspected": False,
    "next_requirements": [
        "Running Docker daemon and built language-agent images",
        "A configured supported model provider with valid credentials",
        "Record actual model, prompts, tokens, cost and predictions after a real run",
    ],
}
out = root / "results/evidence_demo/baseline_preflight.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
