"""Report three-case run prerequisites without reading credential values or calling a model."""

import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
DOCKER_DESKTOP_CLI = Path("/Applications/Docker.app/Contents/Resources/bin/docker")
IMAGES = ("vex-bench-python-opencode:latest", "vex-bench-go-opencode:latest")
CONFIG_PATHS = ("env/opencode/opencode.env", "env/opencode/opencode.json")


def docker_command() -> list[str] | None:
    installed = shutil.which("docker")
    if installed:
        return [installed]
    if DOCKER_DESKTOP_CLI.is_file():
        return [str(DOCKER_DESKTOP_CLI), "--context", "desktop-linux"]
    return None


def run_docker(command: list[str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([*command, *args], capture_output=True, text=True, timeout=20)


def source_snapshots() -> dict[str, bool]:
    tasks = ROOT / "benchmark/tasks/milestone_demo.jsonl"
    found = {}
    for line in tasks.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        task = json.loads(line)
        parts = urlparse(task["repo_url"]).path.strip("/").split("/")
        source = ROOT / "benchmark/repos" / parts[0] / parts[1] / task["commit_sha"]
        found[task["task_id"]] = source.is_dir()
    return found


def main() -> None:
    command = docker_command()
    daemon = False
    detail = "Docker command unavailable"
    images = {image: False for image in IMAGES}
    if command:
        try:
            result = run_docker(command, "info", "--format", "{{.ServerVersion}}")
            # Some Docker CLI versions return 0 with an empty stdout on connection failure.
            daemon = result.returncode == 0 and bool(result.stdout.strip())
            detail = (
                result.stdout.strip() if daemon else result.stderr.strip() or "No Docker server"
            )
            if daemon:
                for image in IMAGES:
                    result = run_docker(command, "image", "inspect", "--format", "{{.Id}}", image)
                    images[image] = result.returncode == 0 and bool(result.stdout.strip())
        except subprocess.TimeoutExpired:
            detail = "Docker command timed out"

    config = {path: (ROOT / path).is_file() for path in CONFIG_PATHS}
    sources = source_snapshots()
    requirements = []
    if not daemon:
        requirements.append("Start Docker Desktop and select a working Docker context")
    if not all(images.values()):
        requirements.append("Build the missing Python/Go OpenCode runner images")
    if not all(config.values()):
        requirements.append("Configure an OpenCode model provider and credentials locally")
    if not all(sources.values()):
        requirements.append("Download the missing pinned source snapshots")
    report = {
        "docker_command_present": bool(command),
        "docker_daemon_available": daemon,
        "docker_detail": detail,
        "opencode_images_present": images,
        "opencode_configuration_files_present": config,
        "source_snapshots_present": sources,
        "ready_for_live_run": not requirements,
        "baseline_run": False,
        "credential_values_inspected": False,
        "next_requirements": requirements,
    }
    out = ROOT / "results/evidence_demo/baseline_preflight.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
