"""Create six label-free, shareable review cases from the recorded model runs."""

import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "reports/llm_judge_bundle"
ZIP_PATH = ROOT / "results/llm_judge_bundle.zip"
OWNER_MAP = ROOT / "results/llm_judge_owner_map.json"

CASES = (
    ("01", "three_case_pilot", "fastapi-fastapi-febf6b6-CVE-2024-47874"),
    ("02", "three_case_assisted", "infiniflow-ragflow-c68767a-CVE-2024-36039"),
    ("03", "three_case_pilot", "kubernetes-minikube-e7bf515-CVE-2019-5736"),
    ("04", "three_case_assisted", "fastapi-fastapi-febf6b6-CVE-2024-47874"),
    ("05", "three_case_pilot", "infiniflow-ragflow-c68767a-CVE-2024-36039"),
    ("06", "three_case_assisted", "kubernetes-minikube-e7bf515-CVE-2019-5736"),
)

SOURCES = {
    "fastapi": (
        "https://github.com/fastapi/fastapi",
        ("https://github.com/Kludex/starlette/security/advisories/GHSA-f96h-pmfr-66vw",),
    ),
    "infiniflow": (
        "https://github.com/infiniflow/ragflow",
        (
            "https://github.com/PyMySQL/PyMySQL/releases/tag/v1.1.1",
            "https://github.com/advisories/GHSA-v9hf-5j83-6xpp",
        ),
    ),
    "kubernetes": (
        "https://github.com/kubernetes/minikube",
        ("https://www.jpcert.or.jp/english/at/2019/at190007.html",),
    ),
}


def _brief(packet: dict) -> str:
    organization = packet["task_id"].split("-", 1)[0]
    repo_url, advisories = SOURCES[organization]
    sha = packet["snapshot_sha"]
    lines = [
        f"# {packet['cve_id']} review case",
        "",
        f"Repository snapshot: {repo_url}/tree/{sha}",
        "",
        "Vulnerability sources for independent checking:",
        *[f"- {url}" for url in advisories],
        "",
        "## Model answer",
        "",
        f"Proposed category: `{packet['proposed_category']}`",
        "",
        packet["reasoning"],
        "",
        "## Questions to judge",
        "",
        *[f"- **{item['id']}**: {item['question']}" for item in packet["obligations"]],
        "",
        "## Cited source lines",
        "",
    ]
    for citation in packet["citations"]:
        start, end = citation["start_line"], citation["end_line"]
        path = citation["path"]
        url = f"{repo_url}/blob/{sha}/{path}#L{start}-L{end}"
        lines.extend(
            (
                f"### {citation['id']}: `{path}:{start}-{end}`",
                "",
                f"Source at pinned commit: {url}",
                "",
                "```text",
                citation["quote"],
                "```",
                "",
            )
        )
    lines.extend(("## Model claims", ""))
    for claim in packet["claims"]:
        ids = ", ".join(claim["citation_ids"])
        lines.extend(
            (
                f"- **{claim['id']}** ({ids}; local check: `{claim['local_status']}`): "
                f"{claim['statement']}",
                "",
            )
        )
    lines.extend(
        (
            "The exact packet is `packet.json`. `integrity_valid` checks quoted bytes,",
            "not whether a source supports the security conclusion. Return one filled",
            "`annotation.json` based on `annotation.template.json`.",
            "",
        )
    )
    return "\n".join(lines)


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    mapping = []
    for number, source_name, task_id in CASES:
        source = ROOT / "reports" / source_name
        packet = json.loads((source / "review_packets" / f"{task_id}.json").read_text())
        template = json.loads(
            (source / "review_annotation_templates" / f"{task_id}.json").read_text()
        )
        assert packet["packet_sha256"] == template["packet_sha256"]
        case_dir = OUTPUT / f"case_{number}"
        case_dir.mkdir(exist_ok=True)
        (case_dir / "packet.json").write_text(
            json.dumps(packet, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (case_dir / "annotation.template.json").write_text(
            json.dumps(template, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (case_dir / "brief.md").write_text(_brief(packet), encoding="utf-8")
        mapping.append({"case": f"case_{number}", "source_run": source_name, "task_id": task_id})

    OWNER_MAP.parent.mkdir(parents=True, exist_ok=True)
    OWNER_MAP.write_text(json.dumps(mapping, indent=2) + "\n", encoding="utf-8")
    ZIP_PATH.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ZIP_PATH, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(OUTPUT.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=Path("llm_judge_bundle") / path.relative_to(OUTPUT))
    print(json.dumps({"cases": len(mapping), "bundle": str(ZIP_PATH)}))


if __name__ == "__main__":
    main()
