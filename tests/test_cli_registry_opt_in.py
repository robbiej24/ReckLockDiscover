"""CLI coverage for the ReckLock Registry opt-in path."""

from __future__ import annotations

from pathlib import Path

from recklock_scanner.cli import app, registry_opt_in_prompt
from typer.testing import CliRunner


def _repo_with_registry_candidate(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "deploy.sh").write_text(
        "#!/bin/bash\nkubectl apply -f infra.yaml\nexport AWS_SECRET_ACCESS_KEY=longverysecretvalue1234567890\n",
        encoding="utf-8",
    )
    return repo


def test_registry_opt_in_prompt_uses_adoption_friendly_copy() -> None:
    assert registry_opt_in_prompt(6) == (
        "ReckLock Discover found 6 AI agents. Add them to your ReckLock Registry so you can display:\n\n"
        "- That you own them\n"
        "- What their capabilities are\n"
        "- Which risks they carry &\n"
        "- Allow other people who want to license your agents to contact you?"
    )


def test_add_to_registry_writes_manifest_drafts(tmp_path: Path) -> None:
    repo = _repo_with_registry_candidate(tmp_path)
    out_dir = tmp_path / "reports"
    runner = CliRunner()

    result = runner.invoke(app, ["scan", str(repo), "--output-dir", str(out_dir), "--add-to-registry"])

    assert result.exit_code == 0, result.output
    assert list((out_dir / "recklock_manifest_exports").glob("*.yaml"))
    assert "manifests_written" in result.output


def test_skip_registry_does_not_write_manifest_drafts(tmp_path: Path) -> None:
    repo = _repo_with_registry_candidate(tmp_path)
    out_dir = tmp_path / "reports"
    runner = CliRunner()

    result = runner.invoke(app, ["scan", str(repo), "--output-dir", str(out_dir), "--skip-registry"])

    assert result.exit_code == 0, result.output
    assert not (out_dir / "recklock_manifest_exports").exists()
