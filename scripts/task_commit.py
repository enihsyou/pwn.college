"""Commit only the local changes for the currently running challenge."""

import subprocess
from pathlib import Path

import task_init


def challenge_directory(metadata: task_init.ChallengeMetadata) -> Path:
    """Return the repository-relative directory for a challenge."""
    return Path("challenges", metadata.dojo_id, metadata.module_id, metadata.challenge_id)


def run_git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run Git at the repository root without changing its author configuration."""
    return subprocess.run(
        ["git", *args],
        cwd=task_init.REPOSITORY_ROOT,
        check=check,
        text=True,
    )


def replace_staging_area(challenge_dir: Path) -> bool:
    """Stage the challenge directory and nothing else."""
    pathspec = challenge_dir.as_posix()
    run_git("reset", "--quiet")
    run_git("add", "--", pathspec)
    diff = run_git("diff", "--cached", "--quiet", "--", pathspec, check=False)
    if diff.returncode not in (0, 1):
        raise subprocess.CalledProcessError(diff.returncode, diff.args)
    return diff.returncode == 1


def main() -> int:
    try:
        metadata = task_init.current_challenge_metadata()
        challenge_dir = challenge_directory(metadata)
        if not (task_init.REPOSITORY_ROOT / challenge_dir).is_dir():
            raise task_init.ApiError(
                f"{challenge_dir.as_posix()} does not exist; run task init first"
            )
        if not replace_staging_area(challenge_dir):
            task_init.console.print(
                f"[bold yellow]Nothing to commit in:[/] {challenge_dir.as_posix()}"
            )
            return 1

        message = f"feat: {metadata.module_name} - {metadata.challenge_name}"
        return run_git("commit", "-m", message, check=False).returncode
    except task_init.ApiError as error:
        task_init.console.print(f"[bold red]Error:[/] {error}")
        return 1
    except subprocess.CalledProcessError as error:
        task_init.console.print(
            f"[bold red]Error:[/] git {error.cmd[1]} failed with exit code {error.returncode}"
        )
        return error.returncode


if __name__ == "__main__":
    raise SystemExit(main())
