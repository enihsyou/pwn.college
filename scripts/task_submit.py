"""Run the local solution for the currently running pwn.college challenge."""

import subprocess
from pathlib import Path

import task_init

# File suffixes dojo.py knows how to deploy and run; keep in sync with
# dojo.remote_command when new languages are added.
SUPPORTED_SOLUTION_SUFFIXES = frozenset({".py", ".c"})


def solution_path(metadata) -> Path:
    """Return the solution path by scanning the challenge directory.

    The challenge directory may contain either ``flag.py`` or ``flag.c`` (or
    other dojo-supported variants); the script is not hard-coded. Raises
    ``task_init.ApiError`` when the directory is missing, contains no
    recognised solution, or contains more than one candidate so the caller
    can surface a clear error instead of silently picking the wrong file.
    """
    challenge_dir = (
        task_init.REPOSITORY_ROOT
        / "challenges"
        / metadata.dojo_id
        / metadata.module_id
        / metadata.challenge_id
    )
    candidates = sorted(
        path
        for path in challenge_dir.glob("flag.*")
        if path.is_file() and path.suffix in SUPPORTED_SOLUTION_SUFFIXES
    )
    if len(candidates) == 1:
        return candidates[0]

    listing = ", ".join(path.name for path in candidates) or "<none>"
    relative_dir = challenge_dir.relative_to(task_init.REPOSITORY_ROOT).as_posix()
    raise task_init.ApiError(
        f"Cannot determine a unique solution in {relative_dir} "
        f"(found: {listing}); expected exactly one flag.{{py,c}}"
    )


def main() -> int:
    try:
        token = task_init.read_access_token()
        api = task_init.PwnCollegeApi(token)
        context = api.current_challenge()
        metadata = task_init.resolve_challenge_metadata(context, api.modules(context["dojo"]))
        script = solution_path(metadata)
    except task_init.ApiError as error:
        task_init.console.print(f"[bold red]Error:[/] {error}")
        return 1

    if not script.is_file():
        relative_script = script.relative_to(task_init.REPOSITORY_ROOT).as_posix()
        task_init.console.print(
            f"[bold red]Error:[/] {relative_script} does not exist; run task init first"
        )
        return 1

    relative_script = script.relative_to(task_init.REPOSITORY_ROOT)
    return subprocess.run(
        ["uv", "run", "dojo.py", relative_script.as_posix()],
        cwd=task_init.REPOSITORY_ROOT,
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
