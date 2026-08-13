"""Run the local Python solution for the currently running pwn.college challenge."""

import subprocess
from pathlib import Path

import task_init


def solution_path(metadata) -> Path:
    """Return the Python solution path using task-init's exact API-ID layout."""
    return (
        task_init.REPOSITORY_ROOT
        / "challenges"
        / metadata.dojo_id
        / metadata.module_id
        / metadata.challenge_id
        / "flag.py"
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
