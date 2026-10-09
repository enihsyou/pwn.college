"""Create a local solution for the currently running pwn.college challenge."""

import argparse
from pathlib import Path

from rich.console import Console

from scripts import pwn_college_api as api

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

# The Python template is intentionally small: challenge-specific interaction
# belongs in one_round, while dojotool still handles the common I/O plumbing.
PYTHON_TEMPLATE = """import pwn
from dojotool import find_challenge, submit
from dojotool.pwntool import tee


def one_round(io: pwn.process): 
    pass


def ctf() -> None:
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        tee(io)
        wait = 1
        try:
            one_round(io)
            wait = io.default
        finally:
            submit(io.recvrepeat(wait))


if __name__ == "__main__":
    ctf()
"""

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Initialize a solution for the running pwn.college challenge."
    )
    parser.add_argument(
        "extension",
        choices=("py", "sh", "c"),
        default="py",
        nargs="?",
        help="solution file extension (default: py)",
    )
    return parser.parse_args()


def render_solution(metadata: api.ChallengeMetadata, extension: str) -> str:
    """Render the required two-line provenance header followed by the template."""
    comment = "//" if extension == "c" else "#"
    header = (
        f"{comment} {metadata.module_name} - {metadata.challenge_name}\n"
        f"{comment} https://pwn.college/{metadata.dojo_id}/{metadata.module_id}/"
        f"{metadata.challenge_id}\n\n"
    )
    return header + (PYTHON_TEMPLATE if extension == "py" else "")


def create_solution_file(
    metadata: api.ChallengeMetadata,
    extension: str,
    repository_root: Path = REPOSITORY_ROOT,
) -> Path:
    """Create the API-ID path without overwriting an existing solution."""
    api.path_identifier(metadata.dojo_id, "dojo", "challenge metadata")
    api.path_identifier(metadata.module_id, "module", "challenge metadata")
    api.path_identifier(metadata.challenge_id, "challenge", "challenge metadata")
    api.header_text(metadata.module_name, "module name", "challenge metadata")
    api.header_text(metadata.challenge_name, "challenge name", "challenge metadata")
    folder = (
        repository_root
        / "challenges"
        / metadata.dojo_id
        / metadata.module_id
        / metadata.challenge_id
    )
    flag_file = folder / f"flag.{extension}"
    if flag_file.exists():
        return flag_file
    folder.mkdir(parents=True, exist_ok=True)
    flag_file.write_text(render_solution(metadata, extension), encoding="utf-8", newline="\n")
    return flag_file


def main() -> int:
    args = parse_args()
    try:
        metadata = api.current_challenge_metadata()
        flag_file = create_solution_file(metadata, args.extension)
    except api.ApiError as error:
        console.print(f"[bold red]Error:[/] {error}")
        return 1

    relative_file = flag_file.relative_to(REPOSITORY_ROOT).as_posix()
    console.print(f"[bold green]Challenge at:[/] {relative_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
