"""Create a local solution path from the active pwn.college challenge hostname.

The hostname identifies only the module and challenge. The missing dojo path is
recovered from DESCRIPTION.md locations in the public pwncollege/challenges
repository.
"""

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from rich.console import Console

# A recursive tree is large, but it is the only unauthenticated request needed
# to discover a challenge when its dojo (an ancestor directory) is unknown.
GITHUB_TREE_URL = (
    "https://api.github.com/repos/pwncollege/challenges/git/trees/main?recursive=1"
)
# Cache only the filtered DESCRIPTION.md parents, not the complete Git tree.
# tempfile selects the platform's system-managed temporary/cache directory.
CACHE_FILE = (
    Path(tempfile.gettempdir()) / "pwncollege-challenges-description-directories.json"
)
# Increment this when the on-disk cache schema changes.
CACHE_VERSION = 1
# All paths returned by GitHub are resolved relative to this checkout.
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
# OpenSSH configuration may provide authentication details for this host.
SSH_HOST = "hacker@dojo.pwn.college"
# A suffix is removed only when its counterpart exists beside the matched
# challenge, preventing unrelated names that happen to end in "-0" or "-easy"
# from being shortened.
VARIANT_SUFFIXES = {
    "-0": "-1",
    "-1": "-0",
    "-easy": "-hard",
    "-hard": "-easy",
}
# Keep the generated Python solution consistent with the repository's existing
# task-init template. Shell solutions intentionally receive only the title.
PYTHON_TEMPLATE = """import pwn
from dojotool import find_challenge, tee


def one_round(io: pwn.process) -> None:
    pass


def ctf() -> None:
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        tee(io)
        try:
            one_round(io)
            io.recvrepeat()
        except Exception:
            io.recvrepeat(0.5)
            raise


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
        choices=("py", "sh"),
        default="py",
        nargs="?",
        help="solution file extension (default: py)",
    )
    return parser.parse_args()


def read_hostname() -> str:
    """Return the active challenge hostname from the remote container."""
    result = subprocess.run(
        ["ssh", "-q", SSH_HOST, "hostname"],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or f"ssh exited with status {result.returncode}"
        raise RuntimeError(f"Could not read the challenge hostname: {detail}")

    return result.stdout.strip()


def parse_hostname(hostname: str) -> tuple[str, str]:
    """Extract the module and challenge from a normal or practice hostname."""
    parts = hostname.split("~")
    if len(parts) == 3 and parts[0] == "practice":
        parts = parts[1:]
    if len(parts) != 2 or not all(parts):
        raise RuntimeError(f"Unexpected challenge hostname: {hostname!r}")
    return parts[0], parts[1]


def read_directory_cache() -> tuple[str | None, list[PurePosixPath]]:
    """Load the ETag and filtered challenge directories from system cache."""
    try:
        payload = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        if payload.get("version") != CACHE_VERSION:
            return None, []
        raw_directories = payload["directories"]
        if not isinstance(raw_directories, list):
            return None, []
        directories = [
            PurePosixPath(path)
            for path in raw_directories
            if isinstance(path, str)
        ]
        etag = payload.get("etag")
        return etag if isinstance(etag, str) else None, directories
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return None, []


def write_directory_cache(
    etag: str | None,
    directories: list[PurePosixPath],
) -> None:
    """Persist compact API results; cache failures must not block task init."""
    payload = {
        "version": CACHE_VERSION,
        "etag": etag,
        "directories": [path.as_posix() for path in directories],
    }
    try:
        CACHE_FILE.write_text(
            json.dumps(payload, separators=(",", ":")),
            encoding="utf-8",
        )
    except OSError as error:
        console.print(f"[yellow]Warning:[/] Could not update cache: {error}")


def request_repository_tree(etag: str | None) -> tuple[dict, str | None]:
    """Fetch the tree, asking GitHub for an empty 304 response when unchanged."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "pwn-college-task-init",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if etag:
        headers["If-None-Match"] = etag

    request = Request(GITHUB_TREE_URL, headers=headers)
    with urlopen(request, timeout=30) as response:
        return json.load(response), response.headers.get("ETag")


def extract_description_directories(payload: dict) -> list[PurePosixPath]:
    """Reduce the Git tree to directories that define actual challenges."""
    if payload.get("truncated"):
        raise RuntimeError("GitHub returned a truncated repository tree")

    directories = []
    for entry in payload.get("tree", []):
        path = entry.get("path", "")
        if entry.get("type") != "blob" or not path.endswith("/DESCRIPTION.md"):
            continue
        directory = PurePosixPath(path).parent
        if directory.parts and directory.parts[0] == "challenges":
            directories.append(directory)
    return directories


def fetch_description_directories() -> list[PurePosixPath]:
    """Return current challenge directories with ETag and offline fallback."""
    cached_etag, cached_directories = read_directory_cache()
    try:
        payload, etag = request_repository_tree(cached_etag)
    except HTTPError as error:
        # urllib represents 304 as HTTPError even though it is a cache hit.
        if error.code == 304 and cached_directories:
            return cached_directories
        if cached_directories:
            console.print(
                f"[yellow]Warning:[/] GitHub returned HTTP {error.code}; "
                "using cached challenge directories"
            )
            return cached_directories
        raise RuntimeError(f"GitHub API returned HTTP {error.code}") from error
    except URLError as error:
        if cached_directories:
            console.print(
                "[yellow]Warning:[/] GitHub is unavailable; "
                "using cached challenge directories"
            )
            return cached_directories
        raise RuntimeError(
            f"Could not reach the GitHub API: {error.reason}"
        ) from error

    directories = extract_description_directories(payload)
    write_directory_cache(etag, directories)
    return directories


def compact_name(value: str) -> str:
    """Produce a loose comparison key for punctuation differences."""
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def add_word_boundaries(value: str) -> str:
    """Convert hostname forms such as level11-1 to repository form level-11-1."""
    value = re.sub(r"(?<=[a-z])(?=\d)", "-", value.casefold())
    return re.sub(r"(?<=\d)(?=[a-z])", "-", value)


def match_score(actual: str, requested: str) -> int | None:
    """Rank exact matches ahead of normalized and punctuation-free matches."""
    if actual.casefold() == requested.casefold():
        return 0
    if actual.casefold() == add_word_boundaries(requested):
        return 1
    if compact_name(actual) == compact_name(requested):
        return 2
    return None


def find_challenge_directory(
    directories: list[PurePosixPath],
    module: str,
    challenge: str,
) -> PurePosixPath:
    """Find one unambiguous DESCRIPTION.md directory for the hostname."""
    matches = []
    for directory in directories:
        if len(directory.parts) < 3:
            continue
        if compact_name(directory.parent.name) != compact_name(module):
            continue
        score = match_score(directory.name, challenge)
        if score is not None:
            matches.append((score, directory))

    if not matches:
        raise RuntimeError(f"No DESCRIPTION.md directory matches {module}~{challenge}")

    best_score = min(score for score, _ in matches)
    best_matches = sorted(
        directory for score, directory in matches if score == best_score
    )
    if len(best_matches) > 1:
        choices = "\n".join(f"  - {path.as_posix()}" for path in best_matches)
        raise RuntimeError(
            f"Multiple challenge directories match {module}~{challenge}:\n{choices}"
        )
    return best_matches[0]


def remove_confirmed_variant(
    directory: PurePosixPath,
    directories: list[PurePosixPath],
) -> PurePosixPath:
    """Collapse a confirmed easy/hard pair into one local solution directory."""
    sibling_names = {
        candidate.name.casefold()
        for candidate in directories
        if candidate.parent == directory.parent
    }
    name = directory.name
    lower_name = name.casefold()
    for suffix, counterpart in VARIANT_SUFFIXES.items():
        if not lower_name.endswith(suffix):
            continue
        base_name = name[: -len(suffix)]
        if f"{base_name}{counterpart}".casefold() in sibling_names:
            return directory.with_name(base_name)
    return directory


def solution_title(challenge_name: str) -> str:
    return challenge_name.replace("-", " ").title()


def create_solution_file(directory: PurePosixPath, extension: str) -> Path:
    """Create the selected template without overwriting an existing solution."""
    folder = REPOSITORY_ROOT.joinpath(*directory.parts)
    flag_file = folder / f"flag.{extension}"
    if flag_file.exists():
        return flag_file

    folder.mkdir(parents=True, exist_ok=True)
    title = solution_title(directory.name)
    body = f"# {title}\n"
    if extension == "py":
        body += PYTHON_TEMPLATE
    flag_file.write_text(body, encoding="utf-8", newline="\n")
    return flag_file


def main() -> int:
    args = parse_args()
    try:
        hostname = read_hostname()
        module, challenge = parse_hostname(hostname)
        directories = fetch_description_directories()
        # source_directory retains the exact upstream easy/hard variant.
        source_directory = find_challenge_directory(
            directories,
            module,
            challenge,
        )
        # solution_directory may merge a confirmed pair into one local folder.
        solution_directory = remove_confirmed_variant(
            source_directory,
            directories,
        )
        flag_file = create_solution_file(solution_directory, args.extension)
    except RuntimeError as error:
        console.print(f"[bold red]Error:[/] {error}")
        return 1

    relative_file = flag_file.relative_to(REPOSITORY_ROOT).as_posix()
    console.print(f"[bold green]Challenge at:[/] {relative_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
