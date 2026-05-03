import argparse
import os
import runpy
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Args:
    file: str
    directory: str


def find_challenge(search_path="/challenge") -> str:
    xs = [
        str(f.absolute())
        for f in Path(search_path).iterdir()
        if f.is_file() and os.access(f, os.X_OK) and (f.stat().st_mode & stat.S_ISUID)
    ]
    if not xs:
        raise FileNotFoundError(f"No executable found in {search_path}")
    if len(xs) > 1:
        raise FileNotFoundError(f"Multiple executables found in {search_path}")
    return xs[0]


def run_python(path: str, *args) -> None:
    sys.argv = [path, *args]
    runpy.run_path(path, run_name="__main__")


def runner_name_for(path: str) -> str:
    suffix = Path(path).suffix
    if suffix == ".py":
        return "python"
    raise NotImplementedError(f"Unsupported file type: {suffix or Path(path).name}")


def run_file(path: str, *args) -> None:
    runners = {
        "python": run_python,
        # Future language hooks belong here: shell, c, make, ...
    }
    runners[runner_name_for(path)](path, *args)


def parse_args() -> Args:
    parser = argparse.ArgumentParser(
        description="Remote pwn.college runner. Usually invoked by main.py."
    )
    parser.add_argument("file", help="remote file to execute")
    parser.add_argument(
        "-d",
        "--directory",
        default="/tmp",
        help="remote deployment directory",
    )
    namespace = parser.parse_args()
    return Args(namespace.file, namespace.directory)


def main() -> None:
    args = parse_args()
    os.chdir(args.directory)
    run_file(args.file, find_challenge())


if __name__ == "__main__":
    main()
