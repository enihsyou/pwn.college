"""Plan and (optionally) apply the legacy challenge path migration.

The old tree stored solutions below ``challenges/legacy/{dojo}`` and often
used the challenge display name as the final directory.  The API is the source
of truth for the destination: ``challenges/{dojo}/{module_id}/{challenge_id}``.
The default mode is a report-only dry run; pass ``--apply`` to move only
unambiguous directories whose destination does not already exist.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

API_BASE_URL = "https://pwn.college/pwncollege_api/v1"
TOKEN_NAME = "DOJO_ACCESS_TOKEN"
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
LEGACY_ROOT = REPOSITORY_ROOT / "challenges" / "legacy"
REQUEST_TIMEOUT_SECONDS = 30


class MigrationError(RuntimeError):
    """A recoverable migration/API error."""


@dataclass(frozen=True)
class Challenge:
    id: str
    name: str


@dataclass(frozen=True)
class Module:
    id: str
    name: str
    challenges: tuple[Challenge, ...]


@dataclass(frozen=True)
class Candidate:
    source: Path
    dojo_id: str
    module: Module
    challenge: Challenge
    reason: str

    @property
    def target(self) -> Path:
        return (
            REPOSITORY_ROOT
            / "challenges"
            / self.dojo_id
            / self.module.id
            / self.challenge.id
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the printed, conflict-free migration plan",
    )
    return parser.parse_args()


def _env_file_token() -> str:
    env_path = REPOSITORY_ROOT / ".env"
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key.strip() == TOKEN_NAME:
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            return value
    return ""


def access_token() -> str:
    token = os.environ.get(TOKEN_NAME, "").strip() or _env_file_token()
    if not token:
        raise MigrationError(
            f"{TOKEN_NAME} is not set and was not found in {REPOSITORY_ROOT / '.env'}"
        )
    return token


def _api_json(path: str, token: str) -> dict[str, Any]:
    request = Request(
        f"{API_BASE_URL}{path}",
        method="GET",
        headers={
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise MigrationError(f"API returned HTTP {error.code} for {path}") from error
    except (URLError, OSError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationError(f"API request failed for {path}: {error}") from error
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise MigrationError(f"API returned an unsuccessful response for {path}")
    return payload


def _safe_id(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
    ):
        raise MigrationError(f"{context} is not a safe non-empty path ID")
    return value


def load_modules(dojo_id: str, token: str) -> tuple[Module, ...]:
    payload = _api_json(f"/dojos/{quote(dojo_id, safe='')}/modules", token)
    raw_modules = payload.get("modules")
    if not isinstance(raw_modules, list):
        raise MigrationError(f"API modules response for {dojo_id!r} has no modules list")
    modules: list[Module] = []
    seen_modules: set[str] = set()
    for index, raw_module in enumerate(raw_modules):
        if not isinstance(raw_module, dict):
            raise MigrationError(f"module {index} for {dojo_id!r} is not an object")
        module_id = _safe_id(raw_module.get("id"), f"module {index} ID")
        module_name = raw_module.get("name")
        if not isinstance(module_name, str) or not module_name:
            raise MigrationError(f"module {module_id!r} has no display name")
        if module_id in seen_modules:
            raise MigrationError(f"duplicate module ID {module_id!r} in {dojo_id!r}")
        seen_modules.add(module_id)
        raw_challenges = raw_module.get("challenges")
        if not isinstance(raw_challenges, list):
            raise MigrationError(f"module {module_id!r} has no challenges list")
        challenges: list[Challenge] = []
        seen_challenges: set[str] = set()
        for challenge_index, raw_challenge in enumerate(raw_challenges):
            if not isinstance(raw_challenge, dict):
                raise MigrationError(
                    f"challenge {challenge_index} in {module_id!r} is not an object"
                )
            challenge_id = _safe_id(
                raw_challenge.get("id"),
                f"challenge {challenge_index} ID in {module_id!r}",
            )
            challenge_name = raw_challenge.get("name")
            if not isinstance(challenge_name, str) or not challenge_name:
                raise MigrationError(f"challenge {challenge_id!r} has no display name")
            if challenge_id in seen_challenges:
                raise MigrationError(
                    f"duplicate challenge ID {challenge_id!r} in {module_id!r}"
                )
            seen_challenges.add(challenge_id)
            challenges.append(Challenge(challenge_id, challenge_name))
        modules.append(Module(module_id, module_name, tuple(challenges)))
    return tuple(modules)


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")


def compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def header_urls(source: Path) -> set[str]:
    """Read URL provenance from the first few lines, if a solution has it."""
    urls: set[str] = set()
    for file_path in source.iterdir():
        if not file_path.is_file():
            continue
        try:
            text = "\n".join(file_path.read_text(encoding="utf-8").splitlines()[:8])
        except (OSError, UnicodeDecodeError):
            continue
        urls.update(
            re.findall(
                r"https://pwn\.college/([^\s`#]+)",
                text,
            )
        )
    return urls


def url_challenge_ids(source: Path, dojo_id: str, module_id: str) -> set[str]:
    prefix = f"{dojo_id}/{module_id}/"
    result: set[str] = set()
    for value in header_urls(source):
        if value.startswith(prefix):
            challenge_id = value[len(prefix) :].split("/", 1)[0]
            if challenge_id:
                result.add(challenge_id)
    return result


def map_challenge(
    source: Path,
    dojo_id: str,
    module: Module,
) -> tuple[Challenge | None, str]:
    folder = source.name
    by_id = [challenge for challenge in module.challenges if challenge.id == folder]
    if len(by_id) == 1:
        return by_id[0], "exact API ID"

    from_url = url_challenge_ids(source, dojo_id, module.id)
    url_matches = [challenge for challenge in module.challenges if challenge.id in from_url]
    if len(url_matches) == 1:
        return url_matches[0], "file header URL"
    if len(url_matches) > 1:
        return None, "conflicting file header URLs"

    folder_slug = slug(folder)
    display_matches = [
        challenge
        for challenge in module.challenges
        if slug(challenge.name) == folder_slug or slug(challenge.id) == folder_slug
    ]
    if len(display_matches) == 1:
        return display_matches[0], "API display-name slug"
    if len(display_matches) > 1:
        return None, "ambiguous API display-name slug (likely -0/-1 pair)"

    # Older folders commonly dropped the easy/hard (or -0/-1) suffix.  That
    # name intentionally identifies two API records, so it is unsafe to pick
    # either record without a provenance URL.
    base_matches: list[Challenge] = []
    folder_compact = compact(folder)
    for challenge in module.challenges:
        for suffix in ("-0", "-1", "-easy", "-hard"):
            if challenge.id.endswith(suffix) and (
                slug(challenge.id[: -len(suffix)]) == folder_slug
                or compact(challenge.id[: -len(suffix)]) == folder_compact
            ):
                base_matches.append(challenge)
                break
            name_slug = slug(challenge.name)
            for name_suffix in ("-easy", "-hard"):
                if name_slug.endswith(name_suffix) and name_slug[: -len(name_suffix)] == folder_slug:
                    base_matches.append(challenge)
                    break
            else:
                continue
            break
    unique_base_matches = {challenge.id: challenge for challenge in base_matches}
    if len(unique_base_matches) > 1:
        return None, "ambiguous API base name (likely -0/-1 pair)"
    if len(unique_base_matches) == 1:
        return next(iter(unique_base_matches.values())), "API base name"

    compact_matches = [
        challenge
        for challenge in module.challenges
        if folder_compact == compact(challenge.name)
    ]
    if len(compact_matches) == 1:
        return compact_matches[0], "normalized API ID/name"
    if len(compact_matches) > 1:
        return None, "ambiguous normalized API ID/name"
    return None, "no exact API ID, display name, or header URL mapping"


def legacy_challenge_dirs(dojo_root: Path, modules: tuple[Module, ...]) -> list[tuple[Path, Module]]:
    module_by_id = {module.id: module for module in modules}
    result: list[tuple[Path, Module]] = []
    for module_dir in sorted(dojo_root.iterdir()):
        if not module_dir.is_dir():
            continue
        module = module_by_id.get(module_dir.name)
        if module is None:
            print(f"KEEP {module_dir}: module directory is not an exact API module ID")
            continue
        for challenge_dir in sorted(module_dir.iterdir()):
            if challenge_dir.is_dir():
                result.append((challenge_dir, module))
    return result


def clean_empty_legacy_dirs() -> None:
    for path in sorted(LEGACY_ROOT.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_dir():
            try:
                path.rmdir()
            except OSError:
                pass


def main() -> int:
    args = parse_args()
    if not LEGACY_ROOT.is_dir():
        print(f"No legacy tree found: {LEGACY_ROOT}")
        return 0
    try:
        token = access_token()
        dojo_dirs = sorted(path for path in LEGACY_ROOT.iterdir() if path.is_dir())
        plans: list[Candidate] = []
        keep_count = 0
        for dojo_root in dojo_dirs:
            dojo_id = dojo_root.name
            try:
                modules = load_modules(dojo_id, token)
            except MigrationError as error:
                print(f"KEEP {dojo_root}: {error}")
                keep_count += sum(1 for _ in dojo_root.rglob("*") if _.is_dir())
                continue
            for source, module in legacy_challenge_dirs(dojo_root, modules):
                challenge, reason = map_challenge(source, dojo_id, module)
                if challenge is None:
                    print(f"KEEP {source}: {reason}")
                    keep_count += 1
                    continue
                candidate = Candidate(source, dojo_id, module, challenge, reason)
                if candidate.target.exists():
                    print(f"KEEP {source}: destination already exists: {candidate.target}")
                    keep_count += 1
                    continue
                print(f"MOVE {source} -> {candidate.target} ({reason})")
                plans.append(candidate)

        print(f"Plan: {len(plans)} movable, {keep_count} kept")
        if not args.apply:
            print("Dry run only; pass --apply to execute these moves.")
            return 0

        moved = 0
        for candidate in plans:
            if candidate.target.exists():
                print(f"KEEP {candidate.source}: destination appeared before apply")
                continue
            candidate.target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(candidate.source), str(candidate.target))
            moved += 1
            print(f"MOVED {candidate.source} -> {candidate.target}")
        clean_empty_legacy_dirs()
        print(f"Applied: {moved} moved, {len(plans) - moved} skipped")
        return 0
    except MigrationError as error:
        print(f"ERROR: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
