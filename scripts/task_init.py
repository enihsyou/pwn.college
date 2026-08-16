"""Create a local solution for the currently running pwn.college challenge.

The pwn.college API is the source of truth for both the running challenge and
its human-readable names. Keeping discovery here (rather than inferring it
from machine metadata or a repository tree) makes the generated URL and local
path refer to the same API IDs.
"""

import argparse
import hashlib
import json
import os
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from rich.console import Console

API_BASE_URL = "https://pwn.college/pwncollege_api/v1"
ACCESS_TOKEN_VARIABLE = "DOJO_ACCESS_TOKEN"
REQUEST_TIMEOUT_SECONDS = 30
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

# The Python template is intentionally small: challenge-specific interaction
# belongs in one_round, while dojotool still handles the common I/O plumbing.
PYTHON_TEMPLATE = """import pwn
from dojotool import find_challenge, submit, tee


def one_round(io: pwn.process) -> str: ...


def ctf() -> None:
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        tee(io)
        try:
            flag = one_round(io)
        finally:
            io.recvrepeat(1)
        submit(flag)


if __name__ == "__main__":
    ctf()
"""

console = Console()


class ApiError(RuntimeError):
    """An actionable failure while querying the pwn.college API."""


class ApiSchemaError(ApiError):
    """The API returned JSON that does not match the expected schema."""


class ApiTransportError(ApiError):
    """The API could not be reached or returned an HTTP transport error."""


class JsonObject:
    """Small path-aware accessor for the JSON objects consumed by this script."""

    def __init__(self, value: Any, path: str) -> None:
        if not isinstance(value, Mapping):
            raise ApiSchemaError(f"{path} must be a JSON object")
        self.value = value
        self.path = path

    def _missing(self, key: str) -> ApiSchemaError:
        return ApiSchemaError(f"{self.path}.{key} is missing")

    def optional(self, key: str) -> Any:
        return self.value.get(key)

    def required(self, key: str) -> Any:
        if key not in self.value:
            raise self._missing(key)
        return self.value[key]

    def string(self, key: str) -> str:
        value = self.required(key)
        if not isinstance(value, str) or not value:
            raise ApiSchemaError(f"{self.path}.{key} must be a non-empty string")
        return value

    def optional_string(self, key: str) -> str | None:
        value = self.optional(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ApiSchemaError(f"{self.path}.{key} must be a string or null")
        return value

    def boolean(self, key: str) -> bool:
        value = self.required(key)
        if not isinstance(value, bool):
            raise ApiSchemaError(f"{self.path}.{key} must be a boolean")
        return value

    def integer(self, key: str) -> int:
        value = self.required(key)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ApiSchemaError(f"{self.path}.{key} must be an integer")
        return value

    def list(self, key: str) -> list[Any]:
        value = self.required(key)
        if not isinstance(value, list):
            raise ApiSchemaError(f"{self.path}.{key} must be a list")
        return value

    def object(self, key: str) -> "JsonObject":
        return JsonObject(self.required(key), f"{self.path}.{key}")


@dataclass(frozen=True)
class JsonCacheEntry[T]:
    """A validated cache value plus the metadata needed for revalidation."""

    path: Path
    value: T
    etag: str | None


class JsonFileCache[T]:
    """Reusable versioned JSON-file cache with TTL and conditional metadata."""

    def __init__(
        self,
        directory: Path,
        namespace: str,
        version: int,
        ttl_seconds: int,
        key_field: str,
        key_to_filename: Callable[[str], str],
        decode: Callable[[JsonObject], T],
        encode: Callable[[T], Any],
        label: str,
    ) -> None:
        self.directory = directory
        self.namespace = namespace
        self.version = version
        self.ttl_seconds = ttl_seconds
        self.key_field = key_field
        self.key_to_filename = key_to_filename
        self.decode = decode
        self.encode = encode
        self.label = label

    def path_for(self, key: str) -> Path:
        filename = f"{self.namespace}-{self.key_to_filename(key)}.json"
        return self.directory / filename

    def read(self, key: str) -> JsonCacheEntry[T] | None:
        path = self.path_for(key)
        try:
            cached = JsonObject(
                json.loads(path.read_text(encoding="utf-8")),
                f"{self.label} cache",
            )
            if cached.integer("version") != self.version:
                return None
            if cached.string(self.key_field) != key:
                return None
            etag = cached.optional_string("etag")
            if etag is not None and any(character in etag for character in ("\r", "\n")):
                return None
            value = self.decode(cached.object("response"))
        except (OSError, json.JSONDecodeError, ApiError, TypeError):
            return None
        return JsonCacheEntry(path=path, value=value, etag=etag)

    def is_fresh(self, entry: JsonCacheEntry[T]) -> bool:
        try:
            age = time.time() - entry.path.stat().st_mtime
        except OSError:
            return False
        return age <= self.ttl_seconds

    def touch(self, entry: JsonCacheEntry[T]) -> None:
        try:
            entry.path.touch()
        except OSError as error:
            console.print(f"[yellow]Warning:[/] Could not refresh {self.label} cache age: {error}")

    def write(self, key: str, value: T, etag: str | None) -> None:
        envelope = {
            "version": self.version,
            self.key_field: key,
            "etag": etag,
            "response": self.encode(value),
        }
        try:
            self.path_for(key).write_text(
                json.dumps(envelope, separators=(",", ":")),
                encoding="utf-8",
            )
        except (OSError, TypeError) as error:
            console.print(f"[yellow]Warning:[/] Could not update {self.label} cache: {error}")


@dataclass(frozen=True)
class ChallengeMetadata:
    """IDs used for paths/URLs and names used in the generated header."""

    dojo_id: str
    module_id: str
    challenge_id: str
    module_name: str
    challenge_name: str


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


def read_access_token(environ: Mapping[str, str] | None = None) -> str:
    """Read the token without ever including its value in an error message."""
    variables = os.environ if environ is None else environ
    token = variables.get(ACCESS_TOKEN_VARIABLE, "").strip()
    if not token:
        raise ApiError(
            f"{ACCESS_TOKEN_VARIABLE} is not set; export a pwn.college Access Token "
            "before running task init"
        )
    return token


def _safe_detail(detail: Any, token: str) -> str:
    """Bound and redact API-provided detail before displaying it to the user."""
    if not isinstance(detail, str) or not detail.strip():
        return "unspecified error"
    text = detail.strip().replace(token, "<redacted>")
    return text[:500]


class PwnCollegeApi:
    """Small JSON client with the exact authentication headers required here."""

    def __init__(self, token: str, base_url: str = API_BASE_URL) -> None:
        self._token = token
        self._base_url = base_url.rstrip("/")

    def _open_json(
        self,
        path: str,
        extra_headers: Mapping[str, str] | None = None,
    ) -> tuple[dict[str, Any] | None, Any]:
        # Content-Type is required even for GET: CTFd's token middleware only
        # parses the Authorization header for an exact JSON content type.
        headers = {
            "Authorization": f"Token {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)
        conditional_request = any(name.casefold() == "if-none-match" for name in headers)
        request = Request(
            f"{self._base_url}{path}",
            method="GET",
            headers=headers,
        )
        try:
            with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                if conditional_request and getattr(response, "status", None) == 304:
                    return None, response.headers
                raw_body = response.read()
                response_headers = response.headers
        except HTTPError as error:
            try:
                if conditional_request and error.code == 304:
                    return None, error.headers
                reason = error.msg
                if error.code == 500:
                    reason = "the DOJO_ACCESS_TOKEN may be expired or revoked"
                raise ApiTransportError(
                    f"pwn.college API returned HTTP {error.code} for {path}: {reason}"
                ) from error
            finally:
                error.close()
        except (URLError, TimeoutError, OSError) as error:
            reason = getattr(error, "reason", None) or str(error)
            raise ApiTransportError(
                f"Could not reach pwn.college API for {path}: {reason}"
            ) from error

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ApiSchemaError(f"pwn.college API returned invalid JSON for {path}") from error
        response = JsonObject(payload, f"pwn.college API response for {path}")
        success = response.boolean("success")
        if not success:
            detail = _safe_detail(response.optional("error"), self._token)
            raise ApiError(f"pwn.college API reported failure for {path}: {detail}")
        return dict(response.value), response_headers

    def _request_json(self, path: str) -> dict[str, Any]:
        payload, _ = self._open_json(path)
        if payload is None:
            raise ApiTransportError(f"pwn.college API returned HTTP 304 for {path}")
        return payload

    def current_challenge(self) -> dict[str, Any]:
        """Return the API's current dojo/module/challenge context."""
        payload = self._request_json("/docker")
        response = JsonObject(payload, "pwn.college API response for /docker")
        return {field: response.string(field) for field in ("dojo", "module", "challenge")}

    def modules(self, dojo_id: str) -> dict[str, Any]:
        """Return the module/challenge hierarchy for one dojo ID."""
        encoded_dojo = quote(dojo_id, safe="")
        path = f"/dojos/{encoded_dojo}/modules"
        cache = read_module_cache(dojo_id)
        if cache and module_cache_is_fresh(cache):
            return cache.value

        extra_headers = {"If-None-Match": cache.etag} if cache and cache.etag else None
        try:
            payload, response_headers = self._open_json(
                path,
                extra_headers,
            )
        except ApiTransportError as error:
            if cache:
                console.print(f"[yellow]Warning:[/] {error}; using cached module response")
                return cache.value
            raise

        if payload is None:
            if cache:
                refresh_module_cache_age(cache)
                return cache.value
            raise ApiTransportError(f"pwn.college API returned HTTP 304 for {path}")

        _validate_modules_payload(payload)
        etag = response_headers.get("ETag") if response_headers else None
        write_module_cache(dojo_id, payload, etag)
        return payload


def _path_identifier(value: Any, field: str, context: str) -> str:
    """Apply only the path-safety checks needed before joining local paths."""
    if not isinstance(value, str) or not value:
        raise ApiSchemaError(f"{context}.{field} must be a non-empty string")
    if value in {".", ".."} or any(separator in value for separator in ("/", "\\")):
        raise ApiSchemaError(f"{context}.{field} is not a safe path identifier")
    return value


def _header_text(value: Any, field: str, context: str) -> str:
    """Reject values that could inject lines into generated provenance headers."""
    if not isinstance(value, str) or not value:
        raise ApiSchemaError(f"{context}.{field} must be a non-empty string")
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise ApiSchemaError(f"{context}.{field} contains an invalid line break")
    return value


def _challenge_ids(module: JsonObject) -> set[str]:
    raw_challenges = module.list("challenges")
    ids: set[str] = set()
    for index, challenge in enumerate(raw_challenges):
        challenge_object = JsonObject(
            challenge,
            f"{module.path}.challenges[{index}]",
        )
        challenge_id = challenge_object.string("id")
        _header_text(
            challenge_object.string("name"),
            "name",
            challenge_object.path,
        )
        if challenge_id in ids:
            raise ApiSchemaError(f"{module.path} contains duplicate challenge ID {challenge_id!r}")
        ids.add(challenge_id)
    return ids


def _validate_modules_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the complete module response before using or caching it."""
    response = JsonObject(payload, "modules response")
    success = response.boolean("success")
    if not success:
        raise ApiError("modules response reported success=false")
    raw_modules = response.list("modules")

    module_ids: set[str] = set()
    for index, module in enumerate(raw_modules):
        module_object = JsonObject(module, f"modules[{index}]")
        module_id = module_object.string("id")
        _header_text(
            module_object.string("name"),
            "name",
            module_object.path,
        )
        _challenge_ids(module_object)
        if module_id in module_ids:
            raise ApiSchemaError(f"modules response contains duplicate module ID {module_id!r}")
        module_ids.add(module_id)
    return dict(response.value)


_module_cache = JsonFileCache[dict[str, Any]](
    directory=Path(tempfile.gettempdir()),
    namespace="pwncollege-modules",
    version=1,
    ttl_seconds=7 * 24 * 60 * 60,
    key_field="dojo",
    key_to_filename=lambda dojo_id: hashlib.sha256(dojo_id.encode("utf-8")).hexdigest(),
    decode=lambda response: _validate_modules_payload(response.value),
    encode=lambda payload: payload,
    label="module",
)


def module_cache_path(dojo_id: str) -> Path:
    return _module_cache.path_for(dojo_id)


def read_module_cache(dojo_id: str) -> JsonCacheEntry[dict[str, Any]] | None:
    return _module_cache.read(dojo_id)


def module_cache_is_fresh(cache: JsonCacheEntry[dict[str, Any]]) -> bool:
    return _module_cache.is_fresh(cache)


def refresh_module_cache_age(cache: JsonCacheEntry[dict[str, Any]]) -> None:
    _module_cache.touch(cache)


def write_module_cache(
    dojo_id: str,
    payload: dict[str, Any],
    etag: str | None,
) -> None:
    _module_cache.write(dojo_id, payload, etag)


def _local_challenge_id(challenge_id: str, challenge_ids: set[str]) -> str:
    """Return the exact API ID used as the local directory name.

    ``challenge_ids`` remains an argument for source compatibility with
    callers of the former paired-variant helper; it is intentionally ignored.
    """
    return challenge_id


def resolve_challenge_metadata(
    context: Mapping[str, Any], modules_payload: Mapping[str, Any]
) -> ChallengeMetadata:
    """Match IDs exactly, then derive names and an optional merged local ID."""
    context_object = JsonObject(context, "docker response")
    dojo_id = _path_identifier(context_object.string("dojo"), "dojo", context_object.path)
    module_id = _path_identifier(context_object.string("module"), "module", context_object.path)
    challenge_id = _path_identifier(
        context_object.string("challenge"), "challenge", context_object.path
    )

    response = JsonObject(
        _validate_modules_payload(modules_payload),
        "modules response",
    )
    raw_modules = response.list("modules")

    matching_modules: list[JsonObject] = []
    for index, module in enumerate(raw_modules):
        module_object = JsonObject(module, f"modules[{index}]")
        current_module_id = module_object.string("id")
        if current_module_id == module_id:
            matching_modules.append(module_object)

    if not matching_modules:
        raise ApiError(f"Module ID {module_id!r} was not found in dojo {dojo_id!r}")
    if len(matching_modules) != 1:
        raise ApiSchemaError(f"modules response contains duplicate module ID {module_id!r}")
    module = matching_modules[0]
    module_name = _header_text(module.string("name"), "name", module.path)
    matching_challenges: list[JsonObject] = []
    for index, challenge in enumerate(module.list("challenges")):
        challenge_object = JsonObject(
            challenge,
            f"{module.path}.challenges[{index}]",
        )
        if challenge_object.string("id") == challenge_id:
            matching_challenges.append(challenge_object)
    if not matching_challenges:
        raise ApiError(
            f"Challenge ID {challenge_id!r} was not found in module {module_id!r} "
            f"of dojo {dojo_id!r}"
        )
    if len(matching_challenges) != 1:
        raise ApiSchemaError(
            f"module {module_id!r} contains duplicate challenge ID {challenge_id!r}"
        )
    challenge_name = _header_text(
        matching_challenges[0].string("name"),
        "name",
        matching_challenges[0].path,
    )
    return ChallengeMetadata(
        dojo_id,
        module_id,
        # Paths use the exact API challenge ID.  In particular, do not merge
        # paired ``-0``/``-1`` challenges: each ID identifies a distinct
        # challenge and therefore gets its own directory.
        challenge_id,
        module_name,
        challenge_name,
    )


def render_solution(metadata: ChallengeMetadata, extension: str) -> str:
    """Render the required two-line provenance header followed by the template."""
    comment = "//" if extension == "c" else "#"
    header = (
        f"{comment} {metadata.module_name} - {metadata.challenge_name}\n"
        f"{comment} https://pwn.college/{metadata.dojo_id}/{metadata.module_id}/"
        f"{metadata.challenge_id}\n\n"
    )
    return header + (PYTHON_TEMPLATE if extension == "py" else "")


def create_solution_file(
    metadata: ChallengeMetadata,
    extension: str,
    repository_root: Path = REPOSITORY_ROOT,
) -> Path:
    """Create the API-ID path without overwriting an existing solution."""
    _path_identifier(metadata.dojo_id, "dojo", "challenge metadata")
    _path_identifier(metadata.module_id, "module", "challenge metadata")
    _path_identifier(metadata.challenge_id, "challenge", "challenge metadata")
    _header_text(metadata.module_name, "module name", "challenge metadata")
    _header_text(metadata.challenge_name, "challenge name", "challenge metadata")
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
        token = read_access_token()
        api = PwnCollegeApi(token)
        context = api.current_challenge()
        metadata = resolve_challenge_metadata(context, api.modules(context["dojo"]))
        flag_file = create_solution_file(metadata, args.extension)
    except ApiError as error:
        console.print(f"[bold red]Error:[/] {error}")
        return 1

    relative_file = flag_file.relative_to(REPOSITORY_ROOT).as_posix()
    console.print(f"[bold green]Challenge at:[/] {relative_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
