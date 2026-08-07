import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "task-init.py"
SPEC = importlib.util.spec_from_file_location("task_init", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT_PATH}")
task_init = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(task_init)


def modules_payload(*challenge_ids: str) -> dict:
    return {
        "success": True,
        "modules": [
            {
                "id": "race-conditions",
                "name": "Race Conditions",
                "challenges": [
                    {"id": challenge_id, "name": f"Challenge {challenge_id}"}
                    for challenge_id in challenge_ids
                ],
            }
        ],
    }


class FakeResponse:
    def __init__(self, payload: dict, headers: dict[str, str] | None = None) -> None:
        self.body = json.dumps(payload).encode("utf-8")
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class FakeNotModifiedResponse:
    status = 304
    headers: ClassVar[dict[str, str]] = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None


class TaskInitTests(unittest.TestCase):
    def test_json_accessor_reports_schema_path(self) -> None:
        with self.assertRaises(task_init.ApiSchemaError) as raised:
            task_init.JsonObject({"modules": []}, "modules response").string("success")
        self.assertIn("modules response.success", str(raised.exception))

    def test_exact_api_ids_resolve_names_and_confirmed_variant(self) -> None:
        metadata = task_init.resolve_challenge_metadata(
            {
                "dojo": "system-security",
                "module": "race-conditions",
                "challenge": "level-11-1",
            },
            {
                "success": True,
                "modules": [
                    {
                        "id": "race-conditions",
                        "name": "Race Conditions",
                        "challenges": [
                            {"id": "level-11-0", "name": "level11.0"},
                            {"id": "level-11-1", "name": "level11.1"},
                        ],
                    }
                ],
            },
        )

        self.assertEqual(metadata.module_name, "Race Conditions")
        self.assertEqual(metadata.challenge_name, "level11.1")
        self.assertEqual(metadata.challenge_id, "level-11-1")
        self.assertEqual(metadata.local_challenge_id, "level-11")

    def test_id_matching_does_not_use_old_normalization(self) -> None:
        with self.assertRaises(task_init.ApiError) as raised:
            task_init.resolve_challenge_metadata(
                {
                    "dojo": "system-security",
                    "module": "race-conditions",
                    "challenge": "level11-1",
                },
                modules_payload("level-11-1"),
            )
        self.assertIn("Challenge ID 'level11-1'", str(raised.exception))

    def test_create_solution_writes_provenance_header_and_template(self) -> None:
        metadata = task_init.ChallengeMetadata(
            "system-security",
            "race-conditions",
            "level-11-1",
            "Race Conditions",
            "level11.1",
            "level-11",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            flag_file = task_init.create_solution_file(
                metadata, "py", Path(temporary_directory)
            )
            self.assertEqual(
                flag_file,
                Path(temporary_directory)
                / "challenges"
                / "legacy"
                / "system-security"
                / "race-conditions"
                / "level-11"
                / "flag.py",
            )
            lines = flag_file.read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                lines[:2],
                [
                    "# Race Conditions - level11.1",
                    "# https://pwn.college/system-security/race-conditions/level-11-1",
                ],
            )
            self.assertIn("def ctf()", flag_file.read_text(encoding="utf-8"))

    def test_existing_solution_is_not_overwritten(self) -> None:
        metadata = task_init.ChallengeMetadata(
            "system-security",
            "race-conditions",
            "level-11-1",
            "Race Conditions",
            "level11.1",
            "level-11",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = (
                Path(temporary_directory)
                / "challenges"
                / "legacy"
                / "system-security"
                / "race-conditions"
                / "level-11"
            )
            target.mkdir(parents=True)
            existing = target / "flag.py"
            existing.write_text("# user content\n", encoding="utf-8")

            returned = task_init.create_solution_file(
                metadata, "py", Path(temporary_directory)
            )

            self.assertEqual(returned, existing)
            self.assertEqual(existing.read_text(encoding="utf-8"), "# user content\n")

    def test_api_uses_required_headers_and_paths(self) -> None:
        requests = []

        def fake_urlopen(request, timeout):
            requests.append((request, timeout))
            return FakeResponse(
                {
                    "success": True,
                    "dojo": "system-security",
                    "module": "race-conditions",
                    "challenge": "level-1-0",
                }
            )

        api = task_init.PwnCollegeApi("secret-token", "https://example.invalid/api")
        with patch.object(task_init, "urlopen", side_effect=fake_urlopen):
            response = api.current_challenge()

        self.assertEqual(response["module"], "race-conditions")
        request, timeout = requests[0]
        self.assertEqual(request.full_url, "https://example.invalid/api/docker")
        self.assertEqual(request.get_header("Authorization"), "Token secret-token")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(request.get_header("Accept"), "application/json")
        self.assertEqual(timeout, task_init.REQUEST_TIMEOUT_SECONDS)

    def test_open_json_accepts_case_insensitive_conditional_header_304(self) -> None:
        api = task_init.PwnCollegeApi("secret-token", "https://example.invalid/api")
        with patch.object(
            task_init,
            "urlopen",
            return_value=FakeNotModifiedResponse(),
        ):
            payload, headers = api._open_json(
                "/dojos/dojo-a/modules",
                {"if-none-match": '"etag-a"'},
            )
        self.assertIsNone(payload)
        self.assertEqual(headers, {})

    def test_fresh_module_cache_avoids_network_and_is_dojo_specific(self) -> None:
        payload = modules_payload("level-11-1")
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(
                task_init._module_cache, "directory", Path(temporary_directory)
            ),
        ):
            task_init.write_module_cache("dojo-a", payload, '"etag-a"')
            task_init.write_module_cache("dojo-b", payload, '"etag-b"')
            api = task_init.PwnCollegeApi("secret-token", "https://example.invalid/api")
            with patch.object(
                task_init,
                "urlopen",
                side_effect=AssertionError("fresh cache should avoid network"),
            ):
                self.assertEqual(api.modules("dojo-a"), payload)
            self.assertNotEqual(
                task_init.module_cache_path("dojo-a"),
                task_init.module_cache_path("dojo-b"),
            )

    def test_stale_module_cache_sends_etag_and_304_refreshes_age(self) -> None:
        payload = modules_payload("level-11-1")
        requests = []

        def fake_urlopen(request, timeout):
            requests.append((request, timeout))
            raise task_init.HTTPError(request.full_url, 304, "Not Modified", {}, None)

        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(
                task_init._module_cache, "directory", Path(temporary_directory)
            ),
        ):
            task_init.write_module_cache("dojo-a", payload, '"etag-a"')
            cache_path = task_init.module_cache_path("dojo-a")
            old_timestamp = 1
            os.utime(cache_path, (old_timestamp, old_timestamp))
            api = task_init.PwnCollegeApi("secret-token", "https://example.invalid/api")
            with patch.object(task_init, "urlopen", side_effect=fake_urlopen):
                self.assertEqual(api.modules("dojo-a"), payload)

            request, timeout = requests[0]
            self.assertEqual(request.get_header("If-none-match"), '"etag-a"')
            self.assertEqual(timeout, task_init.REQUEST_TIMEOUT_SECONDS)
            self.assertGreater(cache_path.stat().st_mtime, old_timestamp)

    def test_missing_token_is_clear_without_value(self) -> None:
        with self.assertRaises(task_init.ApiError) as raised:
            task_init.read_access_token({})
        self.assertIn("DOJO_ACCESS_TOKEN", str(raised.exception))
        self.assertNotIn("secret", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
