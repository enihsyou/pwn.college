import importlib.util
import tempfile
import unittest
from pathlib import Path, PurePosixPath

SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "task-init.py"
SPEC = importlib.util.spec_from_file_location("task_init", SCRIPT_PATH)
assert SPEC and SPEC.loader
task_init = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(task_init)


class InitializeSolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.repository_root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def initialize(
        self,
        hostname: str,
        executable_name: str | None,
        directories: list[PurePosixPath],
        extension: str = "py",
    ) -> Path:
        return task_init.initialize_solution(
            hostname,
            executable_name,
            extension,
            directories,
            self.repository_root,
        )

    def test_hostname_match_creates_python_solution(self) -> None:
        directories = [
            PurePosixPath(
                "challenges/legacy/system-security/race-conditions/level-11-0"
            ),
            PurePosixPath(
                "challenges/legacy/system-security/race-conditions/level-11-1"
            ),
        ]

        flag_file = self.initialize(
            "race-conditions~level11-1",
            None,
            directories,
        )

        expected = self.repository_root / (
            "challenges/legacy/system-security/race-conditions/level-11/flag.py"
        )
        self.assertEqual(flag_file, expected)
        self.assertIn("def ctf()", flag_file.read_text(encoding="utf-8"))

    def test_executable_name_is_fallback_when_hostname_name_does_not_match(self) -> None:
        directories = [
            PurePosixPath(
                "challenges/legacy/system-security/"
                "speculative-execution/babyarch_memflag"
            )
        ]

        flag_file = self.initialize(
            "speculative-execution~shared-memory-1",
            "babyarch_memflag",
            directories,
            "sh",
        )

        expected = self.repository_root / (
            "challenges/legacy/system-security/speculative-execution/"
            "babyarch_memflag/flag.sh"
        )
        self.assertEqual(flag_file, expected)
        self.assertEqual(flag_file.read_text(encoding="utf-8"), "# Babyarch_Memflag\n")

    def test_hostname_match_takes_priority_over_executable_name(self) -> None:
        directories = [
            PurePosixPath("challenges/example/module/direct-name"),
            PurePosixPath("challenges/example/module/fallback-name"),
        ]

        flag_file = self.initialize(
            "module~direct-name",
            "fallback-name",
            directories,
        )

        self.assertIn("direct-name", flag_file.parts)
        self.assertNotIn("fallback-name", flag_file.parts)


if __name__ == "__main__":
    unittest.main()
