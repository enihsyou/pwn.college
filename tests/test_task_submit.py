import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import task_submit


class TaskSubmitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.metadata = task_submit.task_init.ChallengeMetadata(
            "system-security",
            "race-conditions",
            "level-11-1",
            "Race Conditions",
            "level11.1",
        )

    def test_solution_path_matches_task_init_layout(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(
                task_submit.task_init,
                "REPOSITORY_ROOT",
                Path(temporary_directory),
            ),
        ):
            script = (
                Path(temporary_directory)
                / "challenges"
                / "system-security"
                / "race-conditions"
                / "level-11-1"
                / "flag.py"
            )
            script.parent.mkdir(parents=True)
            script.write_text("", encoding="utf-8")
            self.assertEqual(
                task_submit.solution_path(self.metadata),
                script,
            )

    def test_solution_path_supports_shell_script(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(
                task_submit.task_init,
                "REPOSITORY_ROOT",
                Path(temporary_directory),
            ),
        ):
            script = (
                Path(temporary_directory)
                / "challenges"
                / "system-security"
                / "race-conditions"
                / "level-11-1"
                / "flag.sh"
            )
            script.parent.mkdir(parents=True)
            script.write_text("", encoding="utf-8")
            self.assertEqual(task_submit.solution_path(self.metadata), script)

    def test_main_runs_existing_solution_with_uv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory)
            script = (
                repository_root
                / "challenges"
                / "system-security"
                / "race-conditions"
                / "level-11-1"
                / "flag.py"
            )
            script.parent.mkdir(parents=True)
            script.write_text("print('submitted')\n", encoding="utf-8")
            with (
                patch.object(task_submit.task_init, "REPOSITORY_ROOT", repository_root),
                patch.object(
                    task_submit.task_init,
                    "current_challenge_metadata",
                    return_value=self.metadata,
                ),
                patch.object(
                    task_submit.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0),
                ) as run,
            ):
                self.assertEqual(task_submit.main([]), 0)

            run.assert_called_once_with(
                [
                    "uv",
                    "run",
                    "dojo.py",
                    "challenges/system-security/race-conditions/level-11-1/flag.py",
                ],
                cwd=repository_root,
                check=False,
            )

    def test_main_forwards_extra_args_before_script(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_root = Path(temporary_directory)
            script = (
                repository_root
                / "challenges"
                / "system-security"
                / "race-conditions"
                / "level-11-1"
                / "flag.py"
            )
            script.parent.mkdir(parents=True)
            script.write_text("print('submitted')\n", encoding="utf-8")
            with (
                patch.object(task_submit.task_init, "REPOSITORY_ROOT", repository_root),
                patch.object(
                    task_submit.task_init,
                    "current_challenge_metadata",
                    return_value=self.metadata,
                ),
                patch.object(
                    task_submit.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0),
                ) as run,
            ):
                self.assertEqual(task_submit.main(["-r", "-d", "/tmp/alt"]), 0)

            run.assert_called_once_with(
                [
                    "uv",
                    "run",
                    "dojo.py",
                    "-r",
                    "-d",
                    "/tmp/alt",
                    "challenges/system-security/race-conditions/level-11-1/flag.py",
                ],
                cwd=repository_root,
                check=False,
            )
