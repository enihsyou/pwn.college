"""Checks for VM configuration, cache reuse, and instance isolation."""

import argparse
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import StreamRequestHandler, TCPServer
from unittest.mock import patch

from scripts import vm


class VmTests(unittest.TestCase):
    def test_stop_waits_for_shutdown_after_connection_reset(self):
        state = {"uuid": "our-vm"}
        with (
            patch.object(vm, "running", side_effect=[True, ConnectionResetError(), False]),
            patch.object(vm, "qmp", side_effect=ConnectionResetError()) as qmp,
            patch.object(vm.time, "sleep"),
        ):
            vm.stop(state)
        qmp.assert_called_once_with(state, "quit")

    def test_wsl_challenge_path_uses_lf_and_replaces_previous_crlf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "id_ed25519"
            key.touch()
            key.with_name(key.name + ".pub").write_bytes(b"ssh-ed25519 instance\r\n")
            user_home = root / "home"
            (user_home / ".ssh").mkdir(parents=True)
            (user_home / ".ssh/id_ed25519.pub").write_bytes(b"ssh-ed25519 user\r\n")
            (root / "host_key.pub").write_text("ssh-ed25519 example")
            (root / "challenge-path").write_bytes(b"/mnt/r/previous\r\n")
            state = {
                "directory": str(root),
                "key": str(key),
                "challenge": str(root / "challenge"),
                "known_hosts": str(root / "known_hosts"),
                "ssh_port": 2222,
            }
            path = "/mnt/r/TEMP/pwn-college-vm/dojo/module/challenge"
            with (
                patch.object(vm.Path, "home", return_value=user_home),
                patch.object(vm, "linux_path", return_value=path),
                patch.object(vm, "wsl"),
            ):
                vm.build_filesystem(argparse.Namespace(cache=root), state)
            self.assertEqual((root / "challenge-path").read_bytes(), (path + "\n").encode())
            self.assertEqual(
                (root / "authorized_keys").read_bytes(),
                b"ssh-ed25519 instance\nssh-ed25519 user\n",
            )

    def test_scp_uses_instance_credentials_and_preserves_path_arguments(self):
        state = {"ssh_port": 4280, "key": "private key", "known_hosts": "known hosts"}
        source = Path("C:/local files/payloads")
        command = vm.scp_command(state, source, "/home/hacker/my files/", True)
        self.assertEqual(command[0], "scp")
        self.assertEqual(command[1 : 1 + len(vm.ssh_options(state))], vm.ssh_options(state))
        self.assertEqual(
            command[-5:],
            ["-P", "4280", "-r", str(source), "hacker@127.0.0.1:/home/hacker/my files/"],
        )
        self.assertNotIn("-r", vm.scp_command(state, source / "file.py", "/tmp/", False))

    def test_regular_kernel_copies_use_official_symlink_version(self):
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(
                cache=Path(directory),
                instance="software-exploitation/kernel-exploitation/level7",
                kernel=None,
                vmlinux=None,
            )
            manifest = [
                {"path": "vmlinux", "source": "/challenge/vmlinux"},
                {"path": "bzImage", "source": "/challenge/bzImage"},
            ]
            with patch.object(
                vm, "output", return_value='{"target":"../files/2/vmlinux"}'
            ) as metadata:
                vm.resolve_kernel_sources(args, manifest)
            self.assertIn("kernel-exploitation/level7/vmlinux?ref=", metadata.call_args.args[0][-1])
            kernel = args.cache / "kernels/2/bzImage"
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(b"cached kernel")
            with (
                patch.object(vm, "download", return_value=Path("vmlinux2")) as download,
                patch.object(vm, "rsync", side_effect=AssertionError("kernel rsync is forbidden")),
            ):
                self.assertEqual(vm.cached_asset(args, manifest[0]), Path("vmlinux2"))
                download.assert_called_once_with(vm.VMLINUX_URLS["2"], args.cache / "downloads")
                self.assertEqual(vm.cached_asset(args, manifest[1]), kernel)

    def test_unknown_kernel_never_falls_back_to_rsync(self):
        with (
            patch.object(vm, "rsync", side_effect=AssertionError("kernel rsync is forbidden")),
            self.assertRaisesRegex(ValueError, "never downloaded through rsync"),
        ):
            vm.cached_asset(
                argparse.Namespace(), {"path": "vmlinux", "source": "/challenge/vmlinux"}
            )

    def test_prepare_reuses_fixed_directory_without_launching(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = argparse.Namespace(cache=root / "cache", instance=None, wsl="Ubuntu")
            metadata = argparse.Namespace(
                dojo_id="dojo", module_id="module", challenge_id="challenge"
            )
            expected = root / "pwn-college-vm/dojo/module/challenge"
            with (
                patch.object(vm.api, "current_challenge_metadata", return_value=metadata),
                patch.object(vm.tempfile, "gettempdir", return_value=str(root)),
                patch.object(vm, "pull_challenge") as pull,
                patch.object(vm, "build_filesystem"),
                patch.object(vm, "launch", side_effect=AssertionError("prepare must not launch")),
            ):
                vm.prepare(args)
                (expected / "exploit.c").write_text("local work")
                vm.prepare(args)
            self.assertEqual([call.args[1] for call in pull.call_args_list], [expected, expected])
            self.assertEqual((expected / "exploit.c").read_text(), "local work")
            self.assertTrue(
                (args.cache / "instances/dojo/module/challenge/prepared.json").is_file()
            )

    def test_start_only_uses_prepared_files(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            instance = "dojo/module/challenge"
            prepared = {"instance": instance, "wsl": "Ubuntu"}
            vm.write_json(vm.instance_directory(cache, instance) / "prepared.json", prepared)
            args = argparse.Namespace(cache=cache, instance=instance, qemu="qemu")
            with (
                patch.object(
                    vm.api, "current_challenge_metadata", side_effect=AssertionError("offline")
                ),
                patch.object(vm, "build_filesystem", side_effect=AssertionError("no rebuilding")),
                patch.object(vm, "pull_challenge", side_effect=AssertionError("no downloading")),
                patch.object(
                    vm, "launch", side_effect=lambda args, state: state.update(ssh_port=2222)
                ) as launch,
            ):
                vm.start(args)
            launch.assert_called_once_with(args, {**prepared, "qemu": "qemu", "ssh_port": 2222})

    def test_wait_for_ssh_reports_current_boot_panic(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "vm.log"
            previous_boot = b"Old boot: Kernel panic - not syncing\n"
            log.write_bytes(
                previous_boot + b"New boot: Kernel panic - not syncing: No working init found\n"
            )
            state = {"log": str(log), "boot_log_offset": len(previous_boot), "ssh_port": 2222}
            with (
                patch.object(vm, "running", return_value=True),
                self.assertRaisesRegex(ValueError, "Guest kernel panic"),
            ):
                vm.wait_for_ssh(state, 10)

    def test_markers_and_explicit_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            challenge = Path(directory)
            args = argparse.Namespace(kaslr=None, panic_on_oops=None, pti=None)
            self.assertEqual(vm.boot_flags(challenge, args), ["nokaslr"])
            for marker in (".kaslr", ".panic_on_oops", ".nopti"):
                (challenge / marker).touch()
            self.assertEqual(
                vm.boot_flags(challenge, args), ["oops=panic", "panic_on_warn=1", "nopti"]
            )
            args.kaslr, args.panic_on_oops, args.pti = False, False, True
            self.assertEqual(vm.boot_flags(challenge, args), ["nokaslr"])

    def test_instance_cannot_escape_cache(self):
        for instance in (
            "../module/challenge",
            "dojo/../challenge",
            "C:/module/challenge",
            "/a/b/c",
        ):
            with self.subTest(instance=instance), self.assertRaises(ValueError):
                vm.instance_directory(Path("cache"), instance)

    def test_github_proxy_uses_complete_original_url(self):
        url = "https://raw.githubusercontent.com/owner/repo/ref/bzImage"
        self.assertEqual(vm.download_url(url), "https://gh-proxy.org/" + url)
        self.assertEqual(vm.download_url(vm.VMLINUX_URLS["2"]), vm.VMLINUX_URLS["2"])

    def test_wrong_qmp_uuid_never_sends_quit(self):
        commands = []

        class Handler(StreamRequestHandler):
            def handle(self):
                self.wfile.write(b'{"QMP": {}}\r\n')
                while line := self.rfile.readline():
                    name = json.loads(line)["execute"]
                    commands.append(name)
                    result = {"UUID": "another-vm"} if name == "query-uuid" else {}
                    self.wfile.write(json.dumps({"return": result}).encode() + b"\r\n")

        with TCPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            try:
                state = {"qmp_port": server.server_address[1], "uuid": "our-vm"}
                with self.assertRaisesRegex(ValueError, "UUID mismatch"):
                    vm.qmp(state, "quit")
                self.assertEqual(commands, ["qmp_capabilities", "query-uuid"])
            finally:
                thread.join(timeout=5)

    def test_head_name_skips_existing_file_without_get(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                requests.append("HEAD")
                self.send_response(200)
                self.send_header("Content-Disposition", "attachment; filename*=UTF-8''vmlinux2")
                self.end_headers()

            def do_GET(self):
                requests.append("GET")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"kernel")

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
                thread = threading.Thread(target=server.serve_forever)
                thread.start()
                try:
                    url = f"http://127.0.0.1:{server.server_port}/download"
                    target = vm.download(url, cache)
                    self.assertEqual(target.name, "vmlinux2")
                    self.assertEqual(target.read_bytes(), b"kernel")
                    target.write_bytes(b"existing; do not compare contents")
                    self.assertEqual(vm.download(url, cache).read_bytes(), target.read_bytes())
                    self.assertEqual(requests, ["HEAD", "GET", "HEAD"])
                finally:
                    server.shutdown()
                    thread.join()


if __name__ == "__main__":
    unittest.main()
