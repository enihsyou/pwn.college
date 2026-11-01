import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import dojo


class DojoArgsTests(unittest.TestCase):
    def test_ip_port_and_identity_reach_ssh_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "flag.py"
            script.touch()
            key = root / "private key"
            with patch.object(
                sys,
                "argv",
                [
                    "dojo.py",
                    "--ssh",
                    "hacker@127.0.0.1:4280",
                    "--identity",
                    str(key),
                    str(script),
                ],
            ):
                args = dojo.parse_args()
            self.assertEqual(
                args.ssh_connection,
                {"user": "hacker", "host": "127.0.0.1", "port": 4280, "keyfile": str(key)},
            )
