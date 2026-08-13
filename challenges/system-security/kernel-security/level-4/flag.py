# Level 4
import fcntl
import os

fd = os.open("/proc/pwncollege", os.O_RDWR)
try:
    arg = bytearray(b"srungttywgwxmrht\x00")
    ret = fcntl.ioctl(fd, 1337, arg, True)
    print("ioctl return:", ret)
    print("buffer:", arg)
finally:
    os.close(fd)

with open("/flag", encoding="utf-8") as f:
    print(f.read())
