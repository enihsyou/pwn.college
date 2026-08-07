import re
import sys

from pwn import PTY, process

p = process('/challenge/run', stdin=PTY, stdout=PTY)
c, k = 0, 0
while True:
    line = p.recvline(timeout=1)
    sys.stdout.write(line)
    if b'flag' in line:
        break
    if m := re.search(rb"Encrypted Character: (.)", line):
        c = ord(m.group(1))
        continue
    if m := re.search(rb"XOR Key: (0x..)", line):
        k = int(m.group(1), 0)
        d = c ^ k
        p.sendline(chr(d).encode())
        continue

p.stream()
