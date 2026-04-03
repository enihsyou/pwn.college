import re, sys
from pwn import process, PTY, log, context

p = process('/challenge/run', stdin=PTY, stdout=PTY)
c, k = 0, 0
while True:
    l = p.recvline(timeout=1)
    sys.stdout.write(l)
    if b'flag' in l:
        break
    if m := re.search(rb"Encrypted Character: (.)", l):
        c = ord(m.group(1))
        continue
    if m := re.search(rb"XOR Key: (0x..)", l):
        k = int(m.group(1), 0)
        d = c ^ k
        p.sendline(chr(d).encode())
        continue

p.stream()
