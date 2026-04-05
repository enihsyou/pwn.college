import re
import sys
from pwn import process, log
from Crypto.Util.strxor import strxor

def ctf():
    p = process('/challenge/run', level='debug')

    while True:
        try:
            received = p.recvuntil(b'?', timeout=1)
            c_match = re.search(rb"Encrypted String: (.+)\n", received)
            k_match = re.search(rb"XOR Key String: (.+)\n", received)

            if c_match and k_match:
                c = c_match.group(1)
                k = k_match.group(1)
                d = strxor(c, k)
                p.sendline(d)
            else:
                log.failure("Expected patterns not found in the received data.")

        except EOFError:
            final_data = p.clean(timeout=1)
            log.success(f"Final output: \n{final_data.decode(errors='ignore')}")
            break

if __name__ == "__main__":
    ctf()
