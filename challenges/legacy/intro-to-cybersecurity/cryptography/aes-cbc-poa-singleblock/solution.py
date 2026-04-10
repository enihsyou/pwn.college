from Crypto.Util.Padding import unpad
from pwn import process, log, xor


BLOCK_SIZE = 16


def format_iv(zeroing_iv, pad_val):
    return '??' * (BLOCK_SIZE - pad_val) + bytes(zeroing_iv[-pad_val:]).hex()


def single_block_attack(block, oracle, p):
    """Returns the decryption of the given ciphertext block"""

    # zeroing_iv starts out nulled. each iteration of the main loop will add
    # one byte to it, working from right to left, until it is fully populated,
    # at which point it contains the result of DEC(ct_block)
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE + 1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if oracle(iv, block):
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv, block):
                        continue  # false positive; keep searching
                break
        else:
            raise Exception("未找到有效的填充字节")

        zeroing_iv[-pad_val] = candidate ^ pad_val
        p.status(f"DEC(ct) = {format_iv(zeroing_iv, pad_val)}")
    return bytes(zeroing_iv)


def full_attack(iv, ct, oracle):
    """Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext"""
    assert len(iv) == BLOCK_SIZE and len(ct) % BLOCK_SIZE == 0

    msg = iv + ct
    blocks = [msg[i:i + BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    result = b""

    total_blocks = len(ct) // BLOCK_SIZE
    with log.progress(f"开始恢复明文块") as p:
        iv = blocks[0]
        for idx, ct in enumerate(blocks[1:], 1):
            p.status(f"{idx}/{total_blocks} ({idx/total_blocks:.2%})")
            with log.progress(f"  恢复块 #{idx}") as p:
                dec = single_block_attack(ct, oracle, p)
                pt = xor(iv, dec)
                p.success(f"{pt}")
            iv = ct
            result += pt
        p.success(f"共恢复 {total_blocks} 个块")

    return result


def ctf():
    log.info("正在运行 /challenge/dispatcher ...")
    p = process(['/challenge/dispatcher', 'pw'])
    dispatcher_output = p.recvall().decode(errors="ignore").strip()
    p.close()

    log.success(f"dispatcher 输出: {dispatcher_output}")
    challenge = bytes.fromhex(dispatcher_output.split()[1])
    iv = challenge[:BLOCK_SIZE]
    ct = challenge[BLOCK_SIZE:]

    log.info("正在运行 /challenge/worker ...")
    p = process('/challenge/worker')
    p.clean(timeout=1)

    def oracle(iv_bytes, ct_block):
        p.sendline(f"TASK: {(iv_bytes + ct_block).hex()}".encode())
        response = p.recvline(timeout=0.2).strip()  # type: ignore
        return b'Error' not in response

    log.info("开始 Padding Oracle 攻击...")
    pt = full_attack(iv, ct, oracle)
    pt = unpad(pt, BLOCK_SIZE)
    log.success(f"恢复的明文: {pt!r}  (长度: {len(pt)} 字节)")


if __name__ == "__main__":
    ctf()
