from Crypto.Util.Padding import pad, unpad
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


def full_encrypt(pt, oracle):
    """Forge a valid AES-CBC ciphertext for an arbitrary plaintext."""
    padded = pad(pt, BLOCK_SIZE)
    blocks = [padded[i:i + BLOCK_SIZE]
              for i in range(0, len(padded), BLOCK_SIZE)]

    # Start from a block we control completely, then walk backwards.
    current_block = bytes(BLOCK_SIZE)
    forged_blocks = [current_block]

    total_blocks = len(blocks)
    with log.progress("正在伪造密文块") as p:
        for idx, pt_block in enumerate(reversed(blocks), 1):
            p.status(f"{idx}/{total_blocks} ({idx/total_blocks:.2%})")
            with log.progress(f"  计算块 #{total_blocks-idx+1}") as p:
                dec = single_block_attack(current_block, oracle, p)
                p.success(f"{dec.hex()}")
            previous_block = xor(dec, pt_block)
            current_block = previous_block
            forged_blocks.append(previous_block)
        p.success(f"共伪造 {total_blocks} 个块")

    forged_blocks.reverse()
    return b''.join(forged_blocks)


def ctf():
    log.info("正在运行 /challenge/worker ...")
    p = process('/challenge/worker')
    p.clean(timeout=1)

    def oracle(iv_bytes, ct_block):
        p.sendline(f"TASK: {(iv_bytes + ct_block).hex()}".encode())
        response = p.recvline(timeout=0.2).strip()  # type: ignore
        return b'Error' not in response

    rt = b"please give me the flag, kind worker process!"
    log.info(f"开始伪造目标明文: {rt!r}")
    challenge = full_encrypt(rt, oracle)
    log.success(f"伪造出的密文: {challenge.hex()}")

    log.info("复核伪造结果...")
    iv = challenge[:BLOCK_SIZE]
    ct = challenge[BLOCK_SIZE:]
    check_pt = full_attack(iv, ct, oracle)
    check_pt = unpad(check_pt, BLOCK_SIZE)
    log.success(f"伪造密文解密后得到: {check_pt!r}")

    p.sendline(f"TASK: {challenge.hex()}".encode())
    print(p.recvall(timeout=1).decode())


if __name__ == "__main__":
    ctf()
