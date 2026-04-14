import struct
import re


LEN_COLOR_ESC = 24
ESCAPED_PIXEL = re.compile(
    rb"\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m", re.DOTALL)
DEFAULT_FILE = "answer.cimg"
DEFAULT_SOURCE = "desired_output.bin"

S_PIXEL = struct.Struct("<BBBB")


def load_raw_input(source_path: str) -> bytes:
    # dump with two steps
    # objdump -t /challenge/cimg | grep desired_output
    # gdb -batch -ex "dump memory desired_output.bin 0x404020 (0x404020 + 0x6db2)" /challenge/cimg
    with open(source_path, 'rb') as f:
        return f.read()


def parse_pixels(raw_input: bytes):
    w1 = raw_input.index(b'.', 0)
    w2 = raw_input.index(b'.', w1 + 1)
    width = (w2 - w1) // LEN_COLOR_ESC + 1
    height = len(raw_input) // (width * LEN_COLOR_ESC)

    matches = list(ESCAPED_PIXEL.finditer(raw_input))
    expected = width * height
    if len(matches) != expected:
        raise ValueError(f"parsed {len(matches)} pixels, expected {expected}")

    pixels = bytearray()
    for match in matches:
        r, g, b, char = match.groups()
        binary = S_PIXEL.pack(int(r), int(g), int(b), char[0])
        pixels += binary

    return width, height, bytes(pixels)


def directive_whole_draw(pixels):
    header = struct.pack("<H", 55369)
    return header + pixels


def directive_patch_draw(frames, x, y, w, h) -> bytes:
    # 从 frame 中 (x, y) 位置提取一个 w*h 的 patch，作为绘制指令的参数。
    header = struct.pack("<HBBBB", 52965, x, y, w, h)
    pixels = bytearray()
    s = S_PIXEL.size
    for j in range(h):
        for i in range(w):
            binary = frames[y + j][(x + i) * s: (x + i + 1) * s]
            pixels += binary

    return header + pixels


def build_payload(raw_input: bytes) -> bytes:
    width, height, pixels = parse_pixels(raw_input)
    frames = [
        pixels[i * width * S_PIXEL.size: (i + 1) * width * S_PIXEL.size] for i in range(height)
    ]
    directives = [
        directive_patch_draw(frames, 24, 10, 5, 4),  # c part 1
        directive_patch_draw(frames, 23, 12, 1, 1),  # c part 2
        directive_patch_draw(frames, 30, 9, 5, 5),  # I
        directive_patch_draw(frames, 36, 9, 8, 5),  # M
        directive_patch_draw(frames, 45, 9, 7, 5),  # G
        directive_patch_draw(frames, 0, 0, width, 1),
        directive_patch_draw(frames, 0, height-1, width, 1),
        directive_patch_draw(frames, 0, 1, 1, height-2),
        directive_patch_draw(frames, width-1, 1, 1, height-2),
    ]

    header = struct.pack("<4sHBBI", b"cIMG", 3, width, height, len(directives))
    return header + b''.join(directives)


def main():
    source_path = DEFAULT_SOURCE
    file_path = DEFAULT_FILE

    raw_input = load_raw_input(source_path)
    payload = build_payload(raw_input)
    print(f"File size: {len(payload)} bytes")
    with open(file_path, 'wb') as f:
        f.write(payload)

    from pwn import process
    io = process(["/challenge/cimg", file_path])
    print(io.clean().decode(errors='ignore'))
    if io.poll() is None:
        io.interactive()


if __name__ == "__main__":
    main()
