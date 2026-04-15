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


def extract_patch(frames, x, y, w, h):
    s = S_PIXEL.size
    sprite = bytearray()
    for j in range(h):
        for i in range(w):
            binary = frames[y + j][(x + i) * s: (x + i + 1) * s]
            sprite += binary
    return bytes(sprite)


def extract_rgb(frames, x, y):
    s = S_PIXEL.size
    binary = frames[y][x * s: (x + 1) * s]
    r, g, b, _ = S_PIXEL.unpack(binary)
    return r, g, b


def directive_whole_draw(pixels):
    header = struct.pack("<H", 1)
    return header + pixels


def directive_patch_draw(frames, x, y, w, h) -> bytes:
    """ 从 frame 中 (x, y) 位置提取一个 w*h 的 patch，作为绘制指令的参数 """
    header = struct.pack("<HBBBB", 2, x, y, w, h)
    pixels = extract_patch(frames, x, y, w, h)
    return header + pixels


def directive_define_sprite(frames, x, y, w, h, sprite_id) -> bytes:
    """ 将 frames 中 (x, y) 位置的 w*h 大小的 patch 定义为一个带 id 的 sprite """
    header = struct.pack("<HBBB", 3, sprite_id, w, h)
    pixels = extract_patch(frames, x, y, w, h)
    asciis = pixels[3::4]
    return header + asciis


def directive_sprite_draw(sprite_id, r, g, b, x, y) -> bytes:
    header = struct.pack("<HBBBBBB", 4, sprite_id, r, g, b, x, y)
    return header


def build_payload(raw_input: bytes) -> bytes:
    s = S_PIXEL.size
    width, height, pixels = parse_pixels(raw_input)
    frames = [
        pixels[i * width * s: (i + 1) * width * s] for i in range(height)
    ]
    directives = [
        directive_patch_draw(frames, 0, 0, 1, 1),
        directive_patch_draw(frames, 0, height-1, 1, 1),
        directive_patch_draw(frames, width-1, 0, 1, 1),
        directive_patch_draw(frames, width-1, height-1, 1, 1),

        directive_define_sprite(frames, 23, 10, 6, 5, 0),  # c
        directive_sprite_draw(0, *extract_rgb(frames, 23, 12), 23, 10),
        directive_define_sprite(frames, 30, 9, 5, 5, 1),  # I
        directive_sprite_draw(1, *extract_rgb(frames, 30, 10), 30, 9),
        directive_define_sprite(frames, 36, 9, 8, 5, 2),  # M
        directive_sprite_draw(2, *extract_rgb(frames, 36, 10), 36, 9),
        directive_define_sprite(frames, 45, 9, 7, 5, 3),  # G
        directive_sprite_draw(3, *extract_rgb(frames, 45, 11), 45, 9),

        directive_define_sprite(frames, 1, 0, 37, 1, 4),
        directive_sprite_draw(4, *extract_rgb(frames, 1, 0), 1+37*0, 0),
        directive_sprite_draw(4, *extract_rgb(frames, 1, 0), 1+37*1, 0),
        directive_sprite_draw(4, *extract_rgb(frames, 1, 0), 1+37*0, height-1),
        directive_sprite_draw(4, *extract_rgb(frames, 1, 0), 1+37*1, height-1),

        directive_define_sprite(frames, 0, 1, 1, 11, 5),
        directive_sprite_draw(5, *extract_rgb(frames, 0, 1), 0, 1+11*0),
        directive_sprite_draw(5, *extract_rgb(frames, 0, 1), 0, 1+11*1),
        directive_sprite_draw(5, *extract_rgb(frames, 0, 1), width-1, 1+11*0),
        directive_sprite_draw(5, *extract_rgb(frames, 0, 1), width-1, 1+11*1),
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

    # from pwn import process
    # io = process(["/challenge/cimg", file_path])
    # print(io.clean().decode(errors='ignore'))
    # if io.poll() is None:
    #     io.interactive()


if __name__ == "__main__":
    main()
