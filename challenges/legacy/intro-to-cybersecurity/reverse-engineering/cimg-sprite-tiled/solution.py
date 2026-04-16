#!/usr/bin/env python3
import re
from cimgparse import (
    CIMGFile,
    Directive3DefineSprite,
    Directive4DrawSprite,
    Pixel,
)


LEN_COLOR_ESC = len(b"\x1b[38;2;255;255;255m.\x1b[0m")
ESCAPED_PIXEL = re.compile(rb"\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m", re.DOTALL)


def parse_pixels(raw_input: bytes):
    w1 = raw_input.index(b".", 0)
    w2 = raw_input.index(b".", w1 + 1)
    width = (w2 - w1) // LEN_COLOR_ESC + 1
    height = len(raw_input) // (width * LEN_COLOR_ESC)

    matches = list(ESCAPED_PIXEL.finditer(raw_input))
    expected = width * height
    if len(matches) != expected:
        raise ValueError(f"parsed {len(matches)} pixels, expected {expected}")

    pixels: list[Pixel] = []
    for match in matches:
        r, g, b, char = match.groups()
        binary = Pixel(int(r), int(g), int(b), char[0])
        pixels.append(binary)

    return width, height, pixels


def extract_patch(frames: list[list[Pixel]], x, y, w, h) -> list[Pixel]:
    sprite = []
    for j in range(h):
        for i in range(w):
            pixel = frames[y + j][x + i]
            sprite.append(pixel)
    return sprite


def patch_as_sprite(patch: list[Pixel]) -> bytes:
    return bytes(p.ascii for p in patch)


def define_sprite(frames, x, y, w, h):
    return (w, h, patch_as_sprite(extract_patch(frames, x, y, w, h)))


def partial_draw(frames, x, y, w, h):
    return (x, y, w, h, tuple(extract_patch(frames, x, y, w, h)))


def extract_rgb(frames, x, y):
    pixel = extract_patch(frames, x, y, 1, 1)[0]
    return pixel.r, pixel.g, pixel.b


def recreate_cimg(raw_input: bytes) -> CIMGFile:
    width, height, pixels = parse_pixels(raw_input)
    frames = [pixels[i * width : i * width + width] for i in range(height)]
    COLOR_B = extract_rgb(frames, 0, 0)
    COLOR_C = extract_rgb(frames, 25, 10)
    COLOR_I = extract_rgb(frames, 31, 9)
    COLOR_M = extract_rgb(frames, 37, 9)
    COLOR_G = extract_rgb(frames, 47, 9)
    directives = [
        Directive3DefineSprite(0, *define_sprite(frames, 1, 0, 1, 1)),  # -
        Directive3DefineSprite(1, *define_sprite(frames, 0, 1, 1, 1)),  # |
        # c
        Directive3DefineSprite(2, *define_sprite(frames, 23, 10, 6, 4)),
        Directive4DrawSprite(2, *COLOR_C, 23, 10, 1, 1, ord(" ")),
        # I
        Directive3DefineSprite(3, *define_sprite(frames, 30, 9, 5, 5)),
        Directive4DrawSprite(3, *COLOR_I, 30, 9, 1, 1, ord(" ")),
        # M
        Directive3DefineSprite(4, *define_sprite(frames, 36, 9, 8, 5)),
        Directive4DrawSprite(4, *COLOR_M, 36, 9, 1, 1, ord(" ")),
        # G
        Directive3DefineSprite(5, *define_sprite(frames, 45, 9, 7, 5)),
        Directive4DrawSprite(5, *COLOR_G, 45, 9, 1, 1, ord(" ")),
        # corner
        Directive3DefineSprite(
            6,
            1,
            2,
            patch_as_sprite(
                [
                    Pixel(*COLOR_B, ord(".")),
                    Pixel(*COLOR_B, ord("'")),
                ]
            ),
        ),
        Directive4DrawSprite(6, *COLOR_B, 0, 0, width, 1, ord("'")),
        Directive4DrawSprite(6, *COLOR_B, 0, height - 2, width, 1, ord(".")),
        # border
        Directive4DrawSprite(0, *COLOR_B, 1, 0, width - 2, 1, ord(" ")),
        Directive4DrawSprite(0, *COLOR_B, 1, height - 1, width - 2, 1, ord(" ")),
        Directive4DrawSprite(1, *COLOR_B, 0, 1, 1, height - 2, ord(" ")),
        Directive4DrawSprite(1, *COLOR_B, width - 1, 1, 1, height - 2, ord(" ")),
    ]
    cimg = CIMGFile.new_version_4(width, height, directives=directives)
    return cimg


def main() -> None:
    desired_output = extract_string_from_elf("./cimg", "desired_output")
    cimg = recreate_cimg(desired_output)
    cimg.display()
    display_desired_output(desired_output, cimg.header.width, cimg.header.height)
    print(f"{len(cimg.to_bytes())} bytes")
    with open("output.cimg", "wb") as f:
        f.write(cimg.to_bytes())


def extract_string_from_elf(elf_path: str, symbol_name: str) -> bytes:
    from pwn import ELF

    elf = ELF(elf_path, checksec=False)
    addr = elf.symbols[symbol_name]
    data = elf.string(addr)
    return data


def display_desired_output(desired_output, width, height):
    for i in range(0, height):
        print(
            desired_output[
                i * width * LEN_COLOR_ESC : (i + 1) * width * LEN_COLOR_ESC
            ].decode()
        )


if __name__ == "__main__":
    main()
