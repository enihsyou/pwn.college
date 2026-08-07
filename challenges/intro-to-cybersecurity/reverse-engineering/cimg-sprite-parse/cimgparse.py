#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from io import BytesIO
from typing import ClassVar


def _read_exact(stream: BytesIO, n: int, what: str) -> bytes:
    data = stream.read(n)
    if len(data) != n:
        raise ValueError(
            f"unexpected EOF while reading {what}: want {n}, got {len(data)}"
        )
    return data


@dataclass
class CIMGHeader:
    STRUCT: ClassVar = struct.Struct("<4sHBBI")

    magic: bytes
    version: int
    width: int
    height: int
    remaining_directives: int

    @classmethod
    def from_stream(cls, stream: BytesIO) -> CIMGHeader:
        magic, version, width, height, remaining = cls.STRUCT.unpack(
            _read_exact(stream, cls.STRUCT.size, "header")
        )
        header = cls(magic, version, width, height, remaining)
        header.validate()
        return header

    def validate(self) -> None:
        if self.magic != b"cIMG":
            raise ValueError(f"invalid magic: {self.magic!r}")
        if self.version != 3:
            raise ValueError(f"unsupported version: {self.version}")

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(
            self.magic, self.version, self.width, self.height, self.remaining_directives
        )


@dataclass
class Pixel:
    STRUCT: ClassVar = struct.Struct("<BBBB")
    ANSI_FMT: ClassVar = "\x1b[38;2;{r:03d};{g:03d};{b:03d}m{ch}\x1b[0m"

    r: int
    g: int
    b: int
    ascii: int

    @classmethod
    def from_stream(cls, stream: BytesIO, what: str) -> Pixel:
        r, g, b, ascii_val = cls.STRUCT.unpack(
            _read_exact(stream, cls.STRUCT.size, what)
        )
        return cls(r, g, b, ascii_val)

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.r, self.g, self.b, self.ascii)

    def to_ansi(self) -> str:
        return self.ANSI_FMT.format(r=self.r, g=self.g, b=self.b, ch=chr(self.ascii))


@dataclass
class RenderState:
    width: int
    height: int
    framebuffer: list[Pixel]
    sprites: dict[int, Directive3DefineSprite]

    @classmethod
    def blank(cls, width: int, height: int) -> RenderState:
        framebuffer = [Pixel(255, 255, 255, ord(" ")) for _ in range(width * height)]
        return cls(width=width, height=height, framebuffer=framebuffer, sprites={})

    def set_pixel(self, x: int, y: int, pixel: Pixel) -> None:
        if not (0 <= x < self.width and 0 <= y < self.height):
            raise ValueError(f"pixel out of bounds: ({x}, {y})")
        self.framebuffer[y * self.width + x] = pixel


class Directive(ABC):
    _REGISTRY: ClassVar[dict[int, type[Directive]]] = {}
    code: ClassVar[int]

    def __init_subclass__(cls, *, code: int | None = None, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if code is not None:
            cls.code = code
            Directive._REGISTRY[code] = cls

    @classmethod
    def parser_for_code(cls, code: int) -> type[Directive] | None:
        return cls._REGISTRY.get(code)

    @classmethod
    @abstractmethod
    def from_stream(cls, stream: BytesIO, header: CIMGHeader, index: int) -> Directive:
        raise NotImplementedError

    @abstractmethod
    def to_bytes(self) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def apply(self, state: RenderState, idx: int) -> None:
        raise NotImplementedError


@dataclass
class Directive1WholeDraw(Directive, code=1):
    pixels: tuple[Pixel, ...]

    @classmethod
    def from_stream(
        cls, stream: BytesIO, header: CIMGHeader, index: int
    ) -> Directive1WholeDraw:
        count = header.width * header.height
        pixels = tuple(
            Pixel.from_stream(stream, f"directive[{index}] code=1 pixel[{i}]")
            for i in range(count)
        )
        return cls(pixels=pixels)

    def to_bytes(self) -> bytes:
        return struct.pack("<H", self.code) + b"".join(
            p.to_bytes() for p in self.pixels
        )

    def apply(self, state: RenderState, idx: int) -> None:
        expected = state.width * state.height
        if len(self.pixels) != expected:
            raise ValueError(f"directive[{idx}] code=1 pixel count mismatch")
        state.framebuffer = list(self.pixels)


@dataclass
class Directive2PatchDraw(Directive, code=2):
    META_STRUCT: ClassVar = struct.Struct("<BBBB")

    x: int
    y: int
    width: int
    height: int
    pixels: tuple[Pixel, ...]

    @classmethod
    def from_stream(
        cls, stream: BytesIO, _header: CIMGHeader, index: int
    ) -> Directive2PatchDraw:
        x, y, width, height = cls.META_STRUCT.unpack(
            _read_exact(stream, cls.META_STRUCT.size, f"directive[{index}] code=2 meta")
        )
        count = width * height
        pixels = tuple(
            Pixel.from_stream(stream, f"directive[{index}] code=2 pixel[{i}]")
            for i in range(count)
        )
        return cls(x=x, y=y, width=width, height=height, pixels=pixels)

    def to_bytes(self) -> bytes:
        return (
            struct.pack("<H", self.code)
            + self.META_STRUCT.pack(self.x, self.y, self.width, self.height)
            + b"".join(p.to_bytes() for p in self.pixels)
        )

    def apply(self, state: RenderState, idx: int) -> None:
        if len(self.pixels) != self.width * self.height:
            raise ValueError(f"directive[{idx}] code=2 pixel count mismatch")
        p = 0
        for j in range(self.height):
            for i in range(self.width):
                state.set_pixel(self.x + i, self.y + j, self.pixels[p])
                p += 1


@dataclass
class Directive3DefineSprite(Directive, code=3):
    META_STRUCT: ClassVar = struct.Struct("<BBB")

    sprite_id: int
    width: int
    height: int
    ascii_data: bytes

    @classmethod
    def from_stream(
        cls, stream: BytesIO, _header: CIMGHeader, index: int
    ) -> Directive3DefineSprite:
        sprite_id, width, height = cls.META_STRUCT.unpack(
            _read_exact(stream, cls.META_STRUCT.size, f"directive[{index}] code=3 meta")
        )
        ascii_data = _read_exact(
            stream, width * height, f"directive[{index}] code=3 ascii_data"
        )
        return cls(
            sprite_id=sprite_id, width=width, height=height, ascii_data=ascii_data
        )

    def to_bytes(self) -> bytes:
        return (
            struct.pack("<H", self.code)
            + self.META_STRUCT.pack(self.sprite_id, self.width, self.height)
            + self.ascii_data
        )

    def apply(self, state: RenderState, idx: int) -> None:
        if len(self.ascii_data) != self.width * self.height:
            raise ValueError(f"directive[{idx}] code=3 ascii size mismatch")
        state.sprites[self.sprite_id] = self


@dataclass
class Directive4DrawSprite(Directive, code=4):
    META_STRUCT: ClassVar = struct.Struct("<BBBBBB")

    sprite_id: int
    r: int
    g: int
    b: int
    x: int
    y: int

    @classmethod
    def from_stream(
        cls, stream: BytesIO, _header: CIMGHeader, index: int
    ) -> Directive4DrawSprite:
        sprite_id, r, g, b, x, y = cls.META_STRUCT.unpack(
            _read_exact(stream, cls.META_STRUCT.size, f"directive[{index}] code=4 meta")
        )
        return cls(sprite_id=sprite_id, r=r, g=g, b=b, x=x, y=y)

    def to_bytes(self) -> bytes:
        return struct.pack("<H", self.code) + self.META_STRUCT.pack(
            self.sprite_id, self.r, self.g, self.b, self.x, self.y
        )

    def apply(self, state: RenderState, idx: int) -> None:
        sprite = state.sprites.get(self.sprite_id)
        if sprite is None:
            raise ValueError(
                f"directive[{idx}] code=4 unknown sprite_id={self.sprite_id}"
            )
        p = 0
        for j in range(sprite.height):
            for i in range(sprite.width):
                state.set_pixel(
                    self.x + i,
                    self.y + j,
                    Pixel(self.r, self.g, self.b, sprite.ascii_data[p]),
                )
                p += 1


@dataclass
class CIMGFile:
    DIRECTIVE_CODE_STRUCT: ClassVar = struct.Struct("<H")
    NEWLINE_ESCAPE: ClassVar = "\x1b[38;2;000;000;000m\n\x1b[0m"

    header: CIMGHeader
    directives: tuple[Directive, ...]
    trailing: bytes

    @classmethod
    def from_bytes(cls, blob: bytes) -> CIMGFile:
        stream = BytesIO(blob)
        header = CIMGHeader.from_stream(stream)
        directives: list[Directive] = []

        for i in range(header.remaining_directives):
            (code,) = cls.DIRECTIVE_CODE_STRUCT.unpack(
                _read_exact(
                    stream, cls.DIRECTIVE_CODE_STRUCT.size, f"directive[{i}] code"
                )
            )
            directive_cls = Directive.parser_for_code(code)
            if directive_cls is None:
                raise ValueError(f"unknown directive code {code} at index {i}")
            directives.append(directive_cls.from_stream(stream, header, i))

        return cls(header=header, directives=tuple(directives), trailing=stream.read())

    @classmethod
    def from_file(cls, path: str) -> CIMGFile:
        with open(path, "rb") as f:
            return cls.from_bytes(f.read())

    def to_bytes(self) -> bytes:
        normalized_header = CIMGHeader(
            magic=self.header.magic,
            version=self.header.version,
            width=self.header.width,
            height=self.header.height,
            remaining_directives=len(self.directives),
        )
        return (
            normalized_header.to_bytes()
            + b"".join(d.to_bytes() for d in self.directives)
            + self.trailing
        )

    def write_to_file(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(self.to_bytes())

    def _apply_directives(self) -> list[Pixel]:
        state = RenderState.blank(self.header.width, self.header.height)
        for idx, directive in enumerate(self.directives):
            directive.apply(state, idx)
        return state.framebuffer

    def render_terminal(self) -> str:
        framebuffer = self._apply_directives()
        rows = []
        for y in range(self.header.height):
            start = y * self.header.width
            row = "".join(
                p.to_ansi() for p in framebuffer[start : start + self.header.width]
            )
            rows.append(row + self.NEWLINE_ESCAPE)
        return "".join(rows)

    def display(self) -> None:
        sys.stdout.write(self.render_terminal())
        sys.stdout.flush()


def parse_cimg(path: str) -> CIMGFile:
    with open(path, "rb") as f:
        return CIMGFile.from_bytes(f.read())
