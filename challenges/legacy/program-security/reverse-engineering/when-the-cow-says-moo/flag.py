from __future__ import annotations

import itertools
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from struct import Struct

import pwn


@dataclass(frozen=True)
class HeaderData:
    magic: bytes
    version: int
    flag: int
    file_size: int
    total_round: int


@dataclass(frozen=True)
class RoundData:
    entity_id: int
    attempts: int
    length: int
    secret_number: int


class CowGameData:
    _HEADER_STRUCT = Struct("<4sHHII")
    _ROUND_STRUCT = Struct("<IHHQ")

    def __init__(self, file_path: str | Path):
        raw_data = Path(file_path).read_bytes()

        self.header = self._parse_header(raw_data)
        self.rounds = self._parse_rounds(raw_data)
        self._rounds_by_entity_id = {round_data.entity_id: round_data for round_data in self.rounds}

    def require_round(self, entity_id: int) -> RoundData:
        round_data = self._rounds_by_entity_id.get(entity_id)
        if round_data is None:
            raise KeyError(f"entity_id not found: {entity_id:#x}")
        return round_data

    def _parse_header(self, raw_data: bytes) -> HeaderData:
        if len(raw_data) < self._HEADER_STRUCT.size:
            raise ValueError("file is too small to contain a complete header")

        magic, version, flag, file_size, total_round = self._HEADER_STRUCT.unpack_from(raw_data)
        if magic != b"CBGF":
            raise ValueError(f"invalid magic: {magic!r}")
        if file_size != len(raw_data) - self._HEADER_STRUCT.size:
            raise ValueError(
                "data size mismatch: "
                f"header={file_size}, actual={len(raw_data) - self._HEADER_STRUCT.size}"
            )

        return HeaderData(
            magic=magic,
            version=version,
            flag=flag,
            file_size=file_size,
            total_round=total_round,
        )

    def _parse_rounds(self, raw_data: bytes) -> list[RoundData]:
        rounds_offset = self._HEADER_STRUCT.size
        expected_data_size = self.header.total_round * self._ROUND_STRUCT.size
        if expected_data_size != self.header.file_size:
            raise ValueError(
                "round count mismatch: "
                f"rounds={self.header.total_round}, data_size={self.header.file_size}"
            )

        expected_size = rounds_offset + expected_data_size
        if expected_size != len(raw_data):
            raise ValueError(
                f"round data size mismatch: expected={expected_size}, actual={len(raw_data)}"
            )

        return [
            self._parse_round(raw_data, offset)
            for offset in range(rounds_offset, expected_size, self._ROUND_STRUCT.size)
        ]

    def _parse_round(self, raw_data: bytes, offset: int) -> RoundData:
        entity_id, attempts, length, secret_number = self._ROUND_STRUCT.unpack_from(
            raw_data, offset
        )
        return RoundData(
            entity_id=entity_id,
            attempts=attempts,
            length=length,
            secret_number=secret_number,
        )


def choose_wrong_guess(answer: str) -> str:
    available_digits = "1234567890"
    for digits in itertools.permutations(available_digits, len(answer)):
        guess = "".join(digits)
        if guess[0] != "0" and guess != answer:
            return guess
    raise ValueError(f"could not build a wrong guess for answer {answer!r}")


def format_secret_number(secret_number: int, length: int) -> str:
    return f"{secret_number:0{length}d}"


def parse_entity_id(output: bytes) -> int:
    match = re.search(rb"Entry ID (\d+)", output)
    if not match:
        raise ValueError(f"could not find entity id in output: {output!r}")
    return int(match.group(1))


def solve_round(io: pwn.tube, game_data: CowGameData):
    intro = io.recvuntil(b"digits each).\n")
    entity_id = parse_entity_id(intro)
    round_data = game_data.require_round(entity_id)
    answer = format_secret_number(round_data.secret_number, round_data.length)
    wrong_guess = choose_wrong_guess(answer)

    for _ in range(round_data.attempts - 1):
        io.sendline(wrong_guess.encode())
    io.sendline(answer.encode())


def main():
    game_data = CowGameData("/challenge/gamefile.bin")
    with pwn.process("/challenge/when-the-cow-says-moo") as io:
        tee(io)
        solve_round(io, game_data)
        io.recvrepeat()


def tee[T: pwn.tube](process: T) -> T:
    orig_recv_raw = process.recv_raw
    output = sys.__stdout__.buffer  # type: ignore sys.stdout is replaced by pwn.term

    def recv_raw(numb, *args, **kwargs):
        data = orig_recv_raw(numb, *args, **kwargs) or b""  # orig may return str('')
        output.write(data)
        output.flush()
        return data

    process.recv_raw = recv_raw
    return process


if __name__ == "__main__":
    main()
