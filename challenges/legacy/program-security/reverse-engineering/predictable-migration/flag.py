from __future__ import annotations

import itertools
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from struct import Struct

import pwn


@dataclass(frozen=True)
class AttemptRequirement:
    cows: int
    bulls: int


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
    requirements: tuple[AttemptRequirement, ...] = ()


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
        data_size = len(raw_data) - self._HEADER_STRUCT.size
        if file_size != data_size:
            raise ValueError(f"data size mismatch: header={file_size}, actual={data_size}")

        return HeaderData(
            magic=magic,
            version=version,
            flag=flag,
            file_size=file_size,
            total_round=total_round,
        )

    def _parse_rounds(self, raw_data: bytes) -> list[RoundData]:
        if self.header.version == 1:
            return self._parse_rounds_v1(raw_data)
        if self.header.version == 2:
            return self._parse_rounds_v2(raw_data)
        raise ValueError(f"unsupported gamefile version: {self.header.version}")

    def _parse_rounds_v1(self, raw_data: bytes) -> list[RoundData]:
        data_offset = self._HEADER_STRUCT.size
        expected_data_size = self.header.total_round * self._ROUND_STRUCT.size
        if expected_data_size != self.header.file_size:
            raise ValueError(
                "round count mismatch: "
                f"rounds={self.header.total_round}, data_size={self.header.file_size}"
            )

        expected_size = data_offset + expected_data_size
        if expected_size != len(raw_data):
            raise ValueError(
                f"round data size mismatch: expected={expected_size}, actual={len(raw_data)}"
            )

        return [
            self._parse_round(raw_data, offset)
            for offset in range(data_offset, expected_size, self._ROUND_STRUCT.size)
        ]

    def _parse_rounds_v2(self, raw_data: bytes) -> list[RoundData]:
        offset = self._HEADER_STRUCT.size
        end_offset = offset + self.header.file_size
        rounds = []

        for _ in range(self.header.total_round):
            round_data = self._parse_round(raw_data, offset)
            offset += self._ROUND_STRUCT.size

            requirements = self._parse_requirements(raw_data, offset, round_data.attempts)
            offset += len(requirements) * 6
            rounds.append(
                RoundData(
                    entity_id=round_data.entity_id,
                    attempts=round_data.attempts,
                    length=round_data.length,
                    secret_number=round_data.secret_number,
                    requirements=requirements,
                )
            )

        if offset != end_offset:
            raise ValueError(
                f"v2 data size mismatch: expected end={end_offset}, actual end={offset}"
            )
        return rounds

    def _parse_requirements(
        self, raw_data: bytes, offset: int, attempts: int
    ) -> tuple[AttemptRequirement, ...]:
        result = []
        for attempt_index in range(attempts):
            requirement_offset = offset + attempt_index * 6
            requirement = raw_data[requirement_offset : requirement_offset + 6]
            result.append(self._parse_requirement(requirement))
        return tuple(result)

    @staticmethod
    def _parse_requirement(raw_requirement: bytes) -> AttemptRequirement:
        match = re.fullmatch(rb"(\d{2})C(\d{2})B", raw_requirement)
        if not match:
            raise ValueError(f"invalid v2 attempt requirement: {raw_requirement!r}")
        return AttemptRequirement(
            cows=int(match.group(1)),
            bulls=int(match.group(2)),
        )

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


def choose_matching_guess(answer: str, requirement: AttemptRequirement) -> str:
    for guess in iter_valid_guesses(len(answer)):
        if score_guess(answer, guess) == requirement:
            return guess
    raise ValueError(f"could not satisfy requirement {requirement} for answer {answer!r}")


def iter_valid_guesses(length: int):
    for digits in itertools.permutations("1234567890", length):
        if digits[0] != "0":
            yield "".join(digits)


def format_secret_number(secret_number: int, length: int) -> str:
    return f"{secret_number:0{length}d}"


def score_guess(answer: str, guess: str) -> AttemptRequirement:
    bulls = sum(answer_digit == guess_digit for answer_digit, guess_digit in zip(answer, guess))
    matching_digits = sum(
        min(answer.count(str(digit)), guess.count(str(digit))) for digit in range(10)
    )
    return AttemptRequirement(cows=matching_digits - bulls, bulls=bulls)


def parse_entity_id(output: bytes) -> int:
    match = re.search(rb"Entry ID (\d+)", output)
    if not match:
        raise ValueError(f"could not find entity id in output: {output!r}")
    return int(match.group(1))


def solve_round(io: pwn.tube, game_data: CowGameData):
    intro = io.recvuntil(b"digits each).\n")
    entity_id = parse_entity_id(intro)
    round_data = game_data.require_round(entity_id)

    if game_data.header.version == 1:
        solve_round_v1(io, round_data)
        return
    if game_data.header.version == 2:
        solve_round_v2(io, round_data)
        return
    raise ValueError(f"unsupported gamefile version: {game_data.header.version}")


def solve_round_v1(io: pwn.tube, round_data: RoundData):
    answer = format_secret_number(round_data.secret_number, round_data.length)
    wrong_guess = choose_wrong_guess(answer)

    for _ in range(round_data.attempts - 1):
        io.sendline(wrong_guess.encode())
    io.sendline(answer.encode())


def solve_round_v2(io: pwn.tube, round_data: RoundData):
    answer = format_secret_number(round_data.secret_number, round_data.length)
    for requirement in round_data.requirements:
        guess = choose_matching_guess(answer, requirement)
        io.sendline(guess.encode())


def main():
    game_data = CowGameData("/challenge/gamefile.bin")
    with pwn.process("/challenge/predictable-migration") as io:
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
