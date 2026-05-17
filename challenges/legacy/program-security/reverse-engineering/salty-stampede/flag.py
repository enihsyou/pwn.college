from __future__ import annotations

import hashlib
import itertools
import re
import sys
from abc import ABC, abstractmethod
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
    salt: bytes = b""
    requirements: tuple[AttemptRequirement, ...] = ()
    requirement_hashes: tuple[bytes, ...] = ()


class GameVersion(ABC):
    @abstractmethod
    def parse_rounds(self, game_data: CowGameData, raw_data: bytes) -> list[RoundData]:
        raise NotImplementedError

    @abstractmethod
    def solve_round(self, io: pwn.tube, round_data: RoundData):
        raise NotImplementedError

    def format_secret_number(self, round_data: RoundData) -> str:
        return f"{round_data.secret_number:0{round_data.length}d}"

    def iter_valid_guesses(self, length: int):
        for digits in itertools.permutations("1234567890", length):
            if digits[0] != "0":
                yield "".join(digits)

    def score_guess(self, answer: str, guess: str) -> AttemptRequirement:
        bulls = sum(answer_digit == guess_digit for answer_digit, guess_digit in zip(answer, guess))
        matching_digits = sum(
            min(answer.count(str(digit)), guess.count(str(digit))) for digit in range(10)
        )
        return AttemptRequirement(cows=matching_digits - bulls, bulls=bulls)


class GameVersion1(GameVersion):
    def parse_rounds(self, game_data: CowGameData, raw_data: bytes) -> list[RoundData]:
        data_offset = game_data.header_size
        round_size = game_data.round_size
        expected_data_size = game_data.header.total_round * round_size
        if expected_data_size != game_data.header.file_size:
            raise ValueError(
                "round count mismatch: "
                f"rounds={game_data.header.total_round}, "
                f"data_size={game_data.header.file_size}"
            )

        expected_size = data_offset + expected_data_size
        if expected_size != len(raw_data):
            raise ValueError(
                f"round data size mismatch: expected={expected_size}, actual={len(raw_data)}"
            )

        return [
            game_data.parse_round(raw_data, offset)
            for offset in range(data_offset, expected_size, round_size)
        ]

    def solve_round(self, io: pwn.tube, round_data: RoundData):
        answer = self.format_secret_number(round_data)
        wrong_guess = self._choose_wrong_guess(answer)

        for _ in range(round_data.attempts - 1):
            io.sendline(wrong_guess.encode())
        io.sendline(answer.encode())

    def _choose_wrong_guess(self, answer: str) -> str:
        for guess in self.iter_valid_guesses(len(answer)):
            if guess != answer:
                return guess
        raise ValueError(f"could not build a wrong guess for answer {answer!r}")


class VariableRoundGameVersion(GameVersion):
    def parse_rounds(self, game_data: CowGameData, raw_data: bytes) -> list[RoundData]:
        return self.parse_variable_rounds(game_data, raw_data, self.parse_round)

    @abstractmethod
    def parse_round(
        self, game_data: CowGameData, raw_data: bytes, offset: int
    ) -> tuple[RoundData, int]:
        raise NotImplementedError

    def parse_variable_rounds(self, game_data: CowGameData, raw_data: bytes, parser):
        offset = game_data.header_size
        end_offset = offset + game_data.header.file_size
        rounds = []

        for _ in range(game_data.header.total_round):
            round_data, offset = parser(game_data, raw_data, offset)
            rounds.append(round_data)

        if offset != end_offset:
            raise ValueError(f"data size mismatch: expected end={end_offset}, actual end={offset}")
        return rounds


class GameVersion2(VariableRoundGameVersion):
    _REQUIREMENT_SIZE = 6

    def solve_round(self, io: pwn.tube, round_data: RoundData):
        answer = self.format_secret_number(round_data)
        for requirement in round_data.requirements:
            guess = self._choose_matching_guess(answer, requirement)
            io.sendline(guess.encode())

    def parse_round(
        self, game_data: CowGameData, raw_data: bytes, offset: int
    ) -> tuple[RoundData, int]:
        round_data = game_data.parse_round(raw_data, offset)
        offset += game_data.round_size
        requirements = self._parse_requirements(raw_data, offset, round_data.attempts)
        offset += len(requirements) * self._REQUIREMENT_SIZE

        return (
            RoundData(
                entity_id=round_data.entity_id,
                attempts=round_data.attempts,
                length=round_data.length,
                secret_number=round_data.secret_number,
                requirements=requirements,
            ),
            offset,
        )

    def _parse_requirements(
        self, raw_data: bytes, offset: int, attempts: int
    ) -> tuple[AttemptRequirement, ...]:
        return tuple(
            self._parse_requirement(
                raw_data[
                    offset + attempt_index * self._REQUIREMENT_SIZE : offset
                    + (attempt_index + 1) * self._REQUIREMENT_SIZE
                ]
            )
            for attempt_index in range(attempts)
        )

    def _parse_requirement(self, raw_requirement: bytes) -> AttemptRequirement:
        match = re.fullmatch(rb"(\d{2})C(\d{2})B", raw_requirement)
        if not match:
            raise ValueError(f"invalid v2 attempt requirement: {raw_requirement!r}")
        return AttemptRequirement(cows=int(match.group(1)), bulls=int(match.group(2)))

    def _choose_matching_guess(self, answer: str, requirement: AttemptRequirement) -> str:
        for guess in self.iter_valid_guesses(len(answer)):
            if self.score_guess(answer, guess) == requirement:
                return guess
        raise ValueError(f"could not satisfy requirement {requirement} for {answer!r}")


class HashedRequirementGameVersion(VariableRoundGameVersion):
    _REQUIREMENT_SIZE = hashlib.sha256().digest_size

    def parse_requirement_hashes(
        self, raw_data: bytes, offset: int, attempts: int
    ) -> tuple[bytes, ...]:
        return tuple(
            raw_data[
                offset + attempt_index * self._REQUIREMENT_SIZE : offset
                + (attempt_index + 1) * self._REQUIREMENT_SIZE
            ]
            for attempt_index in range(attempts)
        )


class GameVersion3(HashedRequirementGameVersion):
    def solve_round(self, io: pwn.tube, round_data: RoundData):
        answer = self.format_secret_number(round_data)
        for requirement_hash in round_data.requirement_hashes:
            guess = self._choose_matching_hash(answer, requirement_hash)
            io.sendline(guess.encode())

    def parse_round(
        self, game_data: CowGameData, raw_data: bytes, offset: int
    ) -> tuple[RoundData, int]:
        round_data = game_data.parse_round(raw_data, offset)
        offset += game_data.round_size
        requirement_hashes = self.parse_requirement_hashes(raw_data, offset, round_data.attempts)
        offset += len(requirement_hashes) * self._REQUIREMENT_SIZE

        return (
            RoundData(
                entity_id=round_data.entity_id,
                attempts=round_data.attempts,
                length=round_data.length,
                secret_number=round_data.secret_number,
                requirement_hashes=requirement_hashes,
            ),
            offset,
        )

    def _choose_matching_hash(self, answer: str, requirement_hash: bytes) -> str:
        for guess in self.iter_valid_guesses(len(answer)):
            requirement = self.score_guess(answer, guess)
            if self._hash_requirement(requirement) == requirement_hash:
                return guess
        raise ValueError(f"could not satisfy hash {requirement_hash.hex()}")

    def _hash_requirement(self, requirement: AttemptRequirement) -> bytes:
        payload = f"{requirement.cows:02d}C{requirement.bulls:02d}B".encode()
        return hashlib.sha256(payload).digest()


class GameVersion4(HashedRequirementGameVersion):
    _ROUND_STRUCT = Struct("<IHH16sQ")
    _ORDER_STRUCT = Struct("<H")

    def solve_round(self, io: pwn.tube, round_data: RoundData):
        answer = self.format_secret_number(round_data)
        for requirement_hash in round_data.requirement_hashes:
            guess = self._choose_matching_salted_hash(answer, round_data, requirement_hash)
            io.sendline(guess.encode())

    def parse_round(
        self, game_data: CowGameData, raw_data: bytes, offset: int
    ) -> tuple[RoundData, int]:
        round_data = self._parse_salted_round(raw_data, offset)
        offset += self._ROUND_STRUCT.size
        offset += round_data.attempts * self._ORDER_STRUCT.size
        requirement_hashes = self.parse_requirement_hashes(raw_data, offset, round_data.attempts)
        offset += len(requirement_hashes) * self._REQUIREMENT_SIZE

        return (
            RoundData(
                entity_id=round_data.entity_id,
                attempts=round_data.attempts,
                length=round_data.length,
                secret_number=round_data.secret_number,
                salt=round_data.salt,
                requirement_hashes=requirement_hashes,
            ),
            offset,
        )

    def _parse_salted_round(self, raw_data: bytes, offset: int) -> RoundData:
        entity_id, attempts, length, salt, secret_number = self._ROUND_STRUCT.unpack_from(
            raw_data, offset
        )
        return RoundData(
            entity_id=entity_id,
            attempts=attempts,
            length=length,
            secret_number=secret_number,
            salt=salt,
        )

    def _choose_matching_salted_hash(
        self, answer: str, round_data: RoundData, requirement_hash: bytes
    ) -> str:
        for guess in self.iter_valid_guesses(len(answer)):
            requirement = self.score_guess(answer, guess)
            if self._hash_salted_requirement(round_data.salt, requirement) == requirement_hash:
                return guess
        raise ValueError(f"could not satisfy salted hash {requirement_hash.hex()}")

    def _hash_salted_requirement(self, salt: bytes, requirement: AttemptRequirement) -> bytes:
        payload = f"{requirement.cows:02d}C{requirement.bulls:02d}B".encode()
        return hashlib.sha256(salt + payload).digest()


class CowGameData:
    _HEADER_STRUCT = Struct("<4sHHII")
    _ROUND_STRUCT = Struct("<IHHQ")
    _VERSIONS = {
        1: GameVersion1,
        2: GameVersion2,
        3: GameVersion3,
        4: GameVersion4,
    }

    def __init__(self, file_path: str | Path):
        raw_data = Path(file_path).read_bytes()

        self.header = self._parse_header(raw_data)
        self.version = self._load_version(self.header.version)
        self.rounds = self.version.parse_rounds(self, raw_data)
        self._rounds_by_entity_id = {round_data.entity_id: round_data for round_data in self.rounds}

    @property
    def header_size(self) -> int:
        return self._HEADER_STRUCT.size

    @property
    def round_size(self) -> int:
        return self._ROUND_STRUCT.size

    def require_round(self, entity_id: int) -> RoundData:
        round_data = self._rounds_by_entity_id.get(entity_id)
        if round_data is None:
            raise KeyError(f"entity_id not found: {entity_id:#x}")
        return round_data

    def solve_round(self, io: pwn.tube):
        intro = io.recvuntil(b"digits each).\n")
        entity_id = self._parse_entity_id(intro)
        self.version.solve_round(io, self.require_round(entity_id))

    def parse_round(self, raw_data: bytes, offset: int) -> RoundData:
        entity_id, attempts, length, secret_number = self._ROUND_STRUCT.unpack_from(
            raw_data, offset
        )
        return RoundData(
            entity_id=entity_id,
            attempts=attempts,
            length=length,
            secret_number=secret_number,
        )

    def _parse_header(self, raw_data: bytes) -> HeaderData:
        if len(raw_data) < self.header_size:
            raise ValueError("file is too small to contain a complete header")

        magic, version, flag, file_size, total_round = self._HEADER_STRUCT.unpack_from(raw_data)
        if magic != b"CBGF":
            raise ValueError(f"invalid magic: {magic!r}")

        data_size = len(raw_data) - self.header_size
        if file_size != data_size:
            raise ValueError(f"data size mismatch: header={file_size}, actual={data_size}")

        return HeaderData(
            magic=magic,
            version=version,
            flag=flag,
            file_size=file_size,
            total_round=total_round,
        )

    def _load_version(self, version: int) -> GameVersion:
        version_class = self._VERSIONS.get(version)
        if version_class is None:
            raise ValueError(f"unsupported gamefile version: {version}")
        return version_class()

    def _parse_entity_id(self, output: bytes) -> int:
        match = re.search(rb"Entry ID (\d+)", output)
        if not match:
            raise ValueError(f"could not find entity id in output: {output!r}")
        return int(match.group(1))


def main():
    game_data = CowGameData("/challenge/gamefile.bin")
    with pwn.process("/challenge/salty-stampede") as io:
        tee(io)
        game_data.solve_round(io)
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
