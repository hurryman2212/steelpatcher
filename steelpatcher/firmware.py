from __future__ import annotations

import hashlib, struct, zlib

from dataclasses import dataclass


@dataclass(frozen=True)
class FirmwareInformation:
    sha256: str
    initial_stack_pointer: int
    reset_vector: int


def parse_hex_bytes(text: str) -> bytes:
    return bytes.fromhex(text)


def crc32_residue(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def validate_firmware(
    image: bytes,
    mcu_image_start: int,
    image_size: int,
    expected_residue: int,
) -> FirmwareInformation:
    if len(image) != image_size:
        raise ValueError(
            f"firmware size must be 0x{image_size:X} bytes, found 0x{len(image):X}"
        )
    if crc32_residue(image) != expected_residue:
        raise ValueError("firmware CRC32 residue is invalid")
    initial_stack_pointer, reset_vector = struct.unpack_from("<II", image)
    if initial_stack_pointer & 7:
        raise ValueError("initial stack pointer is not 8-byte aligned")
    reset_address = reset_vector & ~1
    if (
        reset_vector & 1 == 0
        or not mcu_image_start <= reset_address < mcu_image_start + image_size
    ):
        raise ValueError("reset vector is not a valid Thumb application address")
    return FirmwareInformation(
        hashlib.sha256(image).hexdigest(), initial_stack_pointer, reset_vector
    )


def append_crc32_residue(payload: bytes) -> bytes:
    image = payload + struct.pack("<I", (~zlib.crc32(payload)) & 0xFFFFFFFF)
    if crc32_residue(image) != 0xFFFFFFFF:
        raise ValueError("failed to construct CRC32 residue")
    return image


def encode_thumb_bw(instruction_address: int, target_address: int) -> bytes:
    offset = target_address - (instruction_address + 4)
    if offset & 1:
        raise ValueError("Thumb B.W target must be halfword aligned")
    if not -(1 << 24) <= offset < (1 << 24):
        raise ValueError("Thumb B.W target is out of range")
    encoded_offset = offset & 0x01FFFFFF
    sign = (encoded_offset >> 24) & 1
    i1 = (encoded_offset >> 23) & 1
    i2 = (encoded_offset >> 22) & 1
    immediate10 = (encoded_offset >> 12) & 0x03FF
    immediate11 = (encoded_offset >> 1) & 0x07FF
    j1 = (~(i1 ^ sign)) & 1
    j2 = (~(i2 ^ sign)) & 1
    first_halfword = 0xF000 | (sign << 10) | immediate10
    second_halfword = 0x9000 | (j1 << 13) | (j2 << 11) | immediate11
    return struct.pack("<HH", first_halfword, second_halfword)


def decode_thumb_b16(instruction_address: int, instruction: bytes) -> int:
    if len(instruction) != 2:
        raise ValueError("a Thumb B instruction must contain exactly two bytes")
    halfword = struct.unpack("<H", instruction)[0]
    if halfword & 0xF800 != 0xE000:
        raise ValueError("instruction is not an unconditional Thumb B")
    offset = (halfword & 0x07FF) << 1
    if offset & 0x0800:
        offset -= 0x1000
    return instruction_address + 4 + offset


def decode_thumb_bl(instruction_address: int, instruction: bytes) -> int:
    if len(instruction) != 4:
        raise ValueError("a Thumb BL instruction must contain exactly four bytes")
    first_halfword, second_halfword = struct.unpack("<HH", instruction)
    if first_halfword & 0xF800 != 0xF000 or second_halfword & 0xD000 != 0xD000:
        raise ValueError("instruction is not a Thumb BL")
    sign = (first_halfword >> 10) & 1
    j1 = (second_halfword >> 13) & 1
    j2 = (second_halfword >> 11) & 1
    i1 = (~(j1 ^ sign)) & 1
    i2 = (~(j2 ^ sign)) & 1
    encoded_offset = (
        (sign << 24)
        | (i1 << 23)
        | (i2 << 22)
        | ((first_halfword & 0x03FF) << 12)
        | ((second_halfword & 0x07FF) << 1)
    )
    if sign:
        encoded_offset -= 1 << 25
    return instruction_address + 4 + encoded_offset


def replace_bytes(
    image: bytearray, offset: int, expected: bytes, replacement: bytes
) -> None:
    if len(expected) != len(replacement):
        raise ValueError("replacement size differs from expected bytes")
    if offset < 0 or offset + len(expected) > len(image):
        raise ValueError(f"replacement offset 0x{offset:X} is outside the firmware")
    actual = bytes(image[offset : offset + len(expected)])
    if actual != expected:
        raise ValueError(
            f"unexpected bytes at file offset 0x{offset:X}: "
            f"expected {expected.hex()}, found {actual.hex()}"
        )
    image[offset : offset + len(replacement)] = replacement
