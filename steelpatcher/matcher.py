from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BytePattern:
    values: bytes
    masks: bytes

    @property
    def size(self) -> int:
        return len(self.values)


def parse_pattern(text: str) -> BytePattern:
    values = bytearray()
    masks = bytearray()
    for token in text.split():
        if token in {"?", "??"}:
            values.append(0)
            masks.append(0)
            continue
        if len(token) != 2:
            raise ValueError(f"invalid byte-pattern token: {token!r}")
        values.append(int(token, 16))
        masks.append(0xFF)
    if not values:
        raise ValueError("byte pattern must not be empty")
    return BytePattern(bytes(values), bytes(masks))


def matches_at(image: bytes, offset: int, pattern: BytePattern) -> bool:
    if offset < 0 or offset + pattern.size > len(image):
        return False
    return all(
        (image[offset + index] & pattern.masks[index])
        == (pattern.values[index] & pattern.masks[index])
        for index in range(pattern.size)
    )


def find_matches(image: bytes, pattern: BytePattern) -> list[int]:
    return [
        offset
        for offset in range(len(image) - pattern.size + 1)
        if matches_at(image, offset, pattern)
    ]


def resolve_pattern(image: bytes, specification: dict[str, Any]) -> int:
    pattern = parse_pattern(specification["pattern"])
    matches = find_matches(image, pattern)
    expected_count = specification.get("count", 1)
    if (
        not isinstance(expected_count, int)
        or isinstance(expected_count, bool)
        or expected_count < 1
    ):
        raise ValueError("pattern match count must be a positive integer")
    if len(matches) != expected_count:
        raise ValueError(
            f"pattern expected {expected_count} match(es), found {len(matches)}"
        )
    return matches[0]
