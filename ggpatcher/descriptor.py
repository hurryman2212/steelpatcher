from __future__ import annotations

import base64, hashlib, hmac, re, secrets, struct

from dataclasses import dataclass
from cryptography.hazmat.decrepit.ciphers.modes import CFB
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

_PCLNTAB_MAGIC = b"\xf1\xff\xff\xff\x00\x00\x01\x08"
_PASSWORD_FUNCTION = "fileencryption.DecryptDeviceFile.func1"
_CONCAT_FUNCTION = "runtime.concatbyte2"
_PASSWORD_PATTERN = re.compile(
    rb"\x48\x8d\x05(?P<first>.{4})"
    rb"\xbb(?P<size>.{4})"
    rb"\x48\x8d\x0d(?P<second>.{4})"
    rb"\x48\x89\xdf"
    rb"\xe8(?P<call>.{4})",
    re.DOTALL,
)
_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")
_ARMOR_BEGIN = "-----BEGIN DESCRIPTOR-----"
_ARMOR_END = "-----END DESCRIPTOR-----"
_AES_BLOCK_SIZE = 16
_S2K_COUNT_BYTE = 0x60


@dataclass(frozen=True)
class _Section:
    address: int
    raw_offset: int
    raw_size: int


class _PeImage:
    def __init__(self, data: bytes) -> None:
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError("SteelSeriesEngine.exe is not a PE image")
        pe_offset = _u32(data, 0x3C)
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError("SteelSeriesEngine.exe has no PE signature")
        coff = pe_offset + 4
        section_count = _u16(data, coff + 2)
        optional_size = _u16(data, coff + 16)
        optional = coff + 20
        if _u16(data, optional) != 0x20B:
            raise ValueError("SteelSeriesEngine.exe is not a PE32+ image")
        image_base = _u64(data, optional + 24)
        section_table = optional + optional_size
        sections = []
        for index in range(section_count):
            header = section_table + index * 40
            if header + 40 > len(data):
                raise ValueError("SteelSeriesEngine.exe has a truncated section table")
            sections.append(
                _Section(
                    image_base + _u32(data, header + 12),
                    _u32(data, header + 20),
                    _u32(data, header + 16),
                )
            )
        self.data = data
        self.sections = sections

    def read(self, address: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("negative PE read size")
        for section in self.sections:
            relative = address - section.address
            if 0 <= relative and relative + size <= section.raw_size:
                offset = section.raw_offset + relative
                if offset + size <= len(self.data):
                    return self.data[offset : offset + size]
        raise ValueError(f"PE address 0x{address:x} is not backed by file data")


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("truncated 16-bit value")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("truncated 32-bit value")
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise ValueError("truncated 64-bit value")
    return struct.unpack_from("<Q", data, offset)[0]


def _signed_u32(data: bytes) -> int:
    return struct.unpack("<i", data)[0]


def _c_string(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if offset < 0 or end < 0:
        raise ValueError("truncated Go function name")
    return data[offset:end].decode("utf-8")


def _go_functions(data: bytes) -> dict[str, tuple[int, int]]:
    for pclntab in _find_all(data, _PCLNTAB_MAGIC):
        try:
            function_count = _u64(data, pclntab + 8)
            text_start = _u64(data, pclntab + 24)
            names = pclntab + _u64(data, pclntab + 32)
            table = pclntab + _u64(data, pclntab + 64)
            if not 0 < function_count < 1_000_000:
                continue
            if table + function_count * 8 + 4 > len(data):
                continue
            functions = {}
            for index in range(function_count):
                entry = _u32(data, table + index * 8)
                record = table + _u32(data, table + index * 8 + 4)
                if _u32(data, record) != entry:
                    raise ValueError("inconsistent Go function table")
                name = _c_string(data, names + _u32(data, record + 4))
                next_entry = _u32(data, table + (index + 1) * 8)
                if next_entry < entry:
                    raise ValueError("unordered Go function table")
                functions[name] = (text_start + entry, next_entry - entry)
            return functions
        except (UnicodeDecodeError, ValueError):
            continue
    raise ValueError("SteelSeriesEngine.exe has no supported Go function table")


def _find_all(data: bytes, needle: bytes) -> list[int]:
    offsets = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return offsets
        offsets.append(offset)
        start = offset + 1


def _unique_function(
    functions: dict[str, tuple[int, int]], suffix: str
) -> tuple[int, int]:
    matches = [value for name, value in functions.items() if name.endswith(suffix)]
    if len(matches) != 1:
        raise ValueError(
            f"expected one Go function ending in {suffix}, found {len(matches)}"
        )
    return matches[0]


def extract_descriptor_password(engine: bytes) -> bytes:
    image = _PeImage(engine)
    functions = _go_functions(engine)
    callback_address, callback_size = _unique_function(functions, _PASSWORD_FUNCTION)
    concat_address, _ = _unique_function(functions, _CONCAT_FUNCTION)
    callback = image.read(callback_address, callback_size)
    matches = list(_PASSWORD_PATTERN.finditer(callback))
    if len(matches) != 1:
        raise ValueError("descriptor password callback has an unsupported layout")
    match = matches[0]
    instruction = callback_address + match.start()
    size = _u32(match.group("size"), 0)
    first_address = instruction + 7 + _signed_u32(match.group("first"))
    second_instruction = instruction + 12
    second_address = second_instruction + 7 + _signed_u32(match.group("second"))
    call_instruction = instruction + 22
    call_address = call_instruction + 5 + _signed_u32(match.group("call"))
    if call_address != concat_address or size != 64:
        raise ValueError("descriptor password callback failed structural validation")
    password = image.read(first_address, size) + image.read(second_address, size)
    if any(byte < 0x20 or byte >= 0x7F for byte in password):
        raise ValueError("descriptor password is not the expected printable constant")
    return password


def _crc24(data: bytes) -> bytes:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return (crc & 0xFFFFFF).to_bytes(3, "big")


def _decode_armor(data: bytes) -> bytes:
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("descriptor armor is not ASCII") from error
    if len(lines) < 5 or lines[0] != _ARMOR_BEGIN or lines[-1] != _ARMOR_END:
        raise ValueError("descriptor armor markers are invalid")
    try:
        separator = lines.index("")
    except ValueError as error:
        raise ValueError("descriptor armor has no header separator") from error
    if separator == 0 or any(":" not in line for line in lines[1:separator]):
        raise ValueError("descriptor armor headers are invalid")
    encoded = []
    checksum = None
    for line in lines[separator + 1 : -1]:
        if line.startswith("="):
            if checksum is not None:
                raise ValueError("descriptor armor has multiple checksums")
            checksum = line[1:]
        elif checksum is not None or not line:
            raise ValueError("descriptor armor payload is malformed")
        else:
            encoded.append(line)
    if checksum is None:
        raise ValueError("descriptor armor has no checksum")
    try:
        payload = base64.b64decode("".join(encoded), validate=True)
        decoded_checksum = base64.b64decode(checksum, validate=True)
    except ValueError as error:
        raise ValueError("descriptor armor contains invalid base64") from error
    if not hmac.compare_digest(decoded_checksum, _crc24(payload)):
        raise ValueError("descriptor armor checksum is invalid")
    return payload


def _encode_armor(data: bytes) -> bytes:
    encoded = base64.b64encode(data).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    checksum = base64.b64encode(_crc24(data)).decode("ascii")
    return (
        "\n".join([_ARMOR_BEGIN, "", *lines, f"={checksum}", _ARMOR_END, ""])
    ).encode("ascii")


def _packet_length(data: bytes, offset: int) -> tuple[int, int, bool]:
    if offset >= len(data):
        raise ValueError("truncated OpenPGP packet length")
    first = data[offset]
    if first < 192:
        return first, offset + 1, False
    if first < 224:
        if offset + 1 >= len(data):
            raise ValueError("truncated OpenPGP packet length")
        return ((first - 192) << 8) + data[offset + 1] + 192, offset + 2, False
    if first == 255:
        if offset + 5 > len(data):
            raise ValueError("truncated OpenPGP packet length")
        return int.from_bytes(data[offset + 1 : offset + 5], "big"), offset + 5, False
    return 1 << (first & 0x1F), offset + 1, True


def _packets(data: bytes) -> list[tuple[int, bytes]]:
    packets = []
    offset = 0
    while offset < len(data):
        header = data[offset]
        offset += 1
        if header & 0x80 == 0:
            raise ValueError("invalid OpenPGP packet header")
        if header & 0x40 == 0:
            tag = (header >> 2) & 0x0F
            length_type = header & 0x03
            length_sizes = {0: 1, 1: 2, 2: 4}
            if length_type == 3:
                packets.append((tag, data[offset:]))
                return packets
            length_size = length_sizes[length_type]
            if offset + length_size > len(data):
                raise ValueError("truncated OpenPGP packet length")
            size = int.from_bytes(data[offset : offset + length_size], "big")
            offset += length_size
            if offset + size > len(data):
                raise ValueError("truncated OpenPGP packet")
            packets.append((tag, data[offset : offset + size]))
            offset += size
            continue
        tag = header & 0x3F
        body = bytearray()
        while True:
            size, offset, partial = _packet_length(data, offset)
            if offset + size > len(data):
                raise ValueError("truncated OpenPGP packet")
            body.extend(data[offset : offset + size])
            offset += size
            if not partial:
                break
        packets.append((tag, bytes(body)))
    return packets


def _encode_length(size: int) -> bytes:
    if size < 0:
        raise ValueError("negative OpenPGP packet size")
    if size < 192:
        return bytes([size])
    if size <= 8383:
        size -= 192
        return bytes([(size >> 8) + 192, size & 0xFF])
    if size <= 0xFFFFFFFF:
        return b"\xff" + size.to_bytes(4, "big")
    raise ValueError("OpenPGP packet is too large")


def _packet(tag: int, body: bytes) -> bytes:
    if not 0 <= tag < 64:
        raise ValueError("invalid OpenPGP packet tag")
    return bytes([0xC0 | tag]) + _encode_length(len(body)) + body


def _s2k_count(encoded: int) -> int:
    return (16 + (encoded & 15)) << ((encoded >> 4) + 6)


def _derive_key(password: bytes, salt: bytes, count_byte: int, size: int) -> bytes:
    count = _s2k_count(count_byte)
    block = salt + password
    if not block or count > 64 * 1024 * 1024:
        raise ValueError("unsupported OpenPGP S2K work factor")
    count = max(count, len(block))
    result = bytearray()
    prefix_size = 0
    while len(result) < size:
        digest = hashlib.sha256(b"\0" * prefix_size)
        remaining = count
        while remaining:
            chunk = block[:remaining]
            digest.update(chunk)
            remaining -= len(chunk)
        result.extend(digest.digest())
        prefix_size += 1
    return bytes(result[:size])


def _cipher_key_size(algorithm: int) -> int:
    sizes = {7: 16, 8: 24, 9: 32}
    try:
        return sizes[algorithm]
    except KeyError as error:
        raise ValueError(f"unsupported OpenPGP cipher algorithm {algorithm}") from error


def _aes_cfb(data: bytes, key: bytes, encrypt: bool) -> bytes:
    context = Cipher(algorithms.AES(key), CFB(bytes(_AES_BLOCK_SIZE)))
    operation = context.encryptor() if encrypt else context.decryptor()
    return operation.update(data) + operation.finalize()


def _session_key(packet: bytes, password: bytes) -> tuple[int, bytes]:
    if len(packet) < 13 or packet[0] != 4 or packet[2:4] != b"\x03\x08":
        raise ValueError("unsupported OpenPGP symmetric-key packet")
    cipher = packet[1]
    key_size = _cipher_key_size(cipher)
    derived = _derive_key(password, packet[4:12], packet[12], key_size)
    encrypted = packet[13:]
    if not encrypted:
        return cipher, derived
    session = _aes_cfb(encrypted, derived, False)
    if len(session) != 1 + _cipher_key_size(session[0]):
        raise ValueError("invalid OpenPGP encrypted session key")
    return session[0], session[1:]


def _literal_data(data: bytes) -> bytes:
    packets = _packets(data)
    if len(packets) != 1 or packets[0][0] != 11:
        raise ValueError("descriptor does not contain one literal OpenPGP packet")
    literal = packets[0][1]
    if len(literal) < 6 or literal[0] not in (ord("b"), ord("t"), ord("u")):
        raise ValueError("descriptor literal OpenPGP packet is invalid")
    name_size = literal[1]
    payload = 2 + name_size + 4
    if payload > len(literal):
        raise ValueError("descriptor literal OpenPGP packet is truncated")
    return literal[payload:]


def decrypt_descriptor(data: bytes, password: bytes) -> bytes:
    packets = _packets(_decode_armor(data))
    if len(packets) != 2 or [tag for tag, _ in packets] != [3, 18]:
        raise ValueError("descriptor has an unsupported OpenPGP packet layout")
    cipher, key = _session_key(packets[0][1], password)
    encrypted = packets[1][1]
    if not encrypted or encrypted[0] != 1:
        raise ValueError("descriptor has no integrity-protected OpenPGP payload")
    if len(key) != _cipher_key_size(cipher):
        raise ValueError("descriptor OpenPGP session key has the wrong size")
    plaintext = _aes_cfb(encrypted[1:], key, False)
    if len(plaintext) < _AES_BLOCK_SIZE + 2 + 22:
        raise ValueError("descriptor OpenPGP payload is truncated")
    if plaintext[14:16] != plaintext[16:18]:
        raise ValueError("descriptor OpenPGP prefix check failed")
    if plaintext[-22:-20] != b"\xd3\x14":
        raise ValueError("descriptor OpenPGP integrity packet is missing")
    if not hmac.compare_digest(hashlib.sha1(plaintext[:-20]).digest(), plaintext[-20:]):
        raise ValueError("descriptor OpenPGP integrity check failed")
    return _literal_data(plaintext[18:-22])


def encrypt_descriptor(plaintext: bytes, password: bytes) -> bytes:
    cipher = 7
    salt = secrets.token_bytes(8)
    session_key = secrets.token_bytes(_cipher_key_size(cipher))
    derived = _derive_key(password, salt, _S2K_COUNT_BYTE, _cipher_key_size(cipher))
    encrypted_session = _aes_cfb(bytes([cipher]) + session_key, derived, True)
    symmetric_key = bytes([4, cipher, 3, 8]) + salt + bytes([_S2K_COUNT_BYTE])
    symmetric_key += encrypted_session

    literal = _packet(11, b"t\0\0\0\0\0" + plaintext)
    prefix = secrets.token_bytes(_AES_BLOCK_SIZE)
    prefix += prefix[-2:]
    integrity_header = b"\xd3\x14"
    protected = prefix + literal + integrity_header
    protected += hashlib.sha1(protected).digest()
    encrypted_data = b"\x01" + _aes_cfb(protected, session_key, True)
    descriptor = _encode_armor(_packet(3, symmetric_key) + _packet(18, encrypted_data))
    if decrypt_descriptor(descriptor, password) != plaintext:
        raise ValueError("generated descriptor failed OpenPGP round-trip verification")
    return descriptor


def _apply_scm_patch(source: bytes, patch: bytes, reverse: bool) -> bytes:
    try:
        source_text = source.decode("utf-8")
        patch_lines = patch.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("SCM source or patch is not UTF-8") from error
    if len(patch_lines) < 3 or not patch_lines[0].startswith("--- "):
        raise ValueError("SCM patch has no original file header")
    if not patch_lines[1].startswith("+++ "):
        raise ValueError("SCM patch has no patched file header")
    newline = "\r\n" if "\r\n" in source_text else "\n"
    if newline == "\r\n" and source_text.replace("\r\n", "").find("\n") >= 0:
        raise ValueError("SCM source has mixed line endings")
    trailing_newline = source_text.endswith(("\n", "\r"))
    source_lines = source_text.replace("\r\n", "\n").splitlines()
    output = []
    source_index = 0
    relocation = 0
    patch_index = 2
    hunk_count = 0
    while patch_index < len(patch_lines):
        header = _HUNK_HEADER.match(patch_lines[patch_index])
        if header is None:
            raise ValueError(f"invalid SCM patch line {patch_index + 1}")
        old_start = int(header.group(1))
        old_size = int(header.group(2) or 1)
        new_start = int(header.group(3))
        new_size = int(header.group(4) or 1)
        source_start = new_start if reverse else old_start
        source_size = new_size if reverse else old_size
        output_size = old_size if reverse else new_size
        source_markers = " +" if reverse else " -"
        output_markers = " -" if reverse else " +"
        patch_index += 1
        hunk_lines = []
        while patch_index < len(patch_lines) and not patch_lines[
            patch_index
        ].startswith("@@ "):
            line = patch_lines[patch_index]
            if not line or line[0] not in " +-":
                raise ValueError(f"invalid SCM patch line {patch_index + 1}")
            hunk_lines.append((line[0], line[1:]))
            patch_index += 1
        source_hunk = [
            content for marker, content in hunk_lines if marker in source_markers
        ]
        matches = [
            index
            for index in range(source_index, len(source_lines) - len(source_hunk) + 1)
            if source_lines[index : index + len(source_hunk)] == source_hunk
        ]
        expected = source_start - 1 + relocation
        if expected in matches:
            hunk_start = expected
        elif len(matches) == 1:
            hunk_start = matches[0]
        else:
            raise ValueError(
                "SCM patch hunk has no unambiguous exact context match; "
                f"found {len(matches)}"
            )
        relocation = hunk_start - (source_start - 1)
        output.extend(source_lines[source_index:hunk_start])
        source_index = hunk_start
        source_seen = 0
        output_seen = 0
        for marker, content in hunk_lines:
            if marker in source_markers:
                if (
                    source_index >= len(source_lines)
                    or source_lines[source_index] != content
                ):
                    raise ValueError("SCM patch context does not match the descriptor")
                source_index += 1
                source_seen += 1
            if marker in output_markers:
                output.append(content)
                output_seen += 1
        if source_seen != source_size or output_seen != output_size:
            raise ValueError("SCM patch hunk line count is inconsistent")
        hunk_count += 1
    if hunk_count == 0:
        raise ValueError("SCM patch contains no hunks")
    output.extend(source_lines[source_index:])
    result = newline.join(output)
    if trailing_newline:
        result += newline
    return result.encode("utf-8")


def apply_scm_patch(source: bytes, patch: bytes) -> bytes:
    return _apply_scm_patch(source, patch, False)


def restore_scm_patch(source: bytes, patch: bytes) -> bytes:
    return _apply_scm_patch(source, patch, True)


def scm_patch_state(source: bytes, patch: bytes) -> str:
    states = []
    try:
        patched = apply_scm_patch(source, patch)
        if restore_scm_patch(patched, patch) != source:
            raise ValueError("SCM patch failed its reverse round-trip")
        states.append("original")
    except ValueError:
        pass
    try:
        restored = restore_scm_patch(source, patch)
        if apply_scm_patch(restored, patch) != source:
            raise ValueError("SCM patch failed its forward round-trip")
        states.append("patched")
    except ValueError:
        pass
    if len(states) != 1:
        raise ValueError("descriptor has an unsupported or ambiguous SCM patch state")
    return states[0]
