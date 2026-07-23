from __future__ import annotations

from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def read_defined_symbols(path: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol["st_shndx"] != "SHN_UNDEF" and symbol.name:
                    symbols[symbol.name] = int(symbol["st_value"])
    return symbols
