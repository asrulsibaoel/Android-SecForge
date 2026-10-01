"""Self-contained ELF parser for Android native libraries.

No external dependency (pyelftools is not assumed). Parses the ELF header,
section headers, the dynamic symbol table (``.dynsym``/``.dynstr``), the static
symbol table when present (``.symtab``/``.strtab``), and the dynamic section
(``DT_NEEDED``/``DT_SONAME``). Handles ELF32/ELF64, little/big endian, and
stripped binaries. Malformed input yields ``ok=False`` with a reason rather than
raising, and no function names are ever invented.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

_MAGIC = b"\x7fELF"

# e_machine values -> friendly architecture names.
_MACHINES = {
    2: "sparc",
    3: "x86",
    8: "mips",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}

_ELF_TYPES = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}

# Section types
_SHT_SYMTAB = 2
_SHT_DYNAMIC = 6
_SHT_DYNSYM = 11

# Dynamic tags
_DT_NEEDED = 1
_DT_SONAME = 14

_STB = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
_STT = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 6: "TLS", 10: "GNU_IFUNC"}
_STV = {0: "DEFAULT", 1: "INTERNAL", 2: "HIDDEN", 3: "PROTECTED"}

_SHN_UNDEF = 0


@dataclass
class ElfSymbol:
    name: str
    value: int
    size: int
    type: str
    binding: str
    visibility: str
    defined: bool
    table: str  # dynsym | symtab

    @property
    def kind(self) -> str:
        if not self.defined:
            return "imported"
        if self.binding == "LOCAL":
            return "local"
        return "exported"


@dataclass
class ParsedELF:
    ok: bool
    error: str | None = None
    elf_class: str = ""  # ELF32 | ELF64
    endianness: str = ""  # little | big
    machine: str = ""
    machine_id: int = 0
    elf_type: str = ""
    entry: int = 0
    soname: str | None = None
    needed: list[str] = field(default_factory=list)
    symbols: list[ElfSymbol] = field(default_factory=list)
    section_count: int = 0
    program_header_count: int = 0
    dynamic_symbols_available: bool = False
    static_symbols_available: bool = False

    @property
    def stripped(self) -> bool:
        return not self.static_symbols_available

    def exported(self) -> list[ElfSymbol]:
        return [s for s in self.symbols if s.kind == "exported"]

    def imported(self) -> list[ElfSymbol]:
        return [s for s in self.symbols if s.kind == "imported"]


def _err(message: str) -> ParsedELF:
    return ParsedELF(ok=False, error=message)


def parse_elf(data: bytes) -> ParsedELF:
    if len(data) < 20 or data[:4] != _MAGIC:
        return _err("not an ELF file")
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        return _err("invalid ELF class")
    if ei_data not in (1, 2):
        return _err("invalid ELF data encoding")
    is64 = ei_class == 2
    endian = "<" if ei_data == 1 else ">"

    try:
        return _parse(data, is64, endian)
    except (struct.error, IndexError, ValueError) as error:
        return _err(f"malformed ELF: {error}")


def _parse(data: bytes, is64: bool, endian: str) -> ParsedELF:
    result = ParsedELF(ok=True)
    result.elf_class = "ELF64" if is64 else "ELF32"
    result.endianness = "little" if endian == "<" else "big"

    # ELF header
    e_type, e_machine = struct.unpack_from(f"{endian}HH", data, 16)
    result.elf_type = _ELF_TYPES.get(e_type, f"0x{e_type:x}")
    result.machine_id = e_machine
    result.machine = _MACHINES.get(e_machine, f"EM_{e_machine}")

    if is64:
        # 64-bit header: e_entry@24 e_phoff@32 e_shoff@40 e_phnum@56
        #                e_shentsize@58 e_shnum@60 e_shstrndx@62
        e_entry, e_phoff, e_shoff = struct.unpack_from(f"{endian}QQQ", data, 24)
        e_phnum = struct.unpack_from(f"{endian}H", data, 56)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(f"{endian}HHH", data, 58)
    else:
        # 32-bit header: e_entry@24 e_phoff@28 e_shoff@32 e_phnum@44
        #                e_shentsize@46 e_shnum@48 e_shstrndx@50
        e_entry, e_phoff, e_shoff = struct.unpack_from(f"{endian}III", data, 24)
        e_phnum = struct.unpack_from(f"{endian}H", data, 44)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(f"{endian}HHH", data, 46)

    result.entry = e_entry
    result.program_header_count = e_phnum

    if e_shoff == 0 or e_shnum == 0:
        # No section headers; only header-level data is available.
        return result

    sections = _read_sections(data, endian, is64, e_shoff, e_shnum, e_shentsize, e_shstrndx)
    result.section_count = len(sections)
    by_name = {section["name"]: section for section in sections}

    # Dynamic section: NEEDED + SONAME.
    dynamic = next((s for s in sections if s["type"] == _SHT_DYNAMIC), None)
    dynstr = by_name.get(".dynstr")
    if dynamic is not None and dynstr is not None:
        result.needed, result.soname = _read_dynamic(data, endian, is64, dynamic, dynstr)

    # Dynamic symbols.
    dynsym = by_name.get(".dynsym") or next((s for s in sections if s["type"] == _SHT_DYNSYM), None)
    if dynsym is not None and dynstr is not None:
        result.symbols.extend(_read_symbols(data, endian, is64, dynsym, dynstr, "dynsym"))
        result.dynamic_symbols_available = True

    # Static symbols (present only in unstripped binaries).
    symtab = by_name.get(".symtab") or next((s for s in sections if s["type"] == _SHT_SYMTAB), None)
    strtab = by_name.get(".strtab")
    if symtab is not None and strtab is not None:
        result.symbols.extend(_read_symbols(data, endian, is64, symtab, strtab, "symtab"))
        result.static_symbols_available = True

    return result


def _cstr(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def _read_sections(data, endian, is64, shoff, shnum, shentsize, shstrndx):
    raw = []
    for index in range(shnum):
        base = shoff + index * shentsize
        if is64:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_align, sh_entsize = (
                struct.unpack_from(f"{endian}IIQQQQIIQQ", data, base)
            )
        else:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_align, sh_entsize = (
                struct.unpack_from(f"{endian}IIIIIIIIII", data, base)
            )
        raw.append(
            {
                "name_off": sh_name,
                "type": sh_type,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "entsize": sh_entsize,
                "name": "",
            }
        )
    # Resolve names via the section-header string table.
    if shstrndx < len(raw):
        strtab_off = raw[shstrndx]["offset"]
        for section in raw:
            section["name"] = _cstr(data, strtab_off + section["name_off"])
    return raw


def _read_dynamic(data, endian, is64, dynamic, dynstr):
    entry_size = 16 if is64 else 8
    fmt = f"{endian}qQ" if is64 else f"{endian}iI"
    needed: list[str] = []
    soname: str | None = None
    offset = dynamic["offset"]
    count = dynamic["size"] // entry_size
    dynstr_off = dynstr["offset"]
    for index in range(count):
        d_tag, d_val = struct.unpack_from(fmt, data, offset + index * entry_size)
        if d_tag == 0:  # DT_NULL terminates
            break
        if d_tag == _DT_NEEDED:
            needed.append(_cstr(data, dynstr_off + d_val))
        elif d_tag == _DT_SONAME:
            soname = _cstr(data, dynstr_off + d_val)
    return needed, soname


def _read_symbols(data, endian, is64, symtab, strtab, table):
    entry_size = 24 if is64 else 16
    strtab_off = strtab["offset"]
    symbols: list[ElfSymbol] = []
    count = symtab["size"] // entry_size if entry_size else 0
    base = symtab["offset"]
    for index in range(count):
        pos = base + index * entry_size
        if is64:
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(f"{endian}IBBHQQ", data, pos)
        else:
            st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(f"{endian}IIIBBH", data, pos)
        name = _cstr(data, strtab_off + st_name)
        if not name:
            continue
        binding = _STB.get(st_info >> 4, str(st_info >> 4))
        sym_type = _STT.get(st_info & 0xF, str(st_info & 0xF))
        visibility = _STV.get(st_other & 0x3, "DEFAULT")
        symbols.append(
            ElfSymbol(
                name=name,
                value=st_value,
                size=st_size,
                type=sym_type,
                binding=binding,
                visibility=visibility,
                defined=st_shndx != _SHN_UNDEF,
                table=table,
            )
        )
    return symbols
