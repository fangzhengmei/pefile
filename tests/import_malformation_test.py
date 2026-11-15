"""Import-table tests separating trustworthy evidence from malformed input.

The embedded :mod:`export_test` images are real PE32 / PE32+ DLLs without an
import directory.  Each test grows the ``.rdata`` section and writes a
hand-crafted import directory on top of it, which makes it possible to place a
descriptor, a thunk table or a terminator exactly on the last byte of the file.

Every assertion pairs the *warning* pefile emitted with the *import objects* it
exposed, so a future change cannot silently turn a damaged structure into a
trustworthy feature.
"""

import struct
import unittest
from hashlib import md5

from export_test import PE_32, PE_64

import pefile

POINTER_SIZE = {32: 4, 64: 8}
ORDINAL_FLAG = {32: 0x80000000, 64: 0x8000000000000000}
TEMPLATES = {32: bytes(PE_32), 64: bytes(PE_64)}

IMPORT_DIRECTORY = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
DELAY_IMPORT_DIRECTORY = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]
BOUND_IMPORT_DIRECTORY = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"]

IMPORT_ATTRIBUTE = {
    IMPORT_DIRECTORY: "DIRECTORY_ENTRY_IMPORT",
    DELAY_IMPORT_DIRECTORY: "DIRECTORY_ENTRY_DELAY_IMPORT",
    BOUND_IMPORT_DIRECTORY: "DIRECTORY_ENTRY_BOUND_IMPORT",
}

# The embedded templates always produce these two warnings: they describe the
# template header, not the import structures written by these tests.
TEMPLATE_WARNINGS = {
    "SizeOfHeaders is smaller than AddressOfEntryPoint: this file cannot run "
    "under Windows 8.",
    "AddressOfEntryPoint lies outside the sections' boundaries. "
    "AddressOfEntryPoint: 0x0",
}


def normalized_imphash(*pairs):
    """Independent reference implementation of pefile's imphash normalization."""
    hashed = []
    for dll, function in pairs:
        library = dll.lower()
        stem, _, extension = library.rpartition(".")
        if stem and extension in ("ocx", "sys", "dll"):
            library = stem
        hashed.append(f"{library}.{function.lower()}")
    return md5(",".join(hashed).encode()).hexdigest()


class SyntheticImage:
    """A writable PE image whose ``.rdata`` RVA equals its file offset."""

    def __init__(self, bits, tail=0x1800):
        self.bits = bits
        self.pointer_size = POINTER_SIZE[bits]
        template = TEMPLATES[bits]
        probe = pefile.PE(data=template, fast_load=True)
        section = probe.sections[0]
        raw_size_offset = section.get_field_absolute_offset("SizeOfRawData")
        virtual_size_offset = section.get_field_absolute_offset("Misc_VirtualSize")
        size_of_image_offset = probe.OPTIONAL_HEADER.get_field_absolute_offset(
            "SizeOfImage"
        )
        data = bytearray(template) + b"\0" * tail
        struct.pack_into("<I", data, raw_size_offset, section.SizeOfRawData + tail)
        struct.pack_into(
            "<I", data, virtual_size_offset, section.Misc_VirtualSize + tail
        )
        struct.pack_into(
            "<I",
            data,
            size_of_image_offset,
            probe.OPTIONAL_HEADER.SizeOfImage + tail,
        )
        probe.close()

        self.data = data
        self.pe = pefile.PE(data=bytes(data), fast_load=True)
        self.section = self.pe.sections[0]
        self.section_end_rva = self.section.VirtualAddress + self.section.SizeOfRawData
        self.cursor = self.section.VirtualAddress + 0x400

    # -- raw access -----------------------------------------------------
    def write(self, rva, blob):
        assert 0 <= rva, hex(rva)
        assert rva + len(blob) <= self.section_end_rva, hex(rva)
        assert self.pe.set_bytes_at_rva(rva, blob), hex(rva)

    def pack_pointer(self, value):
        return struct.pack("<I" if self.bits == 32 else "<Q", value)

    def reserve(self, size, align=8):
        rva = self.cursor
        self.cursor = (self.cursor + size + align - 1) & ~(align - 1)
        assert self.cursor <= self.section_end_rva - 0x40, "image exhausted"
        return rva

    # -- import structures ---------------------------------------------
    def add_string(self, text):
        blob = text.encode() if isinstance(text, str) else text
        rva = self.reserve(len(blob) + 1, 2)
        self.write(rva, blob + b"\0")
        return rva

    def add_hint_name(self, name):
        rva = self.reserve(2 + len(name) + 1, 2)
        self.write(rva, struct.pack("<H", 0) + name.encode() + b"\0")
        return rva

    def encode_symbols(self, symbols):
        values = []
        for kind, value in symbols:
            if kind == "name":
                values.append(self.add_hint_name(value))
            elif kind == "ordinal":
                values.append(ORDINAL_FLAG[self.bits] | value)
            elif kind == "raw":
                values.append(value)
            else:
                raise AssertionError(kind)
        return values

    def add_table(self, values, terminate=True):
        stored = list(values) + ([0] if terminate else [])
        rva = self.reserve(len(stored) * self.pointer_size)
        self.write(rva, b"".join(self.pack_pointer(value) for value in stored))
        return rva

    def import_descriptor(self, dll, symbols, *, delay=False, dll_rva=None):
        if dll_rva is None:
            dll_rva = self.add_string(dll)
        values = self.encode_symbols(symbols)
        ilt = self.add_table(values)
        iat = self.add_table(values)
        if delay:
            return struct.pack("<8I", 1, dll_rva, 0, iat, ilt, 0, 0, 0)
        return struct.pack("<5I", ilt, 0, 0, dll_rva, iat)

    def add_directory(self, descriptors, *, delay=False, terminator=True):
        size = 32 if delay else 20
        blob = b"".join(descriptors)
        if terminator:
            blob += b"\0" * size
        rva = self.reserve(len(blob))
        self.write(rva, blob)
        return rva

    def configure(self, index, rva, size=0x400):
        entry = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
        entry.VirtualAddress = rva
        entry.Size = size

    def parse(self, index):
        for attribute in IMPORT_ATTRIBUTE.values():
            self.pe.__dict__.pop(attribute, None)
        self.pe.parse_data_directories(directories=[index])

    def parse_all_imports(self):
        for attribute in IMPORT_ATTRIBUTE.values():
            self.pe.__dict__.pop(attribute, None)
        self.pe.parse_data_directories(
            directories=[IMPORT_DIRECTORY, DELAY_IMPORT_DIRECTORY]
        )

    # -- queries --------------------------------------------------------
    def warnings(self):
        return [w for w in self.pe.get_warnings() if w not in TEMPLATE_WARNINGS]

    def warning_text(self):
        return "\n".join(self.warnings())

    def entries(self, index):
        return getattr(self.pe, IMPORT_ATTRIBUTE[index], None)

    def imphash(self):
        return self.pe.get_imphash()


def build_simple(
    bits,
    *,
    delay=False,
    symbols=(("name", "FuncA"), ("name", "FuncB")),
    dll="KERNEL32.dll",
):
    image = SyntheticImage(bits)
    descriptor = image.import_descriptor(dll, list(symbols), delay=delay)
    index = DELAY_IMPORT_DIRECTORY if delay else IMPORT_DIRECTORY
    image.configure(index, image.add_directory([descriptor], delay=delay))
    image.parse(index)
    return image, index


def symbols_of(image, index):
    entries = image.entries(index)
    if entries is None:
        return None
    return [
        (entry.dll, [(imp.name, imp.ordinal) for imp in entry.imports])
        for entry in entries
    ]


class TestImportTruncationWarnings(unittest.TestCase):
    """Requirements 1: warnings and import objects stay in sync."""

    def test_valid_imports_produce_no_warnings(self):
        for bits in (32, 64):
            for delay in (False, True):
                with self.subTest(bits=bits, delay=delay):
                    image, index = build_simple(bits, delay=delay)
                    self.assertEqual(image.warnings(), [])
                    self.assertEqual(
                        symbols_of(image, index),
                        [(b"KERNEL32.dll", [(b"FuncA", None), (b"FuncB", None)])],
                    )

    def test_descriptor_truncated_at_end_of_file(self):
        for bits in (32, 64):
            for delay in (False, True):
                with self.subTest(bits=bits, delay=delay):
                    size = 32 if delay else 20
                    image = SyntheticImage(bits)
                    good = image.import_descriptor(
                        "GOOD.dll", [("name", "GoodFunc")], delay=delay
                    )
                    cut = image.import_descriptor(
                        "HALF.dll", [("name", "HalfFunc")], delay=delay
                    )
                    # The file ends after the first 12 bytes of the second
                    # descriptor, so its tail can never be read.
                    partial_rva = image.section_end_rva - 12
                    image.write(partial_rva - size, good)
                    image.write(partial_rva, cut[:12])
                    index = DELAY_IMPORT_DIRECTORY if delay else IMPORT_DIRECTORY
                    image.configure(index, partial_rva - size)
                    image.parse(index)

                    struct_name = (
                        "IMAGE_DELAY_IMPORT_DESCRIPTOR"
                        if delay
                        else "IMAGE_IMPORT_DESCRIPTOR"
                    )
                    self.assertIn(
                        f'Corrupt header "{struct_name}"', image.warning_text()
                    )
                    # Every DLL parsed before the cut is still reported.
                    self.assertEqual(
                        symbols_of(image, index),
                        [(b"GOOD.dll", [(b"GoodFunc", None)])],
                    )
                    if not delay:
                        self.assertEqual(
                            image.imphash(),
                            normalized_imphash(("GOOD.dll", "GoodFunc")),
                        )
                    else:
                        # get_imphash only covers the normal import directory.
                        self.assertEqual(image.imphash(), "")

    def test_missing_terminator_at_end_of_file(self):
        for bits in (32, 64):
            for delay in (False, True):
                with self.subTest(bits=bits, delay=delay):
                    size = 32 if delay else 20
                    image = SyntheticImage(bits)
                    descriptor = image.import_descriptor(
                        "KERNEL32.dll", [("name", "FuncA")], delay=delay
                    )
                    # The descriptor fills the file exactly; the all-zero
                    # terminator slot lies past the end.
                    rva = image.section_end_rva - size
                    image.write(rva, descriptor)
                    index = DELAY_IMPORT_DIRECTORY if delay else IMPORT_DIRECTORY
                    image.configure(index, rva)
                    image.parse(index)

                    label = "Delay import directory" if delay else "import directory"
                    self.assertIn(
                        f"Error parsing the {label} at RVA:", image.warning_text()
                    )
                    self.assertEqual(
                        symbols_of(image, index),
                        [(b"KERNEL32.dll", [(b"FuncA", None)])],
                    )

    def test_misaligned_terminator_keeps_valid_dll(self):
        for bits in (32, 64):
            for delay in (False, True):
                with self.subTest(bits=bits, delay=delay):
                    image = SyntheticImage(bits)
                    good = image.import_descriptor(
                        "KERNEL32.dll", [("name", "FuncA")], delay=delay
                    )
                    # Four zero bytes are taken as the first half of the
                    # terminator; the rest of the all-zero slot is skipped and
                    # the following bytes are parsed as a descriptor.
                    tail = b"\0" * 4 + b"A" * 16 + b"\0" * 64
                    rva = image.reserve(len(good) + len(tail))
                    image.write(rva, good + tail)
                    index = DELAY_IMPORT_DIRECTORY if delay else IMPORT_DIRECTORY
                    image.configure(index, rva)
                    image.parse(index)

                    self.assertIn(
                        "Error parsing the import table. "
                        "Invalid data at RVA: 0x41414141",
                        image.warning_text(),
                    )
                    # The garbage is not promoted to an import object.
                    self.assertEqual(
                        symbols_of(image, index),
                        [(b"KERNEL32.dll", [(b"FuncA", None)])],
                    )
                    if not delay:
                        self.assertEqual(
                            image.imphash(),
                            normalized_imphash(("KERNEL32.dll", "FuncA")),
                        )
                    else:
                        self.assertEqual(image.imphash(), "")

    def test_terminator_shifted_before_second_descriptor(self):
        for bits in (32, 64):
            for delay in (False, True):
                with self.subTest(bits=bits, delay=delay):
                    size = 32 if delay else 20
                    image = SyntheticImage(bits)
                    first = image.import_descriptor(
                        "FIRST.dll", [("name", "FirstFunc")], delay=delay
                    )
                    second = image.import_descriptor(
                        "SECOND.dll", [("name", "SecondFunc")], delay=delay
                    )
                    # The terminator is misplaced four bytes early, so the
                    # second descriptor is parsed one dword out of phase.
                    blob = first + b"\0" * 4 + second + b"\0" * size
                    rva = image.reserve(len(blob))
                    image.write(rva, blob)
                    index = DELAY_IMPORT_DIRECTORY if delay else IMPORT_DIRECTORY
                    image.configure(index, rva)
                    image.parse(index)

                    entries = image.entries(index)
                    self.assertIsNotNone(entries)
                    self.assertEqual(entries[0].dll, b"FIRST.dll")
                    self.assertEqual(
                        [imp.name for imp in entries[0].imports], [b"FirstFunc"]
                    )
                    # The shifted descriptor cannot borrow the real DLL name:
                    # its name field points elsewhere and is rejected.
                    self.assertEqual(entries[1].dll, b"*invalid*")

    def test_truncated_thunk_table_keeps_complete_symbols(self):
        for bits in (32, 64):
            for delay in (False, True):
                for truncated in ("ilt", "iat"):
                    with self.subTest(bits=bits, delay=delay, truncated=truncated):
                        pointer_size = POINTER_SIZE[bits]
                        image = SyntheticImage(bits)
                        dll = image.add_string("KERNEL32.dll")
                        func_a = image.add_hint_name("FuncA")
                        func_b = image.add_hint_name("FuncB")
                        intact = image.add_table([func_a, func_b])
                        # One complete entry followed by two bytes of a
                        # second one, ending at the last byte of the file.
                        cut = image.section_end_rva - pointer_size - 2
                        image.write(cut, image.pack_pointer(func_a) + b"\x22\x33")
                        if truncated == "ilt":
                            ilt, iat = cut, intact
                        else:
                            ilt, iat = intact, cut
                        if delay:
                            descriptor = struct.pack(
                                "<8I", 1, dll, 0, iat, ilt, 0, 0, 0
                            )
                        else:
                            descriptor = struct.pack("<5I", ilt, 0, 0, dll, iat)
                        index = (
                            DELAY_IMPORT_DIRECTORY if delay else IMPORT_DIRECTORY
                        )
                        image.configure(
                            index, image.add_directory([descriptor], delay=delay)
                        )
                        image.parse(index)

                        self.assertIn(
                            "Error parsing the import table. "
                            "Invalid data at RVA:",
                            image.warning_text(),
                        )
                        # Entries from the intact table are still evidence.
                        self.assertEqual(
                            symbols_of(image, index),
                            [
                                (
                                    b"KERNEL32.dll",
                                    [(b"FuncA", None), (b"FuncB", None)],
                                )
                            ],
                        )

    def test_unreadable_thunk_tables_yield_no_import_evidence(self):
        for bits in (32, 64):
            for delay in (False, True):
                with self.subTest(bits=bits, delay=delay):
                    pointer_size = POINTER_SIZE[bits]
                    image = SyntheticImage(bits)
                    dll = image.add_string("KERNEL32.dll")
                    func_a = image.add_hint_name("FuncA")
                    # The table runs into the end of the file, so it can
                    # never be walked to a terminator.
                    cut = image.section_end_rva - 2 * pointer_size - 2
                    image.write(cut, image.pack_pointer(func_a) + b"\x11\x22")
                    if delay:
                        descriptor = struct.pack("<8I", 1, dll, 0, cut, cut, 0, 0, 0)
                    else:
                        descriptor = struct.pack("<5I", cut, 0, 0, dll, cut)
                    index = DELAY_IMPORT_DIRECTORY if delay else IMPORT_DIRECTORY
                    image.configure(
                        index, image.add_directory([descriptor], delay=delay)
                    )
                    image.parse(index)

                    self.assertIn(
                        "Damaged Import Table information. "
                        "ILT and/or IAT appear to be broken.",
                        image.warning_text(),
                    )
                    # No half table is promoted to a normalized feature.
                    self.assertFalse(hasattr(image.pe, IMPORT_ATTRIBUTE[index]))
                    self.assertEqual(image.imphash(), "")


class TestOrdinalAndBoundImports(unittest.TestCase):
    """Requirements 2: ordinals, bound imports and half imports."""

    def test_ordinal_names_resolved_but_imphash_uses_frozen_table(self):
        # ws2_32 ordinal 24 is "GetAddrInfoW" in the frozen imphash table but
        # "WSApSetPostRoutine" in the live table.  The displayed name comes
        # from the live table; the imphash must keep the frozen mapping.
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = SyntheticImage(bits)
                descriptor = image.import_descriptor("ws2_32.dll", [("ordinal", 24)])
                image.configure(
                    IMPORT_DIRECTORY, image.add_directory([descriptor])
                )
                image.parse(IMPORT_DIRECTORY)

                (dll, imports), = symbols_of(image, IMPORT_DIRECTORY)
                self.assertEqual(dll, b"ws2_32.dll")
                self.assertEqual(imports, [(b"WSApSetPostRoutine", 24)])
                (imp,) = image.entries(IMPORT_DIRECTORY)[0].imports
                self.assertTrue(imp.import_by_ordinal)
                self.assertTrue(imp.name_from_ordinal)

                self.assertEqual(
                    image.imphash(),
                    normalized_imphash(("ws2_32.dll", "GetAddrInfoW")),
                )
                self.assertNotEqual(
                    image.imphash(),
                    normalized_imphash(("ws2_32.dll", "WSApSetPostRoutine")),
                )

    def test_unknown_ordinal_is_not_a_named_import(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = SyntheticImage(bits)
                descriptor = image.import_descriptor(
                    "KERNEL32.dll", [("ordinal", 7), ("name", "FuncA")]
                )
                image.configure(
                    IMPORT_DIRECTORY, image.add_directory([descriptor])
                )
                image.parse(IMPORT_DIRECTORY)

                (_, imports), = symbols_of(image, IMPORT_DIRECTORY)
                self.assertEqual(imports, [(None, 7), (b"FuncA", None)])
                first = image.entries(IMPORT_DIRECTORY)[0].imports[0]
                self.assertFalse(first.name_from_ordinal)
                self.assertEqual(
                    image.imphash(),
                    normalized_imphash(
                        ("KERNEL32.dll", "ord7"), ("KERNEL32.dll", "FuncA")
                    ),
                )

    def test_out_of_range_ordinal_discards_the_table(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = SyntheticImage(bits)
                descriptor = image.import_descriptor(
                    "KERNEL32.dll",
                    [("name", "FuncA"), ("raw", ORDINAL_FLAG[bits] | 0x10001)],
                )
                image.configure(
                    IMPORT_DIRECTORY, image.add_directory([descriptor])
                )
                image.parse(IMPORT_DIRECTORY)

                self.assertIn(
                    "Damaged Import Table information.",
                    image.warning_text(),
                )
                self.assertFalse(hasattr(image.pe, "DIRECTORY_ENTRY_IMPORT"))
                # No "ord65537"-style pseudo symbol leaks into the hash.
                self.assertEqual(image.imphash(), "")

    def test_iat_only_ordinal_is_resolved(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = SyntheticImage(bits)
                dll = image.add_string("ws2_32.dll")
                iat = image.add_table([ORDINAL_FLAG[bits] | 23])
                # OriginalFirstThunk is zero: names must come from the IAT.
                descriptor = struct.pack("<5I", 0, 0, 0, dll, iat)
                image.configure(
                    IMPORT_DIRECTORY, image.add_directory([descriptor])
                )
                image.parse(IMPORT_DIRECTORY)

                self.assertEqual(
                    symbols_of(image, IMPORT_DIRECTORY),
                    [(b"ws2_32.dll", [(b"socket", 23)])],
                )
                (imp,) = image.entries(IMPORT_DIRECTORY)[0].imports
                self.assertTrue(imp.import_by_ordinal)
                self.assertEqual(
                    image.imphash(), normalized_imphash(("ws2_32.dll", "socket"))
                )

    def test_bound_addresses_are_not_mistaken_for_ordinals(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = SyntheticImage(bits)
                dll = image.add_string("KERNEL32.dll")
                func_a = image.add_hint_name("FuncA")
                func_b = image.add_hint_name("FuncB")
                ilt = image.add_table([func_a, func_b])
                bound = [0x77001234, 0x77005678]
                iat = image.add_table(bound)
                descriptor = struct.pack("<5I", ilt, 0, 0, dll, iat)
                image.configure(
                    IMPORT_DIRECTORY, image.add_directory([descriptor])
                )
                image.parse(IMPORT_DIRECTORY)

                imports = image.entries(IMPORT_DIRECTORY)[0].imports
                self.assertEqual([imp.name for imp in imports],
                                 [b"FuncA", b"FuncB"])
                self.assertEqual([imp.bound for imp in imports], bound)
                self.assertEqual(
                    [imp.import_by_ordinal for imp in imports], [False, False]
                )
                # Bound addresses never influence the hash.
                self.assertEqual(
                    image.imphash(),
                    normalized_imphash(
                        ("KERNEL32.dll", "FuncA"), ("KERNEL32.dll", "FuncB")
                    ),
                )

    def test_bound_ordinal_keeps_its_ordinal_identity(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = SyntheticImage(bits)
                dll = image.add_string("KERNEL32.dll")
                func_a = image.add_hint_name("FuncA")
                ilt = image.add_table([func_a, ORDINAL_FLAG[bits] | 7])
                iat = image.add_table([0x77001234, 0x77005678])
                descriptor = struct.pack("<5I", ilt, 0, 0, dll, iat)
                image.configure(
                    IMPORT_DIRECTORY, image.add_directory([descriptor])
                )
                image.parse(IMPORT_DIRECTORY)

                imports = image.entries(IMPORT_DIRECTORY)[0].imports
                self.assertEqual(
                    [(imp.name, imp.ordinal, imp.import_by_ordinal) for imp in imports],
                    [(b"FuncA", None, False), (None, 7, True)],
                )
                self.assertEqual(
                    image.imphash(),
                    normalized_imphash(
                        ("KERNEL32.dll", "FuncA"), ("KERNEL32.dll", "ord7")
                    ),
                )

    def test_bound_import_with_truncated_iat_keeps_names(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                pointer_size = POINTER_SIZE[bits]
                image = SyntheticImage(bits)
                dll = image.add_string("KERNEL32.dll")
                func_a = image.add_hint_name("FuncA")
                func_b = image.add_hint_name("FuncB")
                ilt = image.add_table([func_a, func_b])
                cut = image.section_end_rva - 2 * pointer_size - 2
                image.write(
                    cut,
                    image.pack_pointer(0x77001234)
                    + image.pack_pointer(0x77005678)
                    + b"\x11\x22",
                )
                descriptor = struct.pack("<5I", ilt, 0, 0, dll, cut)
                image.configure(
                    IMPORT_DIRECTORY, image.add_directory([descriptor])
                )
                image.parse(IMPORT_DIRECTORY)

                self.assertIn(
                    "Error parsing the import table. Invalid data at RVA:",
                    image.warning_text(),
                )
                imports = image.entries(IMPORT_DIRECTORY)[0].imports
                # Names survive; the unreadable bound addresses are not
                # reported as if they were trustworthy.
                self.assertEqual([imp.name for imp in imports],
                                 [b"FuncA", b"FuncB"])
                self.assertEqual([imp.bound for imp in imports], [None, None])
                self.assertEqual(
                    image.imphash(),
                    normalized_imphash(
                        ("KERNEL32.dll", "FuncA"), ("KERNEL32.dll", "FuncB")
                    ),
                )

    def test_failed_half_import_is_not_a_normalized_feature(self):
        for bits in (32, 64):
            for delay in (False, True):
                with self.subTest(bits=bits, delay=delay):
                    image = SyntheticImage(bits)
                    # A valid name followed by an AddressOfData that cannot be
                    # read makes the table unparseable halfway through.
                    descriptor = image.import_descriptor(
                        "KERNEL32.dll",
                        [("name", "FuncA"), ("raw", 0x5F00000), ("raw", 0x5F00004)],
                        delay=delay,
                    )
                    index = (
                        DELAY_IMPORT_DIRECTORY if delay else IMPORT_DIRECTORY
                    )
                    image.configure(index, image.add_directory([descriptor],
                                                               delay=delay))
                    image.parse(index)

                    self.assertIn(
                        "Invalid entries, aborting parsing.",
                        image.warning_text(),
                    )
                    self.assertFalse(hasattr(image.pe, IMPORT_ATTRIBUTE[index]))
                    self.assertEqual(image.imphash(), "")

    def test_failed_half_import_does_not_drop_preceding_dll(self):
        for bits in (32, 64):
            for delay in (False, True):
                with self.subTest(bits=bits, delay=delay):
                    image = SyntheticImage(bits)
                    good = image.import_descriptor(
                        "GOOD.dll", [("name", "GoodFunc")], delay=delay
                    )
                    half = image.import_descriptor(
                        "HALF.dll",
                        [("name", "HalfFunc"), ("raw", 0x5F00000)],
                        delay=delay,
                    )
                    index = (
                        DELAY_IMPORT_DIRECTORY if delay else IMPORT_DIRECTORY
                    )
                    image.configure(
                        index, image.add_directory([good, half], delay=delay)
                    )
                    image.parse(index)

                    self.assertIn(
                        "Invalid entries, aborting parsing.",
                        image.warning_text(),
                    )
                    # The healthy DLL is still evidence; the failed one is not
                    # represented at all.
                    self.assertEqual(
                        symbols_of(image, index),
                        [(b"GOOD.dll", [(b"GoodFunc", None)])],
                    )
                    if not delay:
                        self.assertEqual(
                            image.imphash(),
                            normalized_imphash(("GOOD.dll", "GoodFunc")),
                        )
                    else:
                        self.assertEqual(image.imphash(), "")

    def test_malformed_suffix_keeps_preceding_dll(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = SyntheticImage(bits)
                good = image.import_descriptor("GOOD.dll", [("name", "GoodFunc")])
                # The second DLL name contains bytes that cannot appear in a
                # DOS filename; it must be flagged, not trusted verbatim.
                bad_name = image.add_string("BAD\x01NAME.dll")
                bad = image.import_descriptor(
                    "ignored", [("name", "BadFunc")], dll_rva=bad_name
                )
                image.configure(
                    IMPORT_DIRECTORY, image.add_directory([good, bad])
                )
                image.parse(IMPORT_DIRECTORY)

                self.assertEqual(image.warnings(), [])
                entries = image.entries(IMPORT_DIRECTORY)
                self.assertEqual(
                    [entry.dll for entry in entries], [b"GOOD.dll", b"*invalid*"]
                )
                self.assertEqual(
                    [imp.name for imp in entries[0].imports], [b"GoodFunc"]
                )
                self.assertEqual(
                    [imp.name for imp in entries[1].imports], [b"BadFunc"]
                )
                self.assertEqual(
                    image.imphash(),
                    normalized_imphash(
                        ("GOOD.dll", "GoodFunc"), ("*invalid*", "BadFunc")
                    ),
                )

    def test_invalid_function_name_is_not_exposed_as_symbol(self):
        for bits in (32, 64):
            for delay in (False, True):
                with self.subTest(bits=bits, delay=delay):
                    image = SyntheticImage(bits)
                    # The middle name holds a control byte, so it cannot be a
                    # mangled symbol name.  The surrounding names are intact.
                    descriptor = image.import_descriptor(
                        "KERNEL32.dll",
                        [
                            ("name", "FuncA"),
                            ("name", "Bad\x01Name"),
                            ("name", "FuncC"),
                        ],
                        delay=delay,
                    )
                    index = (
                        DELAY_IMPORT_DIRECTORY if delay else IMPORT_DIRECTORY
                    )
                    image.configure(
                        index, image.add_directory([descriptor], delay=delay)
                    )
                    image.parse(index)

                    self.assertEqual(image.warnings(), [])
                    self.assertEqual(
                        symbols_of(image, index),
                        [
                            (
                                b"KERNEL32.dll",
                                [(b"FuncA", None), (b"FuncC", None)],
                            )
                        ],
                    )
                    if not delay:
                        self.assertEqual(
                            image.imphash(),
                            normalized_imphash(
                                ("KERNEL32.dll", "FuncA"),
                                ("KERNEL32.dll", "FuncC"),
                            ),
                        )

    def test_broken_descriptor_in_middle_keeps_neighbouring_dlls(self):
        for bits in (32, 64):
            for delay in (False, True):
                with self.subTest(bits=bits, delay=delay):
                    image = SyntheticImage(bits)
                    first = image.import_descriptor(
                        "FIRST.dll", [("name", "FirstFunc")], delay=delay
                    )
                    broken_name = image.add_string("BROKEN.dll")
                    unreadable = 0x40000000
                    ilt = image.add_table([unreadable])
                    iat = image.add_table([unreadable])
                    if delay:
                        broken = struct.pack(
                            "<8I", 1, broken_name, 0, iat, ilt, 0, 0, 0
                        )
                    else:
                        broken = struct.pack("<5I", ilt, 0, 0, broken_name, iat)
                    third = image.import_descriptor(
                        "THIRD.dll", [("name", "ThirdFunc")], delay=delay
                    )
                    index = (
                        DELAY_IMPORT_DIRECTORY if delay else IMPORT_DIRECTORY
                    )
                    image.configure(
                        index,
                        image.add_directory([first, broken, third], delay=delay),
                    )
                    image.parse(index)

                    self.assertIn(
                        "Invalid entries, aborting parsing.",
                        image.warning_text(),
                    )
                    self.assertEqual(
                        symbols_of(image, index),
                        [
                            (b"FIRST.dll", [(b"FirstFunc", None)]),
                            (b"THIRD.dll", [(b"ThirdFunc", None)]),
                        ],
                    )
                    if not delay:
                        self.assertEqual(
                            image.imphash(),
                            normalized_imphash(
                                ("FIRST.dll", "FirstFunc"),
                                ("THIRD.dll", "ThirdFunc"),
                            ),
                        )

    def test_legacy_delay_descriptor_pointer_values_are_normalized(self):
        # Pre-VS6 delay descriptors store VAs (ImageBase + RVA) instead of
        # RVAs.  Only 32-bit images can use that layout.
        image = SyntheticImage(32)
        image_base = image.pe.OPTIONAL_HEADER.ImageBase
        name_rva = image.add_string("KERNEL32.dll")
        func_a = image.add_hint_name("FuncA")
        ilt = image.add_table([func_a])
        iat = image.add_table([func_a])
        rva = image.reserve(64)
        image.write(
            rva,
            struct.pack(
                "<8I",
                0,
                image_base + name_rva,
                0,
                image_base + iat,
                image_base + ilt,
                0,
                0,
                0,
            )
            + b"\0" * 32,
        )
        image.configure(DELAY_IMPORT_DIRECTORY, rva)
        image.parse(DELAY_IMPORT_DIRECTORY)

        self.assertEqual(image.warnings(), [])
        (entry,) = image.entries(DELAY_IMPORT_DIRECTORY)
        self.assertEqual(entry.dll, b"KERNEL32.dll")
        # The stored VAs are exposed as RVAs after normalization.
        self.assertEqual(entry.struct.szName, name_rva)
        self.assertEqual(entry.struct.pINT, ilt)
        self.assertEqual(entry.struct.pIAT, iat)
        self.assertEqual([imp.name for imp in entry.imports], [b"FuncA"])


class TestBoundImportDirectory(unittest.TestCase):
    """Requirement 2: the bound import directory (directory 11)."""

    @staticmethod
    def layout(image, names, forwarder_counts=None):
        """Write bound import descriptors and return the directory RVA."""
        base = image.reserve(0x100)
        offsets = []
        cursor = 0x40
        for name in names:
            image.write(base + cursor, name + b"\0")
            offsets.append(cursor)
            cursor += len(name) + 1
        blob = b""
        for index, (offset, name) in enumerate(zip(offsets, names)):
            refs = (forwarder_counts or [0] * len(names))[index]
            blob += struct.pack("<IHH", 0x1000 + index, offset, refs)
        image.write(base, blob + b"\0" * 8)
        return base

    def test_valid_bound_import_directory(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = SyntheticImage(bits)
                base = self.layout(image, [b"KERNEL32.dll", b"USER32.dll"])
                image.configure(BOUND_IMPORT_DIRECTORY, base)
                image.parse(BOUND_IMPORT_DIRECTORY)

                self.assertEqual(image.warnings(), [])
                entries = image.entries(BOUND_IMPORT_DIRECTORY)
                self.assertEqual(
                    [entry.name for entry in entries],
                    [b"KERNEL32.dll", b"USER32.dll"],
                )
                self.assertEqual(
                    [entry.struct.TimeDateStamp for entry in entries],
                    [0x1000, 0x1001],
                )

    def test_truncated_bound_import_directory(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = SyntheticImage(bits)
                # Only two bytes of the first descriptor fit in the file.
                rva = image.section_end_rva - 2
                image.write(rva, b"\x01\x02")
                image.configure(BOUND_IMPORT_DIRECTORY, rva)
                image.parse(BOUND_IMPORT_DIRECTORY)

                self.assertIn(
                    'Corrupt header "IMAGE_BOUND_IMPORT_DESCRIPTOR"',
                    image.warning_text(),
                )
                self.assertIn(
                    "The Bound Imports directory exists but can't be parsed.",
                    image.warning_text(),
                )
                self.assertFalse(
                    hasattr(image.pe, "DIRECTORY_ENTRY_BOUND_IMPORT")
                )

    def test_malformed_bound_import_suffix_keeps_prefix(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = SyntheticImage(bits)
                base = image.reserve(0x100)
                image.write(base + 0x40, b"KERNEL32.dll\0")
                image.write(base + 0x50, b"BAD\xffNAME.dll\0")
                image.write(
                    base,
                    struct.pack("<IHH", 0x11111111, 0x40, 0)
                    + struct.pack("<IHH", 0x22222222, 0x50, 0)
                    + b"\0" * 8,
                )
                image.configure(BOUND_IMPORT_DIRECTORY, base)
                image.parse(BOUND_IMPORT_DIRECTORY)

                # The malformed name stops the walk but the first DLL stays.
                self.assertEqual(image.warnings(), [])
                self.assertEqual(
                    [entry.name for entry in image.entries(BOUND_IMPORT_DIRECTORY)],
                    [b"KERNEL32.dll"],
                )


class TestPointerWidthParity(unittest.TestCase):
    """Requirement 3: PE32 vs PE32+ pointer width without imphash drift."""

    def test_descriptor_and_thunk_sizes(self):
        for bits in (32, 64):
            for delay in (False, True):
                with self.subTest(bits=bits, delay=delay):
                    image, index = build_simple(bits, delay=delay)
                    (entry,) = image.entries(index)
                    self.assertEqual(entry.struct.sizeof(), 32 if delay else 20)
                    self.assertEqual(
                        entry.imports[1].thunk_rva - entry.imports[0].thunk_rva,
                        POINTER_SIZE[bits],
                    )
                    self.assertEqual(
                        entry.imports[1].address - entry.imports[0].address,
                        POINTER_SIZE[bits],
                    )

    def test_normal_imports_and_imphash_match_across_formats(self):
        results = {}
        for bits in (32, 64):
            image, index = build_simple(
                bits,
                symbols=(("name", "FuncA"), ("ordinal", 7), ("name", "FuncB")),
            )
            self.assertEqual(image.warnings(), [])
            results[bits] = (
                symbols_of(image, index),
                image.imphash(),
            )
        self.assertEqual(results[32], results[64])
        self.assertEqual(
            results[32][1],
            normalized_imphash(
                ("KERNEL32.dll", "FuncA"),
                ("KERNEL32.dll", "ord7"),
                ("KERNEL32.dll", "FuncB"),
            ),
        )

    def test_ordinal_imports_and_imphash_match_across_formats(self):
        results = {}
        for bits in (32, 64):
            image = SyntheticImage(bits)
            descriptor = image.import_descriptor(
                "ws2_32.dll", [("ordinal", 23), ("ordinal", 115), ("name", "FuncA")]
            )
            image.configure(IMPORT_DIRECTORY, image.add_directory([descriptor]))
            image.parse(IMPORT_DIRECTORY)
            self.assertEqual(image.warnings(), [])
            results[bits] = (
                symbols_of(image, IMPORT_DIRECTORY),
                image.imphash(),
            )
        self.assertEqual(results[32], results[64])
        self.assertEqual(
            results[32][1],
            normalized_imphash(
                ("ws2_32.dll", "socket"),
                ("ws2_32.dll", "WSAStartup"),
                ("ws2_32.dll", "FuncA"),
            ),
        )

    def test_ordinal_flag_width_is_respected(self):
        # In PE32 the high bit of a dword marks an ordinal import.  The same
        # numeric value is a plain RVA in PE32+, where the high bit of a qword
        # is required instead.
        pe32 = SyntheticImage(32)
        dll = pe32.add_string("ws2_32.dll")
        table = pe32.add_table([0x80000010])
        pe32.configure(
            IMPORT_DIRECTORY,
            pe32.add_directory([struct.pack("<5I", table, 0, 0, dll, table)]),
        )
        pe32.parse(IMPORT_DIRECTORY)
        self.assertEqual(
            symbols_of(pe32, IMPORT_DIRECTORY),
            [(b"ws2_32.dll", [(b"recv", 16)])],
        )
        self.assertEqual(
            pe32.imphash(), normalized_imphash(("ws2_32.dll", "recv"))
        )

        pe64 = SyntheticImage(64)
        dll = pe64.add_string("ws2_32.dll")
        table = pe64.add_table([0x80000010])
        pe64.configure(
            IMPORT_DIRECTORY,
            pe64.add_directory([struct.pack("<5I", table, 0, 0, dll, table)]),
        )
        pe64.parse(IMPORT_DIRECTORY)
        # Treated as an unreadable RVA, so no half-formed import survives.
        self.assertFalse(hasattr(pe64.pe, "DIRECTORY_ENTRY_IMPORT"))
        self.assertIn(
            "Invalid entries, aborting parsing.", pe64.warning_text()
        )
        self.assertEqual(pe64.imphash(), "")

        # The correctly sized 64-bit ordinal flag is resolved.
        pe64 = SyntheticImage(64)
        dll = pe64.add_string("ws2_32.dll")
        table = pe64.add_table([0x8000000000000010])
        pe64.configure(
            IMPORT_DIRECTORY,
            pe64.add_directory([struct.pack("<5I", table, 0, 0, dll, table)]),
        )
        pe64.parse(IMPORT_DIRECTORY)
        self.assertEqual(
            symbols_of(pe64, IMPORT_DIRECTORY),
            [(b"ws2_32.dll", [(b"recv", 16)])],
        )
        self.assertEqual(
            pe64.imphash(), normalized_imphash(("ws2_32.dll", "recv"))
        )

    def test_delay_imports_do_not_change_imphash(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = SyntheticImage(bits)
                normal = image.import_descriptor(
                    "KERNEL32.dll", [("name", "FuncA"), ("name", "FuncB")]
                )
                delay = image.import_descriptor(
                    "USER32.dll", [("name", "MessageBoxA")], delay=True
                )
                image.configure(
                    IMPORT_DIRECTORY, image.add_directory([normal])
                )
                image.configure(
                    DELAY_IMPORT_DIRECTORY, image.add_directory([delay], delay=True)
                )
                image.parse_all_imports()

                self.assertEqual(image.warnings(), [])
                self.assertEqual(
                    symbols_of(image, DELAY_IMPORT_DIRECTORY),
                    [(b"USER32.dll", [(b"MessageBoxA", None)])],
                )
                # Only the normal directory feeds the imphash.
                self.assertEqual(
                    image.imphash(),
                    normalized_imphash(
                        ("KERNEL32.dll", "FuncA"), ("KERNEL32.dll", "FuncB")
                    ),
                )


if __name__ == "__main__":
    unittest.main()
