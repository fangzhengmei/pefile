"""Security regression tests for section ranges, RVA boundaries and data
directories.

The on-disk view of a PE (file offsets, driven by ``PointerToRawData`` /
``SizeOfRawData``) and its in-memory view (RVAs, driven by ``VirtualAddress`` /
``Misc_VirtualSize``) describe two different address spaces.  Malformed or
hostile files deliberately blur the boundary between them: raw and virtual
ranges can overlap, data directories can point exactly at a boundary, past the
end of the file or at an address that only exists because ``SizeOfImage`` was
inflated.

Every sample in this module is synthesized locally from raw bytes (for both
PE32 and PE32+), so the tests do not depend on any external corpus.  They
distinguish *tolerable* layouts, which pefile must keep parsing deterministically,
from *out-of-bounds* references, which must be rejected without allocating an
unbounded image or perturbing the parsing of the structures that follow.
"""

import struct
import unittest

import pefile


# ---------------------------------------------------------------------------
# Local PE construction helpers
# ---------------------------------------------------------------------------


# A sentinel that cannot be confused with zero padding or real code.
SENTINEL = 0xA5


class SectionSpec:
    """Description of one section handed to :func:`build_pe`."""

    def __init__(
        self,
        name,
        virtual_size,
        virtual_address,
        raw_size,
        raw_pointer,
        data=None,
        characteristics=0x60000020,
    ):
        self.name = name
        self.virtual_size = virtual_size
        self.virtual_address = virtual_address
        self.raw_size = raw_size
        self.raw_pointer = raw_pointer
        # When no explicit payload is given the raw area is filled with a
        # recognizable sentinel so cross-view reads can be compared byte for byte.
        self.data = data if data is not None else bytes((SENTINEL,)) * raw_size
        self.characteristics = characteristics


def build_pe(
    plus=False,
    sections=None,
    directories=None,
    entry_point=0x1000,
    size_of_image=None,
    image_base=None,
    section_alignment=0x1000,
    file_alignment=0x200,
    size_of_headers=0x200,
):
    """Assemble a minimal, internally consistent PE32 or PE32+ image.

    ``sections`` is a list of :class:`SectionSpec`.  ``directories`` maps a data
    directory index to an ``(rva, size)`` tuple.  The returned ``bytes`` object
    is a complete file that :class:`pefile.PE` can parse directly.
    """

    sections = sections or []
    directories = directories or {}
    image_base = image_base if image_base is not None else (
        0x140000000 if plus else 0x400000
    )
    e_lfanew = 0x40
    optional_header_size = 0xF0 if plus else 0xE0
    machine = 0x8664 if plus else 0x14C
    magic = pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS if plus else pefile.OPTIONAL_HEADER_MAGIC_PE

    coff_header = struct.pack(
        "<HHIIIHH",
        machine,
        len(sections),
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        optional_header_size,
        0x0102,  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    if size_of_image is None:
        if sections:
            last = max(
                section.virtual_address
                + max(section.virtual_size, section.raw_size)
                for section in sections
            )
        else:
            last = section_alignment
        size_of_image = (
            (last + section_alignment - 1) // section_alignment
        ) * section_alignment

    if not plus:
        optional_header = struct.pack(
            "<HBBIII",
            magic,
            14,  # MajorLinkerVersion
            0,   # MinorLinkerVersion
            0x1000,  # SizeOfCode
            0,  # SizeOfInitializedData
            0,  # SizeOfUninitializedData
        )
        optional_header += struct.pack(
            "<III",
            entry_point,
            0x1000,  # BaseOfCode
            0x2000,  # BaseOfData (PE32 only)
        )
        optional_header += struct.pack("<I", image_base)
        optional_header += struct.pack("<II", section_alignment, file_alignment)
        optional_header += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
        optional_header += struct.pack("<I", 0)  # Win32VersionValue
        optional_header += struct.pack("<I", size_of_image)
        optional_header += struct.pack("<I", size_of_headers)
        optional_header += struct.pack("<I", 0)  # CheckSum
        optional_header += struct.pack("<HH", 2, 0x8100)  # Subsystem, DllCharacteristics
        optional_header += struct.pack(
            "<IIII", 0x100000, 0x1000, 0x100000, 0x1000
        )
        optional_header += struct.pack("<II", 0, 16)  # LoaderFlags, NumberOfRvaAndSizes
    else:
        optional_header = struct.pack(
            "<HBBIII",
            magic,
            14,
            0,
            0x1000,  # SizeOfCode
            0,  # SizeOfInitializedData
            0,  # SizeOfUninitializedData
        )
        optional_header += struct.pack(
            "<II",
            entry_point,
            0x1000,  # BaseOfCode (no BaseOfData in PE32+)
        )
        optional_header += struct.pack("<Q", image_base)
        optional_header += struct.pack("<II", section_alignment, file_alignment)
        optional_header += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
        optional_header += struct.pack("<I", 0)  # Win32VersionValue
        optional_header += struct.pack("<I", size_of_image)
        optional_header += struct.pack("<I", size_of_headers)
        optional_header += struct.pack("<I", 0)  # CheckSum
        optional_header += struct.pack("<HH", 2, 0x8100)
        optional_header += struct.pack(
            "<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000
        )
        optional_header += struct.pack("<II", 0, 16)

    # Always emit the full 16-entry data directory.
    directory_entries = [(0, 0)] * 16
    for index, (rva, size) in directories.items():
        directory_entries[index] = (rva, size)
    for rva, size in directory_entries:
        optional_header += struct.pack("<II", rva, size)

    assert len(optional_header) == optional_header_size

    headers = (
        b"MZ"
        + b"\0" * (e_lfanew - 2 - 4)
        + struct.pack("<I", e_lfanew)
        + b"PE\0\0"
        + coff_header
        + optional_header
    )
    for section in sections:
        headers += struct.pack(
            "<8sIIIIIIHHI",
            section.name[:8].ljust(8, b"\0"),
            section.virtual_size,
            section.virtual_address,
            section.raw_size,
            section.raw_pointer,
            0,  # PointerToRelocations
            0,  # PointerToLinenumbers
            0,  # NumberOfRelocations
            0,  # NumberOfLinenumbers
            section.characteristics,
        )

    total_size = max(
        [size_of_headers]
        + [section.raw_pointer + section.raw_size for section in sections]
    )
    image = bytearray(total_size)
    image[: len(headers)] = headers
    for section in sections:
        payload = section.data
        image[
            section.raw_pointer : section.raw_pointer + len(payload)
        ] = payload
    return bytes(image)


def build_import_pe(plus=False):
    """Build a PE carrying one import descriptor, an ILT/IAT pair and a base
    relocation that fixes up the IAT slot.

    Returns ``(data, layout)`` where ``layout`` exposes the relevant RVAs and the
    original value stored in the IAT slot (an RVA pointing at the hint/name).
    """

    thunk_size = 8 if plus else 4
    section_rva = 0x1000
    raw_pointer = 0x200

    # Offsets inside the section's raw/virtual payload.
    ilt_off, iat_off = 0x00, 0x20
    descriptor_off = 0x40
    hint_name_off = 0x70
    dll_name_off = 0xA0
    reloc_off = 0x100

    ilt_rva = section_rva + ilt_off
    iat_rva = section_rva + iat_off
    descriptor_rva = section_rva + descriptor_off
    hint_name_rva = section_rva + hint_name_off
    dll_name_rva = section_rva + dll_name_off
    reloc_rva = section_rva + reloc_off

    blob = bytearray(0x300)
    thunk_format = "<Q" if plus else "<I"
    struct.pack_into(thunk_format, blob, ilt_off, hint_name_rva)
    struct.pack_into(thunk_format, blob, iat_off, hint_name_rva)

    hint_name = struct.pack("<H", 1) + b"ExitProcess\0"
    blob[hint_name_off : hint_name_off + len(hint_name)] = hint_name
    dll_name = b"KERNEL32.DLL\0"
    blob[dll_name_off : dll_name_off + len(dll_name)] = dll_name

    # IMAGE_IMPORT_DESCRIPTOR: OriginalFirstThunk, TimeDateStamp,
    # ForwarderChain, Name, FirstThunk.
    struct.pack_into(
        "<IIIII",
        blob,
        descriptor_off,
        ilt_rva,
        0,
        0,
        dll_name_rva,
        iat_rva,
    )

    # One base-relocation block fixing up the IAT slot.  Type 3 is HIGHLOW for
    # PE32, type 10 is DIR64 for PE32+.
    reloc_type = 10 if plus else 3
    struct.pack_into("<II", blob, reloc_off, section_rva, 8 + 2)
    struct.pack_into("<H", blob, reloc_off + 8, (reloc_type << 12) | iat_off)

    directories = {
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]: (
            descriptor_rva,
            20,
        ),
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]: (
            reloc_rva,
            10,
        ),
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]: (
            iat_rva,
            thunk_size * 2,
        ),
    }

    section = SectionSpec(
        b".rdata",
        virtual_size=len(blob),
        virtual_address=section_rva,
        raw_size=len(blob),
        raw_pointer=raw_pointer,
        data=bytes(blob),
    )
    data = build_pe(
        plus=plus,
        sections=[section],
        directories=directories,
        entry_point=section_rva,
    )

    layout = {
        "section_rva": section_rva,
        "ilt_rva": ilt_rva,
        "iat_rva": iat_rva,
        "descriptor_rva": descriptor_rva,
        "hint_name_rva": hint_name_rva,
        "dll_name_rva": dll_name_rva,
        "reloc_rva": reloc_rva,
        "thunk_size": thunk_size,
        "original_iat_value": hint_name_rva,
    }
    return data, layout


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSectionRangeAndRVABoundaries(unittest.TestCase):
    """File-offset vs RVA resolution across raw and virtual section ranges."""

    def _adjacent_sections(self):
        # Virtual ranges are adjacent (no overlap); raw ranges deliberately
        # overlap because .text claims 0x400 bytes starting at 0x200 while
        # .rdata starts at 0x400.
        return [
            SectionSpec(b".text", 0x1000, 0x1000, 0x400, 0x200, data=b"TEXT"),
            SectionSpec(b".rdata", 0x1000, 0x2000, 0x400, 0x400, data=b"RDATA"),
        ]

    def test_rva_round_trip_matches_file_and_mapped_views(self):
        """The same byte must be reachable through file offset, RVA and the
        memory-mapped image, and all three views must agree."""

        for plus in (False, True):
            with self.subTest(pe="PE32+" if plus else "PE32"):
                sections = [
                    SectionSpec(
                        b".text",
                        0x1000,
                        0x1000,
                        0x400,
                        0x200,
                        data=bytes((SENTINEL,)) * 0x400,
                    )
                ]
                data = build_pe(plus=plus, sections=sections)
                pe = pefile.PE(data=data)

                rva = 0x1010
                offset = pe.get_offset_from_rva(rva)
                # File view and RVA view agree.
                self.assertEqual(pe.get_data(rva, 4), data[offset : offset + 4])
                # The mapped image places the byte at its RVA.
                mapped = pe.get_memory_mapped_image()
                self.assertEqual(mapped[rva : rva + 4], data[offset : offset + 4])
                # The reverse mapping closes the loop.
                self.assertEqual(pe.get_rva_from_offset(offset), rva)

    def test_exact_virtual_boundary_is_half_open(self):
        """A section covers [VirtualAddress, VirtualAddress + size); the RVA at
        the exact end belongs to the next section, not the current one."""

        data = build_pe(sections=self._adjacent_sections())
        pe = pefile.PE(data=data)

        self.assertEqual(
            pe.get_section_by_rva(0x1FFF).Name.rstrip(b"\0"), b".text"
        )
        self.assertEqual(
            pe.get_section_by_rva(0x2000).Name.rstrip(b"\0"), b".rdata"
        )
        self.assertEqual(
            pe.get_section_by_rva(0x2FFF).Name.rstrip(b"\0"), b".rdata"
        )
        # One past the final section is not contained anywhere.
        self.assertIsNone(pe.get_section_by_rva(0x3000))

    def test_overlapping_virtual_ranges_resolve_deterministically(self):
        """Two sections mapped at the same VirtualAddress: the first one in the
        VirtualAddress-sorted table wins every RVA lookup, deterministically."""

        sections = [
            SectionSpec(b".a", 0x1000, 0x1000, 0x200, 0x200, data=b"AAAA"),
            SectionSpec(b".b", 0x1000, 0x1000, 0x200, 0x400, data=b"BBBB"),
        ]
        data = build_pe(sections=sections)
        pe = pefile.PE(data=data)

        winner = pe.get_section_by_rva(0x1010)
        self.assertEqual(winner.Name.rstrip(b"\0"), b".a")
        # Repeated lookups must keep returning the same section.
        for _ in range(5):
            self.assertIs(pe.get_section_by_rva(0x1010), winner)
        # The RVA resolves to the winning section's raw pointer, not .b's.
        self.assertEqual(pe.get_offset_from_rva(0x1010), 0x210)

    def test_overlapping_raw_ranges_first_section_owns_offset(self):
        """When raw ranges overlap, get_section_by_offset returns the first
        section that contains the offset; offset->RVA stays self-consistent."""

        data = build_pe(sections=self._adjacent_sections())
        pe = pefile.PE(data=data)

        # File offset 0x400 is claimed by both sections; .text wins.
        self.assertEqual(
            pe.get_section_by_offset(0x400).Name.rstrip(b"\0"), b".text"
        )
        self.assertEqual(pe.get_rva_from_offset(0x300), 0x1100)
        # The later, non-overlapped part of .rdata resolves normally.
        self.assertEqual(
            pe.get_section_by_offset(0x7FF).Name.rstrip(b"\0"), b".rdata"
        )

    def test_header_region_offset_maps_to_identical_rva(self):
        """Offsets before the first section describe the headers, where RVA and
        file offset are the same value."""

        data = build_pe(sections=self._adjacent_sections())
        pe = pefile.PE(data=data)

        self.assertEqual(pe.get_rva_from_offset(0x40), 0x40)
        self.assertEqual(pe.get_offset_from_rva(0x40), 0x40)


class TestOutOfBoundsDirectoryReferences(unittest.TestCase):
    """Data directories whose RVA escapes every section and the file."""

    def _single_section(self):
        return [
            SectionSpec(b".text", 0x200, 0x1000, 0x200, 0x200)
        ]

    def test_directory_rva_past_end_of_file_raises_and_warns(self):
        """An import directory pointing outside the file is an out-of-bounds
        reference: offset resolution raises and the directory is not attached."""

        bad_rva = 0x99999
        data = build_pe(
            sections=self._single_section(),
            directories={
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]: (
                    bad_rva,
                    0x14,
                )
            },
        )
        pe = pefile.PE(data=data)

        with self.assertRaises(pefile.PEFormatError):
            pe.get_offset_from_rva(bad_rva)
        # The scalar accessors degrade to None instead of raising.
        self.assertIsNone(pe.get_dword_at_rva(bad_rva))
        # The failed directory is simply absent, with a recorded warning.
        self.assertFalse(hasattr(pe, "DIRECTORY_ENTRY_IMPORT"))
        self.assertTrue(
            any("import directory" in warning for warning in pe.get_warnings())
        )

    def test_rva_just_past_section_end_is_out_of_bounds(self):
        """The first RVA beyond the section's half-open range cannot be fetched,
        even though it sits well inside the nominal image."""

        data = build_pe(sections=self._single_section())
        pe = pefile.PE(data=data)

        self.assertIsNone(pe.get_section_by_rva(0x1200))
        with self.assertRaises(pefile.PEFormatError):
            pe.get_data(0x1200, 4)
        self.assertIsNone(pe.get_dword_at_rva(0x1200))

    def test_rva_at_section_start_is_tolerable(self):
        """A directory whose RVA lands exactly on a section start is a tolerable
        layout and must parse without a fatal error."""

        data = build_pe(
            sections=self._single_section(),
            directories={
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]: (
                    0x1000,
                    0,
                )
            },
        )
        pe = pefile.PE(data=data)
        # The RVA resolves cleanly to the section's first raw byte.
        self.assertEqual(pe.get_offset_from_rva(0x1000), 0x200)
        self.assertTrue(
            all("ebug" not in warning for warning in pe.get_warnings())
        )

    def test_partial_read_past_virtual_size_is_silently_clipped(self):
        """A read that starts inside a section but runs past its virtual end is
        a tolerable, clipped read: the returned bytes stop at the boundary."""

        data = build_pe(sections=self._single_section())
        pe = pefile.PE(data=data)

        # Only 0x10 bytes exist between 0x11F0 and the end at 0x1200.
        self.assertEqual(len(pe.get_data(0x11F0, 0x100)), 0x10)

    def test_failed_directory_does_not_affect_later_parsing(self):
        """A bad import directory must not poison independent parsing: a fresh
        parse of a valid relocation directory and dump_info/dump_dict keep
        working and produce deterministic results."""

        data, _ = build_import_pe()
        # Corrupt only the import directory RVA, leaving relocations intact.
        pe = pefile.PE(data=data, fast_load=True)
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ].VirtualAddress = 0x88888

        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"],
            ]
        )

        self.assertFalse(hasattr(pe, "DIRECTORY_ENTRY_IMPORT"))
        # The relocation directory, parsed afterwards, is fully populated.
        self.assertTrue(hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"))
        self.assertEqual(
            pe.DIRECTORY_ENTRY_BASERELOC[0].struct.VirtualAddress, 0x1000
        )
        # Structural dumping still succeeds, proving state stayed consistent.
        self.assertIsInstance(pe.dump_info(), str)
        self.assertIsInstance(pe.dump_dict(), dict)

        # Two independent parses of the same malformed input agree.
        first = pefile.PE(data=data, fast_load=True)
        first.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ].VirtualAddress = 0x88888
        first.parse_data_directories()
        second = pefile.PE(data=data, fast_load=True)
        second.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ].VirtualAddress = 0x88888
        second.parse_data_directories()
        self.assertEqual(first.dump_info(), second.dump_info())


class TestMemoryMappedImageAndSizeOfImage(unittest.TestCase):
    """The mapped image must be bounded by real content, never by header lies."""

    def test_inflated_size_of_image_does_not_allocate_giant_image(self):
        """A pathological SizeOfImage must not cause get_memory_mapped_image to
        allocate a buffer proportional to it; output is bounded by the sections."""

        sections = [
            SectionSpec(b".text", 0x1000, 0x1000, 0x400, 0x200)
        ]
        data = build_pe(sections=sections, size_of_image=0x7FFFFFFF)
        pe = pefile.PE(data=data)

        image = pe.get_memory_mapped_image()
        # The claimed image is ~2 GiB; the actual mapped buffer stays tiny and
        # is anchored to the section's real virtual extent, not SizeOfImage.
        self.assertLess(len(image), 0x10000)
        self.assertEqual(len(image), 0x2000)

    def test_far_virtual_address_section_is_skipped_within_cap(self):
        """A section whose VirtualAddress exceeds max_virtual_address is skipped
        rather than forcing a huge zero-filled allocation."""

        sections = [
            SectionSpec(b".text", 0x100, 0x1000, 0x200, 0x200),
            # 0x10001000 is beyond get_memory_mapped_image's default
            # max_virtual_address cap (0x10000000).
            SectionSpec(b".far", 0x100, 0x10001000, 0x200, 0x400),
        ]
        data = build_pe(sections=sections, size_of_image=0x10002000)
        pe = pefile.PE(data=data)

        image = pe.get_memory_mapped_image()
        # The 0x10001000 section is beyond the default cap and must be dropped,
        # keeping the image small.
        self.assertLess(len(image), 0x10000)

    def test_mapped_image_uses_virtual_extent_not_raw_padding(self):
        """Raw file padding past VirtualSize must not leak into the mapped view,
        while BSS beyond SizeOfRawData must be zero-filled (both PE flavours)."""

        for plus in (False, True):
            with self.subTest(pe="PE32+" if plus else "PE32"):
                # VirtualSize 0x800 but 0x1000 raw bytes: trailing raw padding is
                # discarded by the loader.
                sections = [
                    SectionSpec(
                        b".text",
                        0x800,
                        0x1000,
                        0x1000,
                        0x200,
                        data=bytes((SENTINEL,)) * 0x1000,
                    )
                ]
                data = build_pe(plus=plus, sections=sections)
                pe = pefile.PE(data=data)
                image = pe.get_memory_mapped_image()

                self.assertEqual(len(image), 0x1800)
                self.assertEqual(
                    image[0x1000:0x1800], bytes((SENTINEL,)) * 0x800
                )

    def test_mapped_image_bss_gap_is_zero_filled(self):
        """When VirtualSize exceeds SizeOfRawData the uninitialized tail is BSS
        and must read back as zeroes in the mapped view."""

        sections = [
            SectionSpec(
                b".text",
                0x1500,
                0x1000,
                0x1000,
                0x200,
                data=bytes((SENTINEL,)) * 0x1000,
            )
        ]
        data = build_pe(sections=sections)
        pe = pefile.PE(data=data)
        image = pe.get_memory_mapped_image()

        self.assertEqual(image[0x2000:0x2500], b"\0" * 0x500)


class TestEntryPointAndImportInterpretation(unittest.TestCase):
    """Entry point and import address interpretation across views and rebases."""

    def test_entry_point_consistent_between_file_and_mapped_views(self):
        """A valid entry point resolves to the same byte via get_data, the raw
        file offset and the memory-mapped image."""

        payload = b"\xC3" + bytes((SENTINEL,)) * 0x1FF  # first byte is RET
        sections = [
            SectionSpec(b".text", 0x200, 0x1000, 0x200, 0x200, data=payload)
        ]
        data = build_pe(sections=sections, entry_point=0x1000)
        pe = pefile.PE(data=data)

        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        offset = pe.get_offset_from_rva(entry_point)
        mapped = pe.get_memory_mapped_image()

        self.assertEqual(pe.get_data(entry_point, 1), b"\xC3")
        self.assertEqual(data[offset : offset + 1], b"\xC3")
        self.assertEqual(mapped[entry_point : entry_point + 1], b"\xC3")
        # No out-of-bounds entry-point warning for an in-range EP.
        self.assertTrue(
            all(
                "AddressOfEntryPoint" not in warning
                for warning in pe.get_warnings()
            )
        )

    def test_out_of_range_entry_point_is_warned_but_parsing_continues(self):
        """An entry point outside every section is a tolerable anomaly: a warning
        is recorded but the file still parses and the image is produced."""

        sections = [SectionSpec(b".text", 0x200, 0x1000, 0x200, 0x200)]
        data = build_pe(sections=sections, entry_point=0x9000)
        pe = pefile.PE(data=data)

        self.assertTrue(
            any(
                "AddressOfEntryPoint lies outside" in warning
                for warning in pe.get_warnings()
            )
        )
        # The object is otherwise usable.
        self.assertIsNotNone(pe.get_memory_mapped_image())

    def test_imports_parse_in_both_pe32_and_pe32_plus(self):
        """The synthesized import directory yields the expected DLL/symbol for
        both address sizes, proving ILT, IAT and hint/name interpretation agree."""

        for plus in (False, True):
            with self.subTest(pe="PE32+" if plus else "PE32"):
                data, layout = build_import_pe(plus=plus)
                pe = pefile.PE(data=data)

                self.assertEqual(len(pe.DIRECTORY_ENTRY_IMPORT), 1)
                descriptor = pe.DIRECTORY_ENTRY_IMPORT[0]
                self.assertEqual(descriptor.dll, b"KERNEL32.DLL")
                self.assertEqual(
                    [symbol.name for symbol in descriptor.imports],
                    [b"ExitProcess"],
                )
                # The IAT slot initially holds the RVA of the hint/name record.
                getter = pe.get_qword_at_rva if plus else pe.get_dword_at_rva
                self.assertEqual(
                    getter(layout["iat_rva"]), layout["original_iat_value"]
                )

    def test_relocated_directory_address_consistent_across_views(self):
        """After a rebase the IAT directory slot is fixed by the relocation delta
        and the change is visible identically through the raw RVA accessor and
        the rebased memory-mapped image, while a non-relocated byte is untouched.
        """

        new_bases = {False: 0x500000, True: 0x150000000}
        masks = {False: 0xFFFFFFFF, True: 0xFFFFFFFFFFFFFFFF}

        for plus in (False, True):
            with self.subTest(pe="PE32+" if plus else "PE32"):
                data, layout = build_import_pe(plus=plus)
                thunk_size = layout["thunk_size"]
                iat_rva = layout["iat_rva"]

                # Reference image without rebasing.
                base_pe = pefile.PE(data=data)
                original_image = base_pe.get_memory_mapped_image()
                getter = base_pe.get_qword_at_rva if plus else base_pe.get_dword_at_rva
                original_value = getter(iat_rva)

                # get_memory_mapped_image(ImageBase=...) applies relocations to a
                # transient copy and must not mutate the underlying file data.
                rebase_pe = pefile.PE(data=data)
                original_image_base = rebase_pe.OPTIONAL_HEADER.ImageBase
                rebased_image = rebase_pe.get_memory_mapped_image(
                    ImageBase=new_bases[plus]
                )
                self.assertEqual(bytes(rebase_pe.__data__), bytes(data))

                delta = new_bases[plus] - original_image_base
                expected_value = (original_value + delta) & masks[plus]
                self.assertEqual(
                    int.from_bytes(
                        rebased_image[iat_rva : iat_rva + thunk_size], "little"
                    ),
                    expected_value,
                )
                # The un-rebased reference image still carries the original value.
                self.assertEqual(
                    int.from_bytes(
                        original_image[iat_rva : iat_rva + thunk_size], "little"
                    ),
                    original_value,
                )

                # A byte outside the relocated slot is identical in both views.
                probe_rva = layout["hint_name_rva"]
                self.assertEqual(
                    original_image[probe_rva : probe_rva + 4],
                    rebased_image[probe_rva : probe_rva + 4],
                )

                # relocate_image() performs the same fix-up permanently and it is
                # readable back through the RVA scalar accessor.
                permanent_pe = pefile.PE(data=data)
                permanent_pe.relocate_image(new_bases[plus])
                permanent_getter = (
                    permanent_pe.get_qword_at_rva
                    if plus
                    else permanent_pe.get_dword_at_rva
                )
                self.assertEqual(permanent_getter(iat_rva), expected_value)

    def test_relocation_beyond_real_content_fails_safely(self):
        """A relocation directory whose RVA escapes the file must not raise out
        of the parser; it yields no blocks and leaves a warning, and the mapped
        image stays bounded rather than expanding to SizeOfImage."""

        data, _ = build_import_pe()
        pe = pefile.PE(data=data, fast_load=True)
        # Inflate SizeOfImage so a naive implementation might trust the layout,
        # then point the relocation directory at an RVA with no backing bytes.
        pe.OPTIONAL_HEADER.SizeOfImage = 0x40000000
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]
        ].VirtualAddress = 0x30000000

        relocations = pe.parse_relocations_directory(0x30000000, 10)
        self.assertEqual(relocations, [])
        self.assertTrue(
            any("relocation" in warning.lower() for warning in pe.get_warnings())
        )
        # Despite the 1 GiB SizeOfImage, no giant image is produced.
        self.assertLess(len(pe.get_memory_mapped_image()), 0x10000)


if __name__ == "__main__":
    unittest.main()
