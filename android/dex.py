#!/usr/bin/env python3
import dataclasses
import unittest
from binascii import unhexlify
from enum import IntEnum, IntFlag
from struct import pack, unpack
from typing import Any, Dict, List, NewType, Optional, Tuple, Union, cast

from .smali import (
    disassemble_pseudoinstructions,
    SmaliPackedSwitchPayload,
    SmaliFillArrayDataPayload,
    SmaliSparseSwitchPayload,
)

try:
    from compat import Endianness, log_debug, log_error, log_warn
except ModuleNotFoundError:
    from .compat import Endianness, log_debug, log_error, log_warn


#
# LEB128
#


def parse_sleb128(data: bytes) -> Tuple[int, int]:
    """Parse sleb128 and return (value, length in bytes)."""
    i = 0
    val = data[i] & 0x7F
    while data[i] & 0x80:
        i += 1
        val |= (data[i] & 0x7F) << (7 * i)
    if val & (0x40 << (i * 7)):
        for j in range(6 + i * 7, -1, -1):
            if not (val | (1 << j)):
                break
            val ^= 1 << j
        val = -1 - val
    return val, i + 1


def parse_uleb128(data: bytes) -> Tuple[int, int]:
    """Parse uleb128 and return (value, length in bytes)."""
    i = 0
    val = data[i] & 0x7F
    while data[i] & 0x80:
        i += 1
        val |= (data[i] & 0x7F) << (7 * i)
    return val, i + 1


def parse_uleb128p1(data: bytes) -> Tuple[int, int]:
    """Parse uleb128p1 and return (value, length in bytes)."""
    i = 0
    val = data[i] & 0x7F
    while data[i] & 0x80:
        i += 1
        val |= (data[i] & 0x7F) << (7 * i)
    return val - 1, i + 1


class TestLeb128(unittest.TestCase):
    def test_example1(self) -> None:
        """First example from https://source.android.com/devices/tech/dalvik/dex-format.html#leb128"""
        data = b"\x00XXXXX"
        self.assertEqual(parse_sleb128(data), (0, 1))
        self.assertEqual(parse_uleb128(data), (0, 1))
        self.assertEqual(parse_uleb128p1(data), (-1, 1))

    def test_example2(self) -> None:
        """Second example from https://source.android.com/devices/tech/dalvik/dex-format.html#leb128"""
        data = b"\x01XXXXX"
        self.assertEqual(parse_sleb128(data), (1, 1))
        self.assertEqual(parse_uleb128(data), (1, 1))
        self.assertEqual(parse_uleb128p1(data), (0, 1))

    def test_example3(self) -> None:
        """Third example from https://source.android.com/devices/tech/dalvik/dex-format.html#leb128"""
        data = b"\x7fXXXXX"
        self.assertEqual(parse_sleb128(data), (-1, 1))
        self.assertEqual(parse_uleb128(data), (127, 1))
        self.assertEqual(parse_uleb128p1(data), (126, 1))

    def test_example4(self) -> None:
        """Fourth example from https://source.android.com/devices/tech/dalvik/dex-format.html#leb128"""
        data = b"\x80\x7fXXXXX"
        self.assertEqual(parse_sleb128(data), (-128, 2))
        self.assertEqual(parse_uleb128(data), (16256, 2))
        self.assertEqual(parse_uleb128p1(data), (16255, 2))

    def test_5byte(self) -> None:
        data = b"\xff\xff\xff\xff\x0fXXXXX"
        self.assertEqual(parse_sleb128(data), (0xFFFFFFFF, 5))
        self.assertEqual(parse_uleb128(data), (0xFFFFFFFF, 5))
        self.assertEqual(parse_uleb128p1(data), (0xFFFFFFFE, 5))

    def test_wikipedia_signed(self) -> None:
        """Signed example from https://en.wikipedia.org/wiki/LEB128"""
        data = b"\x9b\xf1\x59XXXXX"
        self.assertEqual(parse_sleb128(data), (-624485, 3))

    def test_wikipedia_unsigned(self) -> None:
        """Unsigned example from https://en.wikipedia.org/wiki/LEB128"""
        data = b"\xe5\x8e\x26XXXXX"
        self.assertEqual(parse_uleb128(data), (624485, 3))

    def test_gas_signed(self) -> None:
        """Signed examples from binutils gas
        https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob;f=gas/testsuite/gas/all/sleb128.s;h=e8997ca175d4fcf05374cd45a62ccbc4630c3d1a;hb=refs/heads/master
        https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob;f=gas/testsuite/gas/all/sleb128.d;h=993921ef5be6d8d605c61a3799225a8e3770adcd;hb=refs/heads/master

        The Dex format specifies that all *LEB128 values are 32-bit and <=5
        bytes, but might as well over-test.
        """
        tests = {
            "90e4d0b207": (0x76543210, 5),
            "8080808008": (0x80000000, 5),
            "a18695bb08": (0x87654321, 5),
            "ffffffff0f": (0xFFFFFFFF, 5),
            "f09bafcd78": (-0x76543210, 5),
            "8080808078": (-0x80000000, 5),
            "dff9eac477": (-0x87654321, 5),
            "8180808070": (-0xFFFFFFFF, 5),
            "ef9bafcdf8acd19101": (0x123456789ABCDEF, 9),
            "91e4d0b287d3aeee7e": (-0x123456789ABCDEF, 9),
            "81808080808060": (-0x7FFFFFFFFFFF, 7),
            "80808080808060": (-0x800000000000, 7),
            "8180808080808080807f": (-0x7FFFFFFFFFFFFFFF, 10),
            "8080808080808080807f": (-0x8000000000000000, 10),
            "8080808070": (-0x100000000, 5),
            "80808080808040": (-0x1000000000000, 7),
        }
        for data in tests:
            self.assertEqual(parse_sleb128(unhexlify(data)), tests[data])


#
# MUTF-8
#


def parse_mutf8(data: bytes) -> Tuple[str, int]:
    """Parse MUTF-8 and return (string, length in bytes)."""
    chars = list()  # list of strings
    part_of_surrogate_pair = False
    surrogate_first = 0
    i = 0
    while data[i] != 0:
        if data[i] & 0x80:
            if data[i] & 0x20:
                # 3 bytes
                code_point = ord(data[i : i + 3].decode("utf-8", "surrogatepass"))
                if part_of_surrogate_pair:
                    # Second part of pair
                    # Use little-endian encoding for python
                    bb = pack("<H", surrogate_first) + pack("<H", code_point)
                    chars.append(bb.decode("utf-16", "surrogatepass"))
                    part_of_surrogate_pair = False
                else:
                    if code_point < 0xD7FF or 0xE000 < code_point < 0xFFFF:
                        # Not part of pair
                        chars.append(chr(code_point))
                    else:
                        # First part of pair
                        part_of_surrogate_pair = True
                        surrogate_first = code_point
                i += 3
            else:
                # 2 bytes
                if data[i : i + 2] == b"\xc0\x80":
                    chars.append("\x00")
                else:
                    chars.append(data[i : i + 2].decode("utf-8"))
                i += 2
        else:
            # single byte
            chars.append(chr(data[i]))
            i += 1
    if part_of_surrogate_pair:
        chars.append(pack("<H", surrogate_first).decode("utf-16", "surrogatepass"))
    return "".join(chars), i + 1


class TestMutf8(unittest.TestCase):
    def test_empty_string(self) -> None:
        self.assertEqual(parse_mutf8(b"\x00AAAAA"), ("", 1))

    def test_null_byte(self) -> None:
        self.assertEqual(parse_mutf8(b"\xc0\x80\x00"), ("\x00", 3))

    def test_one_byte_chars(self) -> None:
        self.assertEqual(parse_mutf8(b"A\x00"), ("A", 2))
        self.assertEqual(parse_mutf8(b"\x01\x00"), ("\x01", 2))
        self.assertEqual(parse_mutf8(b" \x00"), (" ", 2))
        self.assertEqual(parse_mutf8(b"\x7e\x00"), ("~", 2))
        self.assertEqual(parse_mutf8(b"hello\x00"), ("hello", 6))

    def test_two_byte_chars(self) -> None:
        self.assertEqual(parse_mutf8(b"\xc2\xa2\x00"), ("¢", 3))
        self.assertEqual(parse_mutf8(b"\xc3\x98\x00"), ("Ø", 3))
        self.assertEqual(parse_mutf8(b"\xc3\xa6\x00"), ("æ", 3))
        self.assertEqual(parse_mutf8(b"\xcf\x84\x00"), ("τ", 3))
        self.assertEqual(parse_mutf8(b"\xc2\xa0\x00"), ("\xa0", 3))
        self.assertEqual(parse_mutf8(b"\xdf\xbf\x00"), ("\u07ff", 3))

    def test_three_byte_chars(self) -> None:
        self.assertEqual(parse_mutf8(b"\xe0\xa4\xb9\x00"), ("\u0939", 4))
        self.assertEqual(parse_mutf8(b"\xe2\x82\xac\x00"), ("€", 4))
        self.assertEqual(parse_mutf8(b"\xe3\x81\x82\x00"), ("あ", 4))

    def test_surrogate_singleton(self) -> None:
        self.assertEqual(parse_mutf8(b"\xed\xa0\x80\x00"), ("\ud800", 4))

    def test_six_byte_chars(self) -> None:
        self.assertEqual(
            parse_mutf8(b"\xed\xae\x80\xed\xb0\x80\x00"), ("\U000f0000", 7)
        )


#
# DexFile
#


DexType = NewType("DexType", str)
# Offset from beginning of file
FileOffset = NewType("FileOffset", int)
# Offset from beginning of data section
# DataOffset = NewType("DataOffset", int)
# Offset from beginning of section
# SectionOffset = NewType("SectionOffset", int)
# Word offset from beginning of code block
BytecodeAddress = NewType("BytecodeAddress", int)

NO_INDEX = 0xFFFFFFFF


@dataclasses.dataclass
class MapListItem:
    size: int
    offset: FileOffset


class MapType(IntEnum):
    """Dex map_item type codes

    https://source.android.com/devices/tech/dalvik/dex-format.html#type-codes
    """

    TYPE_HEADER_ITEM = 0x0000
    TYPE_STRING_ID_ITEM = 0x0001
    TYPE_TYPE_ID_ITEM = 0x0002
    TYPE_PROTO_ID_ITEM = 0x0003
    TYPE_FIELD_ID_ITEM = 0x0004
    TYPE_METHOD_ID_ITEM = 0x0005
    TYPE_CLASS_DEF_ITEM = 0x0006
    TYPE_CALL_SITE_ID_ITEM = 0x0007
    TYPE_METHOD_HANDLE_ITEM = 0x0008
    TYPE_MAP_LIST = 0x1000
    TYPE_TYPE_LIST = 0x1001
    TYPE_ANNOTATION_SET_REF_LIST = 0x1002
    TYPE_ANNOTATION_SET_ITEM = 0x1003
    TYPE_CLASS_DATA_ITEM = 0x2000
    TYPE_CODE_ITEM = 0x2001
    TYPE_STRING_DATA_ITEM = 0x2002
    TYPE_DEBUG_INFO_ITEM = 0x2003
    TYPE_ANNOTATION_ITEM = 0x2004
    TYPE_ENCODED_ARRAY_ITEM = 0x2005
    TYPE_ANNOTATIONS_DIRECTORY_ITEM = 0x2006


class MethodHandleType(IntEnum):
    """Dex method_handle_item type codes

    https://source.android.com/devices/tech/dalvik/dex-format.html#method-handle-type-codes
    """

    METHOD_HANDLE_TYPE_STATIC_PUT = 0x00
    METHOD_HANDLE_TYPE_STATIC_GET = 0x01
    METHOD_HANDLE_TYPE_INSTANCE_PUT = 0x02
    METHOD_HANDLE_TYPE_INSTANCE_GET = 0x03
    METHOD_HANDLE_TYPE_INVOKE_STATIC = 0x04
    METHOD_HANDLE_TYPE_INVOKE_INSTANCE = 0x05
    METHOD_HANDLE_TYPE_INVOKE_CONSTRUCTOR = 0x06
    METHOD_HANDLE_TYPE_INVOKE_DIRECT = 0x07
    METHOD_HANDLE_TYPE_INVOKE_INTERFACE = 0x08


class AccessFlagEnum(IntFlag):
    """access_flags bitfield values for classes, fields, and methods

    e.g. public, final, volatile
    https://source.android.com/devices/tech/dalvik/dex-format.html#access-flags
    """

    ACC_PUBLIC = 0x1
    ACC_PRIVATE = 0x2
    ACC_PROTECTED = 0x4
    ACC_STATIC = 0x8
    ACC_FINAL = 0x10
    ACC_SYNCHRONIZED = 0x20
    ACC_VOLATILE = 0x40
    ACC_BRIDGE = 0x40
    ACC_TRANSIENT = 0x80
    ACC_VARARGS = 0x80
    ACC_NATIVE = 0x100
    ACC_INTERFACE = 0x200
    ACC_ABSTRACT = 0x400
    ACC_STRICT = 0x800
    ACC_SYNTHETIC = 0x1000
    ACC_ANNOTATION = 0x2000
    ACC_ENUM = 0x4000
    unused = 0x8000
    ACC_CONSTRUCTOR = 0x10000
    ACC_DECLARED_SYNCHRONIZED = 0x20000


class AccessFlag:
    def __init__(self, val: int, context: str):
        if context not in ("method", "field", "class"):
            raise ValueError(f"Context {context} not valid for AccessFlag")
        self.value = val
        self.context = context

    def __str__(self) -> str:
        """Make human-readable string.

        In Java-land, the order is:
        public protected private abstract static final transient volatile
        synchronized native strictfp interface.
        Sources:
        https://developer.android.com/reference/java/lang/reflect/Modifier.html#toString(int)
        http://cr.openjdk.java.net/~alundblad/styleguide/index-v6.html#toc-modifiers
        https://docs.oracle.com/javase/specs/jls/se11/html/jls-8.html#jls-8.1.1

        In Dex-land, dexgen orders them as:
        public private protected static final super synchronized bridge
        volatile varargs transient native interface abstract strictfp synthetic
        annotation enum constructor declared_synchronized.
        Sources:
        https://android.googlesource.com/platform/dalvik2/+/refs/heads/master/dexgen/src/com/android/dexgen/rop/code/AccessFlags.java#297
        https://github.com/JesusFreke/smali/blob/239b64ba003accffd1b0cf7c1c58d35435f5e94a/dexlib2/src/main/java/org/jf/dexlib2/AccessFlags.java
        """
        val = self.value
        res = list()
        if val & AccessFlagEnum.ACC_PUBLIC:
            res.append("public")
            val ^= AccessFlagEnum.ACC_PUBLIC
        if val & AccessFlagEnum.ACC_PRIVATE:
            res.append("private")
            val ^= AccessFlagEnum.ACC_PRIVATE
        if val & AccessFlagEnum.ACC_PROTECTED:
            res.append("protected")
            val ^= AccessFlagEnum.ACC_PROTECTED
        if val & AccessFlagEnum.ACC_STATIC:
            res.append("static")
            val ^= AccessFlagEnum.ACC_STATIC
        if val & AccessFlagEnum.ACC_FINAL:
            res.append("final")
            val ^= AccessFlagEnum.ACC_FINAL
        if val & AccessFlagEnum.ACC_SYNCHRONIZED:
            if self.context == "class":
                res.append("super")
            else:
                res.append("synchronized")
            val ^= AccessFlagEnum.ACC_SYNCHRONIZED
        if val & AccessFlagEnum.ACC_VOLATILE:
            if self.context == "method":
                res.append("bridge")
            else:
                res.append("volatile")
            val ^= AccessFlagEnum.ACC_VOLATILE
        if val & AccessFlagEnum.ACC_TRANSIENT:
            if self.context == "method":
                res.append("varargs")
            else:
                res.append("transient")
            val ^= AccessFlagEnum.ACC_TRANSIENT
        if val & AccessFlagEnum.ACC_NATIVE:
            res.append("native")
            val ^= AccessFlagEnum.ACC_NATIVE
        if val & AccessFlagEnum.ACC_INTERFACE:
            res.append("interface")
            val ^= AccessFlagEnum.ACC_INTERFACE
        if val & AccessFlagEnum.ACC_ABSTRACT:
            res.append("abstract")
            val ^= AccessFlagEnum.ACC_ABSTRACT
        if val & AccessFlagEnum.ACC_STRICT:
            res.append("strictfp")
            val ^= AccessFlagEnum.ACC_STRICT
        if val & AccessFlagEnum.ACC_SYNTHETIC:
            res.append("synthetic")
            val ^= AccessFlagEnum.ACC_SYNTHETIC
        if val & AccessFlagEnum.ACC_ANNOTATION:
            res.append("annotation")
            val ^= AccessFlagEnum.ACC_ANNOTATION
        if val & AccessFlagEnum.ACC_ENUM:
            res.append("enum")
            val ^= AccessFlagEnum.ACC_ENUM
        if val & AccessFlagEnum.ACC_CONSTRUCTOR:
            res.append("constructor")
            val ^= AccessFlagEnum.ACC_CONSTRUCTOR
        if val & AccessFlagEnum.ACC_DECLARED_SYNCHRONIZED:
            res.append("declared_synchronized")
            val ^= AccessFlagEnum.ACC_DECLARED_SYNCHRONIZED

        if val:
            raise ValueError(
                f"Failed to make string with all access flags. Value: {hex(self.value)}. Remaining: {hex(val)}"
            )
        if len(res):
            return " ".join(res) + " "
        else:
            return " ".join(res)


class TestAccessFlag(unittest.TestCase):
    def test_none(self) -> None:
        """No modifiers."""
        self.assertEqual(str(AccessFlag(0, "class")), "")
        self.assertEqual(str(AccessFlag(0, "method")), "")
        self.assertEqual(str(AccessFlag(0, "field")), "")

    def test_single(self) -> None:
        """Single modifier."""
        self.assertEqual(str(AccessFlag(AccessFlagEnum.ACC_PUBLIC, "class")), "public")

    def test_sorted(self) -> None:
        """Cases with specified orders."""
        self.assertEqual(
            str(
                AccessFlag(
                    AccessFlagEnum.ACC_PUBLIC | AccessFlagEnum.ACC_STATIC, "method"
                )
            ),
            "public static",
        )

    # TODO


class ValueType(IntEnum):
    """Dex encoded_value type codes

    https://source.android.com/devices/tech/dalvik/dex-format.html#value-formats
    """

    VALUE_BYTE = 0x00
    VALUE_SHORT = 0x02
    VALUE_CHAR = 0x03
    VALUE_INT = 0x04
    VALUE_LONG = 0x06
    VALUE_FLOAT = 0x10
    VALUE_DOUBLE = 0x11
    VALUE_METHOD_TYPE = 0x15
    VALUE_METHOD_HANDLE = 0x16
    VALUE_STRING = 0x17
    VALUE_TYPE = 0x18
    VALUE_FIELD = 0x19
    VALUE_METHOD = 0x1A
    VALUE_ENUM = 0x1B
    VALUE_ARRAY = 0x1C
    VALUE_ANNOTATION = 0x1D
    VALUE_NULL = 0x1E
    VALUE_BOOLEAN = 0x1F


@dataclasses.dataclass
class DexValue:
    """Dex encoded_value object

    https://source.android.com/devices/tech/dalvik/dex-format.html#encoding
    """

    type_: ValueType
    value: Any


DexEncodedArray = List[DexValue]


@dataclasses.dataclass
class DexProtoId:
    """Dex proto_id_item object

    https://source.android.com/devices/tech/dalvik/dex-format.html#encoding
    """

    shorty: str
    return_type: DexType
    parameters: List[DexType]


@dataclasses.dataclass
class DexEncodedCatchHandler:
    """Dex encoded_catch_handler object

    https://source.android.com/devices/tech/dalvik/dex-format.html#encoded-catch-handler
    """

    size: int
    handlers: List[Tuple[DexType, int]]
    catch_all_addr: BytecodeAddress = cast(BytecodeAddress, -1)


@dataclasses.dataclass
class DexTryItem:
    """Dex try_item object

    https://source.android.com/devices/tech/dalvik/dex-format.html#type-item
    """

    start_addr: BytecodeAddress
    insn_count: int
    handler: DexEncodedCatchHandler


@dataclasses.dataclass
class DexCodeItem:
    """Dex code_item object

    https://source.android.com/devices/tech/dalvik/dex-format.html#code-item
    """

    registers_size: int
    ins_size: int
    outs_size: int
    tries_size: int
    debug_info: FileOffset  # TODO debug
    insns_size: int
    insns: bytes
    _insns_off: FileOffset
    tries: List[DexTryItem]


@dataclasses.dataclass
class DexFieldId:
    """Dex field_id_item object

    https://source.android.com/devices/tech/dalvik/dex-format.html#field-id-item
    """

    class_: DexType
    type_: DexType
    name: str


@dataclasses.dataclass
class DexEncodedField:
    """Dex encoded_field object

    https://source.android.com/devices/tech/dalvik/dex-format.html#encoded-field-format
    """

    field: DexFieldId
    access_flags: AccessFlag


@dataclasses.dataclass
class DexMethodId:
    """Dex method_id_item object

    https://source.android.com/devices/tech/dalvik/dex-format.html#method-id-item
    """

    class_: DexType
    proto: DexProtoId
    name: str
    _insns_off: Optional[FileOffset] = None


@dataclasses.dataclass
class DexEncodedMethod:
    """Dex encoded_method

    https://source.android.com/devices/tech/dalvik/dex-format.html#encoded-method
    """

    method: DexMethodId
    access_flags: AccessFlag
    code: Optional[DexCodeItem]


@dataclasses.dataclass
class DexMethodHandle:
    """Dex method_handle_item object

    https://source.android.com/devices/tech/dalvik/dex-format.html#method-handle-item
    """

    type_: MethodHandleType
    field_or_method_id: Union[DexFieldId, DexMethodId]


@dataclasses.dataclass
class DexClassData:
    static_fields: List[DexEncodedField]
    instance_fields: List[DexEncodedField]
    direct_methods: List[DexEncodedMethod]
    virtual_methods: List[DexEncodedMethod]


@dataclasses.dataclass
class DexClassDef:
    class_type: DexType
    access_flags: AccessFlag
    superclass: Optional[DexType]
    interfaces: Optional[List[DexType]]
    source_file: Optional[str]
    annotations: Optional[FileOffset]  # TODO
    class_data: Optional[DexClassData]
    static_values: Optional[List[DexValue]]


def _parse_ushort(endianness: Endianness, data: bytes) -> int:
    if endianness == Endianness.LittleEndian:
        return cast(int, unpack("<H", data)[0])
    else:
        return cast(int, unpack(">H", data)[0])


def _parse_uint(endianness: Endianness, data: bytes) -> int:
    if endianness == Endianness.LittleEndian:
        return cast(int, unpack("<I", data)[0])
    else:
        return cast(int, unpack(">I", data)[0])


class DexFile(object):
    """Object to contain the entire parsed Dex."""

    def _parse_ushort(self, data: bytes) -> int:
        return _parse_ushort(self.endianness, data)

    def _parse_uint(self, data: bytes) -> int:
        return _parse_uint(self.endianness, data)

    def __init__(self, data: bytes) -> None:
        endian_bytes = data[40:44]
        if endian_bytes == b"\x12\x34\x56\x78":
            self.endianness = Endianness.BigEndian
        elif endian_bytes == b"\x78\x56\x34\x12":
            self.endianness = Endianness.LittleEndian
        else:
            raise ValueError(f'Invalid endianness found: {endian_bytes!r}')
        if self.endianness == Endianness.BigEndian:
            # It is likely that these do not exist at all, but who knows
            log_warn(
                "This is a big-endian file. The author was unable to find one of these to test with, so there will probably be errors. Please open an issue with a copy of this file!"
            )

        map_off = self._parse_uint(data[52:56])
        map_size = self._parse_uint(data[map_off : map_off + 4])

        # Parse map list items. First we collect them all, and then we parse
        # them in an order that satisfies dependency relationships. For
        # example, string_ids/strings need to be parsed first, and type_ids
        # need to be parsed before type_lists, which need to be parsed before
        # protos. Strings are the first items in the map list, but protos come
        # before type_lists, so we can't just go in order.
        map_list = dict()
        for i in range(map_off + 4, 4 + map_off + map_size * 12, 12):
            item_type = self._parse_ushort(data[i : i + 2])
            item_size = self._parse_uint(data[i + 4 : i + 8])
            item_offset = cast(FileOffset, self._parse_uint(data[i + 8 : i + 12]))
            # log_debug(f'found type: "{item_type}", "{MapType(item_type).name}"')
            map_list[item_type] = MapListItem(size=item_size, offset=item_offset)

        # Ignore sections we don't need to reparse
        map_list.pop(MapType.TYPE_HEADER_ITEM)
        # The map list is what this part is parsing. No recursion
        map_list.pop(MapType.TYPE_MAP_LIST)

        # string_ids and strings
        mi = map_list.pop(MapType.TYPE_STRING_ID_ITEM)
        self.parse_string_ids(
            data[mi.offset : mi.offset + 4 * mi.size], mi.size, mi.offset
        )
        self.make_strings(data)
        del self.string_ids
        map_list.pop(MapType.TYPE_STRING_DATA_ITEM)  # Already handled

        # Then, type_ids and type_lists
        mi = map_list.pop(MapType.TYPE_TYPE_ID_ITEM)
        self.parse_type_ids(
            data[mi.offset : mi.offset + 4 * mi.size], mi.size, mi.offset
        )
        try:
            mi = map_list.pop(MapType.TYPE_TYPE_LIST)
            self.parse_type_lists(data[mi.offset :], mi.size, mi.offset)
        except KeyError:
            log_warn("No type list section")

        # Need proto ids before method ids and both method ids and field
        # ids before class data before class definitions
        mi = map_list.pop(MapType.TYPE_PROTO_ID_ITEM)
        self.parse_proto_ids(
            data[mi.offset : mi.offset + 12 * mi.size], mi.size, mi.offset
        )
        mi = map_list.pop(MapType.TYPE_METHOD_ID_ITEM)
        self.parse_method_ids(data[mi.offset :], mi.size, mi.offset)
        try:
            mi = map_list.pop(MapType.TYPE_FIELD_ID_ITEM)
            self.parse_field_ids(
                data[mi.offset : mi.offset + 8 * mi.size], mi.size, mi.offset
            )
        except KeyError:
            log_warn("No field id section.")
        mi = map_list.pop(MapType.TYPE_CODE_ITEM)
        self.parse_code_items(data[mi.offset :], mi.size, mi.offset)
        mi = map_list.pop(MapType.TYPE_CLASS_DATA_ITEM)
        self.parse_class_data(data[mi.offset :], mi.size, mi.offset)
        del self.code_items

        # Need encoded_array_items before class_defs
        try:
            mi = map_list.pop(MapType.TYPE_ENCODED_ARRAY_ITEM)
            self.parse_encoded_array_items(data[mi.offset :], mi.size, mi.offset)
        except KeyError:
            log_warn("No encoded array section.")
        del self.proto_ids

        # Rest are in order of MapType constant
        mi = map_list.pop(MapType.TYPE_CLASS_DEF_ITEM)
        self.parse_class_defs(
            data[mi.offset : mi.offset + 32 * mi.size], mi.size, mi.offset
        )
        try:
            del self.type_lists
            del self.class_data_items
        except AttributeError:
            pass

        try:
            mi = map_list.pop(MapType.TYPE_CALL_SITE_ID_ITEM)
            self.parse_call_site_ids(
                data[mi.offset : mi.offset + 4 * mi.size], mi.size, mi.offset
            )
        except KeyError:
            log_warn("No calls")

        try:
            mi = map_list.pop(MapType.TYPE_METHOD_HANDLE_ITEM)
            self.parse_method_handles(
                data[mi.offset : mi.offset + 8 * mi.size], mi.size, mi.offset
            )
        except KeyError:
            log_warn("No methods")

        # TODO annotations
        try:
            mi = map_list.pop(MapType.TYPE_ANNOTATION_ITEM)
            mi = map_list.pop(MapType.TYPE_ANNOTATIONS_DIRECTORY_ITEM)
            # self.parse_annotation_set_refs(data[mi.offset:mi.offset+4+mi.size*4], mi.size)
            mi = map_list.pop(MapType.TYPE_ANNOTATION_SET_ITEM)
        except KeyError:
            log_warn("No annotations")
        try:
            mi = map_list.pop(MapType.TYPE_ANNOTATION_SET_REF_LIST)
            # self.parse_annotation_sets(data[mi.offset:mi.offset+4+mi.size*4], mi.size)
        except KeyError:
            log_warn("No annotations set refs")

        # TODO debug info
        try:
            mi = map_list.pop(MapType.TYPE_DEBUG_INFO_ITEM)
        except KeyError:
            log_warn("No debug info items")

        for item_type in map_list:
            log_error(f"unknown type {hex(item_type)}")

    def parse_string_ids(
        self, data: bytes, size: int, offset_to_section: FileOffset
    ) -> None:
        i_offset = (4 - (offset_to_section)) % 4
        self.string_ids = [
            self._parse_uint(data[i : i + 4])
            for i in range(i_offset, size * 4 + i_offset, 4)
        ]

    def make_strings(self, data: bytes) -> None:
        self.strings: List[str] = list()
        for string_data_off in self.string_ids:
            utf16_size, off = parse_uleb128(data[string_data_off : string_data_off + 5])
            try:
                string, string_size_off = parse_mutf8(data[string_data_off + off :])
            except UnicodeDecodeError:
                # This should never be reached
                t = data[
                    string_data_off
                    + off : string_data_off
                    + off
                    + data[string_data_off + off :].index(b"\x00")
                ]
                log_error(f"Failed to decode MUTF8: {t!r}")
                raise
            self.strings.append(string)
            plen = len(string.encode("utf-16", "surrogatepass")) // 2 - 1
            if plen != utf16_size:
                # This should never be reached
                log_error(
                    f'String {repr(string)} at string offset "{string_data_off}" Python length {plen} does not match expected length {utf16_size}'
                )

    def parse_type_ids(
        self, data: bytes, size: int, offset_to_section: FileOffset
    ) -> None:
        i_offset = (4 - (offset_to_section)) % 4
        self.type_ids: List[DexType] = [
            DexType(self.strings[self._parse_uint(data[i : i + 4])])
            for i in range(i_offset, size * 4 + i_offset, 4)
        ]

    def parse_proto_ids(
        self, data: bytes, size: int, offset_to_section: FileOffset
    ) -> None:
        i_offset = (4 - (offset_to_section)) % 4
        self.proto_ids: List[DexProtoId] = [
            DexProtoId(
                shorty=self.strings[self._parse_uint(data[i : i + 4])],
                return_type=self.type_ids[self._parse_uint(data[i + 4 : i + 8])],
                parameters=self.type_lists[
                    cast(FileOffset, self._parse_uint(data[i + 8 : i + 12]))
                ]
                if self._parse_uint(data[i + 8 : i + 12])
                else list(),
            )
            for i in range(i_offset, size * 12 + i_offset, 12)
        ]
        for proto in self.proto_ids:
            if len(proto.shorty) - 1 != len(proto.parameters):
                log_error("Shorty does not match parameters")

    def parse_field_ids(
        self, data: bytes, size: int, offset_to_section: FileOffset
    ) -> None:
        i_offset = (4 - (offset_to_section)) % 4
        self.field_ids = [
            DexFieldId(
                self.type_ids[self._parse_ushort(data[i : i + 2])],
                self.type_ids[self._parse_ushort(data[i + 2 : i + 4])],
                self.strings[self._parse_uint(data[i + 4 : i + 8])],
            )
            for i in range(i_offset, i_offset + size * 8, 8)
        ]

    def parse_method_ids(
        self, data: bytes, size: int, offset_to_section: FileOffset
    ) -> None:
        i_offset = (4 - (offset_to_section)) % 4
        self.method_ids = [
            DexMethodId(
                class_=self.type_ids[self._parse_ushort(data[i : i + 2])],
                proto=self.proto_ids[self._parse_ushort(data[i + 2 : i + 4])],
                name=self.strings[self._parse_uint(data[i + 4 : i + 8])],
            )
            for i in range(i_offset, size * 8 + i_offset, 8)
        ]

    def parse_class_defs(
        self, data: bytes, size: int, offset_to_section: FileOffset
    ) -> None:
        i_offset = (4 - (offset_to_section)) % 4
        self.class_defs = [
            DexClassDef(
                class_type=self.type_ids[self._parse_uint(data[i : i + 4])],
                access_flags=AccessFlag(self._parse_uint(data[i + 4 : i + 8]), "class"),
                superclass=self.type_ids[self._parse_uint(data[i + 8 : i + 12])]
                if self._parse_uint(data[i + 8 : i + 12]) != NO_INDEX
                else None,
                interfaces=self.type_lists[
                    cast(FileOffset, self._parse_uint(data[i + 12 : i + 16]))
                ]
                if self._parse_uint(data[i + 12 : i + 16]) != 0
                else None,
                source_file=self.strings[self._parse_uint(data[i + 16 : i + 20])]
                if self._parse_uint(data[i + 16 : i + 20]) != NO_INDEX
                else None,
                annotations=cast(FileOffset, self._parse_uint(data[i + 20 : i + 24])),
                class_data=self.class_data_items[
                    self._parse_uint(data[i + 24 : i + 28])
                ]
                if self._parse_uint(data[i + 24 : i + 28]) != 0
                else None,
                static_values=self.encoded_arrays[
                    self._parse_uint(data[i + 28 : i + 32])
                ]
                if self._parse_uint(data[i + 28 : i + 32])
                else None,  # FIXME: this should be padded to length of static fields in class
            )
            for i in range(i_offset, size * 32 + i_offset, 32)
        ]

    def parse_call_site_ids(
        self, data: bytes, size: int, offset_to_section: FileOffset
    ) -> None:
        self.call_site_ids = [
            self._parse_uint(data[i : i + 4]) for i in range(0, size * 4, 4)
        ]

    def parse_method_handles(
        self, data: bytes, size: int, offset_to_section: FileOffset
    ) -> None:
        i_offset = (4 - (offset_to_section)) % 4
        self.method_handles: List[DexMethodHandle] = list()
        for i in range(i_offset, size * 8 + i_offset, 8):
            method_handle_type = MethodHandleType(self._parse_ushort(data[i : i + 2]))
            id_ = self._parse_ushort(data[i + 2 : i + 4])
            self.method_handles.append(
                DexMethodHandle(
                    type_=method_handle_type,
                    field_or_method_id=self.method_ids[id_]
                    if id_ <= 0x3
                    else self.field_ids[id_],
                )
            )

    def parse_type_lists(
        self, data: bytes, size: int, offset_to_section: FileOffset
    ) -> None:
        self.type_lists: Dict[FileOffset, List[DexType]] = dict()
        i = 0
        for num in range(size):
            i += (4 - (i + offset_to_section)) % 4
            type_list_size = self._parse_uint(data[i : i + 4])
            self.type_lists[cast(FileOffset, offset_to_section + i)] = [
                self.type_ids[self._parse_ushort(data[j : j + 2])]
                for j in range(i + 4, i + 4 + type_list_size * 2, 2)
            ]
            i += 4 + type_list_size * 2

    def _parse_encoded_fields(
        self, data: bytes, size: int
    ) -> Tuple[List[DexEncodedField], int]:
        fields = list()
        i = 0
        field_idx = 0
        for num in range(size):
            field_idx_diff, off1 = parse_uleb128(data[i : i + 5])
            field_idx += field_idx_diff
            access_flags, off2 = parse_uleb128(data[i + off1 : i + off1 + 5])
            fields.append(
                DexEncodedField(
                    self.field_ids[field_idx], AccessFlag(access_flags, "field")
                )
            )
            i += off1 + off2
        return fields, i

    def _parse_encoded_methods(
        self, data: bytes, size: int
    ) -> Tuple[List[DexEncodedMethod], int]:
        methods = list()
        i = 0
        method_idx = 0
        for num in range(size):
            method_idx_diff, off1 = parse_uleb128(data[i : i + 5])
            method_idx += method_idx_diff
            access_flags, off2 = parse_uleb128(data[i + off1 : i + off1 + 5])
            code_off, off3 = cast(
                Tuple[FileOffset, int],
                parse_uleb128(data[i + off1 + off2 : i + off1 + off2 + 5]),
            )
            method = self.method_ids[method_idx]
            if method._insns_off is not None and method._insns_off != code_off + 16:
                log_warn(
                    f"More than 1 code block assigned to same method {method} with 2nd code block at {code_off}"
                )
            else:
                method._insns_off = cast(FileOffset, code_off + 16)
            methods.append(
                DexEncodedMethod(
                    method=method,
                    access_flags=AccessFlag(access_flags, "method"),
                    code=self.code_items[code_off] if code_off else None,
                )
            )
            i += off1 + off2 + off3
        return methods, i

    def parse_class_data(
        self, data: bytes, size: int, offset_to_section: FileOffset
    ) -> None:
        self.class_data_items: Dict[int, DexClassData] = dict()
        i = 0
        for num in range(size):
            class_data_off = offset_to_section + i
            static_fields_size, off = parse_uleb128(data[i : i + 5])
            i += off
            instance_fields_size, off = parse_uleb128(data[i : i + 5])
            i += off
            direct_methods_size, off = parse_uleb128(data[i : i + 5])
            i += off
            virtual_methods_size, off = parse_uleb128(data[i : i + 5])
            i += off
            static_fields: List[DexEncodedField] = list()
            instance_fields: List[DexEncodedField] = list()
            direct_methods: List[DexEncodedMethod] = list()
            virtual_methods: List[DexEncodedMethod] = list()
            if static_fields_size:
                static_fields, off = self._parse_encoded_fields(
                    data[i : i + 5 * 2 * static_fields_size], static_fields_size
                )
                i += off
            if instance_fields_size:
                instance_fields, off = self._parse_encoded_fields(
                    data[i : i + 5 * 2 * instance_fields_size], instance_fields_size
                )
                i += off
            if direct_methods_size:
                direct_methods, off = self._parse_encoded_methods(
                    data[i : i + 5 * 3 * direct_methods_size], direct_methods_size
                )
                i += off
            if virtual_methods_size:
                virtual_methods, off = self._parse_encoded_methods(
                    data[i : i + 5 * 3 * virtual_methods_size], virtual_methods_size
                )
                i += off
            self.class_data_items[class_data_off] = DexClassData(
                static_fields, instance_fields, direct_methods, virtual_methods
            )

    def parse_code_items(
        self, data: bytes, size: int, offset_to_section: FileOffset
    ) -> None:
        self.code_items: Dict[FileOffset, DexCodeItem] = dict()
        self.pseudoinstructions: Dict[
            FileOffset,
            Union[
                SmaliPackedSwitchPayload,
                SmaliFillArrayDataPayload,
                SmaliSparseSwitchPayload,
            ],
        ] = dict()
        i = 0
        for num in range(size):
            code_item_off: FileOffset = cast(FileOffset, offset_to_section + i)
            insns_size_ = self._parse_uint(data[i + 12 : i + 16])
            code_item = DexCodeItem(
                registers_size=self._parse_ushort(data[i : i + 2]),
                ins_size=self._parse_ushort(data[i + 2 : i + 4]),
                outs_size=self._parse_ushort(data[i + 4 : i + 6]),
                tries_size=self._parse_ushort(data[i + 6 : i + 8]),
                debug_info=cast(
                    FileOffset, self._parse_uint(data[i + 8 : i + 12])
                ),  # TODO debug_info_item offset
                insns_size=insns_size_,
                # insns is stored as an array of endian-sensitive shorts
                insns=b"".join(
                    [
                        pack(">H", self._parse_ushort(data[j : j + 2]))
                        for j in range(i + 16, i + 16 + insns_size_ * 2, 2)
                    ]
                ),
                _insns_off=cast(FileOffset, i + 16 + offset_to_section),
                tries=list(),  # try/catch items get filled in below
            )

            i += (
                16
                + 2 * code_item.insns_size
                # "two bytes of padding... only present if tries_size is
                # non-zero and insns_size is odd."
                + 2 * (code_item.tries_size and (code_item.insns_size % 2))
            )

            # This part is very confusing, sorry
            if code_item.tries_size:
                assert (i + offset_to_section) % 4 == 0
                tries_off = i
                # Parse handlers first and then come back for tries
                i += code_item.tries_size * 8

                # Parse handlers
                encoded_catch_handler_list_off = i
                encoded_catch_handler_list_size, off = parse_uleb128(data[i : i + 5])
                i += off
                handler_list = dict()
                for num2 in range(encoded_catch_handler_list_size):
                    encoded_handler_off = i - encoded_catch_handler_list_off
                    encoded_catch_handler_size, off = parse_sleb128(data[i : i + 5])
                    i += off
                    handlers = list()
                    for num3 in range(abs(encoded_catch_handler_size)):
                        type_idx, off = parse_uleb128(data[i : i + 5])
                        i += off
                        addr, off = parse_uleb128(data[i : i + 5])
                        i += off
                        handlers.append((self.type_ids[type_idx], addr))

                    if encoded_catch_handler_size <= 0:
                        catch_all_addr, off = cast(
                            Tuple[BytecodeAddress, int], parse_uleb128(data[i : i + 5])
                        )
                        i += off
                        encoded_handler = DexEncodedCatchHandler(
                            size=abs(encoded_catch_handler_size),
                            handlers=handlers,
                            catch_all_addr=catch_all_addr,
                        )
                    else:
                        encoded_handler = DexEncodedCatchHandler(
                            size=encoded_catch_handler_size, handlers=handlers
                        )
                    handler_list[encoded_handler_off] = encoded_handler

                # Parse tries
                for num2 in range(code_item.tries_size):
                    code_item.tries.append(
                        DexTryItem(
                            start_addr=cast(
                                BytecodeAddress,
                                self._parse_uint(data[tries_off : tries_off + 4]),
                            ),
                            insn_count=self._parse_ushort(
                                data[tries_off + 4 : tries_off + 6]
                            ),
                            handler=handler_list[
                                self._parse_ushort(data[tries_off + 6 : tries_off + 8])
                            ],
                        )
                    )
                    tries_off += 8
            self.code_items[code_item_off] = code_item

            # Disassemble code to parse out pseudoinstruction data blocks
            self.pseudoinstructions.update(
                disassemble_pseudoinstructions(code_item.insns, code_item_off + 16)
            )

            # code_items are 4-byte aligned
            i += (4 - (i + offset_to_section)) % 4

    def _parse_encoded_value(self, data: bytes) -> Tuple[DexValue, int]:
        def _sign_extend(data: bytes, size: int) -> bytes:
            return (b"\xff" if data[0] & 0xF0 else b"\x00") * (size - len(data)) + data

        def _zero_extend_right(data: bytes, size: int) -> bytes:
            # FIXME is this the right way?
            return data + b"\x00" * (size - len(data))

        def _zero_extend(data: bytes, size: int) -> bytes:
            return data + b"\x00" * (size - len(data))

        def _make_res(
            value_type: ValueType,
            value_arg: int,
            struct_type: str,
            data: bytes,
            lookup: List[Any] = None,
        ) -> Tuple[DexValue, int]:
            if lookup:
                return (
                    DexValue(
                        type_=value_type,
                        value=lookup[unpack("<" + struct_type, data)[0]],
                    ),
                    value_arg + 2,
                )
            else:
                return (
                    DexValue(
                        type_=value_type, value=unpack("<" + struct_type, data)[0]
                    ),
                    value_arg + 2,
                )

        value_arg = data[0] >> 5
        value_type = ValueType(data[0] & 0x1F)
        if value_type == ValueType.VALUE_BYTE:
            return _make_res(value_type, value_arg, "b", data[1:2])
        elif value_type == ValueType.VALUE_SHORT:
            return _make_res(
                value_type, value_arg, "h", _sign_extend(data[1 : value_arg + 2], 2)
            )
        elif value_type == ValueType.VALUE_CHAR:
            return _make_res(
                value_type, value_arg, "H", _zero_extend(data[1 : value_arg + 2], 2)
            )
        elif value_type == ValueType.VALUE_INT:
            return _make_res(
                value_type, value_arg, "i", _sign_extend(data[1 : value_arg + 2], 4)
            )
        elif value_type == ValueType.VALUE_LONG:
            return _make_res(
                value_type, value_arg, "q", _sign_extend(data[1 : value_arg + 2], 8)
            )
        elif value_type == ValueType.VALUE_FLOAT:
            return _make_res(
                value_type,
                value_arg,
                "f",
                _zero_extend_right(data[1 : value_arg + 2], 4),
            )
        elif value_type == ValueType.VALUE_DOUBLE:
            return _make_res(
                value_type,
                value_arg,
                "d",
                _zero_extend_right(data[1 : value_arg + 2], 8),
            )
        elif value_type == ValueType.VALUE_METHOD_TYPE:
            return _make_res(
                value_type,
                value_arg,
                "I",
                _zero_extend(data[1 : value_arg + 2], 4),
                self.proto_ids,
            )
        elif value_type == ValueType.VALUE_METHOD_HANDLE:
            return _make_res(
                value_type,
                value_arg,
                "I",
                _zero_extend(data[1 : value_arg + 2], 4),
                self.method_handles,
            )
        elif value_type == ValueType.VALUE_STRING:
            return _make_res(
                value_type,
                value_arg,
                "I",
                _zero_extend(data[1 : value_arg + 2], 4),
                self.strings,
            )
        elif value_type == ValueType.VALUE_TYPE:
            return _make_res(
                value_type,
                value_arg,
                "I",
                _zero_extend(data[1 : value_arg + 2], 4),
                self.type_ids,
            )
        elif value_type == ValueType.VALUE_FIELD:
            return _make_res(
                value_type,
                value_arg,
                "I",
                _zero_extend(data[1 : value_arg + 2], 4),
                self.field_ids,
            )
        elif value_type == ValueType.VALUE_METHOD:
            return _make_res(
                value_type,
                value_arg,
                "I",
                _zero_extend(data[1 : value_arg + 2], 4),
                self.method_ids,
            )
        elif value_type == ValueType.VALUE_ENUM:
            return _make_res(
                value_type,
                value_arg,
                "I",
                _zero_extend(data[1 : value_arg + 2], 4),
                self.field_ids,
            )

        elif value_type == ValueType.VALUE_ARRAY:
            array, off = self._parse_encoded_array(data[1:])
            return (DexValue(type_=value_type, value=array), off + 1)
        # elif value_type == ValueType.VALUE_ANNOTATION:
        # TODO
        elif value_type == ValueType.VALUE_NULL:
            return (DexValue(type_=value_type, value=None), 1)
        elif value_type == ValueType.VALUE_BOOLEAN:
            return (DexValue(type_=value_type, value=bool(value_arg)), 1)

        else:
            raise ValueError(f'invalid value_type "{hex(value_type)}"')

    def _parse_encoded_array(self, data: bytes) -> Tuple[DexEncodedArray, int]:
        array = list()
        array_size, i = parse_uleb128(data[:5])
        for num in range(array_size):
            value, off = self._parse_encoded_value(data[i:])
            i += off
            array.append(value)
        return array, i

    def parse_encoded_array_items(
        self, data: bytes, size: int, offset_to_section: FileOffset
    ) -> None:
        self.encoded_arrays: Dict[int, DexEncodedArray] = dict()
        i = 0
        for num in range(size):
            array, off = self._parse_encoded_array(data[i:])
            self.encoded_arrays[offset_to_section + i] = array
            i += off


if __name__ == "__main__":
    unittest.main()
