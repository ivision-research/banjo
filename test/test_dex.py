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


class TestAccessFlag(unittest.TestCase):
    def test_none(self) -> None:
        """No modifiers."""
        self.assertEqual(str(AccessFlag(0, "class")), "")
        self.assertEqual(str(AccessFlag(0, "method")), "")
        self.assertEqual(str(AccessFlag(0, "field")), "")

    def test_single(self) -> None:
        """Single modifier."""
        self.assertEqual(str(AccessFlag(AccessFlagEnum.ACC_PUBLIC, "class")), "public ")

    def test_sorted(self) -> None:
        """Cases with specified orders."""
        self.assertEqual(
            str(
                AccessFlag(
                    AccessFlagEnum.ACC_PUBLIC | AccessFlagEnum.ACC_STATIC, "method"
                )
            ),
            "public static ",
        )
        self.assertEqual(
            str(
                AccessFlag(
                    AccessFlagEnum.ACC_PUBLIC
                    | AccessFlagEnum.ACC_PRIVATE
                    | AccessFlagEnum.ACC_PROTECTED
                    | AccessFlagEnum.ACC_STATIC
                    | AccessFlagEnum.ACC_FINAL
                    | AccessFlagEnum.ACC_SYNCHRONIZED
                    | AccessFlagEnum.ACC_VOLATILE
                    | AccessFlagEnum.ACC_TRANSIENT
                    | AccessFlagEnum.ACC_NATIVE
                    | AccessFlagEnum.ACC_INTERFACE
                    | AccessFlagEnum.ACC_ABSTRACT
                    | AccessFlagEnum.ACC_STRICT
                    | AccessFlagEnum.ACC_SYNTHETIC
                    | AccessFlagEnum.ACC_ANNOTATION
                    | AccessFlagEnum.ACC_ENUM
                    | AccessFlagEnum.ACC_CONSTRUCTOR
                    | AccessFlagEnum.ACC_DECLARED_SYNCHRONIZED,
                    "method",
                )
            ),
            "public private protected static final synchronized bridge varargs native interface abstract strictfp synthetic annotation enum constructor declared_synchronized ",
        )
        self.assertEqual(
            str(
                AccessFlag(
                    AccessFlagEnum.ACC_PUBLIC
                    | AccessFlagEnum.ACC_PRIVATE
                    | AccessFlagEnum.ACC_PROTECTED
                    | AccessFlagEnum.ACC_STATIC
                    | AccessFlagEnum.ACC_FINAL
                    | AccessFlagEnum.ACC_SYNCHRONIZED
                    | AccessFlagEnum.ACC_VOLATILE
                    | AccessFlagEnum.ACC_TRANSIENT
                    | AccessFlagEnum.ACC_NATIVE
                    | AccessFlagEnum.ACC_INTERFACE
                    | AccessFlagEnum.ACC_ABSTRACT
                    | AccessFlagEnum.ACC_STRICT
                    | AccessFlagEnum.ACC_SYNTHETIC
                    | AccessFlagEnum.ACC_ANNOTATION
                    | AccessFlagEnum.ACC_ENUM
                    | AccessFlagEnum.ACC_CONSTRUCTOR
                    | AccessFlagEnum.ACC_DECLARED_SYNCHRONIZED,
                    "field",
                )
            ),
            "public private protected static final synchronized volatile transient native interface abstract strictfp synthetic annotation enum constructor declared_synchronized ",
        )
        self.assertEqual(
            str(
                AccessFlag(
                    AccessFlagEnum.ACC_PUBLIC
                    | AccessFlagEnum.ACC_PRIVATE
                    | AccessFlagEnum.ACC_PROTECTED
                    | AccessFlagEnum.ACC_STATIC
                    | AccessFlagEnum.ACC_FINAL
                    | AccessFlagEnum.ACC_SYNCHRONIZED
                    | AccessFlagEnum.ACC_VOLATILE
                    | AccessFlagEnum.ACC_TRANSIENT
                    | AccessFlagEnum.ACC_NATIVE
                    | AccessFlagEnum.ACC_INTERFACE
                    | AccessFlagEnum.ACC_ABSTRACT
                    | AccessFlagEnum.ACC_STRICT
                    | AccessFlagEnum.ACC_SYNTHETIC
                    | AccessFlagEnum.ACC_ANNOTATION
                    | AccessFlagEnum.ACC_ENUM
                    | AccessFlagEnum.ACC_CONSTRUCTOR
                    | AccessFlagEnum.ACC_DECLARED_SYNCHRONIZED,
                    "class",
                )
            ),
            "public private protected static final super volatile transient native interface abstract strictfp synthetic annotation enum constructor declared_synchronized ",
        )
