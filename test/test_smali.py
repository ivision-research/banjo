class TestFormatParsing(unittest.TestCase):
    def test_10x(self) -> None:
        """10x -> ØØ|op"""
        self.assertEqual(parse_with_format(b"\x00\x0e", "ØØ|op"), {})

    def test_11n(self) -> None:
        """11n -> B|A|op"""
        self.assertEqual(parse_with_format(b"\x10\x12", "B|A|op"), {"A": 0, "B": 1})

    def test_21h(self) -> None:
        """21h -> AA|op BBBB"""
        self.assertEqual(
            parse_with_format(b"\x00\x15\x00\x02", "AA|op BBBB"), {"A": 0, "B": 0x2}
        )

    def test_21c(self) -> None:
        """21c -> AA|op BBBB"""
        self.assertEqual(
            parse_with_format(b"\x00\x67\x00\x00", "AA|op BBBB"), {"A": 0, "B": 0}
        )

    def test_31i(self) -> None:
        """31i -> AA|op BBBBlo BBBBhi"""
        self.assertEqual(
            parse_with_format(b"\x01\x14\xff\xff\x00\xff", "AA|op BBBBlo BBBBhi"),
            {"A": 1, "B": 0x00FFFFFF},
        )

    def test_35c(self) -> None:
        """35c -> A|G|op BBBB F|E|D|C"""
        self.assertEqual(
            parse_with_format(b"\x10\x70\x00\x07\x00\x00", "A|G|op BBBB F|E|D|C"),
            {"A": 1, "B": 7, "C": 0, "D": 0, "E": 0, "F": 0, "G": 0},
        )

    def test_51l(self) -> None:
        """51l -> AA|op BBBBlo BBBB BBBB BBBBhi"""
        self.assertEqual(
            parse_with_format(
                b"\x01\x18\x01\x02\x03\x04\x05\x06\x07\x08",
                "AA|op BBBBlo BBBB BBBB BBBBhi",
            ),
            {"A": 1, "B": 0x0708050603040102},
        )


class TestFormattingArgsWithSyntax(unittest.TestCase):
    def test_no_format(self) -> None:
        self.assertEqual(format_args_with_syntax({}, "hi there"), "hi there")
        self.assertEqual(format_args_with_syntax({"A": 4}, "hi there"), "hi there")

    def test_single_replacement(self) -> None:
        self.assertEqual(
            format_args_with_syntax({"A": 3}, "the number is A"), "the number is 3"
        )
        self.assertEqual(format_args_with_syntax({"B": 4}, "hiBthere"), "hi4there")

    def test_long_replacement(self) -> None:
        self.assertEqual(
            format_args_with_syntax({"A": 3}, "the number is AA"), "the number is 3"
        )
        self.assertEqual(format_args_with_syntax({"A": 4}, "long numAAAA"), "long num4")

    def test_large_replacement(self) -> None:
        self.assertEqual(
            format_args_with_syntax({"A": 0x999}, "the number is AAAA"), "the number is 999"
        )

    def test_multiple_replacements(self) -> None:
        self.assertEqual(
            format_args_with_syntax({"A": 1, "B": 0}, "first A then B"),
            "first 1 then 0",
        )
        self.assertEqual(
            format_args_with_syntax({"A": 4, "B": 5}, "first AAAA then BBBB"),
            "first 4 then 5",
        )

    def test_signed_replacements(self) -> None:
        self.assertEqual(
            format_args_with_syntax({"A": 0xF}, "negative A"), "negative -1"
        )
        self.assertEqual(
            format_args_with_syntax({"A": 0xFF}, "negative AA"), "negative -1"
        )
        self.assertEqual(
            format_args_with_syntax({"A": 0xF6}, "negative AA"), "negative -a"
        )

    def test_unsigned_replacements(self) -> None:
        self.assertEqual(
            format_args_with_syntax({"A": 0xF}, "positive vA"), "positive vf"
        )
        self.assertEqual(
            format_args_with_syntax({"A": 0xFFFF}, "positive field@AAAA"),
            "positive field@ffff",
        )
        self.assertEqual(
            format_args_with_syntax({"A": 0xF}, "positive vAA"), "positive vf"
        )


class TestNibbleSlicing(unittest.TestCase):
    def test_single_even(self) -> None:
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 0), 1)
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 2), 3)
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 4), 5)
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 6), 7)

    def test_single_odd(self) -> None:
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 1), 2)
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 3), 4)
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 5), 6)
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 7), 8)

    def test_byte(self) -> None:
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 0, 2), 0x12)
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 2, 2), 0x34)
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 4, 2), 0x56)
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 6, 2), 0x78)

    def test_two_byte(self) -> None:
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 0, 4), 0x1234)
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 2, 4), 0x3456)
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 4, 4), 0x5678)

    def test_four_byte(self) -> None:
        self.assertEqual(slice_nibbles(b"\x12\x34\x56\x78", 0, 8), 0x56781234)
        self.assertEqual(slice_nibbles(b"\x00\x12\x34\x56\x78", 2, 8), 0x56781234)
        self.assertEqual(slice_nibbles(b"\x00\x12\x34\x56\x78\x00", 2, 8), 0x56781234)

    def test_eight_byte(self) -> None:
        self.assertEqual(
            slice_nibbles(b"\x12\x34\x56\x78\x9a\xbc\xde\xf0", 0, 16),
            0xDEF09ABC56781234,
        )
        self.assertEqual(
            slice_nibbles(b"\x00\x12\x34\x56\x78\x9a\xbc\xde\xf0", 2, 16),
            0xDEF09ABC56781234,
        )
