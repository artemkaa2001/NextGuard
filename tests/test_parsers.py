import ipaddress
import json
import unittest

from nextguard.parsers import ParseError, collapse_exact, parse_dshield, parse_lines, parse_spamhaus


class ParserTests(unittest.TestCase):
    def test_lines_comments_duplicates_ipv6(self):
        nets, skipped, _ = parse_lines(b"# x\n192.0.2.1\n192.0.2.1 # duplicate\n2001:db8::/32\n")
        self.assertEqual([str(x) for x in nets], ["192.0.2.1/32", "192.0.2.1/32"])
        self.assertEqual(skipped, 1)

    def test_invalid_and_default_route_reject_whole_document(self):
        for data in (b"192.0.2.1\nbad\n", b"0.0.0.0/0\n", b"<html>error</html>"):
            with self.subTest(data=data), self.assertRaises(ParseError):
                parse_lines(data)

    def test_empty_contract(self):
        with self.assertRaises(ParseError):
            parse_lines(b"# empty\n")
        self.assertEqual(parse_lines(b"# empty\n", allow_empty=True)[0], [])

    def test_dshield_range_is_exact(self):
        nets, _, _ = parse_dshield(b"Start End Count\n192.0.2.1 192.0.2.3 3 attacks\n")
        self.assertEqual([str(x) for x in nets], ["192.0.2.1/32", "192.0.2.2/31"])

    def test_spamhaus_json_and_json_lines(self):
        for data in (json.dumps([{"cidr": "192.0.2.0/24"}]).encode(), b'{"cidr":"192.0.2.0/24"}\n'):
            nets, _, _ = parse_spamhaus(data)
            self.assertEqual(str(nets[0]), "192.0.2.0/24")

    def test_collapse_never_expands_membership(self):
        original = [ipaddress.ip_network("192.0.2.0/25"), ipaddress.ip_network("192.0.2.128/25"), ipaddress.ip_network("198.51.100.8/32")]
        collapsed = collapse_exact(original)
        for address in (ipaddress.ip_address(i) for i in range(2**10)):
            self.assertEqual(any(address in n for n in original), any(address in n for n in collapsed))
        self.assertEqual([str(x) for x in collapsed], ["192.0.2.0/24", "198.51.100.8/32"])


if __name__ == "__main__":
    unittest.main()
