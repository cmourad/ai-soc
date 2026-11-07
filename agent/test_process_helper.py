import unittest

import process_helper


class SocketTableTests(unittest.TestCase):
    def test_parses_ipv4_and_ipv6_five_tuples(self):
        header = "sl local_address rem_address st tx_queue rx_queue tr tm retr uid timeout inode"
        ipv4 = process_helper.parse_socket_table(
            [header, "0: 0100007F:C350 08080808:01BB 01 0:0 0:0 0 1000 0 4242"],
            "TCP",
            4,
        )
        ipv6 = process_helper.parse_socket_table(
            [
                header,
                "0: B80D0120000000000000000001000000:C351 0000000000000000FFFF000008080808:01BB 01 0:0 0:0 0 1000 0 4343",
            ],
            "TCP",
            6,
        )
        self.assertEqual(ipv4, [(('TCP', '127.0.0.1', 50000, '8.8.8.8', 443), '4242')])
        self.assertEqual(
            ipv6,
            [(('TCP', '2001:db8::1', 50001, '::ffff:8.8.8.8', 443), '4343')],
        )


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.cache = process_helper.SocketOwnerCache(ttl=12, clock=lambda: self.now)
        self.key = ("TCP", "192.0.2.9", 51000, "203.0.113.9", 443)

    def test_exact_tuple_correlates_to_comm_only(self):
        self.cache.observe([(self.key, "firefox")])
        self.assertEqual(self.cache.lookup(self.key), "firefox")
        self.assertIsNone(self.cache.lookup((*self.key[:-1], 8443)))

    def test_ambiguous_tuple_is_unknown(self):
        self.cache.observe([(self.key, "firefox"), (self.key, "curl")])
        self.assertIsNone(self.cache.lookup(self.key))

    def test_current_socket_without_an_owner_invalidates_an_old_match(self):
        self.cache.observe([(self.key, "firefox")])
        self.cache.observe([(self.key, None)])
        self.assertIsNone(self.cache.lookup(self.key))

    def test_entry_expires_after_short_ttl(self):
        self.cache.observe([(self.key, "firefox")])
        self.now += 12.1
        self.assertIsNone(self.cache.lookup(self.key))


if __name__ == "__main__":
    unittest.main()
