import ipaddress
import unittest
from unittest import mock

import guard
import history


class ShapeRefusalTests(unittest.TestCase):
    """Addresses refused for what they are, before any list is consulted."""

    def setUp(self):
        with mock.patch.object(guard.Guard, "refresh"):
            self.guard = guard.Guard()
            self.guard.protected = set()

    def test_malformed_input_is_refused(self):
        for value in ("", "not-an-ip", "999.1.1.1", "192.0.2.1/24", "1.2.3.4 "):
            self.assertTrue(self.guard.shape_refused(value), value)

    def test_addresses_that_can_never_be_a_hostile_remote_are_refused(self):
        for value in ("127.0.0.1", "::1", "224.0.0.1", "ff02::1", "169.254.1.1", "fe80::1",
                      "0.0.0.0", "::"):
            self.assertTrue(self.guard.shape_refused(value), value)

    def test_docker_bridge_space_is_refused_but_other_rfc1918_is_not(self):
        # Blocking the bridge breaks every local container and never helps.
        self.assertTrue(self.guard.shape_refused("172.17.0.2"))
        self.assertTrue(self.guard.shape_refused("172.31.255.254"))
        self.assertFalse(self.guard.shape_refused("172.32.0.1"))
        self.assertFalse(self.guard.shape_refused("192.0.2.50"))
        self.assertFalse(self.guard.shape_refused("10.0.0.5"))

    def test_ordinary_public_addresses_are_blockable(self):
        for value in ("203.0.113.4", "8.8.8.8", "2001:db8::1"):
            self.assertFalse(self.guard.shape_refused(value), value)
            self.assertFalse(self.guard.is_protected(value), value)


class ProtectedSetTests(unittest.TestCase):
    def test_every_discovered_source_ends_up_protected(self):
        with (
            mock.patch.object(guard, "own_ips", return_value={"192.0.2.9"}),
            mock.patch.object(guard, "gateway_ips", return_value={"192.0.2.1"}),
            mock.patch.object(guard, "nameserver_ips", return_value={"192.0.2.2"}),
            mock.patch.object(guard, "allowlist_ips", return_value={"203.0.113.7"}),
        ):
            g = guard.Guard()

        for ip in ("192.0.2.9", "192.0.2.1", "192.0.2.2", "203.0.113.7"):
            self.assertTrue(g.is_protected(ip), ip)
        self.assertFalse(g.is_protected("203.0.113.8"))

    def test_listed_hides_entries_that_are_refused_by_shape_anyway(self):
        with (
            mock.patch.object(guard, "own_ips", return_value={"192.0.2.9", "fe80::1"}),
            mock.patch.object(guard, "gateway_ips", return_value=set()),
            mock.patch.object(guard, "nameserver_ips", return_value=set()),
            mock.patch.object(guard, "allowlist_ips", return_value=set()),
        ):
            g = guard.Guard()

        # 255.255.255.255 stays visible: nothing about its shape refuses it, so
        # the static entry is the only thing protecting it. The link-local
        # address is hidden because it is refused either way.
        self.assertEqual(g.listed(), ["192.0.2.9", "255.255.255.255"])
        self.assertTrue(g.is_protected("fe80::1"), "still refused, just not listed")


class EscalationTests(unittest.TestCase):
    def test_the_ladder_is_monotonic_and_lands_on_the_documented_steps(self):
        steps = [history.block_seconds(count) for count in range(1, 8)]
        self.assertEqual(steps[0], 3_600)
        self.assertEqual(steps[1:4], [86_400] * 3)
        self.assertEqual(steps[4:], [30 * 86_400] * 3)
        self.assertEqual(steps, sorted(steps), "a repeat offence must never shorten a block")


class SetSelectionTests(unittest.TestCase):
    def test_each_family_lands_in_its_own_set(self):
        import nft

        self.assertEqual(nft._set_for("203.0.113.4"), "blocked")
        self.assertEqual(nft._set_for("2001:db8::1"), "blocked6")
        with self.assertRaises(ValueError):
            nft._set_for("not-an-ip")


if __name__ == "__main__":
    unittest.main()
