import assert from "node:assert/strict";
import { test } from "node:test";
import { geolocate, toUint32, toUint128 } from "./geo.js";

// ---------------------------------------------------------------------------
// Offline geolocation. The table is generated, so these pin the decoder and the
// boundary behaviour rather than the data — a wrong binary search silently
// mislocates every dot on the map instead of failing.
// ---------------------------------------------------------------------------

test("well-known addresses land in the right country", () => {
  assert.equal(geolocate("8.8.8.8")?.countryCode, "US");
  assert.equal(geolocate("212.27.48.10")?.countryCode, "FR");
  assert.equal(geolocate("202.12.27.33")?.countryCode, "JP");
  assert.equal(geolocate("196.216.2.1")?.countryCode, "ZA");
  assert.equal(geolocate("200.3.14.10")?.countryCode, "UY");
});

test("a located address carries a name and coordinates", () => {
  const found = geolocate("8.8.8.8");
  assert.equal(found?.country, "United States");
  assert.match(found?.asn ?? "", /^AS15169\b/);
  assert.ok(typeof found?.lat === "number" && typeof found?.lon === "number");
});

test("compressed, expanded, and IPv4-tail IPv6 forms parse identically", () => {
  const expected = 0x20010db8000000000000ff0000428329n;
  assert.equal(toUint128("2001:db8::ff00:42:8329"), expected);
  assert.equal(toUint128("2001:0db8:0000:0000:0000:ff00:0042:8329"), expected);
  assert.equal(toUint128("::ffff:192.0.2.128"), 0x00000000000000000000ffffc0000280n);
});

test("malformed IPv6 addresses are rejected", () => {
  for (const value of ["2001:db8", "2001::db8::1", "1:2:3:4:5:6:7:8:9", "fe80::1%eth0"]) {
    assert.equal(toUint128(value), null, value);
  }
});

test("IPv6 attribution includes country and network owner", () => {
  const google = geolocate("2001:4860:4860::8888");
  assert.equal(google?.countryCode, "US");
  assert.match(google?.asn ?? "", /^AS15169\b/);
  assert.match(google?.organization ?? "", /GOOGLE/i);
});

test("private and unroutable space is not located", () => {
  assert.equal(geolocate("192.0.2.9"), null);
  assert.equal(geolocate("10.0.0.1"), null);
  assert.equal(geolocate("0.0.0.0"), null);
});

test("malformed addresses are rejected rather than mislocated", () => {
  assert.equal(toUint32("999.1.1.1"), null);
  assert.equal(toUint32("1.2.3"), null);
  assert.equal(toUint32("1.2.3.4.5"), null);
  assert.equal(toUint32("1.2.3.04"), null);
  assert.equal(toUint32(""), null);
  assert.equal(geolocate("not an ip"), null);
});

test("the top of the address space terminates (unsigned 32-bit regression)", () => {
  assert.equal(toUint32("255.255.255.255"), 4_294_967_295);
  assert.doesNotThrow(() => geolocate("255.255.255.255"));
  assert.doesNotThrow(() => geolocate("223.255.255.255"));
});

test("lookups either land inside a range or return null, never on a neighbour", () => {
  // 127/8 is loopback: reserved, never delegated, and bracketed by real ranges.
  assert.equal(geolocate("127.0.0.1"), null);
});

test("inclusive range edges do not fall into the adjacent IPv6 prefix", () => {
  const lastGoogle = geolocate("2001:4860:1024:ffff:ffff:ffff:ffff:ffff");
  const firstGoogleCloud = geolocate("2001:4860:1025::");
  assert.match(lastGoogle?.asn ?? "", /^AS15169\b/);
  assert.match(firstGoogleCloud?.asn ?? "", /^AS32381\b/);
});

test("inclusive IPv4 ASN end is found and the first address after it is not borrowed", () => {
  assert.match(geolocate("1.0.0.255")?.asn ?? "", /^AS13335\b/);
  assert.equal(geolocate("1.0.1.0")?.asn, null);
});
