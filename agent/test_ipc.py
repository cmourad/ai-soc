import struct
import unittest

import ipc


class ChunkedReader:
    """Socket-like reader that proves the framing handles arbitrary stream splits."""

    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv(self, size):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) <= size:
            return chunk
        self.chunks.insert(0, chunk[size:])
        return chunk[:size]


class FramingTests(unittest.TestCase):
    def test_framing_survives_partial_reads(self):
        body = b'{"op":"list"}'
        framed = struct.pack("!I", len(body)) + body
        reader = ChunkedReader([framed[:1], framed[1:3], framed[3:7], framed[7:]])
        self.assertEqual(ipc.recv_bytes(reader), body)

    def test_header_split_across_packets_is_accepted(self):
        # The bug this module exists to prevent: a helper reading the four-byte
        # header with one recv rejects a valid request whenever the kernel
        # splits it.
        self.assertEqual(ipc.read_frame(ChunkedReader([b"\x00\x00", b"\x00\x02", b"{}"])), {})

    def test_framing_rejects_oversized_and_empty_requests(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            ipc.recv_bytes(ChunkedReader([struct.pack("!I", 0)]))
        with self.assertRaisesRegex(ValueError, "outside"):
            ipc.recv_bytes(ChunkedReader([struct.pack("!I", ipc.MAX_FRAME + 1)]))

    def test_truncated_body_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "closed mid-frame"):
            ipc.recv_bytes(ChunkedReader([struct.pack("!I", 8), b"abc"]))

    def test_frame_round_trips(self):
        value = {"ok": True, "error": None}
        self.assertEqual(ipc.read_frame(ChunkedReader([ipc.frame(value)])), value)


if __name__ == "__main__":
    unittest.main()
