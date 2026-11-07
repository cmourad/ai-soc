import json
import os
import socket
import tempfile
import unittest
import uuid

import aisoc


class ControlProtocolTests(unittest.TestCase):
    def test_explicit_unknown_user_fails_closed(self):
        self.assertEqual(aisoc.configured_control_uids("no-such-aisoc-user"), set())

    def test_unauthorized_peer_is_rejected_before_json_is_parsed(self):
        server_side, client = socket.socketpair()
        try:
            server_side.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        except PermissionError:
            server_side.close()
            client.close()
            self.skipTest("sandbox blocks SO_PEERCRED; run this test outside the sandbox")
        server = aisoc.ControlServer(allowed_uids={os.getuid() + 1})
        # _accept normally reserves this slot before handing the connection to
        # _serve; mirror that here without needing a filesystem socket.
        self.assertTrue(server.connections.acquire(blocking=False))
        worker = __import__("threading").Thread(target=server._serve, args=(server_side,))
        worker.start()
        # Deliberately send no request. Peer authorization happens first.
        reply = json.loads(aisoc.recv_bytes(client).decode())
        self.assertEqual(reply, {"ok": False, "refused": "unauthorized_peer"})
        worker.join(2)
        client.close()


class ControlLedgerTests(unittest.TestCase):
    def test_action_ids_are_idempotent_and_conflicts_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = aisoc.ControlLedger(os.path.join(tmp, "ledger.db"))
            action_id = str(uuid.uuid4())
            self.assertEqual(ledger.begin(action_id, "hash-a"), ("new", None))
            self.assertEqual(ledger.begin(action_id, "hash-a"), ("pending", None))
            result = {"ok": True, "seconds": 60}
            self.assertTrue(ledger.complete(action_id, result))
            self.assertEqual(ledger.begin(action_id, "hash-a"), ("complete", result))
            self.assertEqual(ledger.begin(action_id, "hash-b"), ("conflict", None))


if __name__ == "__main__":
    unittest.main()
