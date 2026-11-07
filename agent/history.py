#!/usr/bin/env python3
"""Durable agent memory: repeat-offender history and the control ledger.

Both are SQLite because both must survive a restart. Escalation that forgets is
escalation an attacker can reset by waiting, and a control ledger that forgets
turns a retried console request into a second firewall change.
"""

import json
import logging
import os
import sqlite3
import time

from config import (
    BLOCK_SECS,
    BLOCK_SECS_QUIET,
    BLOCK_SECS_REPEAT,
    BLOCK_SECS_THIRD,
    OFFENDER_DB,
)

log = logging.getLogger("aisoc")

def block_seconds(count):
    """Escalation curve for repeat offenders: 1st -> 1h, 2nd-4th -> 24h, 5th+ -> 30d."""
    if count >= 5:
        return BLOCK_SECS_THIRD
    if count >= 2:
        return BLOCK_SECS_REPEAT
    return BLOCK_SECS


class OffenderStore:
    """SQLite-backed repeat-offender history so escalation survives restarts.

    stdlib sqlite3 only — the agent stays dependency-free. Falls back to an
    in-memory dict if the DB can't be opened, so a broken store never stalls
    triage (same philosophy as the Loki circuit breaker)."""

    def __init__(self, path=OFFENDER_DB):
        self.path = path
        self.conn = None
        self.fallback = {}  # ip -> [count, last_block_ts]
        try:
            self.conn = sqlite3.connect(path)
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS offenders ("
                "ip TEXT PRIMARY KEY, blocks INTEGER NOT NULL DEFAULT 0, "
                "last_block INTEGER NOT NULL)")
            self.conn.commit()
        except sqlite3.Error as e:
            log.warning("offender db %s unavailable (%s); using in-memory", path, e)
            self.conn = None

    def _reset_quiet(self, blocks, last_block, now):
        return 1 if now - last_block > BLOCK_SECS_QUIET else blocks + 1

    def bump(self, ip, now=None):
        """Record a block; returns the new offense count for this IP."""
        now = now or time.time()
        if self.conn is None:
            cur = self.fallback.get(ip)
            cur = self._reset_quiet(cur[0], cur[1], now) if cur else 1
            self.fallback[ip] = [cur, now]
            return cur
        try:
            row = self.conn.execute(
                "SELECT blocks, last_block FROM offenders WHERE ip = ?",
                (ip,)).fetchone()
            blocks = self._reset_quiet(row[0], row[1], now) if row else 1
            self.conn.execute(
                "INSERT INTO offenders (ip, blocks, last_block) VALUES (?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET blocks = excluded.blocks, "
                "last_block = excluded.last_block", (ip, blocks, now))
            self.conn.commit()
            return blocks
        except sqlite3.Error as e:
            log.warning("offender db write failed for %s (%s); falling back", ip, e)
            self.conn.close()
            self.conn = None
            return self.bump(ip, now)

    def top(self, n=10):
        """Highest block counts, newest first. Empty if DB or fallback empty."""
        if self.conn is not None:
            try:
                return self.conn.execute(
                    "SELECT ip, blocks, last_block FROM offenders "
                    "ORDER BY blocks DESC, last_block DESC LIMIT ?", (n,)).fetchall()
            except sqlite3.Error:
                return []
        rows = sorted(self.fallback.items(), key=lambda kv: (-kv[1][0], -kv[1][1]))
        return [(ip, c, ts) for ip, (c, ts) in rows[:n]]


class ControlLedger:
    """Fail-closed idempotency ledger for privileged control requests.

    An intent is committed before nftables is touched. If the process dies after
    the kernel update but before recording the result, retrying the same action
    ID returns ``in_progress`` instead of executing it a second time. An operator
    can then inspect actual state and submit a new, explicitly attributed action.
    """

    def __init__(self, path=OFFENDER_DB):
        self.conn = None
        try:
            self.conn = sqlite3.connect(path)
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS control_actions ("
                "action_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, "
                "state TEXT NOT NULL CHECK(state IN ('pending','complete')), "
                "response_json TEXT, created INTEGER NOT NULL, completed INTEGER)"
            )
            self.conn.commit()
        except sqlite3.Error as e:
            log.error("control ledger %s unavailable (%s); control mutations disabled", path, e)
            self.conn = None

    def begin(self, action_id, request_hash, now=None):
        """Return (state, cached_response): new, complete, pending, conflict, unavailable."""
        if self.conn is None:
            return "unavailable", None
        now = int(now or time.time())
        try:
            row = self.conn.execute(
                "SELECT request_hash, state, response_json FROM control_actions "
                "WHERE action_id = ?", (action_id,)).fetchone()
            if row:
                if row[0] != request_hash:
                    return "conflict", None
                if row[1] == "pending":
                    return "pending", None
                return "complete", json.loads(row[2])
            self.conn.execute(
                "INSERT INTO control_actions "
                "(action_id, request_hash, state, created) VALUES (?, ?, 'pending', ?)",
                (action_id, request_hash, now))
            self.conn.commit()
            return "new", None
        except (sqlite3.Error, ValueError, TypeError) as e:
            log.error("control ledger begin failed for %s: %s", action_id, e)
            return "unavailable", None

    def complete(self, action_id, response, now=None):
        if self.conn is None:
            return False
        try:
            self.conn.execute(
                "UPDATE control_actions SET state = 'complete', response_json = ?, "
                "completed = ? WHERE action_id = ? AND state = 'pending'",
                (json.dumps(response, sort_keys=True), int(now or time.time()), action_id))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            log.error("control ledger completion failed for %s: %s", action_id, e)
            return False
