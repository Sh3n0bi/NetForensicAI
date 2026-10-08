"""Throttling for failed authentication attempts.

The web UI's shared token is the only access control once it is bound off
loopback, so how fast it can be guessed matters. Before this module a client
could try thousands of tokens a second; with it, a client gets a small number
of wrong guesses per window and is then refused - *including with the correct
token* - until the window frees. Refusing the right token during a lockout is
deliberate: otherwise an attacker could keep guessing and simply watch for the
one request that is not rejected.

Policy:

* Only a credential that was SUPPLIED and WRONG counts. A request with no
  credential at all (someone loading the login page) is not a failure.
* Failures are counted per client address and also across all clients, so
  rotating source addresses does not reset the budget.
* Requests refused during a lockout are not themselves counted, so hammering
  a locked-out endpoint cannot keep extending the lockout indefinitely.
* Memory is bounded: idle clients are dropped and the table has a hard size cap.

Limits: clients behind one reverse proxy share that proxy's address, so one
bad actor can lock out everyone for a window. For a single-investigator tool
that is the right way round - it fails closed, and clears itself in a minute.
This does not replace a long random token; it makes guessing impractical
rather than merely slow.
"""

import math
import threading
import time
from collections import deque

DEFAULT_MAX_FAILURES = 10
DEFAULT_WINDOW_SECONDS = 60.0
# Across every client combined. Higher than the per-client limit so one noisy
# client trips its own limit first, low enough to stop a distributed guess.
DEFAULT_GLOBAL_MAX_FAILURES = 100
# Hard cap on distinct clients tracked at once.
MAX_TRACKED_CLIENTS = 4096


class FailureLimiter:
    """Sliding-window limiter on failed authentication attempts. Thread-safe."""

    def __init__(
        self,
        max_failures=DEFAULT_MAX_FAILURES,
        window_seconds=DEFAULT_WINDOW_SECONDS,
        global_max_failures=DEFAULT_GLOBAL_MAX_FAILURES,
        clock=time.monotonic,
    ):
        self.max_failures = max_failures
        self.window = float(window_seconds)
        self.global_max_failures = global_max_failures
        self._clock = clock
        self._lock = threading.Lock()
        self._by_client = {}
        self._overall = deque()

    def _prune(self, failures, now):
        while failures and now - failures[0] >= self.window:
            failures.popleft()

    def _wait_for(self, failures, limit, now):
        """Seconds until `failures` drops below `limit`, or 0 if it already has."""
        self._prune(failures, now)
        if len(failures) < limit:
            return 0
        # The failure that must age out is the one that put us at the limit.
        oldest_that_matters = failures[len(failures) - limit]
        return max(1, math.ceil(oldest_that_matters + self.window - now))

    def blocked_for(self, client):
        """Seconds the caller must wait before another attempt is considered, or 0."""
        now = self._clock()
        with self._lock:
            per_client = self._wait_for(self._by_client.get(client, deque()), self.max_failures, now)
            overall = self._wait_for(self._overall, self.global_max_failures, now)
            return max(per_client, overall)

    def record_failure(self, client):
        """Count one wrong credential. Callers check blocked_for() first, so a
        refused request is never recorded here."""
        now = self._clock()
        with self._lock:
            failures = self._by_client.setdefault(client, deque())
            self._prune(failures, now)
            failures.append(now)
            self._prune(self._overall, now)
            self._overall.append(now)
            if len(self._by_client) > MAX_TRACKED_CLIENTS:
                self._evict(now)

    def _evict(self, now):
        """Drop idle clients, then, if still over the cap, the least recently failing."""
        for client in [c for c, f in self._by_client.items() if not f or now - f[-1] >= self.window]:
            del self._by_client[client]
        overflow = len(self._by_client) - MAX_TRACKED_CLIENTS
        if overflow > 0:
            oldest_first = sorted(self._by_client, key=lambda c: self._by_client[c][-1])
            for client in oldest_first[:overflow]:
                del self._by_client[client]

    def tracked_clients(self):
        with self._lock:
            return len(self._by_client)
