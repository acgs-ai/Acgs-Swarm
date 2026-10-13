"""Separate worker process; HTTP subscriptions have no execution ownership."""

import argparse
import signal
import time

from .model import ComparisonCancelled, compare
from .store import Conflict, Store


def execute(store, lease):
    if store.heartbeat(lease) == "requested":
        store.ack_cancel(lease)
        return
    payload = store.checkpoint_payload(lease)
    if payload is None:
        try:
            payload = compare(
                store.sources(lease["id"]),
                cancel=lambda: store.heartbeat(lease) == "requested",
            )
        except ComparisonCancelled:
            store.ack_cancel(lease)
            return
        store.checkpoint(lease, payload)
    if store.heartbeat(lease) == "requested":
        store.ack_cancel(lease)
        return
    store.save_blob(lease)
    store.publish(lease)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="document_workspace/data/workspace.db")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    store = Store(args.db)
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(
        "SYNTHETIC fixture worker; no model calls. Reconciliation:",
        store.reconcile(),
        flush=True,
    )
    while not stopping:
        lease = store.claim("fixture-worker")
        if lease:
            try:
                execute(store, lease)
            except Conflict as exc:
                print("Transition rejected:", exc, flush=True)
                # Stale leases cannot publish failures either.
                try:
                    store.fail(lease, str(exc))
                except Conflict:
                    pass
            except (ValueError, OSError, TypeError, KeyError) as exc:
                store.fail(lease, type(exc).__name__)
        if args.once:
            return
        if not lease:
            time.sleep(0.25)


if __name__ == "__main__":
    main()
