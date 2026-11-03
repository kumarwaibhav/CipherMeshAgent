"""Pin the inputs of the Phase D replay into data/replay/ with a SHA-256 manifest.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

The replay must give the same result on every run, so it never reads data/snapshots/
(which every live run overwrites). This script copies the text-free derived payloads of
the GCP, AWS, CISA KEV and AI Incident Database feeds, plus the hand-written Azure what-if
fixture, into data/replay/ and writes MANIFEST.json. The demo checks every hash before use.

Usage: python demo/pin_replay_inputs.py      (run once; the pinned files are committed)
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ciphermesh.knowledge import load_graph  # noqa: E402
from ciphermesh.knowledge.feeds import (AiIncidentConnector, AwsHealthConnector, CisaKevConnector,  # noqa: E402
                                        GcpStatusConnector, SnapshotStore)

REPLAY = ROOT / "data" / "replay"
WHATIF = ROOT / "ciphermesh" / "knowledge" / "data" / "whatif_azure_status.xml"


def main() -> int:
    graph = load_graph()
    store = SnapshotStore(ROOT / "data" / "snapshots")
    REPLAY.mkdir(parents=True, exist_ok=True)
    files = {}
    for conn in (GcpStatusConnector(graph), AwsHealthConnector(graph), CisaKevConnector(graph),
                 AiIncidentConnector(graph)):
        meta = json.loads(store.paths(conn.name, conn.ext)[1].read_text(encoding="utf-8"))
        body = store.file_for(conn.name, conn.ext).read_bytes()
        if meta.get("raw_redistributed") is not False:
            body = conn.derivative(body)            # never pin third-party prose
        name = f"{conn.name}.derived.{conn.ext}"
        (REPLAY / name).write_bytes(body)
        files[name] = {"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body), "source": meta["url"],
                       "source_fetched_at": meta["fetched_at"],
                       "source_original_sha256": meta.get("original_sha256") or meta.get("sha256"),
                       "kind": "text-free derivative of a real live payload"}
    shutil.copyfile(WHATIF, REPLAY / WHATIF.name)
    body = WHATIF.read_bytes()
    files[WHATIF.name] = {"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body),
                          "kind": "hand-written what-if fixture (not real Microsoft data)"}
    manifest = {"pinned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "replay_as_of": "2026-02-27T13:00:00+00:00", "files": files}
    (REPLAY / "MANIFEST.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    for n, f in files.items():
        print(f"pinned {n:<32} {f['bytes']:>9} B  sha256={f['sha256'][:16]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
