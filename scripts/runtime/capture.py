#!/usr/bin/env python3
"""Capture selected function evidence from an explicitly supplied process or binary."""
import argparse
import hashlib
import json
from pathlib import Path
import threading
import time
import sys
import uuid


def main():
    import frida

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("plan", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--seconds", type=float, default=30)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    if not 0 < args.seconds <= 3600:
        parser.error("seconds must be between 0 and 3600")
    if not 1 <= plan["max_events"] <= 200000:
        parser.error("max_events must be between 1 and 200000")
    if not 0 <= plan["samples_per_function"] <= 128:
        parser.error("samples_per_function must be between 0 and 128")
    if not 1 <= len(plan["functions"]) <= 10000:
        parser.error("capture requires 1 to 10000 functions")
    for function in plan["functions"]:
        if not 0 <= function["arguments"] <= 8 or not 0 <= function.get("snapshot_bytes", 0) <= 4096:
            parser.error("invalid argument count or snapshot size")
    binary = args.binary.resolve(strict=True)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest != plan["binary_sha256"]:
        parser.error("capture plan belongs to a different binary")
    device = frida.get_local_device()
    spawned = args.pid is None
    pid = device.spawn([str(binary)]) if spawned else args.pid
    session = None
    events = []
    errors = []
    ended = threading.Event()
    try:
        session = device.attach(pid)
        session.on("detached", lambda *_: ended.set())
        script = session.create_script(Path(__file__).with_name("collector.js").read_text())
        def message(value, _data):
            if value["type"] == "send":
                events.append(value["payload"])
            else:
                errors.append(value)
                ended.set()
        script.on("message", message)
        script.load()
        metadata = script.exports_sync.start(plan)
        if Path(metadata["path"]).resolve() != binary:
            raise ValueError("Attached process uses a different main module")
        if spawned:
            device.resume(pid)
        started = time.monotonic()
        while not ended.is_set():
            remaining = max(0, args.seconds - (time.monotonic() - started))
            print(f"Capture: {len(events)} observations; elapsed {time.monotonic() - started:.0f}s; up to {remaining:.0f}s remaining", file=sys.stderr, flush=True)
            if remaining <= 0 or ended.wait(min(5, remaining)):
                break
        dropped = 0
        stopped_cleanly = False
        if not ended.is_set():
            dropped = script.exports_sync.stop()["dropped_events"]
            stopped_cleanly = True
        if errors:
            raise RuntimeError(f"Collector error: {errors[0]}")
        # Process exit can lose buffered events. Record this uncertainty in collector metadata.
        trace = {"version": 1, "id": str(uuid.uuid4()), "binary_sha256": digest,
                 "scenario": args.scenario, "image_base": plan["image_base"],
                 "pointer_width": metadata["pointer_width"],
                 "collector": f"frida-{frida.__version__}; bounded entry coverage; malloc/free={metadata['allocator_hooks']}; clean_stop={stopped_cleanly}",
                 "dropped_events": dropped, "events": events}
        args.output.write_text(json.dumps(trace, indent=2) + "\n")
        print(f"Saved {len(events)} observations to {args.output}")
    except BaseException:
        if spawned:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass
        raise
    finally:
        if session:
            try:
                session.detach()
            except frida.InvalidOperationError:
                pass


if __name__ == "__main__":
    main()
