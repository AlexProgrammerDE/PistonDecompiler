#!/usr/bin/env python3
"""Record an explicit target, with a durable journal and optional managed controls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shlex
import sys
import threading
import time
import uuid


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def read_journal(path):
    """Only a torn final line can be discarded. Earlier corruption is an error."""
    events = []
    with path.open('rb') as stream:
        for line in stream:
            if not line.endswith(b'\n'):
                break
            events.append(json.loads(line))
    return events


def finalize(directory, complete=False):
    metadata = json.loads((directory / 'metadata.json').read_text())
    events = read_journal(directory / 'events.jsonl')
    progress = json.loads((directory / 'progress.json').read_text()) if (directory / 'progress.json').exists() else {}
    metadata['events'] = events
    metadata['dropped_events'] = progress.get('dropped_events', 0)
    metadata['collector'] += f'; clean_stop={complete}; interrupted={not complete}'
    atomic_json(directory / 'trace.json', metadata)
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path, nargs='?')
    parser.add_argument('plan', type=Path, nargs='?')
    parser.add_argument('output', type=Path, nargs='?')
    parser.add_argument('--scenario')
    parser.add_argument('--pid', type=int)
    parser.add_argument('--seconds', type=float, default=300)
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--recover', type=Path)
    parser.add_argument('--mark', type=Path)
    parser.add_argument('--mark-active', type=Path)
    parser.add_argument('--label', default='Hotkey marker')
    parser.add_argument('--managed', action='store_true')
    args = parser.parse_args()
    if args.mark_active:
        identity = json.loads((args.mark_active / 'active.json').read_text())['id']
        uuid.UUID(identity)
        args.mark = args.mark_active / identity
        state = json.loads((args.mark / 'progress.json').read_text())['state']
        if state != 'recording':
            parser.error('There is no active recording')
    if args.mark:
        if not (args.mark / 'commands').is_dir():
            parser.error('Unknown recording directory')
        atomic_json(args.mark / 'commands' / (str(uuid.uuid4()) + '.json'), {'action': 'marker', 'label': args.label})
        return
    if args.recover:
        finalize(args.recover)
        return
    import frida
    if not args.binary or not args.plan or not args.output or not args.scenario:
        parser.error('binary, plan, output and scenario are required')
    plan = json.loads(args.plan.read_text())
    if not 0 < args.seconds <= 3600:
        parser.error('seconds must be between 0 and 3600')
    if not 1 <= plan['max_events'] <= 200000 or not 0 <= plan['samples_per_function'] <= 128:
        parser.error('invalid event or sample limit')
    if not 1 <= len(plan['functions']) <= 10000:
        parser.error('capture requires 1 to 10000 functions')
    for function in plan['functions']:
        if not 0 <= function['arguments'] <= 8 or not 0 <= function.get('snapshot_bytes', 0) <= 4096:
            parser.error('invalid argument count or snapshot size')
    binary = args.binary.resolve(strict=True)
    with binary.open('rb') as executable_stream:
        digest = hashlib.file_digest(executable_stream, 'sha256').hexdigest()
    if digest != plan['binary_sha256']:
        parser.error('capture plan belongs to a different binary')
    directory = args.directory or args.output.with_suffix('.recording')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    commands = directory / 'commands'
    commands.mkdir(exist_ok=True)
    messages = queue.Queue(maxsize=8192)
    ended = threading.Event()
    stop = threading.Event()
    lost = 0
    overflow = False
    def receive(value, _data):
        nonlocal lost, overflow
        if overflow:
            lost += 1
            return
        try:
            messages.put_nowait(value)
        except queue.Full:
            overflow = True
            lost += 1
            stop.set()
    if args.managed:
        def parent_watch():
            while os.read(0, 1):
                pass
            stop.set()
        threading.Thread(target=parent_watch, daemon=True).start()
    listener = None
    hotkey = 'Unavailable; use Add marker or the desktop shortcut command'
    try:
        from pynput.keyboard import GlobalHotKeys
        listener = GlobalHotKeys({'<ctrl>+<alt>+m': lambda: atomic_json(commands / (str(uuid.uuid4()) + '.json'), {'action': 'marker', 'label': 'Hotkey marker'})})
        listener.start()
        hotkey = 'Ctrl+Alt+M (desktop support required)'
    except Exception:
        pass
    device = frida.get_local_device()
    spawned = args.pid is None
    pid = device.spawn([str(binary), *plan.get('argv', [])], cwd=plan.get('cwd') or str(binary.parent)) if spawned else args.pid
    session = None
    script = None
    ready = False
    count = 0
    counts = {}
    disk_bytes = 0
    started = time.monotonic()
    error = None
    dropped = 0
    marker_count = 0
    skipped_functions = 0
    last_marker = ''
    complete = False
    disk_full = False
    def progress(state):
        atomic_json(directory / 'progress.json', {'state': state, 'events': count, 'bytes': disk_bytes,
            'elapsed_seconds': int(time.monotonic() - started), 'remaining_seconds': max(0, int(args.seconds - (time.monotonic() - started))),
            'skipped_functions': skipped_functions, 'counts': counts, 'dropped_events': dropped + lost, 'pid': pid, 'recorder_pid': os.getpid(), 'hotkey': hotkey,
            'markers': marker_count, 'last_marker': last_marker, 'error': error,
            'shortcut_command': shlex.join([sys.executable, plan.get('marker_script', str(Path(__file__).resolve())), '--mark-active', str(directory.parent)])})
    try:
        session = device.attach(pid)
        session.on('detached', lambda *_: ended.set())
        script = session.create_script(Path(__file__).with_name('collector.js').read_text())
        script.on('message', receive)
        script.load()
        identity = script.exports_sync.identity()
        if Path(identity['path']).resolve() != binary:
            raise ValueError('Attached process uses a different main module')
        metadata = {'version': 1, 'id': plan.get('session_id', str(uuid.uuid4())), 'binary_sha256': digest,
            'scenario': args.scenario, 'image_base': plan['image_base'], 'pointer_width': identity['pointer_width'],
            'collector': f'frida-{frida.__version__}; architecture={identity["architecture"]}; module_base={identity["base"]}; bounded samples; plan=plan.json', 'dropped_events': 0}
        atomic_json(directory / 'metadata.json', metadata)
        atomic_json(directory / 'plan.json', plan)
        # The journal exists before any instrumentation emits observations.
        with (directory / 'events.jsonl').open('xb') as journal:
            setup = script.exports_sync.start(plan)
            skipped_functions = setup.get('skipped_functions', 0)
            metadata['collector'] += f'; uninstrumented_functions={skipped_functions}; malloc/free={setup["allocator_hooks"]}'
            atomic_json(directory / 'metadata.json', metadata)
            ready = True
            if spawned:
                device.resume(pid)
            last_flush = 0
            stopping = False
            drain_until = None
            while True:
                now = time.monotonic()
                for command in sorted(commands.glob('*.json')):
                    value = json.loads(command.read_text())
                    if value['action'] == 'stop':
                        stop.set()
                    elif value['action'] == 'marker' and not stopping:
                        script.exports_sync.marker(value.get('label') or 'Marker')
                    command.unlink()
                if not stopping and (stop.is_set() or ended.is_set() or now - started >= args.seconds or disk_bytes >= 24 * 1024 * 1024):
                    stopping = True
                    if not ended.is_set():
                        dropped = script.exports_sync.stop()['dropped_events']
                        complete = True
                    drain_until = time.monotonic() + 0.3
                try:
                    message = messages.get(timeout=0.05)
                    if message['type'] == 'send':
                        event = message['payload']
                        line = (json.dumps(event, separators=(',', ':')) + '\n').encode()
                        if not disk_full and disk_bytes + len(line) <= 28 * 1024 * 1024:
                            journal.write(line)
                            count += 1
                            kind = event.get('kind', 'unknown')
                            counts[kind] = counts.get(kind, 0) + 1
                            disk_bytes += len(line)
                            if event.get('kind') == 'marker':
                                marker_count += 1
                                last_marker = event['label']
                        else:
                            disk_full = True
                            lost += 1
                            stop.set()
                    else:
                        error = message.get('description', str(message))
                        stop.set()
                except queue.Empty:
                    pass
                if now - last_flush >= 0.5 or stopping:
                    journal.flush()
                    os.fsync(journal.fileno())
                    progress('stopping' if stopping else 'recording')
                    last_flush = now
                if stopping and messages.empty() and time.monotonic() >= drain_until:
                    break
        progress('failed' if error else 'complete' if complete else 'interrupted')
        trace = finalize(directory, complete and not error)
        if args.output != directory / 'trace.json':
            atomic_json(args.output, trace)
        if error:
            raise RuntimeError(error)
    except BaseException as exc:
        error = str(exc)
        progress('failed')
        # Never kill a process the user attached to, or a successfully launched app.
        if spawned and not ready:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass
        raise
    finally:
        if listener:
            listener.stop()
        if session:
            try:
                session.detach()
            except frida.InvalidOperationError:
                pass


if __name__ == '__main__':
    main()
