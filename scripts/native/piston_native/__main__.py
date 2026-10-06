"""Run private, build-pinned native cases and compare translated observations."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import NativeMachine, PEImage, integer


def run_fixture(binary, fixture):
    if fixture.get("format") != 1 or len(fixture.get("sha256", "")) != 64:
        raise ValueError("Expected fixture format 1 and binary SHA-256")
    cases = fixture["cases"]
    if not 1 <= len(cases) <= 10000:
        raise ValueError("Expected 1 to 10000 cases")
    image = PEImage(binary, fixture["sha256"])
    results = []
    ids = set()
    for case in cases:
        case_id = case["id"]
        if not isinstance(case_id, str) or case_id in ids:
            raise ValueError("Each case needs a unique string ID")
        ids.add(case_id)
        machine = NativeMachine(image)
        for patch in fixture.get("patches", []) + case.get("patches", []):
            machine.write(image.base + integer(patch["rva"]), bytes.fromhex(patch["hex"]))
        for stub in fixture.get("return_boundaries", []) + case.get("return_boundaries", []):
            machine.hook_return(image.base + integer(stub["rva"]), integer(stub.get("value", 0)))
        for memory in case.get("memory", []):
            data = bytes.fromhex(memory["hex"])
            if len(data) > machine.arena_size:
                raise ValueError("Memory initializer exceeds arena")
            machine.write(integer(memory["address"]), data)
        entry = image.base + integer(case["entry_rva"])
        machine.call(entry, registers=case.get("registers", {}), extra=[integer(v) for v in case.get("stack_arguments", [])],
                     instruction_limit=fixture.get("instruction_limit", 30000), timeout_ms=fixture.get("timeout_ms", 1000))
        observed = {}
        for probe in case["observe"]:
            if probe["name"] in observed:
                raise ValueError("Duplicate observation name")
            if "register" in probe:
                observed[probe["name"]] = hex(machine.uc.reg_read(machine.register(probe["register"])))
            else:
                length = integer(probe["length"])
                if not 1 <= length <= 65536:
                    raise ValueError("Invalid observation length")
                observed[probe["name"]] = bytes(machine.uc.mem_read(integer(probe["address"]), length)).hex()
        if "expected" in case and observed != case["expected"]:
            raise AssertionError(f"Native expectation mismatch in {case_id}: {observed!r}")
        results.append({"id": case_id, "input": case.get("input", {}), "observed": observed, "boundaries": machine.boundaries, "patches": fixture.get("patches", []) + case.get("patches", [])})
    return {"sha256": image.sha256, "image_base": hex(image.base), "cases": results,
            "scope": "Selected native instructions with explicit memory, patches and return boundaries; excludes live game behavior"}


def compare(results, command, timeout=60):
    requests = "".join(json.dumps({"id": case["id"], "input": case["input"]}) + "\n" for case in results["cases"])
    process = subprocess.run(command, input=requests, capture_output=True, text=True, timeout=timeout, check=True)
    replies = [json.loads(line) for line in process.stdout.splitlines()]
    expected = {case["id"]: case["observed"] for case in results["cases"]}
    seen = set()
    mismatches = []
    for reply in replies:
        case_id = reply["id"]
        if case_id not in expected or case_id in seen:
            raise ValueError("Comparator returned an unknown or duplicate case ID")
        seen.add(case_id)
        if reply["observed"] != expected[case_id]:
            mismatches.append({"id": case_id, "native": expected[case_id], "translated": reply["observed"]})
    if seen != set(expected):
        raise ValueError("Comparator did not return every case")
    return mismatches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", nargs=argparse.REMAINDER, help="Trusted local comparator command; JSON lines on stdin/stdout")
    args = parser.parse_args()
    results = run_fixture(args.binary, json.loads(args.fixture.read_text()))
    if args.compare is not None:
        if not args.compare:
            parser.error("--compare requires a command")
        results["mismatches"] = compare(results, args.compare)
    encoded = json.dumps(results, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")
    if results.get("mismatches"):
        sys.exit(1)


if __name__ == "__main__":
    main()
