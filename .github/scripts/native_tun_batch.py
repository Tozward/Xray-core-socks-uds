"""Compare splice read batches on one runner without changing the dependency."""

import hashlib
import json
import os
from pathlib import Path
import random
import re
import statistics
import subprocess


ROOT = Path("batch-evidence").resolve()
ROOT.mkdir(exist_ok=True)
env = dict(os.environ, GOMAXPROCS="4")
subprocess.run(["go", "mod", "download", "github.com/sagernet/sing-tun"], env=env, check=True)
module = json.loads(subprocess.check_output(
    ["go", "list", "-m", "-json", "github.com/sagernet/sing-tun"], env=env))
source = Path(module["Replace"]["Dir"]) / "stack_go_splice.go"
original = source.read_text()
needle = "goSpliceReadChunk  = 2 * goSlabSize"
if original.count(needle) != 1:
    raise SystemExit("Pinned splice batch declaration changed; review the experiment")
variants = ["64", "128", "256"]
manifest = {"module": module, "original_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "variants": {}}
for variant in variants:
    directory = ROOT / variant
    directory.mkdir(exist_ok=True)
    replacement = directory / "stack_go_splice.go"
    replacement.write_text(original.replace(needle, f"goSpliceReadChunk  = {int(variant) // 32} * goSlabSize"))
    overlay = directory / "overlay.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(replacement)}}))
    binary = directory / "native-tun-bench"
    subprocess.run(["go", "test", f"-overlay={overlay}", "-tags", "with_sing_tun", "-c",
                    "./proxy/singtun", "-o", str(binary)], env=env, check=True)
    manifest["variants"][variant] = {"splice_sha256": hashlib.sha256(replacement.read_bytes()).hexdigest(),
                                       "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
(ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2))


def measure(variant, name, repetition, fairness=False):
    pattern = "/".join("^" + re.escape(component) + "$" for component in name.split("/"))
    command = ["sudo", "env", "GOMAXPROCS=4", "XRAY_REQUIRE_NATIVE_TUN_TESTS=1",
               str(ROOT / variant / "native-tun-bench"), "-test.run", "^$", "-test.bench", pattern,
               "-test.benchmem", "-test.benchtime=1x" if fairness else "-test.benchtime=1s",
               "-test.count=1", "-test.timeout=2m"]
    path = ROOT / variant / name / f"repeat-{repetition}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=150)
    path.write_text(result.stdout + result.stderr)
    if result.returncode != 0:
        raise SystemExit(f"Benchmark failed: {path}\n{result.stdout}\n{result.stderr}")
    output = result.stdout
    rows = [line.split() for line in output.splitlines() if " ns/op" in line and " allocs/op" in line]
    if len(rows) != 1 or any(marker in output for marker in ("--- FAIL:", "WARNING: DATA RACE", "SKIP")):
        raise SystemExit(f"Incomplete benchmark: {path}")
    fields = rows[0]
    if re.sub(r"-\d+$", "", fields[0]) != name:
        raise SystemExit(f"Unexpected benchmark selection: {path}: {fields[0]}")
    metrics = {fields[index + 1]: float(fields[index]) for index in range(2, len(fields) - 1, 2)}
    if metrics.get("path-MTU") != 9000:
        raise SystemExit(f"Unexpected path MTU: {path}")
    if not fairness:
        if metrics.get("cpu-ms/op", 0) <= 0 or metrics.get("jumbo-max-IP-B", 0) <= 9000:
            raise SystemExit(f"Missing CPU/jumbo evidence: {path}")
        workload = name.split("/")[2]
        for direction in ("up", "down"):
            minimum = 4 * 1024 * 1024 if workload == "duplex" or workload == {"up": "upload", "down": "download"}[direction] else 1
            if metrics.get(f"native-{direction}-B/op", 0) < minimum:
                raise SystemExit(f"Incomplete native {direction} handoff: {path}")
    elif not (metrics.get("min-completed", 0) > 0 and 0 < metrics.get("Jain-index", 0) <= 1
              and metrics.get("probe-count", 0) > 0 and metrics.get("probe-p99-us", 0) > 0):
        raise SystemExit(f"Incomplete mixed-flow evidence: {path}")
    print(f"{variant}KiB {name} repeat={repetition} {metrics}", flush=True)
    return {"variant_KiB": int(variant), "name": name, "repetition": repetition, "metrics": metrics}


results = []
rng = random.Random(20261103)
bulk = [f"BenchmarkKernelNativeProfile/{transport}/{workload}/mtu_9000/native_bidirectional_jumbo"
        for transport in ("freedom", "freedom_tls13", "vision_tls13")
        for workload in ("upload", "download", "duplex")]
fairness = [f"BenchmarkKernelNativeBatchFairness/{transport}/flows_{flows}"
            for transport in ("freedom_tls13", "vision_tls13") for flows in (1, 4)]
for repetition in range(5):
    cases = bulk + fairness
    rng.shuffle(cases)
    for name in cases:
        order = variants.copy()
        rng.shuffle(order)
        for variant in order:
            results.append(measure(variant, name, repetition, fairness=name in fairness))
            (ROOT / "results.json").write_text(json.dumps(results, indent=2))

summary = []
for name in bulk + fairness:
    for variant in variants:
        samples = [row["metrics"] for row in results if row["name"] == name and row["variant_KiB"] == int(variant)]
        summary.append({"name": name, "variant_KiB": int(variant), "samples": len(samples),
                        "median": {key: statistics.median(row[key] for row in samples) for key in samples[0]}})
(ROOT / "summary.json").write_text(json.dumps(summary, indent=2))
