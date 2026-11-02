"""Build standalone native-TUN archives separately from the default release."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile


TARGETS = ("linux-amd64", "linux-arm64", "darwin-arm64")
NOTICE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "AUTHORS", "CONTRIBUTORS", "PATENTS")
BUILD_FLAGS = ["-tags=with_sing_tun", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid="]


def output(*args, env=None):
    return subprocess.check_output(args, text=True, env=env).strip()


def package_graph(env):
    stream = output("go", "list", "-deps", "-json", "-tags=with_sing_tun", "./main", env=env)
    decoder = json.JSONDecoder()
    modules = {}
    while stream:
        package, end = decoder.raw_decode(stream)
        stream = stream[end:].lstrip()
        module = package.get("Module")
        if module is None:
            continue
        entry = modules.setdefault(module["Path"], {"module": module, "directories": set()})
        entry["directories"].add(Path(package["Dir"]).resolve())
    return modules


def notice_files(root, directories):
    notices = set()
    parents = {root}
    for directory in directories:
        while directory != root:
            directory.relative_to(root)
            parents.add(directory)
            directory = directory.parent
    for directory in parents:
        for candidate in directory.iterdir():
            name = candidate.name.upper()
            if not (name.startswith(NOTICE_PREFIXES) or "NOTICE" in name):
                continue
            if candidate.is_symlink():
                continue
            files = candidate.rglob("*") if candidate.is_dir() else [candidate]
            for path in files:
                if path.is_file() and not path.is_symlink():
                    notices.add(path)
    if not notices:
        raise RuntimeError(f"No copyright/license notice found for {root.name}")
    return sorted(notices)


def module_notices(graph, directory, commit):
    records = []
    for identity, entry in sorted(graph.items()):
        module = entry["module"]
        source = module.get("Replace", module)
        version = source.get("Version", "")
        if not module.get("Main") and not version:
            raise RuntimeError("Native release requires versioned module replacements: " + identity)
        root = Path(source["Dir"]).resolve()
        destination = Path("licenses") / (identity + "@" + (version or commit))
        notices = []
        for path in notice_files(root, entry["directories"]):
            target = directory / destination / path.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            notices.append(target.relative_to(directory).as_posix())
        records.append({
            "path": identity, "version": module.get("Version", ""),
            "source_path": source["Path"], "source_version": version,
            "sum": source.get("Sum", ""), "notices": notices,
        })
    return records


def package_target(target, root, commit, dirty, go_version, goroot):
    goos, goarch = target.split("-")
    env = dict(os.environ, CGO_ENABLED="0", GOOS=goos, GOARCH=goarch, GOWORK="off", GOFLAGS="")
    directory = root / target
    directory.mkdir()
    executable = directory / "xray-native"
    subprocess.run(["go", "build", *BUILD_FLAGS, "-o", str(executable), "./main"], env=env, check=True)
    graph = package_graph(env)
    modules = module_notices(graph, directory, commit)
    shutil.copyfile(".github/licenses/GPL-3.0.txt", directory / "COPYING")
    shutil.copyfile("LICENSE", directory / "LICENSE-Xray-MPL-2.0")
    runtime = directory / "licenses" / "Go-runtime"
    runtime.mkdir()
    for name in ("LICENSE", "PATENTS", "AUTHORS", "CONTRIBUTORS"):
        source = goroot / name
        if source.is_file():
            shutil.copyfile(source, runtime / name)
    if not (runtime / "LICENSE").is_file():
        raise RuntimeError("Go runtime LICENSE is missing")
    source_url = "https://github.com/Tozward/Xray-core-socks-uds/tree/" + commit
    source = {
        "source_commit": commit, "source_url": source_url, "working_tree_dirty": dirty,
        "target": {"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0"},
        "go_version": go_version, "build_flags": BUILD_FLAGS, "modules": modules,
        "go_mod_sha256": hashlib.sha256(Path("go.mod").read_bytes()).hexdigest(),
        "go_sum_sha256": hashlib.sha256(Path("go.sum").read_bytes()).hexdigest(),
    }
    (directory / "SOURCE.json").write_text(json.dumps(source, indent=2) + "\n")
    (directory / "NATIVE-NOTICES.txt").write_text(
        "This native executable includes the optional GPLv3 SagerNet sing and sing-tun libraries.\n"
        "The combined native executable is distributed under GPLv3; each component retains its source license.\n"
        "COPYING contains GPLv3. LICENSE-Xray-MPL-2.0 retains Xray's source license.\n"
        "Original module copyright, license, patent and attribution notices are under licenses/.\n"
        "SOURCE.json lists the runtime-linked module versions, replacements and build flags.\n"
        "Corresponding project source: " + source_url + "\n"
        "Corresponding dependency sources are available at the versioned module paths in SOURCE.json.\n"
        "Source releases and modifications must retain their original notices.\n"
    )
    (directory / "README.txt").write_text(
        "Xray native Sing TUN\n\n"
        "Run xray-native with an Xray configuration containing a sing-tun inbound.\n"
        "The host owns TUN addresses, routes, DNS and outbound socket protection/interface binding.\n"
        "Avoid routing the core's own outbound sockets back into the TUN.\n"
        "When xray.tun.fd is supplied, the core duplicates it; the host retains the original descriptor.\n"
        "Match the configured addresses and MTU to the host interface. TCP and UDP are supported;\n"
        "this inbound does not provide ICMP forwarding or automatic route/DNS configuration.\n"
        "Geodata files are not bundled; supply any files referenced by the configuration.\n\n"
        "The native build is separate from the default MPL-only core distribution.\n"
        "Windows is not packaged: this native inbound's device adapter supports Linux/macOS.\n"
        "macOS cross-compilation is not real-utun runtime validation. Hosted macOS checks were\n"
        "unavailable due to runner capacity, and local real-utun cases require additional privilege.\n"
        "See the source audit records for the checks that actually ran; no desktop battery claim is made.\n\n"
        "To reproduce, obtain the exact source commit and module versions in SOURCE.json and use\n"
        "the recorded Go toolchain. From that source checkout, execute the following build command\n"
        "with the GOOS/GOARCH/CGO_ENABLED values recorded for this archive:\n\n"
        "  go build -tags=with_sing_tun -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o xray-native ./main\n"
    )
    archive_path = root / ("Xray-native-" + target + ".zip")
    with zipfile.ZipFile(archive_path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(directory).as_posix())
    return archive_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", nargs="+", choices=TARGETS, default=TARGETS)
    args = parser.parse_args()
    commit = output("git", "rev-parse", "HEAD")
    dirty = bool(output("git", "status", "--porcelain"))
    root = Path("native-release").resolve()
    root.mkdir()
    go_version = output("go", "version")
    goroot = Path(output("go", "env", "GOROOT"))
    archives = [package_target(target, root, commit, dirty, go_version, goroot) for target in args.targets]
    sums = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name for path in archives]
    (root / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    print("Packaged native targets: " + ", ".join(args.targets))


if __name__ == "__main__":
    main()
