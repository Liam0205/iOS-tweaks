#!/usr/bin/env python3
"""Deploy a dev build to the gh-pages/dev/ Sileo repo."""

import gzip
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from glob import glob
from pathlib import Path


def run(cmd, **kwargs):
    kwargs.setdefault("check", True)
    kwargs.setdefault("text", True)
    return subprocess.run(cmd, **kwargs)


def run_output(cmd, **kwargs):
    kwargs.setdefault("check", True)
    kwargs.setdefault("text", True)
    return subprocess.run(cmd, stdout=subprocess.PIPE, **kwargs).stdout.strip()


def parse_control(control_path):
    fields = {}
    with open(control_path) as f:
        for line in f:
            if ":" in line:
                key, val = line.split(":", 1)
                fields[key.strip()] = val.strip()
    return fields


def find_deb(tweak_dir):
    debs = glob(str(tweak_dir / "packages" / "*.deb"))
    return Path(debs[0]) if debs else None


def generate_packages(dev_dir, control_fields):
    result = run_output(["dpkg-scanpackages", "debs", "/dev/null"], cwd=dev_dir,
                        stderr=subprocess.DEVNULL)
    pkg_id = control_fields["Package"]
    section = control_fields.get("Section")
    if section:
        result = re.sub(
            rf"(Package: {re.escape(pkg_id)}\n(?:(?!^$).*\n)*?)(Section:.*)",
            rf"\g<1>Section: {section}",
            result, flags=re.MULTILINE,
        )

    packages_path = dev_dir / "Packages"
    packages_path.write_text(result)

    with open(packages_path, "rb") as f_in:
        data = f_in.read()
    with gzip.open(dev_dir / "Packages.gz", "wb") as f_out:
        f_out.write(data)
    run(["bzip2", "-k", "-f", "Packages"], cwd=dev_dir)


def generate_release(dev_dir):
    lines = [
        "Origin: 0x01-dev",
        "Label: 0x01-dev",
        "Suite: unstable",
        "Version: 1.0",
        "Codename: unstable",
        "Architectures: iphoneos-arm64",
        "Components: main",
        "Description: 0x01 Dev Builds",
    ]
    files = ["Packages", "Packages.gz", "Packages.bz2"]

    for algo_name, algo in [("MD5Sum", "md5"), ("SHA256", "sha256")]:
        lines.append(f"{algo_name}:")
        for fname in files:
            fpath = dev_dir / fname
            data = fpath.read_bytes()
            h = hashlib.new(algo, data).hexdigest()
            lines.append(f" {h} {len(data)} {fname}")

    (dev_dir / "Release").write_text("\n".join(lines) + "\n")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <tweak-dir>", file=sys.stderr)
        sys.exit(1)

    repo_root = Path(__file__).resolve().parent
    tweak_dir = repo_root / sys.argv[1].rstrip("/")

    control_path = tweak_dir / "control"
    if not control_path.exists():
        print(f"Error: {control_path} not found", file=sys.stderr)
        sys.exit(1)

    fields = parse_control(control_path)
    pkg_id = fields["Package"]
    version = fields["Version"]

    deb = find_deb(tweak_dir)
    if not deb:
        print(f"No .deb in {tweak_dir}/packages/ — build first with make package")
        sys.exit(1)

    print(f"Deploying: {deb.name}")

    work = Path(tempfile.mkdtemp())
    try:
        os.chdir(repo_root)
        run(["git", "fetch", "origin", "gh-pages:gh-pages"],
            stderr=subprocess.DEVNULL, check=False)
        run(["git", "worktree", "add", str(work / "gh-pages"), "gh-pages"])

        dev_dir = work / "gh-pages" / "dev"
        debs_dir = dev_dir / "debs"
        debs_dir.mkdir(parents=True, exist_ok=True)

        for old in debs_dir.glob(f"{pkg_id}_*.deb"):
            old.unlink()
        shutil.copy2(deb, debs_dir)

        generate_packages(dev_dir, fields)
        generate_release(dev_dir)

        gh_pages = work / "gh-pages"
        run(["git", "add", "dev/"], cwd=gh_pages)

        result = subprocess.run(
            ["git", "diff", "--cached", "--quiet"],
            cwd=gh_pages,
        )
        if result.returncode == 0:
            print("Nothing to deploy (no changes)")
            return

        run(["git", "commit", "-m", f"dev: {pkg_id} {version}"], cwd=gh_pages)
        run(["git", "push", "origin", "gh-pages"], cwd=gh_pages)

        print(f"\nDone! Dev repo updated: https://tweaks.0x01.page/dev/")
        print(f"  Package: {pkg_id} {version}")
    finally:
        os.chdir(repo_root)
        run(["git", "worktree", "remove", str(work / "gh-pages")], check=False)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
