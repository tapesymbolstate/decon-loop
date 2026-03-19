#!/usr/bin/env python3
"""Discover the identity and open-source origin of a binary.

Analyzes strings, symbols, and embedded metadata to determine:
- What software the binary is (name, version)
- Whether it has an open-source repository
- The exact version tag to clone

Usage: python3 discover_source.py <binary_path> [--output-dir output/discovery]

Output: output/discovery/identity.json
{
  "name": "bun",
  "version": "1.2.8",
  "repo_url": "https://github.com/oven-sh/bun.git",
  "tag": "bun-v1.2.8",
  "languages": ["zig", "cpp"],
  "confidence": "high",
  "evidence": ["version string match", "repo URL in binary", ...]
}
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def extract_strings(binary_path: str, min_len: int = 6) -> list[str]:
    result = subprocess.run(
        ["strings", "-n", str(min_len), binary_path],
        capture_output=True, text=True, timeout=120
    )
    return result.stdout.splitlines()


def extract_symbols(binary_path: str) -> list[str]:
    result = subprocess.run(
        ["nm", "-j", binary_path],
        capture_output=True, text=True, timeout=60
    )
    return result.stdout.splitlines()


def detect_identity(strings_list: list[str], symbols: list[str]) -> dict:
    """Try to identify the software from strings and symbols."""
    identity = {
        "name": None,
        "version": None,
        "repo_url": None,
        "tag": None,
        "languages": [],
        "confidence": "none",
        "evidence": [],
        "source_dir_hint": None,
    }

    all_text = "\n".join(strings_list[:100000])

    for detector in [
        _detect_from_github_urls,
        _detect_from_known_signatures,
        _detect_from_version_strings,
        _detect_from_build_paths,
        _detect_from_symbols,
    ]:
        detector(strings_list, symbols, all_text, identity)

    # Fill in source_dir_hint from known DB if we matched by other means
    if identity["name"] and identity["name"] in _KNOWN_SOFTWARE:
        sig = _KNOWN_SOFTWARE[identity["name"]]
        if not identity["repo_url"] and sig.get("repo_url"):
            identity["repo_url"] = sig["repo_url"]
        if not identity.get("source_dir_hint") and sig.get("source_dir_hint"):
            identity["source_dir_hint"] = sig["source_dir_hint"]

    _detect_languages(strings_list, symbols, all_text, identity)
    _compute_confidence(identity)

    return identity


def _detect_from_github_urls(strings_list, symbols, all_text, identity):
    """Look for GitHub URLs embedded in the binary."""
    gh_patterns = [
        r'github\.com/([a-zA-Z0-9_-]+)/([a-zA-Z0-9_.-]+)',
        r'raw\.githubusercontent\.com/([a-zA-Z0-9_-]+)/([a-zA-Z0-9_.-]+)',
    ]
    repo_counts = {}
    for s in strings_list[:100000]:
        for pat in gh_patterns:
            for m in re.finditer(pat, s):
                owner, repo = m.group(1), m.group(2).rstrip('.git')
                key = f"{owner}/{repo}"
                if key not in _IGNORE_REPOS:
                    repo_counts[key] = repo_counts.get(key, 0) + 1

    if repo_counts:
        top_repo = max(repo_counts, key=repo_counts.get)
        owner, repo = top_repo.split("/")
        identity["repo_url"] = f"https://github.com/{top_repo}.git"
        if not identity["name"]:
            identity["name"] = repo.lower()
        identity["evidence"].append(f"GitHub URL found: {top_repo} ({repo_counts[top_repo]} refs)")


def _detect_from_version_strings(strings_list, symbols, all_text, identity):
    """Look for version strings like 'bun 1.2.8' or 'node v20.1.0'."""
    version_patterns = [
        (r'(?:^|\s)(\w+)[/ ]v?(\d+\.\d+\.\d+)(?:\s|$)', None),
        (r'(\w+)-v?(\d+\.\d+\.\d+)', None),
        (r'Version:\s*v?(\d+\.\d+\.\d+)', "version_only"),
    ]
    for s in strings_list[:50000]:
        for pat, kind in version_patterns:
            m = re.search(pat, s)
            if m:
                if kind == "version_only":
                    if not identity["version"]:
                        identity["version"] = m.group(1)
                        identity["evidence"].append(f"Version string: {s.strip()[:80]}")
                else:
                    name_candidate = m.group(1).lower()
                    ver = m.group(2)
                    if name_candidate in _KNOWN_SOFTWARE:
                        identity["name"] = name_candidate
                        identity["version"] = ver
                        identity["evidence"].append(f"Version string: {name_candidate} {ver}")
                        return


def _detect_from_known_signatures(strings_list, symbols, all_text, identity):
    """Match against known software signatures."""
    for sig in _KNOWN_SOFTWARE.values():
        matched_markers = []
        for marker in sig.get("string_markers", []):
            if marker in all_text:
                matched_markers.append(marker)

        if len(matched_markers) >= sig.get("min_markers", 2):
            if not identity["name"]:
                identity["name"] = sig["name"]
            if not identity["repo_url"]:
                identity["repo_url"] = sig.get("repo_url")
            identity["evidence"].append(
                f"Signature match: {sig['name']} ({len(matched_markers)} markers: {matched_markers[:3]})"
            )
            if sig.get("source_dir_hint"):
                identity["source_dir_hint"] = sig["source_dir_hint"]
            break


def _detect_from_build_paths(strings_list, symbols, all_text, identity):
    """Look for build/source paths that hint at the project."""
    path_patterns = [
        r'(/[Uu]sers/\w+/[\w/.+-]+)',
        r'(src/[\w/.+-]+\.\w+)',
        r'(\w+/src/[\w/.+-]+)',
    ]
    paths = set()
    for s in strings_list[:100000]:
        for pat in path_patterns:
            for m in re.finditer(pat, s):
                paths.add(m.group(1))

    if paths:
        ext_counts = {}
        for p in paths:
            ext = Path(p).suffix
            if ext:
                ext_counts[ext] = ext_counts.get(ext, 0) + 1
        identity["evidence"].append(f"Build paths found: {len(paths)} paths, extensions: {ext_counts}")


def _detect_from_symbols(strings_list, symbols, all_text, identity):
    """Use exported symbol patterns to identify the software."""
    symbol_set = set(symbols[:5000])

    napi_count = sum(1 for s in symbol_set if s.startswith("_napi_"))
    uv_count = sum(1 for s in symbol_set if s.startswith("_uv_"))
    node_count = sum(1 for s in symbol_set if "node" in s.lower())

    if napi_count > 50:
        identity["evidence"].append(f"N-API symbols: {napi_count} (Node.js compatible runtime)")
    if uv_count > 20:
        identity["evidence"].append(f"libuv symbols: {uv_count}")


def _detect_languages(strings_list, symbols, all_text, identity):
    """Detect programming languages used."""
    langs = set()

    zig_indicators = [".zig", "zig-linux", "zig-macos", "ZIG_PROGRESS"]
    cpp_indicators = ["__cxa_throw", "std::__1", "libc++", "__cxxabiv1"]
    rust_indicators = ["_cargo_registry", "rust_begin_unwind", ".rs:"]
    go_indicators = ["runtime.gopanic", "go.buildid"]
    swift_indicators = ["Swift.", "swift_demangle"]

    for indicator in zig_indicators:
        if indicator in all_text:
            langs.add("zig")
            break
    for indicator in cpp_indicators:
        if indicator in all_text:
            langs.add("cpp")
            break
    for indicator in rust_indicators:
        if indicator in all_text:
            langs.add("rust")
            break
    for indicator in go_indicators:
        if indicator in all_text:
            langs.add("go")
            break
    for indicator in swift_indicators:
        if indicator in all_text:
            langs.add("swift")
            break

    c_indicators = [".c:", "printf", "fprintf"]
    if not langs:
        for indicator in c_indicators:
            if indicator in all_text:
                langs.add("c")
                break

    identity["languages"] = sorted(langs)


def _compute_confidence(identity):
    evidence_count = len(identity["evidence"])
    has_name = identity["name"] is not None
    has_version = identity["version"] is not None
    has_repo = identity["repo_url"] is not None

    if has_name and has_version and has_repo and evidence_count >= 3:
        identity["confidence"] = "high"
    elif has_name and has_repo and evidence_count >= 2:
        identity["confidence"] = "medium"
    elif has_name and evidence_count >= 1:
        identity["confidence"] = "low"
    else:
        identity["confidence"] = "none"


def resolve_tag(identity: dict) -> str | None:
    """Try to determine the git tag for the identified version."""
    name = identity.get("name", "")
    version = identity.get("version", "")
    if not name or not version:
        return None

    tag_formats = [
        f"v{version}",
        f"{name}-v{version}",
        f"{name}-{version}",
        f"{version}",
        f"release-{version}",
    ]

    repo_url = identity.get("repo_url")
    if repo_url:
        try:
            result = subprocess.run(
                ["git", "ls-remote", "--tags", repo_url],
                capture_output=True, text=True, timeout=30
            )
            remote_tags = set()
            for line in result.stdout.splitlines():
                tag = line.split("refs/tags/")[-1].rstrip("^{}")
                remote_tags.add(tag)

            for fmt in tag_formats:
                if fmt in remote_tags:
                    return fmt
        except (subprocess.TimeoutExpired, Exception):
            pass

    return tag_formats[0]


def clone_source(identity: dict, dest_dir: str) -> bool:
    """Clone the identified source repo."""
    repo_url = identity.get("repo_url")
    tag = identity.get("tag")
    if not repo_url:
        return False

    dest = Path(dest_dir)
    if (dest / "src").exists() or (dest / "lib").exists():
        print(f"Source already exists at {dest}")
        return True

    dest.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["git", "clone", "--depth", "1"]
    if tag:
        cmd.extend(["--branch", tag])
    cmd.extend([repo_url, str(dest)])

    print(f"Cloning {repo_url} (tag: {tag}) → {dest}")
    try:
        subprocess.run(cmd, check=True, timeout=300)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"Clone failed: {e}")
        cmd_no_tag = ["git", "clone", "--depth", "1", repo_url, str(dest)]
        try:
            subprocess.run(cmd_no_tag, check=True, timeout=300)
            return True
        except Exception:
            return False


# ─── Known software database ────────────────────────────────────────────────
# This is extensible — add entries as new binaries are encountered.

_KNOWN_SOFTWARE = {
    "bun": {
        "name": "bun",
        "repo_url": "https://github.com/oven-sh/bun.git",
        "string_markers": [
            "Bun.serve", "bun create", "bun install",
            "BUN_INSTALL", "bunfig.toml", "bun.lockb",
        ],
        "min_markers": 2,
        "source_dir_hint": "src/",
    },
    "node": {
        "name": "node",
        "repo_url": "https://github.com/nodejs/node.git",
        "string_markers": [
            "process.versions.node", "NODE_VERSION",
            "node::Environment", "node_modules",
        ],
        "min_markers": 2,
        "source_dir_hint": "src/",
    },
    "deno": {
        "name": "deno",
        "repo_url": "https://github.com/denoland/deno.git",
        "string_markers": [
            "deno_core", "Deno.serve", "DENO_DIR",
            "deno.json", "deno.lock",
        ],
        "min_markers": 2,
        "source_dir_hint": "cli/",
    },
    "redis": {
        "name": "redis",
        "repo_url": "https://github.com/redis/redis.git",
        "string_markers": [
            "redis_version", "REDIS_PORT", "appendonly",
            "redis-server", "redis-cli",
        ],
        "min_markers": 2,
        "source_dir_hint": "src/",
    },
    "nginx": {
        "name": "nginx",
        "repo_url": "https://github.com/nginx/nginx.git",
        "string_markers": [
            "nginx/", "ngx_http_", "nginx.conf",
            "worker_processes", "ngx_event_",
        ],
        "min_markers": 2,
        "source_dir_hint": "src/",
    },
    "sqlite": {
        "name": "sqlite",
        "repo_url": "https://github.com/sqlite/sqlite.git",
        "string_markers": [
            "sqlite3_open", "SQLITE_OK", "sqlite_master",
            "CREATE TABLE", "sqlite3_prepare",
        ],
        "min_markers": 3,
        "source_dir_hint": "src/",
    },
    "curl": {
        "name": "curl",
        "repo_url": "https://github.com/curl/curl.git",
        "string_markers": [
            "curl_easy_", "CURLOPT_", "libcurl",
            "curl_global_init",
        ],
        "min_markers": 2,
        "source_dir_hint": "lib/",
    },
    "ffmpeg": {
        "name": "ffmpeg",
        "repo_url": "https://github.com/FFmpeg/FFmpeg.git",
        "string_markers": [
            "avcodec_", "avformat_", "libavutil",
            "ffmpeg version", "AVCodecContext",
        ],
        "min_markers": 2,
        "source_dir_hint": "libavcodec/",
    },
}

_IGNORE_REPOS = {
    "nicbarker/clay",
    "nicbarker/clay.git",
}


def main():
    parser = argparse.ArgumentParser(description="Discover identity and source of a binary")
    parser.add_argument("binary_path", help="Path to the binary to analyze")
    parser.add_argument("--output-dir", default="output/discovery", help="Output directory")
    parser.add_argument("--clone", action="store_true", help="Also clone the source if found")
    parser.add_argument("--reference-dir", default="reference-src", help="Where to clone source")
    args = parser.parse_args()

    if not os.path.isfile(args.binary_path):
        print(f"Error: binary not found at {args.binary_path}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    print("Extracting strings...")
    strings_list = extract_strings(args.binary_path)
    print(f"  {len(strings_list)} strings extracted")

    print("Extracting symbols...")
    symbols = extract_symbols(args.binary_path)
    print(f"  {len(symbols)} symbols extracted")

    print("Identifying software...")
    identity = detect_identity(strings_list, symbols)

    if identity["name"] and identity["version"]:
        print(f"  Identified: {identity['name']} {identity['version']}")
        print(f"  Repo: {identity['repo_url'] or 'unknown'}")
        print(f"  Languages: {', '.join(identity['languages']) or 'unknown'}")
        print(f"  Confidence: {identity['confidence']}")

        tag = resolve_tag(identity)
        if tag:
            identity["tag"] = tag
            print(f"  Tag: {tag}")
    else:
        print("  Could not identify the software.")
        print(f"  Evidence gathered: {identity['evidence']}")

    output_path = os.path.join(args.output_dir, "identity.json")
    with open(output_path, "w") as f:
        json.dump(identity, f, indent=2)
    print(f"\nIdentity saved to {output_path}")

    if args.clone and identity["repo_url"]:
        dest = os.path.join(args.reference_dir, identity["name"])
        success = clone_source(identity, dest)
        if success:
            identity["local_source_path"] = dest
            with open(output_path, "w") as f:
                json.dump(identity, f, indent=2)
            print(f"Source cloned to {dest}")

    for ev in identity["evidence"]:
        print(f"  - {ev}")

    return 0 if identity["confidence"] != "none" else 1


if __name__ == "__main__":
    sys.exit(main())
