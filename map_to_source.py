#!/usr/bin/env python3
"""Map Ghidra-decompiled functions to original source code.

Generic tool — works with any binary + reference source combination.
Uses multiple matching strategies: symbol names, embedded strings,
source path references, and call graph propagation.

Usage: python3 map_to_source.py <binary_path> [--reference-dir reference-src/<name>]

Requires:
  - output/ghidra/function_boundaries.tsv
  - output/ghidra/call_graph.tsv
  - output/ghidra/functions/  (individual decompiled files)
  - output/discovery/identity.json (from discover_source.py)
  - reference-src/<name>/  (cloned source)

Output:
  - output/mapping/function_map.tsv
  - output/mapping/helper_aliases.tsv
  - output/mapping/stats.json
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


def load_identity(discovery_dir: str = "output/discovery") -> dict:
    path = os.path.join(discovery_dir, "identity.json")
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        return json.load(f)


def load_function_boundaries(path: str = "output/ghidra/function_boundaries.tsv") -> list[dict]:
    if not os.path.isfile(path):
        return []
    rows = []
    with open(path) as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            rows.append(row)
    return rows


def load_call_graph(path: str = "output/ghidra/call_graph.tsv") -> tuple[dict, dict]:
    callers_of = defaultdict(set)
    callees_of = defaultdict(set)
    if not os.path.isfile(path):
        return callers_of, callees_of
    with open(path) as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            caller = row["caller_name"]
            callee = row["callee_name"]
            callees_of[caller].add(callee)
            callers_of[callee].add(caller)
    return callers_of, callees_of


def build_source_function_index(source_dir: str) -> dict[str, list[tuple[str, int, str]]]:
    """Scan source files for function definitions. Returns {name: [(file, line, lang)]}."""
    index = defaultdict(list)
    source_path = Path(source_dir)
    if not source_path.exists():
        return index

    patterns = {
        ".zig": re.compile(r'(?:pub\s+)?(?:export\s+)?fn\s+(\w+)\s*\('),
        ".cpp": re.compile(r'^[a-zA-Z_][\w:*&<> ]*\s+(\w+)\s*\(', re.MULTILINE),
        ".c": re.compile(r'^[a-zA-Z_][\w:*& ]*\s+(\w+)\s*\(', re.MULTILINE),
        ".h": re.compile(r'^[a-zA-Z_][\w:*& ]*\s+(\w+)\s*\(', re.MULTILINE),
        ".hpp": re.compile(r'^[a-zA-Z_][\w:*&<> ]*\s+(\w+)\s*\(', re.MULTILINE),
        ".rs": re.compile(r'(?:pub\s+)?fn\s+(\w+)\s*[<(]'),
        ".go": re.compile(r'^func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(', re.MULTILINE),
        ".swift": re.compile(r'(?:public\s+)?func\s+(\w+)\s*[<(]'),
    }

    lang_map = {
        ".zig": "zig", ".cpp": "cpp", ".c": "c", ".h": "c",
        ".hpp": "cpp", ".rs": "rust", ".go": "go", ".swift": "swift",
    }

    for ext, pattern in patterns.items():
        for fpath in source_path.rglob(f"*{ext}"):
            rel_path = str(fpath.relative_to(source_path))
            if any(skip in rel_path for skip in ["vendor/", "node_modules/", "test/", "bench/"]):
                continue
            try:
                content = fpath.read_text(errors="replace")
                for i, line in enumerate(content.splitlines(), 1):
                    m = pattern.match(line) if ext in (".cpp", ".c", ".h", ".hpp") else pattern.search(line)
                    if m:
                        fname = m.group(1)
                        if len(fname) > 2 and fname not in ("if", "for", "while", "return", "switch"):
                            index[fname].append((rel_path, i, lang_map[ext]))
            except Exception:
                continue

    return index


def build_ghidra_string_index(functions_dir: str = "output/ghidra/functions") -> dict[str, list[str]]:
    """Extract string literals from each Ghidra decompiled function. Returns {func_name: [strings]}."""
    index = {}
    func_dir = Path(functions_dir)
    if not func_dir.exists():
        return index

    string_pat = re.compile(r'"([^"]{6,})"')
    path_pat = re.compile(r'([\w./+-]+\.\w{1,4}:\d+)')

    for subdir in func_dir.iterdir():
        if not subdir.is_dir():
            continue
        for fpath in subdir.glob("*.c"):
            func_name = fpath.stem.rsplit("_", 1)[0] if "_" in fpath.stem else fpath.stem
            try:
                content = fpath.read_text(errors="replace")
                strings = string_pat.findall(content)
                paths = path_pat.findall(content)
                if strings or paths:
                    index[func_name] = strings + paths
            except Exception:
                continue

    return index


def build_source_string_index(source_dir: str) -> dict[str, list[tuple[str, int]]]:
    """Build reverse index: distinctive string → [(source_file, line)]. Returns {string: [(file, line)]}."""
    index = defaultdict(list)
    source_path = Path(source_dir)
    if not source_path.exists():
        return index

    string_pat = re.compile(r'"([^"]{10,80})"')

    for ext in (".zig", ".cpp", ".c", ".h", ".rs", ".go", ".swift"):
        for fpath in source_path.rglob(f"*{ext}"):
            rel = str(fpath.relative_to(source_path))
            if any(skip in rel for skip in ["vendor/", "node_modules/", "test/"]):
                continue
            try:
                for i, line in enumerate(fpath.read_text(errors="replace").splitlines(), 1):
                    for m in string_pat.finditer(line):
                        index[m.group(1)].append((rel, i))
            except Exception:
                continue

    return index


class FunctionMapper:
    def __init__(self, functions, callers_of, callees_of, source_func_idx,
                 ghidra_str_idx, source_str_idx, source_dir, identity):
        self.functions = functions
        self.func_by_name = {f["name"]: f for f in functions}
        self.callers_of = callers_of
        self.callees_of = callees_of
        self.source_func_idx = source_func_idx
        self.ghidra_str_idx = ghidra_str_idx
        self.source_str_idx = source_str_idx
        self.source_dir = source_dir
        self.identity = identity
        self.mappings = {}
        self.aliases = {}

    def run_all(self):
        print("\n--- Phase B: Direct symbol matching ---")
        self.direct_symbol_match()
        print(f"  {len(self.mappings)} functions mapped")

        print("\n--- Phase C: String-anchored matching ---")
        self.string_anchored_match()
        print(f"  {len(self.mappings)} functions mapped")

        print("\n--- Phase D: Call graph propagation ---")
        self.call_graph_propagation(iterations=3)
        print(f"  {len(self.mappings)} functions mapped")

    def direct_symbol_match(self):
        for func in self.functions:
            name = func["name"]
            if name.startswith("FUN_") or name.startswith("thunk_"):
                continue

            clean_name = name.lstrip("_")

            if clean_name in self.source_func_idx:
                entries = self.source_func_idx[clean_name]
                best = entries[0]
                self._add_mapping(name, best[0], best[1], "high", "direct_symbol", clean_name, best[2])
            else:
                demangled = self._demangle(name)
                if demangled and demangled != name:
                    func_part = demangled.split("::")[-1].split("(")[0].strip()
                    if func_part in self.source_func_idx:
                        entries = self.source_func_idx[func_part]
                        best = entries[0]
                        self._add_mapping(name, best[0], best[1], "medium", "demangled_symbol",
                                          func_part, best[2])

    def string_anchored_match(self):
        for func_name, strings in self.ghidra_str_idx.items():
            if func_name in self.mappings:
                continue

            source_path_matches = {}
            for s in strings:
                path_match = re.match(r'([\w./+-]+\.\w{1,4}):(\d+)', s)
                if path_match:
                    rel_path = path_match.group(1)
                    line_num = int(path_match.group(2))
                    full_path = Path(self.source_dir) / rel_path
                    if not full_path.exists():
                        for alt in Path(self.source_dir).rglob(Path(rel_path).name):
                            full_path = alt
                            rel_path = str(alt.relative_to(self.source_dir))
                            break
                    if full_path.exists():
                        source_path_matches[rel_path] = line_num

                if s in self.source_str_idx:
                    locs = self.source_str_idx[s]
                    if len(locs) == 1:
                        source_path_matches[locs[0][0]] = locs[0][1]
                    elif len(locs) <= 3:
                        for loc in locs:
                            source_path_matches.setdefault(loc[0], loc[1])

            if source_path_matches:
                best_file = max(source_path_matches, key=lambda f: 1)
                best_line = source_path_matches[best_file]
                lang = _lang_from_ext(best_file)
                original_name = self._find_function_at_line(best_file, best_line)
                confidence = "high" if original_name else "medium"
                self._add_mapping(func_name, best_file, best_line, confidence,
                                  "string_anchor", original_name or func_name, lang)

    def call_graph_propagation(self, iterations=3):
        for iteration in range(iterations):
            new_mappings = {}
            for func_name, mapping in list(self.mappings.items()):
                callees = self.callees_of.get(func_name, set())
                for callee in callees:
                    if callee in self.mappings or callee in new_mappings:
                        continue
                    if callee.startswith("FUN_"):
                        callee_funcs = self._find_callees_in_source(
                            mapping["source_file"], mapping["source_line"]
                        )
                        if callee_funcs:
                            for cf_name, cf_file, cf_line, cf_lang in callee_funcs:
                                if cf_name not in [m.get("original_name") for m in self.mappings.values()]:
                                    new_mappings[callee] = {
                                        "source_file": cf_file,
                                        "source_line": cf_line,
                                        "confidence": "low",
                                        "match_method": f"callgraph_iter{iteration+1}",
                                        "original_name": cf_name,
                                        "source_language": cf_lang,
                                    }
                                    self.aliases[callee] = cf_name
                                    break

            if not new_mappings:
                print(f"  Iteration {iteration+1}: no new mappings, stopping")
                break
            self.mappings.update(new_mappings)
            print(f"  Iteration {iteration+1}: +{len(new_mappings)} mappings")

    def _add_mapping(self, ghidra_name, source_file, source_line, confidence,
                     method, original_name, language):
        self.mappings[ghidra_name] = {
            "source_file": source_file,
            "source_line": source_line,
            "confidence": confidence,
            "match_method": method,
            "original_name": original_name,
            "source_language": language,
        }
        if ghidra_name.startswith("FUN_") and original_name != ghidra_name:
            self.aliases[ghidra_name] = original_name

    def _demangle(self, name):
        try:
            result = subprocess.run(
                ["c++filt", name], capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip()
        except Exception:
            return name

    def _find_function_at_line(self, rel_path, line_num):
        full_path = Path(self.source_dir) / rel_path
        if not full_path.exists():
            return None
        try:
            lines = full_path.read_text(errors="replace").splitlines()
            ext = full_path.suffix
            if ext == ".zig":
                pat = re.compile(r'(?:pub\s+)?(?:export\s+)?fn\s+(\w+)\s*\(')
            else:
                pat = re.compile(r'^[a-zA-Z_][\w:*&<> ]*\s+(\w+)\s*\(')

            for i in range(max(0, line_num - 20), min(len(lines), line_num + 5)):
                m = pat.search(lines[i]) if ext == ".zig" else pat.match(lines[i])
                if m:
                    return m.group(1)
        except Exception:
            pass
        return None

    def _find_callees_in_source(self, source_file, source_line):
        full_path = Path(self.source_dir) / source_file
        if not full_path.exists():
            return []
        try:
            lines = full_path.read_text(errors="replace").splitlines()
            start = max(0, source_line - 5)
            end = min(len(lines), source_line + 50)
            chunk = "\n".join(lines[start:end])
            call_pat = re.compile(r'(\w+)\s*\(')
            calls = call_pat.findall(chunk)
            results = []
            for cname in calls:
                if cname in self.source_func_idx:
                    entries = self.source_func_idx[cname]
                    if entries:
                        e = entries[0]
                        results.append((cname, e[0], e[1], e[2]))
            return results
        except Exception:
            return []

    def write_outputs(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)

        map_path = os.path.join(output_dir, "function_map.tsv")
        with open(map_path, "w") as f:
            f.write("ghidra_function_name\tghidra_address\tsource_file\tsource_line\t"
                    "confidence\tmatch_method\toriginal_name\tsource_language\n")
            for func in self.functions:
                name = func["name"]
                if name in self.mappings:
                    m = self.mappings[name]
                    f.write(f"{name}\t{func['entry_address']}\t{m['source_file']}\t"
                            f"{m['source_line']}\t{m['confidence']}\t{m['match_method']}\t"
                            f"{m['original_name']}\t{m['source_language']}\n")

        alias_path = os.path.join(output_dir, "helper_aliases.tsv")
        with open(alias_path, "w") as f:
            f.write("ghidra_name\toriginal_name\n")
            for gname, oname in sorted(self.aliases.items()):
                f.write(f"{gname}\t{oname}\n")

        by_method = defaultdict(int)
        by_confidence = defaultdict(int)
        by_language = defaultdict(int)
        for m in self.mappings.values():
            by_method[m["match_method"]] += 1
            by_confidence[m["confidence"]] += 1
            by_language[m["source_language"]] += 1

        stats = {
            "total_functions": len(self.functions),
            "mapped_functions": len(self.mappings),
            "coverage_percent": round(len(self.mappings) / max(len(self.functions), 1) * 100, 2),
            "aliases": len(self.aliases),
            "by_method": dict(by_method),
            "by_confidence": dict(by_confidence),
            "by_language": dict(by_language),
        }
        stats_path = os.path.join(output_dir, "stats.json")
        with open(stats_path, "w") as f:
            json.dump(stats, f, indent=2)

        print(f"\n=== Mapping Statistics ===")
        print(f"Total functions:  {stats['total_functions']}")
        print(f"Mapped:           {stats['mapped_functions']} ({stats['coverage_percent']}%)")
        print(f"Aliases:          {stats['aliases']}")
        print(f"By method:        {dict(by_method)}")
        print(f"By confidence:    {dict(by_confidence)}")
        print(f"By language:      {dict(by_language)}")


def _lang_from_ext(path: str) -> str:
    ext = Path(path).suffix
    return {".zig": "zig", ".cpp": "cpp", ".c": "c", ".h": "c",
            ".rs": "rust", ".go": "go", ".swift": "swift"}.get(ext, "unknown")


def main():
    parser = argparse.ArgumentParser(description="Map Ghidra functions to source code")
    parser.add_argument("binary_path", help="Path to the target binary")
    parser.add_argument("--reference-dir", help="Path to reference source (auto-detected from identity.json)")
    parser.add_argument("--output-dir", default="output/mapping")
    args = parser.parse_args()

    identity = load_identity()
    if not args.reference_dir:
        name = identity.get("name", "")
        local = identity.get("local_source_path")
        if local and os.path.isdir(local):
            args.reference_dir = local
        elif name:
            args.reference_dir = f"reference-src/{name}"

    if not args.reference_dir or not os.path.isdir(args.reference_dir):
        print(f"Error: reference source not found at {args.reference_dir}")
        print("Run discover_source.py --clone first.")
        sys.exit(1)

    print(f"Reference source: {args.reference_dir}")
    print(f"Identity: {identity.get('name', '?')} {identity.get('version', '?')}")

    print("\n--- Phase A: Building indexes ---")

    print("  Loading function boundaries...")
    functions = load_function_boundaries()
    print(f"  {len(functions)} functions")

    print("  Loading call graph...")
    callers_of, callees_of = load_call_graph()
    print(f"  {sum(len(v) for v in callees_of.values())} edges")

    src_hint = identity.get("source_dir_hint", "src/")
    source_search_dir = args.reference_dir
    hint_path = os.path.join(args.reference_dir, src_hint)
    if os.path.isdir(hint_path):
        source_search_dir = args.reference_dir

    print("  Building source function index...")
    source_func_idx = build_source_function_index(source_search_dir)
    print(f"  {len(source_func_idx)} unique function names")

    print("  Building Ghidra string index...")
    ghidra_str_idx = build_ghidra_string_index()
    print(f"  {len(ghidra_str_idx)} functions with strings")

    print("  Building source string index...")
    source_str_idx = build_source_string_index(source_search_dir)
    print(f"  {len(source_str_idx)} unique strings indexed")

    mapper = FunctionMapper(
        functions, callers_of, callees_of,
        source_func_idx, ghidra_str_idx, source_str_idx,
        source_search_dir, identity
    )
    mapper.run_all()
    mapper.write_outputs(args.output_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())
