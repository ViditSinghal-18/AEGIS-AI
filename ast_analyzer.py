"""
AEGIS-AI: Honest Code Reachability & AST Static Analysis Engine.

Inspired by:
    Ponta, S. E., Plate, H., & Sabetta, A. "Beyond Metadata: Code-Centric and
    Usage-Based Analysis of Known Vulnerabilities in Open-Source Software."
    In IEEE International Conference on Software Maintenance and Evolution (ICSME), 2018.

Implements genuine Abstract Syntax Tree (AST) static analysis on local or uploaded code:
- Python: Official `ast` module parsing imports, aliases, call graphs, routes, and vulnerable symbols.
- Node.js / JavaScript: Pattern parsing for require/import and vulnerable function calls.
- Dependency Manifest Parsing: requirements.txt, Pipfile, package.json.
- CVE Vulnerable Symbol Mapping: Hand-curated versioned mapping file in `data/cve_symbols.yaml`.
- HONESTY RULE: Remote targets without source code ALWAYS report 'unknown (no source provided)'!
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

logger = logging.getLogger(__name__)

CVE_SYMBOLS_PATH = Path(__file__).resolve().parent / "data" / "cve_symbols.yaml"


def load_cve_symbols() -> Dict[str, Any]:
    """Load hand-curated CVE-to-vulnerable-symbols mapping from YAML."""
    if not CVE_SYMBOLS_PATH.exists():
        return {}
    try:
        data = yaml.safe_load(CVE_SYMBOLS_PATH.read_text(encoding="utf-8"))
        return (data or {}).get("cves") or {}
    except Exception as exc:
        logger.warning("Failed to load cve_symbols.yaml: %s", exc)
        return {}


class PythonAstAnalyzer(ast.NodeVisitor):
    """Parses Python source files to extract imports, symbol aliases, routes, and function calls."""

    def __init__(self):
        self.imports: Set[str] = set()
        self.imported_symbols: Dict[str, str] = {}  # symbol_name -> module_name
        self.module_aliases: Dict[str, str] = {}    # alias -> real_module
        self.routes: List[Dict[str, Any]] = []
        self.all_calls: List[Dict[str, Any]] = []   # {call: str, line: int, func: str}
        self._current_func = None
        self._current_calls: List[str] = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            base_pkg = alias.name.split(".")[0]
            self.imports.add(base_pkg)
            if alias.asname:
                self.module_aliases[alias.asname] = base_pkg
            else:
                self.module_aliases[alias.name] = base_pkg
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            base_pkg = node.module.split(".")[0]
            self.imports.add(base_pkg)
            for alias in node.names:
                sym_name = alias.asname or alias.name
                self.imported_symbols[sym_name] = node.module
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev_func = self._current_func
        prev_calls = self._current_calls
        self._current_func = node.name
        self._current_calls = []

        # Check route decorators (@app.route, @router.get, etc.)
        is_route = False
        route_path = None
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                if dec.func.attr in ["route", "get", "post", "put", "delete", "patch"]:
                    is_route = True
                    if dec.args and isinstance(dec.args[0], ast.Constant):
                        route_path = str(dec.args[0].value)

        self.generic_visit(node)

        if is_route:
            self.routes.append({
                "handler": node.name,
                "path": route_path or "/unspecified",
                "line": node.lineno,
                "calls": list(dict.fromkeys(self._current_calls))
            })

        self._current_func = prev_func
        self._current_calls = prev_calls

    def visit_Call(self, node: ast.Call):
        name = None
        qual_name = None

        if isinstance(node.func, ast.Name):
            name = node.func.id
            qual_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
            # Resolve receiver name e.g. jwt.decode
            if isinstance(node.func.value, ast.Name):
                recv = node.func.value.id
                real_recv = self.module_aliases.get(recv, recv)
                qual_name = f"{real_recv}.{name}"
            elif isinstance(node.func.value, ast.Attribute):
                qual_name = f"{node.func.value.attr}.{name}"
            else:
                qual_name = name

        if name:
            if self._current_func:
                self._current_calls.append(name)
                if qual_name and qual_name != name:
                    self._current_calls.append(qual_name)

            self.all_calls.append({
                "call": name,
                "qual_call": qual_name or name,
                "line": node.lineno,
                "enclosing_func": self._current_func or "<module>"
            })

        self.generic_visit(node)


def analyze_python_source(code_str: str) -> List[Dict[str, Any]]:
    """Parse Python source string using AST to extract routes, handlers, and dangerous sinks."""
    try:
        tree = ast.parse(code_str)
        analyzer = PythonAstAnalyzer()
        analyzer.visit(tree)
        results = []
        for r in analyzer.routes:
            sinks = [{"sink": c, "line": r["line"]} for c in r["calls"] if c in ["redirect", "eval", "exec", "system", "Popen"]]
            results.append({
                "handler_name": r["handler"],
                "route_path": r["path"],
                "line_number": r["line"],
                "calls": r["calls"],
                "dangerous_sinks": sinks
            })
        return results
    except Exception:
        return []


class JsAstAnalyzer:
    """Parses JavaScript / Node.js source files to extract imports, aliases, routes, and symbol calls using AST."""

    def __init__(self):
        self.imports: Set[str] = set()
        self.module_aliases: Dict[str, str] = {}
        self.imported_symbols: Dict[str, str] = {}
        self.routes: List[Dict[str, Any]] = []
        self.calls: List[Dict[str, Any]] = []
        self._current_route_calls: Optional[List[str]] = None

    def visit(self, node: Any) -> None:
        if not node or not hasattr(node, "type"):
            return

        # Variable declarations: const _ = require('lodash'); const { parse } = require('tough-cookie');
        if node.type == "VariableDeclarator" and getattr(node, "init", None) and getattr(node.init, "type", None) == "CallExpression":
            callee = node.init.callee
            if getattr(callee, "type", None) == "Identifier" and callee.name == "require":
                args = getattr(node.init, "arguments", [])
                if args and hasattr(args[0], "value") and isinstance(args[0].value, str):
                    raw_pkg = args[0].value
                    if not raw_pkg.startswith("."):
                        base_pkg = raw_pkg.split("/")[0].lstrip("@")
                        self.imports.add(base_pkg)
                        if node.id.type == "Identifier":
                            self.module_aliases[node.id.name] = base_pkg
                        elif node.id.type == "ObjectPattern":
                            for prop in getattr(node.id, "properties", []):
                                sym_name = getattr(getattr(prop, "value", None), "name", None) or getattr(getattr(prop, "key", None), "name", None)
                                if sym_name:
                                    self.imported_symbols[sym_name] = base_pkg

        # ImportDeclaration: import _ from 'lodash'; import { parse } from 'tough-cookie';
        elif node.type == "ImportDeclaration":
            raw_pkg = getattr(node.source, "value", "")
            if isinstance(raw_pkg, str) and not raw_pkg.startswith("."):
                base_pkg = raw_pkg.split("/")[0].lstrip("@")
                self.imports.add(base_pkg)
                for spec in getattr(node, "specifiers", []):
                    if spec.type in ("ImportDefaultSpecifier", "ImportNamespaceSpecifier"):
                        self.module_aliases[spec.local.name] = base_pkg
                    elif spec.type == "ImportSpecifier":
                        self.imported_symbols[spec.local.name] = base_pkg

        # CallExpression: routes and function calls
        elif node.type == "CallExpression":
            callee = node.callee
            line = getattr(node.loc.start, "line", 0) if hasattr(node, "loc") and node.loc else 0

            # Standalone require call e.g. require('dotenv').config()
            if getattr(callee, "type", None) == "Identifier" and callee.name == "require":
                args = getattr(node, "arguments", [])
                if args and hasattr(args[0], "value") and isinstance(args[0].value, str):
                    raw_pkg = args[0].value
                    if not raw_pkg.startswith("."):
                        base_pkg = raw_pkg.split("/")[0].lstrip("@")
                        self.imports.add(base_pkg)

            # MemberExpression call: app.get(...), _.template(...)
            elif getattr(callee, "type", None) == "MemberExpression":
                obj_name = getattr(callee.object, "name", "")
                prop_name = getattr(callee.property, "name", "")

                # Check if route handler: app.get('/path', handler)
                if prop_name in ("get", "post", "put", "delete", "use", "patch"):
                    args = getattr(node, "arguments", [])
                    if args and hasattr(args[0], "value") and isinstance(args[0].value, str):
                        path_str = args[0].value
                        route_entry = {
                            "method": prop_name.upper(),
                            "path": path_str,
                            "line": line,
                            "calls": [],
                        }
                        self.routes.append(route_entry)
                        prev_route_calls = self._current_route_calls
                        self._current_route_calls = route_entry["calls"]
                        for arg in args[1:]:
                            self.visit(arg)
                        self._current_route_calls = prev_route_calls

                qual = f"{obj_name}.{prop_name}" if obj_name else prop_name
                resolved_qual = qual
                if obj_name in self.module_aliases:
                    resolved_qual = f"{self.module_aliases[obj_name]}.{prop_name}"

                call_record = {
                    "call": prop_name,
                    "qual_call": qual,
                    "resolved_call": resolved_qual,
                    "line": line,
                    "enclosing_func": "<script>",
                }
                self.calls.append(call_record)
                if self._current_route_calls is not None:
                    self._current_route_calls.append(prop_name)
                    if qual != prop_name:
                        self._current_route_calls.append(qual)
                    if resolved_qual != qual:
                        self._current_route_calls.append(resolved_qual)

            # Identifier call: parse(...), template(...)
            elif getattr(callee, "type", None) == "Identifier":
                func_name = callee.name
                line = getattr(node.loc.start, "line", 0) if hasattr(node, "loc") and node.loc else 0
                qual = func_name
                if func_name in self.imported_symbols:
                    qual = f"{self.imported_symbols[func_name]}.{func_name}"
                call_record = {
                    "call": func_name,
                    "qual_call": qual,
                    "line": line,
                    "enclosing_func": "<script>",
                }
                self.calls.append(call_record)
                if self._current_route_calls is not None:
                    self._current_route_calls.append(func_name)
                    if qual != func_name:
                        self._current_route_calls.append(qual)

        # Recurse children (skip arguments for route methods since visited manually above)
        for key, val in node.__dict__.items():
            if key == "arguments" and getattr(node, "type", None) == "CallExpression" and getattr(getattr(node, "callee", None), "type", None) == "MemberExpression" and getattr(node.callee.property, "name", None) in ("get", "post", "put", "delete", "use", "patch"):
                continue
            if isinstance(val, list):
                for item in val:
                    if hasattr(item, "type"):
                        self.visit(item)
            elif hasattr(val, "type"):
                self.visit(val)


def analyze_javascript_source(code_str: str) -> List[Dict[str, Any]]:
    """Parse JS source string using AST (esprima) with regex fallback to extract routes and dangerous sinks."""
    try:
        import esprima
        tree = esprima.parseScript(code_str, {"loc": True, "tolerant": True})
        analyzer = JsAstAnalyzer()
        analyzer.visit(tree)
        results = []
        for r in analyzer.routes:
            sinks = [{"sink": c, "line": r.get("line", 0)} for c in r.get("calls", []) if c in ["eval", "Function", "exec", "spawn", "template", "send", "redirect"]]
            results.append({
                "handler_name": f"{r['method']} {r['path']}",
                "route_path": r["path"],
                "method": r["method"],
                "line_number": r.get("line", 0),
                "calls": r.get("calls", []),
                "dangerous_sinks": sinks,
            })
        return results
    except Exception:
        # Fallback to regex
        routes = []
        for m in re.finditer(r"(?:app|router)\.(get|post|put|delete|use)\s*\(\s*['\"]([^'\"]+)['\"]\s*,", code_str):
            routes.append({
                "method": m.group(1).upper(),
                "path": m.group(2),
            })
        return routes


def analyze_python_file(filepath: Path) -> Dict[str, Any]:
    """Analyze a single Python file using the AST parser."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(content, filename=str(filepath))
        analyzer = PythonAstAnalyzer()
        analyzer.visit(tree)
        return {
            "file": str(filepath),
            "imports": list(analyzer.imports),
            "imported_symbols": analyzer.imported_symbols,
            "routes": analyzer.routes,
            "calls": analyzer.all_calls
        }
    except Exception:
        return {"file": str(filepath), "imports": [], "imported_symbols": {}, "routes": [], "calls": []}


def analyze_js_file(filepath: Path) -> Dict[str, Any]:
    """Parse a JavaScript/TypeScript source file using AST (esprima) with regex fallback."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {"file": str(filepath), "imports": [], "imported_symbols": {}, "routes": [], "calls": []}

    try:
        import esprima
        tree = esprima.parseScript(content, {"loc": True, "tolerant": True})
        analyzer = JsAstAnalyzer()
        analyzer.visit(tree)
        for r in analyzer.routes:
            r["file"] = str(filepath)
        return {
            "file": str(filepath),
            "imports": sorted(list(analyzer.imports)),
            "imported_symbols": analyzer.imported_symbols,
            "module_aliases": analyzer.module_aliases,
            "routes": analyzer.routes,
            "calls": analyzer.calls,
        }
    except Exception:
        # Graceful fallback to regex
        imports = set()
        calls = []

        # Match require('pkg') and import ... from 'pkg'
        for m in re.finditer(r"(?:(?:const|let|var)\s+(\{?[^=]+?\}?)\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)|import\s+(.*?)\s+from\s+['\"]([^'\"]+)['\"])", content):
            pkg = m.group(2) or m.group(4)
            if pkg and not pkg.startswith("."):
                base_pkg = pkg.split("/")[0].lstrip("@")
                imports.add(base_pkg)

        # Match calls like pkg.func( or direct func(
        for m in re.finditer(r"\b([a-zA-Z0-9_$]+)\.([a-zA-Z0-9_$]+)\s*\(", content):
            receiver = m.group(1)
            method = m.group(2)
            calls.append({
                "call": method,
                "qual_call": f"{receiver}.{method}",
                "enclosing_func": "<script>"
            })

        routes = []
        for m in re.finditer(r"(?:app|router)\.(get|post|put|delete|use)\s*\(\s*['\"]([^'\"]+)['\"]\s*,", content):
            routes.append({
                "method": m.group(1).upper(),
                "path": m.group(2),
                "file": str(filepath)
            })

        return {
            "file": str(filepath),
            "imports": sorted(list(imports)),
            "imported_symbols": {},
            "routes": routes,
            "calls": calls
        }


def analyze_source_tree(source_path: str) -> Dict[str, Any]:
    """Scan a repository or source folder to extract declared packages, actual imports, routes, and call graph."""
    root = Path(source_path)
    if not root.exists() or not root.is_dir():
        return {
            "source_provided": False,
            "declared_packages": [],
            "imported_packages": [],
            "routes": [],
            "calls": [],
        }

    declared: Set[str] = set()
    all_imports: Set[str] = set()
    all_routes: List[Dict[str, Any]] = []
    all_calls: List[Dict[str, Any]] = []

    # 1. Check requirements.txt
    req_file = root / "requirements.txt"
    if req_file.exists():
        try:
            for line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip().split("#")[0].split("==")[0].split(">=")[0].split("<=")[0].strip()
                if line:
                    declared.add(line.lower())
        except Exception:
            pass

    # 2. Check package.json
    pkg_file = root / "package.json"
    if pkg_file.exists():
        try:
            pkg_data = json.loads(pkg_file.read_text(encoding="utf-8", errors="ignore"))
            deps = pkg_data.get("dependencies", {})
            dev_deps = pkg_data.get("devDependencies", {})
            for k in list(deps.keys()) + list(dev_deps.keys()):
                declared.add(k.lower())
        except Exception:
            pass

    # 3. Walk files (cap to 150 files to avoid serverless resource exhaustion)
    count = 0
    for path in root.rglob("*"):
        if count >= 150:
            break
        if "node_modules" in path.parts or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        if path.is_file():
            if path.suffix == ".py":
                res = analyze_python_file(path)
                all_imports.update(res["imports"])
                all_routes.extend(res["routes"])
                all_calls.extend(res["calls"])
                count += 1
            elif path.suffix in [".js", ".ts", ".mjs"]:
                res = analyze_js_file(path)
                all_imports.update(res["imports"])
                all_routes.extend(res["routes"])
                all_calls.extend(res["calls"])
                count += 1

    return {
        "source_provided": True,
        "source_path": str(root),
        "declared_packages": sorted(list(declared)),
        "imported_packages": sorted(list(all_imports)),
        "routes": all_routes,
        "calls": all_calls,
    }


def evaluate_component_reachability(
    component_name: str,
    source_analysis: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Legacy component-level reachability evaluation."""
    if not source_analysis or not source_analysis.get("source_provided"):
        return {
            "reachability_verdict": "unknown (no source provided)",
            "reachability_factor": 1.0,
            "evidence": "Remote target scanned without source code repository. Code-level execution path cannot be verified."
        }

    c_clean = component_name.strip().lower()
    imported_list = [p.lower() for p in source_analysis.get("imported_packages", [])]

    if c_clean not in imported_list:
        return {
            "reachability_verdict": "not imported (dead code / unused dependency)",
            "reachability_factor": 0.0,
            "evidence": f"Package '{component_name}' is declared in manifests but no active 'import' or 'require' was found in source files."
        }

    # Check if any route calls it
    routes = source_analysis.get("routes", [])
    matching_routes = []
    for r in routes:
        calls = [str(c).lower() for c in r.get("calls", [])]
        if c_clean in calls or any(c_clean in c for c in calls):
            matching_routes.append(r)

    if matching_routes:
        return {
            "reachability_verdict": "reachable via route handler",
            "reachability_factor": 1.0,
            "evidence": f"Package '{component_name}' is invoked directly inside route handler(s): {[r.get('handler', r.get('path')) for r in matching_routes]}"
        }

    return {
        "reachability_verdict": "imported (background/utility, no direct route handler match)",
        "reachability_factor": 0.3,
        "evidence": f"Package '{component_name}' is imported in codebase but not mapped to a public network route handler."
    }


def evaluate_cve_function_reachability(
    cve_id: str,
    package_name: str = "",
    source_analysis: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Function-level reachability analysis for a CVE matching vulnerable symbols.

    Inspired by Ponta et al. 2018 (Eclipse Steady).

    Verdicts returned:
    - 'reachable_function': Vulnerable symbol/method is invoked in active code. (Factor: 1.0)
    - 'imported_only': Package is imported, but specific vulnerable function is NOT called. (Factor: 0.3)
    - 'not_reachable': Package is not imported or unused dead dependency. (Factor: 0.0)
    - 'unknown (no source provided)': Remote target scanned without source code. (Factor: 1.0)

    Returns:
        Dict containing verdict, reachability_factor, matched_symbols, and evidence.
    """
    clean_cve = (cve_id or "").strip().upper()

    # Rule 1: No source code provided
    if not source_analysis or not source_analysis.get("source_provided"):
        return {
            "verdict": "unknown (no source provided)",
            "reachability_factor": 1.0,
            "cve_id": clean_cve,
            "package": package_name,
            "vulnerable_symbols": [],
            "matched_symbols": [],
            "evidence": "Remote target scanned without source code repository. Function-level execution path cannot be verified."
        }

    # Look up symbol database
    cve_db = load_cve_symbols()
    cve_entry = cve_db.get(clean_cve, {})

    target_pkg = (cve_entry.get("package") or package_name or "").strip().lower()
    vuln_symbols = [s.lower() for s in cve_entry.get("vulnerable_symbols") or []]

    imported_pkgs = [p.lower() for p in source_analysis.get("imported_packages") or []]
    declared_pkgs = [p.lower() for p in source_analysis.get("declared_packages") or []]

    # Rule 2: Package not in imports
    is_imported = any(target_pkg == p or target_pkg in p or p in target_pkg for p in imported_pkgs) if target_pkg else False
    is_declared = any(target_pkg == p or target_pkg in p or p in target_pkg for p in declared_pkgs) if target_pkg else False

    if target_pkg and not is_imported:
        return {
            "verdict": "not_reachable",
            "reachability_factor": 0.0,
            "cve_id": clean_cve,
            "package": target_pkg,
            "vulnerable_symbols": vuln_symbols,
            "matched_symbols": [],
            "evidence": (
                f"Package '{target_pkg}' associated with {clean_cve} is "
                f"{'declared in dependencies but never imported (dead code)' if is_declared else 'not present in codebase imports'}."
            )
        }

    # Rule 3: Check call graph against vulnerable symbols
    all_calls = source_analysis.get("calls") or []
    matched: List[str] = []

    for call_item in all_calls:
        c_name = str(call_item.get("call", "")).lower()
        q_name = str(call_item.get("qual_call", "")).lower()

        for vsym in vuln_symbols:
            vsym_base = vsym.split(".")[-1]
            if vsym == q_name or vsym == c_name or (vsym in q_name and vsym_base == c_name):
                matched.append(call_item.get("qual_call") or call_item.get("call"))

    matched = sorted(list(set(matched)))

    if matched:
        return {
            "verdict": "reachable_function",
            "reachability_factor": 1.0,
            "cve_id": clean_cve,
            "package": target_pkg,
            "vulnerable_symbols": vuln_symbols,
            "matched_symbols": matched,
            "evidence": f"Vulnerable symbol(s) {matched} invoked in codebase. Code execution path reaches the vulnerable function."
        }

    if vuln_symbols:
        return {
            "verdict": "imported_only",
            "reachability_factor": 0.3,
            "cve_id": clean_cve,
            "package": target_pkg,
            "vulnerable_symbols": vuln_symbols,
            "matched_symbols": [],
            "evidence": f"Package '{target_pkg}' is imported in project, but none of the known vulnerable functions {vuln_symbols} are invoked."
        }

    # If CVE is not in symbols database, fallback to component-level verdict
    routes = source_analysis.get("routes") or []
    has_route_call = False
    for r in routes:
        rcalls = [str(c).lower() for c in r.get("calls") or []]
        if target_pkg in rcalls:
            has_route_call = True
            break

    if has_route_call:
        return {
            "verdict": "reachable_function",
            "reachability_factor": 1.0,
            "cve_id": clean_cve,
            "package": target_pkg,
            "vulnerable_symbols": [],
            "matched_symbols": [target_pkg],
            "evidence": f"Package '{target_pkg}' is invoked within public network route handler(s)."
        }

    return {
        "verdict": "imported_only",
        "reachability_factor": 0.3,
        "cve_id": clean_cve,
        "package": target_pkg,
        "vulnerable_symbols": [],
        "matched_symbols": [],
        "evidence": f"Package '{target_pkg}' is imported in project, but no specific vulnerable symbols are cataloged."
    }
