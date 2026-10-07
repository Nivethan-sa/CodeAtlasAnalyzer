"""
Runs ONE AI-generated diagram script and prints the DOT it produced.

Usage:  python -I run_diagram.py < script.py      (script on stdin)
Output: JSON on stdout  {"ok": true, "dot": "..."}  or  {"ok": false, "error": "..."}

Defence in depth - none of these layers is trusted on its own:
  1. The script is parsed with `ast` and rejected if it imports anything but
     `graphviz`, touches a dunder attribute, or names a dangerous builtin.
  2. It then runs with a tiny whitelist of builtins and a custom __import__.
  3. The interpreter runs isolated (-I) in a throw-away empty directory with a
     wall-clock timeout, CPU/memory/file-size limits (where the OS supports
     them) and a scrubbed environment - all enforced by the Node caller.
"""
import ast, builtins, contextlib, importlib.util, io, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_CODE_CHARS = 60_000

BANNED_NAMES = {
    "open", "exec", "eval", "compile", "__import__", "input", "globals", "locals", "vars",
    "getattr", "setattr", "delattr", "hasattr", "breakpoint", "exit", "quit", "help",
    "memoryview", "type", "object", "super", "classmethod", "staticmethod", "property",
    "__builtins__", "__loader__", "__spec__", "os", "sys", "subprocess", "socket", "importlib",
}
SAFE_BUILTINS = [
    "print", "len", "range", "enumerate", "zip", "str", "int", "float", "bool", "list", "dict",
    "set", "tuple", "frozenset", "sorted", "min", "max", "sum", "any", "all", "isinstance",
    "abs", "round", "reversed", "map", "filter", "repr", "chr", "ord", "format", "slice",
    "True", "False", "None", "Exception", "ValueError", "KeyError", "TypeError", "IndexError",
]


def fail(msg):
    sys.stdout.write(json.dumps({"ok": False, "error": str(msg)[:1500]}))
    sys.exit(0)


def validate(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] != "graphviz":
                    raise ValueError(f"import of '{a.name}' is not allowed (only graphviz)")
        elif isinstance(node, ast.ImportFrom):
            if node.level or (node.module or "").split(".")[0] != "graphviz":
                raise ValueError(f"import from '{node.module}' is not allowed (only graphviz)")
        elif isinstance(node, ast.Name):
            if node.id in BANNED_NAMES or (node.id.startswith("__") and node.id.endswith("__")):
                raise ValueError(f"use of '{node.id}' is not allowed")
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("_"):
                raise ValueError(f"access to attribute '{node.attr}' is not allowed")
        elif isinstance(node, (ast.AsyncFunctionDef, ast.Await, ast.AsyncFor, ast.AsyncWith,
                               ast.Global, ast.Nonlocal, ast.ClassDef, ast.Yield, ast.YieldFrom)):
            raise ValueError(f"'{type(node).__name__}' is not allowed")


def main():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
        resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    except Exception:
        pass  # Windows / unsupported: the Node wrapper's timeout still applies

    code = sys.stdin.read()
    if not code.strip():
        fail("empty script")
    if len(code) > MAX_CODE_CHARS:
        fail("script is too long")
    try:
        tree = ast.parse(code, "<diagram>")
        validate(tree)
    except SyntaxError as e:
        fail(f"SyntaxError: {e.msg} (line {e.lineno})")
    except ValueError as e:
        fail(f"Rejected by safety check: {e}")

    spec = importlib.util.spec_from_file_location("graphviz", os.path.join(HERE, "graphviz_shim.py"))
    shim = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shim)

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name.split(".")[0] == "graphviz":
            return shim
        raise ImportError(f"import of '{name}' is not allowed")

    safe = {n: getattr(builtins, n) for n in SAFE_BUILTINS if hasattr(builtins, n)}
    safe["__import__"] = guarded_import
    env = {"__builtins__": safe, "__name__": "__diagram__"}

    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            exec(compile(tree, "<diagram>", "exec"), env)
    except Exception as e:
        fail(f"{type(e).__name__}: {e}")

    dot = shim.last_source()
    if not dot:
        printed = out.getvalue().strip()
        if printed.lstrip().startswith(("digraph", "graph", "strict")):
            dot = printed
    if not dot:
        fail("The script did not create a graphviz Digraph/Graph.")
    sys.stdout.write(json.dumps({"ok": True, "dot": dot}))


main()
