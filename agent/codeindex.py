"""Read-only index of a Python/Flask project, built with `ast` (no model)."""
import ast
import re
from difflib import SequenceMatcher
from pathlib import Path

# never read the answer key, scanner output or run results
EXCLUDE_DIRS = {"labels", "tools", "raw", "runs", "instance", "__pycache__", ".git",
                ".venv", "venv", "agentenv", "node_modules"}
FUNCTION = (ast.FunctionDef, ast.AsyncFunctionDef)


def call_name(call):
    """`foo` for foo(...) and obj.foo(...)."""
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def decorator_names(func):
    names = []
    for d in func.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, ast.Attribute):
            names.append(target.attr)
    return names


def span(node):
    """First and last line of a definition, decorators included."""
    first = min([d.lineno for d in getattr(node, "decorator_list", [])] + [node.lineno])
    return first, node.end_lineno


class CodeIndex:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.files = {}   # path -> lines (.py and .html)
        self.trees = {}   # path -> ast of a .py file
        self.defs = {}    # top-level name -> [(path, node)]
        for path in sorted(self.root.rglob("*")):
            parts = path.relative_to(self.root).parts
            if not path.is_file() or path.suffix not in (".py", ".html") or set(parts[:-1]) & EXCLUDE_DIRS:
                continue
            rel = "/".join(parts)
            text = path.read_text(errors="replace")
            self.files[rel] = text.splitlines()
            if path.suffix == ".py":
                try:
                    self.trees[rel] = ast.parse(text)
                except SyntaxError:
                    continue
                self._add_definitions(rel, self.trees[rel])

    def _add_definitions(self, rel, tree):
        for node in tree.body:
            if isinstance(node, (*FUNCTION, ast.ClassDef)):
                self.defs.setdefault(node.name, []).append((rel, node))
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        self.defs.setdefault(t.id, []).append((rel, node))

    def functions(self):
        for rel, tree in self.trees.items():
            for node in tree.body:
                if isinstance(node, FUNCTION):
                    yield rel, node

    def resolve(self, path):
        """Match a path from a scanner or the model to a file in the index."""
        if not path:
            return None
        path = str(path).replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
        if path in self.files:
            return path
        hits = [r for r in self.files if r.endswith("/" + path) or path.endswith("/" + r)]
        return hits[0] if len(hits) == 1 else None

    def line(self, rel, n):
        lines = self.files.get(rel, [])
        return lines[n - 1] if 1 <= n <= len(lines) else ""

    def numbered(self, rel, start, end, mark=None):
        lines = self.files[rel]
        start, end = max(1, start), min(len(lines), end)
        return "\n".join(f"{'>>' if i == mark else '  '}{i:>4} | {lines[i - 1]}" for i in range(start, end + 1))

    def source(self, rel, node, mark=None, max_lines=60):
        first, last = span(node)
        return self.numbered(rel, first, min(last, first + max_lines - 1), mark=mark)

    def enclosing_function(self, rel, line):
        best = None
        for node in ast.walk(self.trees[rel]) if rel in self.trees else []:
            if isinstance(node, FUNCTION):
                first, last = span(node)
                if first <= line <= last and (best is None or first >= span(best)[0]):
                    best = node
        return best

    def visible_def(self, rel, name):
        """The definition of `name` that file `rel` sees: its own, or one it imports with `from .x import`."""
        imported = {}
        for node in self.trees[rel].body if rel in self.trees else []:
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    imported[alias.asname or alias.name] = node.module.split(".")[-1] + ".py"
        candidates = self.defs.get(name, [])
        for drel, node in candidates:
            if drel == rel:
                return drel, node
        for drel, node in candidates:
            if name in imported and (drel == imported[name] or drel.endswith("/" + imported[name])):
                return drel, node
        return None

    def callers(self, name):
        return [(rel, node) for rel, node in self.functions()
                if node.name != name and any(isinstance(sub, ast.Call) and call_name(sub) == name
                                             for sub in ast.walk(node))]

    def calls_on_line(self, func, line):
        """Plain function calls on `line` that pass at least one argument."""
        return [sub.func.id for sub in ast.walk(func)
                if isinstance(sub, ast.Call) and sub.lineno <= line <= (sub.end_lineno or sub.lineno)
                and isinstance(sub.func, ast.Name) and (sub.args or sub.keywords)]

    def views_of_template(self, template_rel):
        name = template_rel.split("/templates/")[-1]
        return [(rel, node) for rel, node in self.functions()
                if any(isinstance(sub, ast.Call) and getattr(sub.func, "id", None) == "render_template"
                       and sub.args and isinstance(sub.args[0], ast.Constant) and sub.args[0].value == name
                       for sub in ast.walk(node))]


# Finding the line the model copied. Small models re-type "x" as 'x', put a multi-line call on one
# line, use `...`, or miscount the line number.

def norm(text):
    return re.sub(r"\s+", "", (text or "").replace('"', "'"))


def contains(window, code):
    """`code` is in `window`; `...` in the copy stands for any text."""
    parts = [p for p in code.split("...") if p]
    pos = 0
    for p in parts:
        pos = window.find(p, pos)
        if pos < 0:
            return False
        pos += len(p)
    return bool(parts)


def anchor(lines, line, code):
    """(line, evidence) where evidence is exact / moved / fuzzy / not_found (made-up code)."""
    code = norm(code)
    if len(code.replace(".", "")) < 4 or not lines:
        return line, "not_found"
    n, want = len(lines), line if isinstance(line, int) else 1
    flat = [norm(x) for x in lines]
    if 1 <= want <= n and flat[want - 1] and contains(flat[want - 1], code):
        return want, "exact"
    for i in sorted(range(1, n + 1), key=lambda i: abs(i - want)):
        for size in range(1, 7):                      # a statement over up to 6 lines
            if len(flat[i - 1]) >= 6 and contains("".join(flat[i - 1:i - 1 + size]), code):
                return i, ("exact" if i == want else "moved")
    scored = [(SequenceMatcher(None, code, flat[i - 1]).ratio(), -abs(i - want), i)
              for i in range(1, n + 1) if len(flat[i - 1]) >= 6]
    best = max(scored, default=None)
    if best and best[0] >= 0.85:
        return best[2], "fuzzy"
    return line, "not_found"
