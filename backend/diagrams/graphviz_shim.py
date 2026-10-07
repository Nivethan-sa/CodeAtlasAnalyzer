"""
A tiny stand-in for the `graphviz` PyPI package.

It exposes the same builder API the AI-generated scripts use (Digraph / Graph,
.node(), .edge(), .attr(), .subgraph(), .source) but only ever produces DOT
*text*. Nothing is rendered, no files are written and no Graphviz binary is
needed - the browser draws the DOT with a bundled copy of Viz.js.
"""

# Attributes that can make a rendered SVG link somewhere or run something.
_BLOCKED_ATTRS = {"url", "href", "target", "tooltip", "labeltooltip", "headtooltip",
                  "tailtooltip", "edgeurl", "edgehref", "headurl", "tailurl",
                  "labelurl", "labelhref", "edgetarget", "headtarget", "tailtarget",
                  "labeltarget", "stylesheet", "fontpath", "imagepath", "image",
                  "shapefile", "samplepoints", "peripheries_unused"}
_MAX_SOURCE_CHARS = 250_000
_ROOTS = []


def _quote(value):
    s = str(value)
    # HTML-like label, same convention as the real package: <...>
    if len(s) >= 2 and s[0] == "<" and s[-1] == ">":
        return s
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", "\\n")
    return '"' + s + '"'


def _attrs(attrs):
    parts = []
    for k, v in attrs.items():
        if v is None:
            continue
        key = str(k).strip().rstrip("_")
        if not key or key.lower() in _BLOCKED_ATTRS:
            continue
        if not all(c.isalnum() or c == "_" for c in key):
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        parts.append(f"{key}={_quote(v)}")
    return (" [" + " ".join(parts) + "]") if parts else ""


class _Base:
    _keyword = "digraph"
    _edge_op = "->"

    def __init__(self, name=None, comment=None, graph_attr=None, node_attr=None,
                 edge_attr=None, body=None, **kwargs):
        self.name = name
        self._lines = []
        self._indent = 1
        self._is_root = True
        if comment:
            self._lines.append("// " + str(comment).replace("\n", " "))
        for kind, a in (("graph", graph_attr), ("node", node_attr), ("edge", edge_attr)):
            if a:
                self.attr(kind, **dict(a))
        # format=, engine=, filename=, directory=, strict= ... are accepted and ignored
        _ROOTS.append(self)

    # ---- builder API -------------------------------------------------
    def attr(self, kw=None, _attributes=None, **attrs):
        attrs = dict(_attributes or {}, **attrs)
        if kw in ("graph", "node", "edge"):
            self._lines.append(f"{'    ' * self._indent}{kw}{_attrs(attrs)};")
        else:
            for k, v in attrs.items():
                a = _attrs({k: v})
                if a:
                    self._lines.append(f"{'    ' * self._indent}{a.strip()[1:-1]};")
        return self

    def node(self, name, label=None, _attributes=None, **attrs):
        attrs = dict(_attributes or {}, **attrs)
        if label is not None:
            attrs["label"] = label
        self._lines.append(f"{'    ' * self._indent}{_quote(name)}{_attrs(attrs)};")
        return self

    def edge(self, tail_name, head_name, label=None, _attributes=None, **attrs):
        attrs = dict(_attributes or {}, **attrs)
        if label is not None:
            attrs["label"] = label
        def end(n):
            n = str(n)
            if ":" in n and not n.startswith("<"):   # node:port form
                a, b = n.split(":", 1)
                return _quote(a) + ":" + _quote(b)
            return _quote(n)
        self._lines.append(f"{'    ' * self._indent}{end(tail_name)} {self._edge_op} {end(head_name)}{_attrs(attrs)};")
        return self

    def edges(self, tail_head_pairs):
        for t, h in tail_head_pairs:
            self.edge(t, h)
        return self

    def nodes(self, names):
        for n in names:
            self.node(n)
        return self

    def subgraph(self, graph=None, name=None, comment=None, graph_attr=None,
                 node_attr=None, edge_attr=None, body=None):
        if graph is not None:                       # dot.subgraph(other_graph)
            for line in graph._lines:
                self._lines.append("    " * (self._indent - 1) + line if False else line)
            return None
        return _SubgraphContext(self, name, comment, graph_attr, node_attr, edge_attr)

    # ---- output ----------------------------------------------------------
    @property
    def source(self):
        head = f"{self._keyword} {_quote(self.name)} {{" if self.name else f"{self._keyword} {{"
        out = "\n".join([head] + self._lines + ["}"])
        return out[:_MAX_SOURCE_CHARS]

    def __str__(self):
        return self.source

    # Rendering is a no-op: the browser does the drawing.
    def render(self, *a, **k): return ""
    def view(self, *a, **k): return ""
    def save(self, *a, **k): return ""
    def pipe(self, *a, **k): return b""
    def clear(self): self._lines = []; return self


class _SubgraphContext(_Base):
    def __init__(self, parent, name, comment, graph_attr, node_attr, edge_attr):
        # deliberately skip _Base.__init__ so it is never registered as a root
        self._parent = parent
        self.name = name
        self._lines = []
        self._indent = parent._indent + 1
        self._is_root = False
        self._keyword = "subgraph"
        self._edge_op = parent._edge_op
        if comment:
            self._lines.append("// " + str(comment).replace("\n", " "))
        for kind, a in (("graph", graph_attr), ("node", node_attr), ("edge", edge_attr)):
            if a:
                self.attr(kind, **dict(a))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pad = "    " * (self._parent._indent)
        head = f"{pad}subgraph {_quote(self.name)} {{" if self.name else f"{pad}subgraph {{"
        self._parent._lines.append(head)
        self._parent._lines.extend(self._lines)
        self._parent._lines.append(f"{pad}}}")
        return False


class Digraph(_Base):
    _keyword = "digraph"
    _edge_op = "->"


class Graph(_Base):
    _keyword = "graph"
    _edge_op = "--"


def nohtml(s):
    return str(s)


def last_source():
    return _ROOTS[-1].source if _ROOTS else None
