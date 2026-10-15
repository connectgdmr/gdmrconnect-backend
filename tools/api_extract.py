"""
Extract a structured API model from the GDMR Connect backend source (AST based).
Used by generate_api_docs.py; run that script to rebuild the API documentation.
"""
import ast, glob, json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the backend repository root
FILES = sorted(glob.glob(os.path.join(ROOT, "routes", "*.py"))) + [os.path.join(ROOT, "app_new.py")]
ACCESS_NAME = re.compile(r"(access|allowed|grant|admin|can_|perm|authori|owner|manager_of|is_hr|_mgr|scope|require)", re.I)
ROLE_WORDS = {"admin", "owner", "manager", "employee"}


def src(node, text):
    return ast.get_source_segment(text, node) or ""


def const_str(n):
    if isinstance(n, ast.Constant) and isinstance(n.value, str):
        return n.value
    if isinstance(n, ast.JoinedStr):
        out = ""
        for v in n.values:
            out += v.value if isinstance(v, ast.Constant) else "{…}"
        return out
    return None


def returns_of(fn, text, module_funcs, depth=0):
    """[(status, message|None, keys|None, kind)] for every return statement."""
    out = []
    for n in ast.walk(fn):
        if not isinstance(n, ast.Return) or n.value is None:
            continue
        v, status = n.value, 200
        if isinstance(v, ast.Tuple) and len(v.elts) >= 2:
            if isinstance(v.elts[1], ast.Constant) and isinstance(v.elts[1].value, int):
                status = v.elts[1].value
            v = v.elts[0]
        if isinstance(v, ast.Call):
            fname = v.func.id if isinstance(v.func, ast.Name) else (v.func.attr if isinstance(v.func, ast.Attribute) else "")
            if fname == "jsonify":
                msg = keys = None
                kind = "json"
                if v.args:
                    a = v.args[0]
                    if isinstance(a, ast.Dict):
                        keys = [const_str(k) for k in a.keys if k is not None and const_str(k)]
                        for k, val in zip(a.keys, a.values):
                            if k is not None and const_str(k) == "message":
                                msg = const_str(val)
                    elif isinstance(a, (ast.List, ast.ListComp)):
                        kind = "array"
                    else:
                        kind = "object"
                out.append((status, msg, keys, kind))
            elif fname in ("send_file", "send_from_directory"):
                out.append((status, None, None, "file"))
            elif fname in module_funcs and depth < 2 and fname != fn.name:
                for r in returns_of(module_funcs[fname], text, module_funcs, depth + 1):
                    out.append((r[0] if status == 200 else status, r[1], r[2], r[3]))
        elif isinstance(v, ast.Constant) and isinstance(v.value, str):
            out.append((status, None, None, "text"))
    return out


def analyse(fn, text, module_funcs, consts=None):
    consts = consts or {}
    info = {"query": [], "body": [], "form": [], "files": [], "headers": [], "access": [], "roles": set()}
    bodyvars, formvars = set(), set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            s = src(n.value, text)
            if "request.json" in s or "get_json" in s:
                bodyvars.add(n.targets[0].id)
            if "request.form" in s:
                formvars.add(n.targets[0].id)

    # local lists of field names, e.g. editable = ["name", ..., *CANDIDATE_TEXT_FIELDS]
    consts = dict(consts)
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and isinstance(n.value, (ast.List, ast.Tuple)):
            vals = []
            for e in n.value.elts:
                if const_str(e):
                    vals.append(const_str(e))
                elif isinstance(e, ast.Starred) and isinstance(e.value, ast.Name) and e.value.id in consts:
                    vals.extend(consts[e.value.id])
            if vals:
                consts[n.targets[0].id] = vals

    def add(lst, k):
        if k and k not in lst:
            lst.append(k)

    def handle_get(base_src, base_name, key):
        if "request.args" in base_src:
            add(info["query"], key)
        elif "request.files" in base_src:
            add(info["files"], key)
        elif "request.headers" in base_src:
            add(info["headers"], key)
        elif "request.form" in base_src or base_name in formvars:
            add(info["form"], key)
        elif "request.json" in base_src or "get_json" in base_src or base_name in bodyvars:
            add(info["body"], key)

    def scan(node, varmap_body, varmap_form):
        for n in ast.walk(node):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get" and n.args:
                k = const_str(n.args[0])
                if k:
                    base = n.func.value
                    handle_get(src(base, text), base.id if isinstance(base, ast.Name) else None, k)
            elif isinstance(n, ast.Subscript):
                k = const_str(n.slice)
                if k:
                    base = n.value
                    handle_get(src(base, text), base.id if isinstance(base, ast.Name) else None, k)
            elif isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.ops[0], ast.In):
                k = const_str(n.left)
                if k and n.comparators:
                    b = n.comparators[0]
                    handle_get(src(b, text), b.id if isinstance(b, ast.Name) else None, k)
            elif isinstance(n, ast.For) and isinstance(n.target, ast.Name):
                lst = None
                if isinstance(n.iter, (ast.List, ast.Tuple)):
                    lst = [const_str(e) for e in n.iter.elts if const_str(e)]
                elif isinstance(n.iter, ast.Name) and n.iter.id in consts:
                    lst = consts[n.iter.id]
                body_src = " ".join(src(b, text) for b in n.body)
                if lst and any(re.search(rf"\b{re.escape(v)}\b", body_src) for v in bodyvars | {"request.json"}) and n.target.id in body_src:
                    for c in lst:
                        add(info["body"], c)
            elif isinstance(n, (ast.DictComp, ast.ListComp, ast.SetComp)):
                for g in n.generators:
                    lst = None
                    if isinstance(g.iter, ast.Name) and g.iter.id in consts:
                        lst = consts[g.iter.id]
                    elif isinstance(g.iter, (ast.List, ast.Tuple)):
                        lst = [const_str(e) for e in g.iter.elts if const_str(e)]
                    elt_src = src(n, text)
                    if lst and any(re.search(rf"\b{re.escape(v)}\b", elt_src) for v in bodyvars | {"request.json"}):
                        for c in lst:
                            add(info["body"], c)

    scan(fn, bodyvars, formvars)
    # one level down: helper functions that receive the body (e.g. _clean(data))
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in module_funcs:
            callee = module_funcs[n.func.id]
            params = [a.arg for a in callee.args.args]
            for i, a in enumerate(n.args):
                if isinstance(a, ast.Name) and a.id in bodyvars and i < len(params):
                    sub = analyse_param(callee, params[i], text)
                    for k in sub:
                        add(info["body"], k)
    # access checks
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            name = n.func.id if isinstance(n.func, ast.Name) else (n.func.attr if isinstance(n.func, ast.Attribute) else "")
            if name and ACCESS_NAME.search(name) and name not in ("jsonify", "get_remote_address", "_parse_date", "_scope_query") and not name.startswith(("_sanitize", "_serialize", "_normalize")):
                mods = [const_str(a) for a in n.args if const_str(a) and const_str(a).isidentifier() or (const_str(a) and re.match(r"^[a-z\-]+$", const_str(a) or ""))]
                write = any(k.arg == "write" and isinstance(k.value, ast.Constant) and k.value.value for k in n.keywords)
                parts = [m for m in mods if m] + (["write"] if write else [])
                tag = name + (f"({', '.join(parts)})" if parts else "")
                if tag not in info["access"]:
                    info["access"].append(tag)
        if isinstance(n, ast.Compare):
            s = src(n, text)
            if "role" in s:
                for c in n.comparators:
                    for e in ([c] if isinstance(c, ast.Constant) else getattr(c, "elts", [])):
                        if isinstance(e, ast.Constant) and e.value in ROLE_WORDS:
                            info["roles"].add(e.value)
    info["roles"] = sorted(info["roles"])
    return info


def analyse_param(fn, param, text):
    keys = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get" and isinstance(n.func.value, ast.Name) and n.func.value.id == param and n.args:
            k = const_str(n.args[0])
            if k and k not in keys:
                keys.append(k)
        elif isinstance(n, ast.Compare) and len(n.ops) == 1 and isinstance(n.ops[0], ast.In) and isinstance(n.comparators[0], ast.Name) and n.comparators[0].id == param:
            k = const_str(n.left)
            if k and k not in keys:
                keys.append(k)
    return keys


def extract():
    endpoints = []
    for path in FILES:
        text = open(path, encoding="utf-8").read()
        tree = ast.parse(text)
        mod = os.path.splitext(os.path.basename(path))[0]
        module_funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        consts = {}
        for n in tree.body:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and isinstance(n.value, (ast.List, ast.Tuple)):
                vals = [const_str(e) for e in n.value.elts if const_str(e)]
                if vals:
                    consts[n.targets[0].id] = vals
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            routes, auth, limits, decs = [], False, [], []
            for d in fn.decorator_list:
                if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "route":
                    rpath = const_str(d.args[0])
                    methods = ["GET"]
                    for k in d.keywords:
                        if k.arg == "methods" and isinstance(k.value, (ast.List, ast.Tuple)):
                            methods = [const_str(e) for e in k.value.elts]
                    routes.append((rpath, methods))
                elif isinstance(d, ast.Name) and d.id == "token_required":
                    auth = True
                elif isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "limit" and d.args:
                    limits.append(const_str(d.args[0]))
                else:
                    decs.append(src(d, text))
            if not routes:
                continue
            info = analyse(fn, text, module_funcs, consts)
            rets = returns_of(fn, text, module_funcs)
            doc = ast.get_docstring(fn) or ""
            for rpath, methods in routes:
                for m in methods:
                    endpoints.append({
                        "module": mod, "function": fn.name, "method": m, "path": rpath,
                        "openapi_path": re.sub(r"<(?:[a-z_]+:)?([^>]+)>", r"{\1}", rpath),
                        "path_params": re.findall(r"<(?:[a-z_]+:)?([^>]+)>", rpath),
                        "login_required": auth, "rate_limits": limits, "doc": doc,
                        "query": info["query"], "body": info["body"], "form": info["form"], "files": info["files"], "headers": info["headers"],
                        "access": info["access"], "roles": info["roles"],
                        "returns": sorted({(r[0], r[1] or "", ",".join(r[2] or []), r[3]) for r in rets}),
                        "line": fn.lineno,
                    })
    return endpoints


if __name__ == "__main__":
    print(len(extract()), "endpoint/method pairs")
