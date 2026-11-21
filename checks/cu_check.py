"""cu_check: create/update permission asymmetry (a write-side revocation check).

Idea: after a permission is revoked, artifacts created while it was held still exist. If the handlers
that MUTATE an artifact (edit, patch, restore, restart, duplicate, ...) check only ownership or a weaker
permission, the revoked user can keep acting through the old artifact. So, per resource, every
permission the CREATE handler checks should also be checked by each mutation handler on that resource.

Known instances: Mattermost GHSA-v549 (edit post after create_post is revoked), Kimai GHSA-c6w6
(restart/duplicate timesheet after permission loss).

Mattermost configuration only for now (routes = api.BaseRoutes.<Res>.Handle(path, api.X(handler)).Methods(...),
permissions = model.Permission<Name> constants). Source-only, regex + name-based call graph, like revcov.

Usage: python3 cu_check.py <server/channels dir> <out.json>
"""
import re, sys, json, pathlib
from collections import defaultdict

DEPTH = 3
PKGS = ["api4"]  # handler-side helpers; app/ layer is not followed (permission checks live in api4)
ROUTE = re.compile(r'api\.BaseRoutes\.(\w+)\.Handle\("([^"]*)",\s*api\.\w+\((\w+)\)\)\.Methods\(([^)]*)\)')
PERM = re.compile(r"\bmodel\.(Permission\w+)\b")
# a permission referenced only to raise an error message is not a check
SET_ERR = re.compile(r"SetPermissionError\(\s*model\.Permission\w+\s*\)")
# permissions that are about something other than the resource itself (admin bypass, attachments)
IGNORE = {"PermissionManageSystem", "PermissionUploadFile"}
# authorship used as authorization: the artifact's author field compared with the session user
# (c.Params.UserId is a URL parameter, not an artifact field, so it does not count)
SESS = r"c\.AppContext\.Session\(\)\.UserId"
AUTHOR = re.compile(rf"(?<!Params)\.(UserId|CreatorId|OwnerId)\s*[!=]=\s*{SESS}|{SESS}\s*[!=]=\s*(?!c\.Params)\w+\.(UserId|CreatorId|OwnerId)")
NOT_MUTATION = re.compile(r"search|/ids$")


def resource(base):
    """Posts/Post/PostsForChannel/PostForUser -> post"""
    b = re.sub(r"For\w+$", "", base)
    return re.sub(r"s$", "", b).lower()


def load(root):
    funcs = {}
    fre = re.compile(r"^func (?:\([^)]*\) )?(\w+)\(.*?(?=^func |\Z)", re.S | re.M)
    for pkg in PKGS:
        for p in (root / pkg).glob("*.go"):
            if p.name.endswith("_test.go"):
                continue
            for m in fre.finditer(p.read_text(errors="ignore")):
                funcs.setdefault(m.group(1), (str(p.relative_to(root)), m.group(0)))
    return funcs


def closure(name, funcs):
    seen, frontier = {name}, {name}
    for _ in range(DEPTH):
        nxt = set()
        for f in frontier:
            if f in funcs:
                nxt |= {c for c in re.findall(r"\b(\w+)\(", funcs[f][1]) if c in funcs} - seen
        seen |= nxt
        frontier = nxt
    return seen


def perms(name, funcs):
    out = set()
    for f in closure(name, funcs):
        out |= set(PERM.findall(SET_ERR.sub("", funcs[f][1])))
    return out - IGNORE


def authored(name, funcs):
    return any(AUTHOR.search(funcs[f][1]) for f in closure(name, funcs))


def main(root, all_mutations=False):
    root = pathlib.Path(root)
    funcs = load(root)
    routes = []
    for p in (root / "api4").glob("*.go"):
        if p.name.endswith("_test.go"):
            continue
        for m in ROUTE.finditer(p.read_text(errors="ignore")):
            base, path, h, meths = m.groups()
            for verb in re.findall(r"Method(\w+)", meths):
                routes.append({"res": resource(base), "base": base, "path": path, "handler": h, "method": verb.upper()})

    by_res = defaultdict(list)
    for r in routes:
        by_res[r["res"]].append(r)
    report = {"resources": {}, "flags": []}
    for res, rs in sorted(by_res.items()):
        # create = POST on the collection root ("<Res>s" with empty path); mutations = PUT/PATCH/POST on the item
        creates = [r for r in rs if r["method"] == "POST" and r["path"] == "" and r["base"].endswith("s")
                   and not r["base"].endswith("For" + r["base"].split("For")[-1]) or
                   (r["method"] == "POST" and r["path"] == "" and r["base"] == res.capitalize() + "s")]
        if not creates:
            continue
        need = set().union(*(perms(c["handler"], funcs) for c in creates))
        muts, seen = [], set()
        for r in rs:
            if r["method"] not in ("PUT", "PATCH", "POST") or r in creates or r["base"].endswith("s") \
                    or NOT_MUTATION.search(r["path"]) or r["handler"] in seen:
                continue
            # the bug shape: the mutation authorises by authorship, so a revoked author still passes
            if not all_mutations and not authored(r["handler"], funcs):
                continue
            seen.add(r["handler"])
            muts.append(r)
        report["resources"][res] = {"create": [c["handler"] for c in creates], "create_perms": sorted(need),
                                    "mutations": {m["handler"]: sorted(perms(m["handler"], funcs)) for m in muts}}
        for m in muts:
            missing = need - perms(m["handler"], funcs)
            if missing:
                report["flags"].append({"resource": res, "handler": m["handler"], "route": f'{m["method"]} {m["base"]}{m["path"]}',
                                        "file": funcs.get(m["handler"], ("?",))[0], "missing": sorted(missing)})
    return report


if __name__ == "__main__":
    r = main(sys.argv[1], all_mutations="--all" in sys.argv)
    json.dump(r, open(sys.argv[2], "w"), indent=1)
    for res, v in r["resources"].items():
        print(f"[{res}] create={v['create']} needs {v['create_perms']}")
    print(f"\nflags ({len(r['flags'])}):")
    for f in r["flags"]:
        print(f"  {f['route']:45} {f['handler']:28} missing {f['missing']}")
