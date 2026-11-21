"""cu_check_vikunja: create/update asymmetry for apps whose models declare CanCreate/CanUpdate/CanDelete
(Vikunja's web.Permissions interface). Same principle as cu_check.py (Mattermost):

  every access check that CanCreate makes on the parent object must also be made by CanUpdate / CanDelete
  when those authorise by authorship (a.GetID() == <obj>.AuthorID / CreatedByID / OwnerID / UserID).

A "check" here = a call to <Parent>.Can<Read|Write|Admin|Update|Create>(...) or a permission helper, recorded as
"<ParentType>.<Method>". Methods of the same receiver are followed (depth 3).

Usage: python3 cu_check_vikunja.py <pkg/models dir> <out.json>
"""
import re, sys, json, pathlib
from collections import defaultdict

FUNC = re.compile(r"^func \((\w+) \*?(\w+)\) (\w+)\((.*?)(?=^func |\Z)", re.S | re.M)
AUTHOR = re.compile(r"\b(AuthorID|CreatedByID|OwnerID|UserID|CreatedBy\.ID)\b\s*[!=]=\s*\w+\.GetID\(\)|\w+\.GetID\(\)\s*[!=]=\s*[\w.]*\b(AuthorID|CreatedByID|OwnerID|UserID)\b")


def load(root):
    meths = defaultdict(dict)  # type -> name -> (recvvar, body)
    for p in pathlib.Path(root).glob("*.go"):
        if p.name.endswith("_test.go"):
            continue
        for m in FUNC.finditer(p.read_text(errors="ignore")):
            meths[m.group(2)][m.group(3)] = (m.group(1), m.group(0), p.name)
    return meths


def checks(typ, name, meths, depth=3):
    """parent-object access checks reachable from typ.name: {'Task.CanWrite', ...}"""
    out, seen, frontier = set(), {name}, [name]
    for _ in range(depth):
        nxt = []
        for n in frontier:
            if n not in meths[typ]:
                continue
            var, body, _ = meths[typ][n]
            # local vars bound to other model types: `t := Task{...}` / `p := &Project{...}` / `p, err := GetProjectSimpleByID(`
            binds = dict(re.findall(r"\b(\w+)\s*:=\s*&?(\w+)\{", body))
            for v, t in re.findall(r"\b(\w+)(?:,\s*\w+)?\s*:?=\s*\w*?Get(\w+?)(?:Simple)?By\w*\(", body):
                binds.setdefault(v, t)
            for v, meth in re.findall(r"\b(\w+)\.(Can\w+)\(", body):
                if v == var:
                    if meth not in seen:
                        seen.add(meth); nxt.append(meth)
                elif v in binds:
                    out.add(f"{binds[v]}.{meth}")
                else:
                    out.add(f"?{v}.{meth}")
            for helper in re.findall(rf"\b{var}\.(\w+)\(", body):
                if helper in meths[typ] and helper not in seen:
                    seen.add(helper); nxt.append(helper)
        frontier = nxt
    return out


def authored(typ, name, meths, depth=3):
    seen, frontier = {name}, [name]
    for _ in range(depth):
        nxt = []
        for n in frontier:
            if n not in meths[typ]:
                continue
            var, body, _ = meths[typ][n]
            if AUTHOR.search(body):
                return True
            for h in re.findall(rf"\b{var}\.(\w+)\(", body):
                if h in meths[typ] and h not in seen:
                    seen.add(h); nxt.append(h)
        frontier = nxt
    return False


def main(root, all_mut=False):
    meths = load(root)
    rep = {"types": {}, "flags": []}
    for typ, ms in sorted(meths.items()):
        if "CanCreate" not in ms:
            continue
        need = checks(typ, "CanCreate", meths)
        row = {"file": ms["CanCreate"][2], "create": sorted(need), "mut": {}}
        for mut in ("CanUpdate", "CanDelete"):
            if mut not in ms:
                continue
            have, auth = checks(typ, mut, meths), authored(typ, mut, meths)
            row["mut"][mut] = {"checks": sorted(have), "authorship": auth}
            missing = need - have
            if missing and (auth or all_mut):
                rep["flags"].append({"type": typ, "method": mut, "file": ms[mut][2], "missing": sorted(missing),
                                     "has": sorted(have), "authorship": auth})
        rep["types"][typ] = row
    return rep


if __name__ == "__main__":
    r = main(sys.argv[1], "--all" in sys.argv)
    json.dump(r, open(sys.argv[2], "w"), indent=1)
    for t, v in r["types"].items():
        print(f"{t:22} create={v['create']}  " + "  ".join(f"{k}={x['checks']}{'*' if x['authorship'] else ''}" for k, x in v["mut"].items()))
    print(f"\nflags ({len(r['flags'])}):  (* = authorises by authorship)")
    for f in r["flags"]:
        print(f"  {f['type']}.{f['method']} ({f['file']}) missing {f['missing']} has {f['has']} authorship={f['authorship']}")
