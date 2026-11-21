"""php_derive_check: derive-from-old-artifact check for Symfony apps (Kimai configuration).

Write-side revocation check, PHP counterpart of cu_check.py. An action that DERIVES a new record from an
old one (clone + save: duplicate, restart, copy) re-uses the old record's references (project, activity, ...).
If the action's gate (an #[IsGranted(attr, subject)] voter decision) does not re-check the user's CURRENT access
to those references, a user whose access was revoked can keep creating records through their old ones.

Known instance: Kimai GHSA-c6w6 (timesheet restart/duplicate after project access is revoked), affected <= 2.57.0.

Per-app configuration: REF_CHECK names the functions that check current access to a referenced object.
Source-only, regex over PHP; voter case bodies are followed through same-class private methods.

Usage: python3 php_derive_check.py <kimai root> <out.json>
"""
import re, sys, json, pathlib

REF_CHECK = re.compile(r"checkTeamAccess\w*\(|isGranted\(\s*'\w+'\s*,\s*\$\w+->get(Project|Activity|Customer)\(")
CTRL_DIRS = ["src/Controller", "src/API"]
METHOD = re.compile(r"((?:\s*#\[[^\n]*\]\n)*)\s*(?:public|protected|private) function (\w+)\((.*?)\)[^{]*\{", re.S)
IS_GRANTED = re.compile(r"#\[IsGranted\('(\w+)'(?:,\s*'(\w+)')?\)\]")
ROUTE = re.compile(r"#\[Route\((?:methods:\s*\[([^\]]*)\],\s*)?path:\s*'([^']*)'(?:.*?methods:\s*\[([^\]]*)\])?")
NON_ENTITY = {"Request", "ParamFetcherInterface", "FormInterface", "User", "UserInterface", "Response"}
SAVE = re.compile(r"->(save\w*|persist|restartTimesheet)\(\s*\$(\w+)")


def body_at(txt, start):
    """text of the brace block that opens at txt[start-1] == '{'"""
    depth, i = 1, start
    while depth and i < len(txt):
        depth += {"{": 1, "}": -1}.get(txt[i], 0)
        i += 1
    return txt[start:i]


def methods(txt):
    out = {}
    for m in METHOD.finditer(txt):
        out[m.group(2)] = {"attrs": m.group(1), "sig": m.group(3), "body": body_at(txt, m.end()),
                           "pos": txt[:m.start()].count("\n") + 1}
    return out


def load_voters(root):
    """attr -> list of (voter file, case body + same-class private methods it calls)"""
    gates = {}
    for p in (root / "src/Voter").glob("*.php"):
        txt = p.read_text(errors="ignore")
        consts = dict(re.findall(r"const (\w+)\s*=\s*'(\w+)'", txt))
        ms = methods(txt)
        for m in re.finditer(r"case\s+(?:'(\w+)'|self::(\w+))\s*:(.*?)(?=\n\s*case\s|\n\s*default\s*:|\n\s{8}\}\n)", txt, re.S):
            attr = m.group(1) or consts.get(m.group(2))
            if not attr:
                continue
            seen, frontier, text = set(), {None}, m.group(3)
            for _ in range(3):  # follow $this->helper( within the voter
                called = set(re.findall(r"\$this->(\w+)\(", text)) & set(ms) - seen
                if not called:
                    break
                seen |= called
                text += "\n".join(ms[c]["body"] for c in called)
            gates.setdefault(attr, []).append((p.name, text))
    return gates


def main(root):
    root = pathlib.Path(root)
    gates = load_voters(root)
    # all controller methods by name, so `$this->duplicate(...)` in a child resolves to the abstract parent
    allm = {}
    files = [p for d in CTRL_DIRS for p in (root / d).rglob("*.php")]
    for p in files:
        for n, m in methods(p.read_text(errors="ignore")).items():
            allm.setdefault(n, (p, m))
    report = {"derive_actions": [], "flags": []}
    for p in files:
        for name, m in methods(p.read_text(errors="ignore")).items():
            routes = ROUTE.findall(m["attrs"])
            if not routes:
                continue
            body, sig = m["body"], m["sig"]
            for callee in set(re.findall(r"\$this->(\w+)\(", body)):  # one level into helpers
                if callee in allm and callee != name:
                    body += "\n" + allm[callee][1]["body"]
                    sig += ", " + allm[callee][1]["sig"]
            # derived objects: clones, and objects that receive a reference copied from an entity the
            # route loaded (`$new->setProject($old->getProject())`, fluent chains included)
            # entity-typed parameters = objects the route loaded (Request, ParamFetcher etc. are not entities)
            params = {v for t, v in re.findall(r"\b([A-Z]\w*)\s+\$(\w+)", sig) if t not in NON_ENTITY}
            targets = set(re.findall(r"\$(\w+)\s*=\s*clone\s+\$(?:" + "|".join(params or {"_"}) + r")\b", body))
            for stmt in body.split(";"):
                stmt = re.split(r"[{}]", stmt)[-1]
                head = re.match(r"\s*\$(\w+)", stmt)
                if head and head.group(1) not in params and any(
                        re.search(rf"->set\w+\(\s*\${q}->get\w+\(\)\s*\)", stmt) for q in params):
                    targets.add(head.group(1))
            saved = {v for _, v in SAVE.findall(body)}
            if not targets & saved:
                continue
            grants = IS_GRANTED.findall(m["attrs"])
            checked = [a for a, s in grants if s and any(REF_CHECK.search(t) for _, t in gates.get(a, []))]
            rec = {"file": str(p.relative_to(root)), "line": m["pos"], "action": name,
                   "routes": [f"{(r[0] or r[2]).replace(chr(39), '')} {r[1]}" for r in routes],
                   "gates": [f"{a}({s})" for a, s in grants], "ref_checked_by": checked}
            report["derive_actions"].append(rec)
            if not checked:
                report["flags"].append(rec)
    return report


if __name__ == "__main__":
    r = main(sys.argv[1])
    json.dump(r, open(sys.argv[2], "w"), indent=1)
    print(f"derive actions: {len(r['derive_actions'])}")
    for x in r["derive_actions"]:
        mark = "FLAG" if x in r["flags"] else "ok  "
        print(f"  {mark} {x['file']}:{x['line']} {x['action']:22} {x['routes']} gates={x['gates']} ref_checked_by={x['ref_checked_by']}")
