# Revenant: partial artifact (write-side checks)

Partial artifact for the paper *Revoked, But Not Gone: Characterising and Detecting Access-Revocation
Vulnerabilities in Open-Source Web Software* (B. Sittikong). Revenant is a static, source-only oracle
for **revocation closure**: after a grant is withdrawn, any state created under it must be cleaned up or
re-checked on use. It never builds or runs the target application.

## What is here

| Path | Contents | Paper |
|---|---|---|
| `checks/cu_check.py` | Create/update check (CU, obligation O3) for Mattermost | Alg. 3 |
| `checks/cu_check_vikunja.py` | CU adapted to Vikunja's `CanCreate/CanUpdate` model methods | Alg. 3 |
| `checks/php_derive_check.py` | Derive check (DV, obligation O4) for Kimai (PHP/Symfony voters) | Sec. 6.5 |
| `results/cu-*.json`, `results/derive-*.json` | Write-side outputs for every subject version (RQ5, RQ6) | Table 13 |
| `results/cu-all-*.json` | The same checks without the authorship filter (`--all`) | Sec. 7.3 |
| `results/rc-cl-flags-gitea-*.json` | Read-check and cleanup-matrix flags for Gitea 1.26.2 / 1.27.0 | Table 13 |
| `reproduce.sh` | Re-runs the write-side checks and compares with `results/` | |

Subject versions: Mattermost 11.5.1 (vulnerable, GHSA-v549-xx3c-6pc8), 11.5.2 (fixed), 12.0.1 (held out);
Vikunja 2.7.1; Kimai 2.56.0 and 2.57.0 (vulnerable, GHSA-c6w6-57jj-62vh), 2.58.0 (fixed), 2.59.0 (held out).
Download each release's source from the project's official repository, then run

```sh
./reproduce.sh <dir with mattermost-v11.5.1/ ... kimai-2.59.0/>
```

Requirements: Python 3.13 (standard library only). Tested with Python 3.13.9.

## What is not here yet, and why

The read-side components are **withheld for now**: the read check (RC), the cleanup matrix (CL), the
`go/ast` route extractor and the package-qualified call-graph builder. Running them on applications outside the
paper's ground truth produced candidate findings that are still going through coordinated disclosure with an
affected vendor. They will be added to this repository once that process is complete. Until then, the Gitea
flag lists in `results/` record their output on the ground-truth version pair, whose vulnerabilities are public.

## Licence

MIT (see `LICENSE`).
