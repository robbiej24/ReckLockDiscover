# ReckLock Discover on GitHub Actions

This page explains **what the manual ReckLock Discover workflow does**, **how to run it**, **what you get back**, & **what to watch for**. It applies to:

- The **standalone** repo [`robbiej24/ReckLockDiscover`](https://github.com/robbiej24/ReckLockDiscover) (mirrored from the HealthyLineups monorepo subtree).
- **HealthyLineups** when the same workflow lives under `.github/workflows/` at the monorepo root & invokes the composite action under `Core/ReckLockFamily/ReckLockShield/ReckLockDiscover`.

When maintainers publish a new Discover release, they bump **`pyproject.toml`**, **`recklock_scanner/constants.py` (`SCANNER_VERSION`)**, then create the matching **`v…`** Git tag on repos where tags matter. **Documentation does not name specific tags** so it stays valid across releases.

**Workflow UI default:** GitHub’s **Run workflow** form prefills **`recklock_release`** from the **`default:`** string in this YAML. After each merge to **`main`** that touches the Discover subtree, **`ReckLock Discover — sync workflow default`** (`.github/workflows/recklock-discover-sync-workflow-default.yml`) runs **`scripts/sync_workflow_dispatch_default.py`** so both copies of **`recklock-discover.yml`** in HealthyLineups stay aligned with **`SCANNER_VERSION`** — no manual edit of **`default:`** should be necessary there.

**OSS repo tags:** **`ReckLock OSS mirror sync`** (HealthyLineups `.github/workflows/recklock-oss-sync.yml`) pushes **`main`** to [`robbiej24/ReckLockDiscover`](https://github.com/robbiej24/ReckLockDiscover) **and** updates the lightweight Git tag **`v{SCANNER_VERSION}`** on that repo so the standalone Actions UI shows the same release tags as the monorepo. Requires secret **`RECKLOCK_OSS_SYNC_TOKEN`** with permission to push contents & tags.

**Immutable checkout** still requires that tag to exist on whichever repo you run the workflow against; **`main` alone** is not an immutable ref for picky consumers.

GitHub **loads the workflow form from whatever ref you pick under “Use workflow from.”** If that ref is an **older tag**, you will still see **older defaults**. Prefer **`main`** (or the release tag you just cut) so the form matches the latest workflow file.

Shorter pointers also live in the **workflow YAML comments** at the top of `.github/workflows/recklock-discover.yml` & in the **`description`** field of `action.yml`.

---

## What the workflow does

1. **Checks out** the Git ref supplied by **`recklock_release`** (a **string**, prefilled with the **current** Discover release tag default from this workflow file) so the scan runs against a **known** snapshot.
2. Runs the **ReckLock Discover** composite action: installs the scanner from that checkout & executes `recklock-discover scan` over the repo root (or configured path).
3. Writes **`recklock_discover_scan_report.json`**, **`recklock_discover_summary_of_findings.md`** (executive summary), & **`recklock_discover_details_of_findings.md`** (full narrative) into the configured output directory.
4. **Uploads** those files as a workflow **artifact** named `recklock-discover-reports` & adds a short **job summary** pointing at them.

The scanner itself is **offline static analysis** (filesystem walk + deterministic detectors). It does **not** call vendor LLM APIs, does **not** upload your source to a third party, & does **not** phone home. See [Security & privacy guarantees](../README.md#security--privacy-guarantees) in the README for product-level guarantees; the sections below add a **GitHub Actions–specific** trust picture.

---

## How to use the workflow (GitHub UI)

1. Open the repository on GitHub → **Actions**.
2. Select **ReckLock Discover** in the workflow list.
3. Click **Run workflow**.
4. **Use workflow from** — Pick **`main`** or the **same** Git tag you intend to scan with **`recklock_release`**. That decides **which copy of this YAML** GitHub uses — including the prefilled **`recklock_release`** default. GitHub often defaults this control to **main**; staying on an **old tag** here is the usual reason people still see **old** defaults in the form.
5. **Pinned ReckLock Discover release tag to scan** (`recklock_release`) — Leave the **prefilled** tag unless you mean to scan another ref (branch names allowed). It must exist on this repository (GitHub checks out that ref **before** the composite action runs).
6. Start the run. When it finishes, open the run → **Summary** for file pointers → **Artifacts** → download **`recklock-discover-reports`**. Open **`recklock_discover_summary_of_findings.md`** first (executive read), then **`recklock_discover_details_of_findings.md`** when you need depth.

### CLI (optional)

If you prefer the terminal & have [`gh`](https://cli.github.com/) configured, pass the **same ref** for **`--ref`** (which workflow file Git loads) & **`-f recklock_release=`** (checkout ref), unless you are experimenting. Example using **`main`** for both:

```bash
REFSPEC=main
gh workflow run recklock-discover.yml --ref "$REFSPEC" -f recklock_release="$REFSPEC"
```

---

## Monorepo vs standalone layout

| Location | Workflow path | Composite action path |
| --- | --- | --- |
| **HealthyLineups** | `.github/workflows/recklock-discover.yml` | `./Core/ReckLockFamily/ReckLockShield/ReckLockDiscover` |
| **ReckLockDiscover (OSS)** | `.github/workflows/recklock-discover.yml` | `./` (repo root is the action) |

Behavior is the same: **checkout chosen ref → scan → upload reports**.

---

## Inputs & outputs

### Workflow inputs

| Input | Meaning |
| --- | --- |
| **`recklock_release`** | Git ref (tag or branch) to check out before scanning. The UI shows the **default string** from this workflow file; edit only when you intend to scan a different ref. |

### Composite action inputs (when you call the action yourself)

See `action.yml` for the full list (`repo-path`, `output-dir`, `min-confidence`, `include` / `exclude`, manifest export flags, `format`). The stock workflow uses **`repo-path: .`**, **`output-dir: recklock-reports`**, & leaves optional filters empty.

### Artifacts

- **Name:** `recklock-discover-reports`
- **Files:** `recklock_discover_summary_of_findings.md`, `recklock_discover_details_of_findings.md`, & `recklock_discover_scan_report.json` under the configured output directory.

Artifact retention follows **repository / org retention settings**. Treat downloads like any other security review material.

---

## Permissions & trust on GitHub

- The workflow requests **`permissions: contents: read`** — it needs to **read** the checked-out tree for the scan. It does **not** ask for `write` to `contents`.
- **Secrets:** the stock workflow does **not** require repository secrets for the scan. Third-party actions (`actions/checkout`, `actions/setup-python`, `actions/upload-artifact`) run under GitHub’s supply chain; pin major versions as you would for any org policy.
- **Forks:** contributors on forks typically **cannot** use `workflow_dispatch` the same way maintainers do unless you explicitly enable or schedule runs; this reduces drive-by abuse of your compute.

---

## Risks & limitations

**Findings are heuristics, not verdicts.** The scanner flags *candidate* automation & sensitive patterns. Expect **false positives** & **false negatives**; use reports for **prioritization & conversation**, not as automatic proof of compromise or compliance.

**Reports may still be sensitive.** Paths, filenames, partial code snippets, & signal labels can reveal architecture or internal project names. **Redaction** reduces raw secret echoing but is not a guarantee against every disclosure; do not post full artifacts in public threads if the repo is private for a reason.

**Two GitHub controls:** **Use workflow from** picks the **workflow file** revision; **`recklock_release`** picks the **checkout** for the scan. If you mix—for example **Use workflow from** = default branch while **`recklock_release`** = an older tag—you may run **newer YAML** against an **older** tree, or the reverse. For **predictable, reviewable runs**, use the **same release tag** for both.

**Large monorepos:** scans are bounded by built-in file / size caps in the scanner; very large trees may skip or truncate per product limits (see architecture docs).

**Shipping a new Discover version:** bump package version & `SCANNER_VERSION`, merge to **`main`** (the **sync workflow default** job patches **`recklock_discover.yml`** if needed), **`git push origin vX.Y.Z`**, & mirror to OSS if you use the split publishing flow (retag the OSS repo too).

---

## Where this documentation lives

| Audience | Location |
| --- | --- |
| Everyone | This file — **`docs/github-actions.md`** |
| Quick scan | Top-of-file comments in **`.github/workflows/recklock-discover.yml`** |
| Action consumers | **`action.yml`** `name` & `description` |
| Overview & links | **[README.md](../README.md)** — GitHub Actions section |

---

## See also

- [Architecture](architecture.md)
- [Detection rules](detection-rules.md)
- [Risk classification](risk-classification.md)
- [ReckLock Discover README](../README.md)
