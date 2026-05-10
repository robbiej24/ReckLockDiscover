# ReckLock Discover on GitHub Actions

This page explains **what the manual ReckLock Discover workflow does**, **how to run it**, **what you get back**, & **what to watch for**. It applies to:

- The **standalone** repo [`robbiej24/ReckLockDiscover`](https://github.com/robbiej24/ReckLockDiscover) (mirrored from the HealthyLineups monorepo subtree).
- **HealthyLineups** when the same workflow lives under `.github/workflows/` at the monorepo root & invokes the composite action under `Core/ReckLockFamily/ReckLockShield/ReckLockDiscover`.

The current **release line** described here is **`v1.0.2`** (Git tag, package **`1.0.2`**, & `SCANNER_VERSION` in code). Keep those aligned when you cut **`v1.0.3`** or later.

Shorter pointers also live in the **workflow YAML comments** at the top of `.github/workflows/recklock-discover.yml` & in the **`description`** field of `action.yml`.

---

## What the workflow does

1. **Checks out** a **pinned release tag** of the repository (default **`v1.0.2`**) so the scan runs against a **known, immutable** tree.
2. Runs the **ReckLock Discover** composite action: installs the scanner from that checkout & executes `recklock-discover scan` over the repo root (or configured path).
3. **Uploads** the generated **`recklock_discover_scan_report.json`** & **`.md`** files as a workflow **artifact** named `recklock-discover-reports`.

The scanner itself is **offline static analysis** (filesystem walk + deterministic detectors). It does **not** call vendor LLM APIs, does **not** upload your source to a third party, & does **not** phone home. See [Security & privacy guarantees](../README.md#security--privacy-guarantees) in the README for product-level guarantees; the sections below add a **GitHub Actions–specific** trust picture.

---

## How to use the workflow (GitHub UI)

1. Open the repository on GitHub → **Actions**.
2. Select **ReckLock Discover** in the workflow list.
3. Click **Run workflow**.
4. **Use workflow from** — Select **`v1.0.2`** (the release tag). That loads the **workflow YAML** from the same snapshot as the scanner checkout, so **documentation, workflow inputs, & code stay aligned**. GitHub may **default** this dropdown to your **default branch** (often named `main`); change it to **`v1.0.2`** unless you are deliberately testing an unreleased workflow change.
5. **Pinned ReckLock Discover release tag to scan** — leave **`v1.0.2`** (or pick the only option). This controls **`actions/checkout`** & therefore **which snapshot of the codebase** gets scanned. **Match this to the same tag you chose in step 4** for normal runs.
6. Start the run. When it finishes, open the run → **Artifacts** → download **`recklock-discover-reports`**.

### CLI (optional)

If you prefer the terminal & have [`gh`](https://cli.github.com/) configured, load the workflow **from** the release tag & pass the same tag as the scan ref:

```bash
gh workflow run recklock-discover.yml --ref v1.0.2 -f recklock_release=v1.0.2
```

Use a different `--ref` only when you intend to run a **non-release** copy of the workflow file (for example a branch with experimental YAML).

---

## Monorepo vs standalone layout

| Location | Workflow path | Composite action path |
| --- | --- | --- |
| **HealthyLineups** | `.github/workflows/recklock-discover.yml` | `./Core/ReckLockFamily/ReckLockShield/ReckLockDiscover` |
| **ReckLockDiscover (OSS)** | `.github/workflows/recklock-discover.yml` | `./` (repo root is the action) |

Behavior is the same: **checkout pinned tag → scan → upload reports**.

---

## Inputs & outputs

### Workflow inputs

| Input | Meaning |
| --- | --- |
| **`recklock_release`** | Git ref (tag) to check out before scanning. Today the only choice is **`v1.0.2`**, matching the [release tag](https://github.com/robbiej24/ReckLockDiscover/releases/tag/v1.0.2) on the OSS repo once published. |

### Composite action inputs (when you call the action yourself)

See `action.yml` for the full list (`repo-path`, `output-dir`, `min-confidence`, `include` / `exclude`, manifest export flags, `format`). The stock workflow uses **`repo-path: .`**, **`output-dir: recklock-reports`**, & leaves optional filters empty.

### Artifacts

- **Name:** `recklock-discover-reports`
- **Files:** `recklock_discover_scan_report.json` & `recklock_discover_scan_report.md` under the configured output directory.

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

**Two GitHub dropdowns:** **Use workflow from** picks the **workflow file** revision; **`recklock_release`** picks the **checkout** for the scan. If you mix—for example **Use workflow from** = default branch & **`recklock_release`** = **`v1.0.2`**—you may run **newer YAML** against an **older** tree, or the reverse. For **predictable, reviewable runs**, set **both** to **`v1.0.2`**.

**Large monorepos:** scans are bounded by built-in file / size caps in the scanner; very large trees may skip or truncate per product limits (see architecture docs).

**Upgrades:** when you ship **`v1.0.3`**, add it to the workflow **`options`** list, bump **`pyproject.toml`**, **`recklock_scanner/constants.py`**, & this doc together, then tag & mirror.

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
