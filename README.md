# Security & Compliance Demo – Technical Documentation

This README describes how the **Security & Compliance Pipeline**, the **Dockerfile**, and the **`scripts/generate-report.js`** script work together.

It is intentionally precise and aligned with the current implementation.

---

## 1. Overview

### 1.1 Goals

This repository demonstrates how to:

- Scan source code and container images for **secrets** and **vulnerabilities**.
- Enforce **image metadata** and **hardening** requirements.
- Generate a single **compliance report** from multiple security tools.
- Fail the CI run when defined **security controls** are not met.

### 1.2 Main components

1. **GitHub Actions workflow** – `.github/workflows/security-compliance.yml`  
   Orchestrates security jobs and produces artifacts.

2. **Dockerfile** – multi-stage build for a Node.js (NestJS) service, using a **distroless, non-root** runtime.

3. **Compliance report generator** – `scripts/generate-report.js`  
   Reads scanner outputs from `artifacts/` and produces `artifacts/compliance-report.md`.

---

## 2. GitHub Actions: Security & Compliance Pipeline

Workflow name: **`Security & Compliance Pipeline`**.

### 2.1 Triggers

The workflow runs on:

- `push` to branches: **`master`**, **`main`**
- `pull_request` targeting: **`master`**, **`main`**
- Manual runs via **`workflow_dispatch`**

### 2.2 Concurrency

```yaml
concurrency:
  group: security-compliance-${{ github.ref }}
  cancel-in-progress: true
```

There is at most one run per ref (branch/PR) at a time; newer runs cancel older ones for the same ref.

### 2.3 Global environment variables

```yaml
env:
  IMAGE_NAME: compliance-app:${{ github.sha }}
  ARTIFACT_DIR: artifacts
  GITLEAKS_VERSION: "8.24.3"
  TRIVY_FAIL_SEVERITY: CRITICAL
  DOCKLE_FAILURE_THRESHOLD: warn
```

- `IMAGE_NAME` – local Docker image tag used for scans.
- `ARTIFACT_DIR` – directory where each job writes its security artifacts.
- `GITLEAKS_VERSION` – pinned version of the Gitleaks CLI.
- `TRIVY_FAIL_SEVERITY` – severity level that fails Trivy gates (`CRITICAL`).
- `DOCKLE_FAILURE_THRESHOLD` – minimum Dockle level that causes failure (`warn`).

### 2.4 Permissions

Workflow-level permissions:

```yaml
permissions:
  contents: read
  security-events: write
  actions: read
```

Jobs that upload SARIF explicitly request `security-events: write` so results appear in **GitHub Code Scanning**.

---

## 3. Job: `gitleaks` – Secret Scanning

**Purpose:** Detect hard-coded secrets in the Git history and working tree using **Gitleaks**.

**Runs on:** `ubuntu-latest`

### 3.1 Steps (simplified)

1. **Checkout code** (shallow clone, `fetch-depth: 1`).  
2. **Create `ARTIFACT_DIR`**.  
3. **`gitleaks/gitleaks-action@v2`** – official action for PR summary/comments (non-blocking).  
4. **Install Gitleaks CLI** – pinned version from `GITLEAKS_VERSION`.  
5. **Run Gitleaks to JSON** (non-blocking):
   - Writes `artifacts/gitleaks.json` and `artifacts/gitleaks.log`.
6. **Run Gitleaks to SARIF** (non-blocking):
   - Writes `artifacts/gitleaks.sarif`.
7. **Job summary section**:
   - Counts findings in `gitleaks.json` using `jq` and prints a tabular summary into `$GITHUB_STEP_SUMMARY`.
8. **Upload SARIF** to GitHub Code Scanning (`github/codeql-action/upload-sarif@v4`).  
9. **Gate: Gitleaks secrets** (blocking):
   - Fails the job if `artifacts/gitleaks.json` is missing.
   - Fails the job if the number of findings > 0.
10. **Upload artifacts**:
    - Uploads `artifacts/` as `security-artifacts-gitleaks` (retention: 7 days).

### 3.2 Failure conditions

The **`gitleaks` job fails** if:

- `gitleaks.json` is missing, **or**
- `gitleaks.json` contains **one or more findings**.

### 3.3 Local secret scanning with pre-commit (Gitleaks)

In addition to the CI `gitleaks` job, this repository also runs Gitleaks **locally** via
[`pre-commit`](https://pre-commit.com/). This prevents developers from committing secrets
before they ever reach the remote repository.

**Configured hook** (`.pre-commit-config.yaml`):

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.29.0
    hooks:
      - id: gitleaks
        name: gitleaks-secrets-scan
        args:
          - --config=.gitleaks.toml
        stages: [pre-commit]
```

Key points:

- `repo` / `rev`  
  Pin Gitleaks to a specific version (**v8.29.0**) to avoid surprise rule changes.
- `id: gitleaks`  
  Uses the official Gitleaks hook implementation.
- `args: --config=.gitleaks.toml`  
  Reuses the same configuration file as CI, so **local and CI behaviour match**.
- `stages: [pre-commit]`  
  Runs on the **pre-commit** stage; it scans only the files staged for commit.

To enable this locally:

1. Install `pre-commit` (e.g. `pip install pre-commit` or via your package manager).
2. Run `pre-commit install` once in this repo.
3. From now on, `gitleaks-secrets-scan` runs automatically on each `git commit` and
   blocks the commit if any new secrets are detected.

You can also run it against all files on demand:

```bash
pre-commit run gitleaks-secrets-scan --all-files
```

### 3.4 `.gitleaks.toml` – Gitleaks configuration

The `.gitleaks.toml` file controls which patterns are considered secrets and which files
or paths are excluded to reduce noise and false positives.

```toml
title = "compliance-app gitleaks config"

[extend]
useDefault = true

[allowlist]
description = "Global allowlist for non-secret files and one intentional example false-positive."
paths = [
  '''\.gitleaks\.toml$''',
  '''(.*?)(jpg|jpeg|png|gif|ico|svg|pdf|zip|tar|gz)$''',
  '''example-fake-secret\.md$'''
]

[[rules]]
id = "generic-credential-assignment"
description = "Generic credentials: password/token/api_key assignment with high-entropy value"
regex = '''(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-\/+=]{16,})["']'''
tags = ["secret", "generic", "high-entropy"]

  [[rules.Entropies]]
  Min = 3.5
  Max = 8.0
  Group = 2
```

Breakdown:

- `title`  
  Human‑readable name for this configuration.

- `[extend] useDefault = true`  
  Start from the **default Gitleaks rules** and add project-specific tweaks on top.
  This gives you a wide baseline of secret patterns (AWS keys, GitHub tokens, etc.)
  without having to re-define them manually.

- `[allowlist]`  
  Defines a **global allowlist** of paths where findings should be ignored.  
  Here, the following patterns are excluded:
  - `\.gitleaks\.toml$` – ignore the config file itself.
  - `(.*?)(jpg|jpeg|png|gif|ico|svg|pdf|zip|tar|gz)$` – ignore typical **binary / image / archive**
    formats which often confuse secret scanners.
  - `example-fake-secret\.md$` – an explicit demo file allowed to contain fake secrets.

  These allowlist entries reduce noise by skipping files where secrets are unlikely or where
  you intentionally store fake examples.

- `[[rules]] generic-credential-assignment`  
  Adds a **custom rule** on top of the defaults to catch generic assignments such as:

  ```text
  password = "S0meSup3rRand0mValue"
  api_key: "XyZ123..."
  token = "abcdEFGHijklMNOPqrst1234"
  ```

  The `regex` does the following:
  - `(?i)` – case‑insensitive matching.
  - `(password|passwd|secret|token|api[_-]?key)` – match common credential keywords.
  - `\s*[:=]\s*` – allow `=` or `:` with optional whitespace.
  - `["']([A-Za-z0-9_\-\/+=]{16,})["']` – capture a quoted value, at least 16 characters
    from a typical “secret‑like” character set. The **second capturing group** is the candidate secret.

  `tags = ["secret", "generic", "high-entropy"]` classifies the rule for reporting and filtering.

- `[[rules.Entropies]]`  
  Adds an **entropy filter** so only “secret‑looking” values are flagged:
  - `Group = 2` – measure entropy on capturing group 2 (the value part, not the entire line).
  - `Min = 3.5`, `Max = 8.0` – ignore very low‑entropy values (e.g. `"password123"`) and filter
    out obviously random but non‑secret data outside that range.

Together, this configuration means:

- You keep the **full default rule set** from Gitleaks.
- You ignore noisy, non‑code files via `allowlist.paths`.
- You add a **generic, high‑entropy credential rule** that catches a wide range of
  `password`/`token`/`api_key` assignments without drowning developers in false positives.

---

## 4. Job: `fs-scan` – Filesystem Scan (Trivy)

**Purpose:** Run **Trivy** against the repository filesystem to detect vulnerabilities and secrets before building an image.

**Depends on:** `gitleaks`

### 4.1 Steps

1. Checkout code.
2. Create `ARTIFACT_DIR`.
3. **Trivy FS (table, non-blocking)**:
   - `scan-type: fs`, `scan-ref: .`
   - `scanners: vuln,secret`
   - `severity: LOW,MEDIUM,HIGH,CRITICAL`
   - `format: table`
   - Output → `artifacts/trivy-fs-table.txt`
   - `exit-code: 0` (never fails here).
4. **Job summary snippet** – prints `trivy-fs-table.txt` into `$GITHUB_STEP_SUMMARY`.
5. **Trivy FS (JSON)**:
   - Same scan, `format: json`
   - Output → `artifacts/trivy-fs.json`
   - `exit-code: 0`.
6. **Trivy FS (SARIF)** – `format: sarif`, output `artifacts/trivy-fs.sarif`, `exit-code: 0`.
7. **Upload FS SARIF** to GitHub Code Scanning.
8. **Gate: Trivy FS CRITICAL** (blocking):
   - Runs Trivy with `severity: ${{ env.TRIVY_FAIL_SEVERITY }}` (`CRITICAL`).
   - `exit-code: 1` → **job fails** when any CRITICAL vulnerabilities are found.
9. Upload `artifacts/` as `security-artifacts-fs` (7 days).

### 4.2 Failure conditions

The **`fs-scan` job fails** if Trivy finds **any CRITICAL** vulnerabilities in the filesystem scan.

---

## 5. Job: `image-build` – Docker Image Build

**Purpose:** Build the application image once and reuse it across downstream jobs.

**Depends on:** `fs-scan`

### 5.1 Steps

1. Checkout code.
2. Build the image:

   ```bash
   docker build --pull -t "$IMAGE_NAME" .
   ```

3. Save the image as a tarball:

   ```bash
   docker save "$IMAGE_NAME" -o docker-image/docker-image.tar
   ```

4. Upload directory `docker-image/` as artifact `docker-image` (retention: 1 day).

### 5.2 Failure conditions

The **`image-build` job fails** if the Docker build or `docker save` command fails.

---

## 6. Job: `image-scan` – Docker Image Scan (Trivy + Metadata)

**Purpose:** Scan the built image with Trivy and enforce basic image metadata.

**Depends on:** `image-build`

### 6.1 Steps

1. Checkout code.
2. Create `ARTIFACT_DIR`.
3. Download `docker-image` artifact and `docker load` it.
4. **Trivy image (table, non-blocking)**:
   - `scan-type: image`, `image-ref: $IMAGE_NAME`
   - `vuln-type: os,library`
   - `severity: LOW,MEDIUM,HIGH,CRITICAL`
   - `format: table`, output `artifacts/trivy-image-table.txt`.
5. **Job summary snippet** – prints `trivy-image-table.txt` into `$GITHUB_STEP_SUMMARY`.
6. **Trivy image (JSON)** → `artifacts/trivy-image.json`, `exit-code: 0`.
7. **Trivy image (SARIF)** → `artifacts/trivy-image.sarif`, `exit-code: 0`.
8. **Upload image SARIF** to GitHub Code Scanning.
9. **Enforce required image labels** (blocking):

   ```bash
   owner=$(docker inspect -f '{{ index .Config.Labels "owner" }}' "$IMAGE_NAME" || echo "")
   version=$(docker inspect -f '{{ index .Config.Labels "org.opencontainers.image.version" }}' "$IMAGE_NAME" || echo "")

   if [ -z "$owner" ] || [ -z "$version" ]; then
     exit 1
   fi
   ```

   - Fails if either `owner` or `org.opencontainers.image.version` label is missing.

10. **Gate: Trivy image CRITICAL** (blocking):
    - `severity: ${{ env.TRIVY_FAIL_SEVERITY }}` (`CRITICAL`)
    - `exit-code: 1` → fails when any CRITICAL vulnerabilities are found.
11. Upload `artifacts/` as `security-artifacts-image` (7 days).

### 6.2 Failure conditions

The **`image-scan` job fails** if:

- The image is missing required labels: `owner` or `org.opencontainers.image.version`, **or**
- Trivy finds **any CRITICAL** vulnerabilities in the image scan.

---

## 7. Job: `sbom` – SBOM Generation (Syft)

**Purpose:** Generate an SBOM for the built image.

**Depends on:** `image-build`

### 7.1 Steps

1. Checkout code.
2. Create `ARTIFACT_DIR`.
3. Download and load `docker-image` artifact.
4. Run **Syft** via `anchore/sbom-action@v0`:

   - `image: $IMAGE_NAME`
   - `output-file: artifacts/sbom.json`
   - `format: cyclonedx-json`
   - `upload-artifact: false` (we upload ourselves).

5. Upload `artifacts/` as `security-artifacts-sbom` (7 days).

### 7.2 Failure conditions

The **`sbom` job fails** if Syft cannot generate `sbom.json`.

---

## 8. Job: `dockle` – Image Hardening (Dockle)

**Purpose:** Run **Dockle** against the built image to check Docker hardening rules.

**Depends on:** `image-build`

### 8.1 Steps

1. Checkout code.
2. Create `ARTIFACT_DIR`.
3. Download and load `docker-image` artifact.
4. Run `erzz/dockle-action@v1.4.0`:

   - `image: $IMAGE_NAME`
   - `report-format: json`
   - `report-name: dockle` (produces `dockle.json` or `dockle-report.json`).
   - `failure-threshold: ${{ env.DOCKLE_FAILURE_THRESHOLD }}` (`warn`).
   - `exit-code: 1` (Dockle failures cause job failure).

5. Move Dockle JSON report into `ARTIFACT_DIR` as `dockle.json` (if present).
6. Generate a Dockle summary in `$GITHUB_STEP_SUMMARY`:
   - Prints totals for FATAL/WARN/INFO/PASS.
   - Renders a table of findings (Level / Code / Title / First alert).
7. Upload `artifacts/` as `security-artifacts-dockle` (7 days).

### 8.2 Failure conditions

The **`dockle` job fails** when Dockle returns a level ≥ `failure-threshold` (`warn`).  

---

## 9. Job: `compliance-report` – Aggregation & Compliance Dashboard

**Purpose:** Merge all security artifacts and generate a single compliance report.

**Depends on (via `needs`)**:

- `gitleaks`
- `fs-scan`
- `image-scan`
- `sbom`
- `dockle`

**Conditional:** `if: ${{ always() }}` – runs regardless of whether previous jobs have failed, so failures appear in the report.

### 9.1 Steps

1. Checkout code.
2. Create `ARTIFACT_DIR`.
3. Download all artifacts into `downloaded-artifacts/`.
4. Flatten/merge artifacts into `${ARTIFACT_DIR}` (files are copied, basename only).
5. Generate a **Security Dashboard** summary in `$GITHUB_STEP_SUMMARY`:
   - Uses `jq` over:
     - `gitleaks.json`
     - `trivy-fs.json`
     - `trivy-image.json`
     - `dockle.json`
   - Reports, for each area, a PASS/FAIL/N/A and key counts.

6. **Setup Node.js** (Node 22) via `actions/setup-node@v4`.
7. Run the report generator:

   ```bash
   node scripts/generate-report.js
   ```

   - Writes `artifacts/compliance-report.md`.
   - Exits with code **1** when controls fail or the report cannot be written.

8. Append `compliance-report.md` contents to `$GITHUB_STEP_SUMMARY` (if the file exists).
9. Upload `artifacts/` as artifact **`compliance-report`** (retention: 30 days).

### 9.2 Failure conditions

The **`compliance-report` job fails** when `scripts/generate-report.js` sets a non-zero exit code (see Section 10.4).

---

## 10. `scripts/generate-report.js` – Compliance Report Generator

**Location:** `scripts/generate-report.js`

**Purpose:**

- Read security artifacts from `ARTIFACT_DIR` (default `artifacts/`).
- Evaluate a fixed set of **security controls** (SEC-01…SEC-06).
- Write the compliance report to `artifacts/compliance-report.md`.
- Print the same report to stdout.
- Set a non-zero exit code when controls fail.

### 10.1 Inputs (artifacts)

By default, the script looks for the following files in `ARTIFACT_DIR`:

- `gitleaks.json`
- `trivy-fs.json`
- `trivy-image.json`
- `dockle.json`
- `sbom.json` (optional but recommended)

`ARTIFACT_DIR` can be overridden via the environment variable `ARTIFACT_DIR`.

Each file is read and parsed as JSON in a **best-effort** manner:

- Missing files are recorded as `found = false`.
- Invalid JSON produces an error string.
- The script does **not** throw; instead, it uses this status when evaluating controls.

### 10.2 Helper summaries

The script derives:

- **Trivy summaries** (`summarizeTrivyVulns`):
  - Traverses `.Results[].Vulnerabilities[]?` and counts issues per severity:
    - CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
- **Dockle summaries** (`summarizeDockleFindings`):
  - Counts findings by `level` from common Dockle JSON shapes.
- **Gitleaks count** (`inferGitleaksFindingCount`):
  - Supports multiple formats:
    - Array at top level.
    - `{ findings: [] }`
    - `{ Leaks: [] }` / `{ leaks: [] }`
    - `{ results: [] }`
    - `{ total: number }`

### 10.3 Controls (SEC-01…SEC-06)

The script evaluates **six controls** and renders them in a Markdown table.

#### SEC-01 – No secrets (Gitleaks)

> **ID:** `SEC-01`  
> **Artifact:** `gitleaks.json`

Logic:

- **PASS** if:
  - `gitleaks.json` exists,
  - is valid JSON, and
  - inferred findings count is **0**.
- **FAIL** if:
  - file is missing,
  - invalid JSON, or
  - findings count **> 0**.

#### SEC-02 – Trivy coverage (FS + image)

> **ID:** `SEC-02`  
> **Artifacts:** `trivy-fs.json`, `trivy-image.json`

Logic:

- **PASS** if both:
  - `trivy-fs.json` exists and is valid JSON.
  - `trivy-image.json` exists and is valid JSON.
- **FAIL** otherwise (missing or invalid).

The details text includes a short summary of Trivy FS and image results, if they could be parsed (total and counts per severity).

#### SEC-03 – Docker hardening scan (Dockle)

> **ID:** `SEC-03`  
> **Artifact:** `dockle.json`

Logic:

- **PASS** if:
  - `dockle.json` exists,
  - is valid JSON, and
  - no findings at level **FATAL**, **ERROR**, or **WARN** (based on the Dockle summary).
- **FAIL** if:
  - file is missing,
  - invalid,
  - or there are any findings at these levels.

If Dockle JSON exists but the structure is unrecognised, the control is treated as informational and marked PASS with a note that the summary was unavailable.

#### SEC-04 – No CRITICAL vulnerabilities (Trivy FS + image)

> **ID:** `SEC-04`  
> **Artifacts:** `trivy-fs.json`, `trivy-image.json`

Logic:

- **PASS** if both:
  - Trivy FS and image reports exist and are valid, and
  - **CRITICAL** count in FS and image summaries is **0**.
- **FAIL** if:
  - Either report is missing or invalid, **or**
  - Any CRITICAL vulnerabilities are present in either FS or image scans.

The details string includes the Trivy FS and image summaries with total and per-severity counts.

#### SEC-05 – SBOM generated

> **ID:** `SEC-05`  
> **Artifact:** `sbom.json`

Logic:

- **PASS** if `sbom.json` exists and is valid JSON.
- **FAIL** otherwise (missing or invalid).

This control does not inspect SBOM content in detail; it only ensures presence and basic validity.

#### SEC-06 – Report generated

> **ID:** `SEC-06`  
> **Artifact:** `compliance-report.md` (output of this script)

Logic:

- The script first **assumes PASS** for SEC-06 when rendering the file version of the report.
- It attempts to write `artifacts/compliance-report.md`.
- If the write succeeds:
  - SEC-06 is finalised as **PASS**, with the full path in details.
- If the write fails:
  - SEC-06 is finalised as **FAIL**, indicating the failure path.

### 10.4 Overall status & exit codes

The script computes an **overall status**:

- **PASS** only if **all controls** are PASS.
- **FAIL** otherwise.

At the end, it:

1. Prints the full Markdown report to stdout (with a “Compliance Report” header, pipeline metadata, and a control table).
2. Sets `process.exitCode = 1` if:
   - `compliance-report.md` could not be written, **or**
   - `finalOverallStatus === FAIL` (i.e. at least one control failed).

This is what makes the **`compliance-report` job** (and therefore the workflow) fail when any control fails, even if earlier gates have already failed.

### 10.5 Report structure

The generated `compliance-report.md` contains:

1. **Title** – `# Compliance Report`
2. **Generation time** (`Generated at: <ISO timestamp>`)
3. **Pipeline context:**
   - Commit (`GITHUB_SHA`)
   - Ref (`GITHUB_REF`)
   - Repository (`GITHUB_REPOSITORY`)
   - Run URL (constructed from `GITHUB_SERVER_URL`, `GITHUB_REPOSITORY`, `GITHUB_RUN_ID`)
4. **Control Summary table:**
   - Columns: Control / Status / Details
   - One row per SEC-XX control.
5. **Overall Status** – bold PASS or FAIL.
6. **Failing Controls** section listing each failing control and its details.

Pipe characters (`|`) in details are escaped to keep the Markdown table valid.

---

## 11. Dockerfile – Detailed Explanation

The Dockerfile implements a **three-stage build** for a NestJS app:

```Dockerfile
FROM node:22-slim AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM node:22-slim AS deps
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

FROM gcr.io/distroless/nodejs22-debian12:nonroot AS runtime
WORKDIR /app

ENV NODE_ENV=production

LABEL owner="Szymon Mytych"       org.opencontainers.image.version="1.0.0"

COPY --from=builder /app/dist ./dist
COPY --from=deps /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3   CMD ["node", "-e", "require('http').get('http://127.0.0.1:3000/health', res => { if (res.statusCode === 200) process.exit(0); else process.exit(1); }).on('error', () => process.exit(1));"]

CMD ["dist/main.js"]
```

### 11.1 `builder` stage

- Base: `node:22-slim`
- Responsibilities:
  - Install build tooling (`curl`) and dependencies (`npm ci`).
  - Compile the NestJS app (`npm run build`) into `dist/`.

### 11.2 `deps` stage

- Base: `node:22-slim`
- Responsibilities:
  - Install **production-only** dependencies via `npm ci --omit=dev`.
- Output:
  - `/app/node_modules` without devDependencies.

### 11.3 `runtime` stage

- Base: `gcr.io/distroless/nodejs22-debian12:nonroot`
- Characteristics:
  - **Distroless**: no shell / package manager inside the final image.
  - **Non-root**: runs as an unprivileged user by default.

- Configuration:
  - `WORKDIR /app`
  - `ENV NODE_ENV=production`
  - Labels:

    ```Dockerfile
    LABEL owner="Szymon Mytych"           org.opencontainers.image.version="1.0.0"
    ```

    These labels are required by the `image-scan` job and enforced by the label check.

- Files copied:

  ```Dockerfile
  COPY --from=builder /app/dist ./dist
  COPY --from=deps /app/node_modules ./node_modules
  COPY --from=builder /app/package*.json ./
  ```

- Port and health check:

  - `EXPOSE 3000` – application listens on port 3000.
  - `HEALTHCHECK` – uses Node’s `http` module to GET `http://127.0.0.1:3000/health`:
    - Success: HTTP 200 → exit 0 (healthy).
    - Failure: non-200 or error → exit 1 (unhealthy).

- Entrypoint:

  ```Dockerfile
  CMD ["dist/main.js"]
  ```

  Distroless Node images already provide the Node runtime as entrypoint, so only the script path is specified.

---

## 12. Summary of Hard Gates

The pipeline enforces the following **blocking conditions**:

1. **Secrets:** any Gitleaks findings → `gitleaks` job fails.
2. **Filesystem vulnerabilities:** any CRITICAL vulns in Trivy FS → `fs-scan` fails.
3. **Image labels:** missing `owner` or `org.opencontainers.image.version` → `image-scan` fails.
4. **Image vulnerabilities:** any CRITICAL vulns in Trivy image scan → `image-scan` fails.
5. **Dockle hardening:** Dockle scoring ≥ `warn` → `dockle` fails.
6. **Compliance controls:** any SEC-0X control fails, or the report file cannot be written →
   `scripts/generate-report.js` exits with code 1 → `compliance-report` job fails.

Together, this ensures that security findings and missing artifacts are surfaced both at **tool level** (individual jobs) and at **policy level** (SEC-01…SEC-06 in the compliance report).
