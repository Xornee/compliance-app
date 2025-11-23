#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const STATUS_PASS = 'PASS';
const STATUS_FAIL = 'FAIL';

const CONTROL_IDS = {
  SEC01: 'SEC-01',
  SEC02: 'SEC-02',
  SEC03: 'SEC-03',
  SEC04: 'SEC-04',
  SEC05: 'SEC-05',
  SEC06: 'SEC-06',
};

const ARTIFACT_DIR =
  process.env.ARTIFACT_DIR || path.resolve(__dirname, '..', 'artifacts');

const FILES = {
  gitleaks: 'gitleaks.json',
  trivyFs: 'trivy-fs.json',
  trivyImage: 'trivy-image.json',
  dockle: 'dockle.json',
  sbom: 'sbom.json',
};

const TRIVY_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

async function main() {
  await ensureDir(ARTIFACT_DIR);

  const timestamp = new Date().toISOString();

  const [gitleaks, trivyFs, trivyImage, dockle, sbom] = await Promise.all([
    readJsonArtifact(FILES.gitleaks),
    readJsonArtifact(FILES.trivyFs),
    readJsonArtifact(FILES.trivyImage),
    readJsonArtifact(FILES.dockle),
    readJsonArtifact(FILES.sbom),
  ]);

  const trivyFsSummary = trivyFs.parsed
    ? summarizeTrivyVulns(trivyFs.data)
    : null;
  const trivyImageSummary = trivyImage.parsed
    ? summarizeTrivyVulns(trivyImage.data)
    : null;
  const dockleSummary = dockle.parsed
    ? summarizeDockleFindings(dockle.data)
    : null;

  const controls = [];

  controls.push(evaluateSec01(gitleaks));

  controls.push(evaluateSec02(trivyFs, trivyImage, trivyFsSummary, trivyImageSummary));

  controls.push(evaluateSec03(dockle, dockleSummary));

  controls.push(evaluateSec04(trivyFs, trivyImage, trivyFsSummary, trivyImageSummary));

  controls.push(evaluateSec05(sbom));

  const sec06 = {
    id: CONTROL_IDS.SEC06,
    status: STATUS_FAIL,
    details: 'Report not yet generated',
  };

  const reportPath = path.join(ARTIFACT_DIR, 'compliance-report.md');
  const sec06Tentative = {
    id: CONTROL_IDS.SEC06,
    status: STATUS_PASS,
    details: 'Compliance report generated',
  };
  const allControlsForFile = [...controls, sec06Tentative];
  const overallStatusForFile = computeOverallStatus(allControlsForFile);
  const markdownContent = renderMarkdown(
    allControlsForFile,
    overallStatusForFile,
    timestamp,
  );

  let writeSucceeded = false;

  try {
    await fs.promises.writeFile(reportPath, markdownContent, 'utf8');
    writeSucceeded = true;
  } catch (err) {
    console.error(
      `ERROR: Failed to write compliance report to ${reportPath}:`,
      err.message,
    );
  }

  if (writeSucceeded) {
    sec06.status = STATUS_PASS;
    sec06.details = `Report generated at ${reportPath}`;
  } else {
    sec06.status = STATUS_FAIL;
    sec06.details = `Failed to generate report at ${reportPath}`;
  }

  const allControlsForConsole = [...controls, sec06];
  const finalOverallStatus = computeOverallStatus(allControlsForConsole);

  const consoleMarkdown = renderMarkdown(
    allControlsForConsole,
    finalOverallStatus,
    timestamp,
  );

  console.log('\n=== Compliance Report ===\n');
  console.log(consoleMarkdown);
  console.log('\n=== End of Compliance Report ===\n');

  if (!writeSucceeded || finalOverallStatus === STATUS_FAIL) {
    process.exitCode = 1;
  }
}

async function ensureDir(dirPath) {
  try {
    await fs.promises.mkdir(dirPath, { recursive: true });
  } catch (err) {
    console.error(`WARNING: Failed to ensure directory ${dirPath}:`, err.message);
  }
}

async function readJsonArtifact(fileName) {
  const fullPath = path.join(ARTIFACT_DIR, fileName);
  const result = {
    name: fileName,
    fullPath,
    found: false,
    parsed: false,
    data: null,
    error: null,
  };

  try {
    const content = await fs.promises.readFile(fullPath, 'utf8');
    result.found = true;

    try {
      result.data = JSON.parse(content);
      result.parsed = true;
    } catch (parseErr) {
      result.error = `Invalid JSON: ${parseErr.message}`;
    }
  } catch (err) {
    if (err.code === 'ENOENT') {
      result.error = 'File not found';
    } else {
      result.found = true; // we attempted to read and hit a non-ENOENT error
      result.error = `Read error: ${err.message}`;
    }
  }

  return result;
}

function evaluateSec01(gitleaksArtifact) {
  const id = CONTROL_IDS.SEC01;

  if (!gitleaksArtifact.found) {
    return {
      id,
      status: STATUS_FAIL,
      details: `${FILES.gitleaks} not found`,
    };
  }

  if (!gitleaksArtifact.parsed) {
    return {
      id,
      status: STATUS_FAIL,
      details: `${FILES.gitleaks} is not valid JSON (${gitleaksArtifact.error})`,
    };
  }

  const { count, error } = inferGitleaksFindingCount(gitleaksArtifact.data);

  if (error) {
    return {
      id,
      status: STATUS_FAIL,
      details: `Unable to determine findings in ${FILES.gitleaks}: ${error}`,
    };
  }

  if (count > 0) {
    return {
      id,
      status: STATUS_FAIL,
      details: `Gitleaks detected ${count} potential secret(s)`,
    };
  }

  return {
    id,
    status: STATUS_PASS,
    details: 'No secrets detected by Gitleaks (0 findings)',
  };
}

function evaluateSec02(trivyFsArtifact, trivyImageArtifact, fsSummary, imageSummary) {
  const id = CONTROL_IDS.SEC02;
  const issues = [];

  if (!trivyFsArtifact.found) {
    issues.push(`${FILES.trivyFs} not found`);
  } else if (!trivyFsArtifact.parsed) {
    issues.push(
      `${FILES.trivyFs} is not valid JSON (${trivyFsArtifact.error})`,
    );
  }

  if (!trivyImageArtifact.found) {
    issues.push(`${FILES.trivyImage} not found`);
  } else if (!trivyImageArtifact.parsed) {
    issues.push(
      `${FILES.trivyImage} is not valid JSON (${trivyImageArtifact.error})`,
    );
  }

  if (issues.length > 0) {
    return {
      id,
      status: STATUS_FAIL,
      details: issues.join('; '),
    };
  }

  const fsSummaryText = fsSummary
    ? formatTrivySummary('FS', fsSummary)
    : 'Trivy FS: summary unavailable (unexpected JSON structure)';
  const imageSummaryText = imageSummary
    ? formatTrivySummary('Image', imageSummary)
    : 'Trivy image: summary unavailable (unexpected JSON structure)';

  return {
    id,
    status: STATUS_PASS,
    details: `${FILES.trivyFs} and ${FILES.trivyImage} present and valid. ${fsSummaryText}; ${imageSummaryText}`,
  };
}

function evaluateSec03(dockleArtifact, dockleSummary) {
  const id = CONTROL_IDS.SEC03;

  if (!dockleArtifact.found) {
    return {
      id,
      status: STATUS_FAIL,
      details: `${FILES.dockle} not found`,
    };
  }

  if (!dockleArtifact.parsed) {
    return {
      id,
      status: STATUS_FAIL,
      details: `${FILES.dockle} is not valid JSON (${dockleArtifact.error})`,
    };
  }

  if (!dockleSummary) {
    return {
      id,
      status: STATUS_PASS,
      details: `${FILES.dockle} present and valid (unable to infer finding levels; treating as informational)`,
    };
  }

  const { counts } = dockleSummary;
  const fatal = counts.FATAL || counts.FATL || 0;
  const error = counts.ERROR || 0;
  const warn = counts.WARN || 0;

  const parts = Object.entries(counts)
    .filter(([, c]) => c > 0)
    .map(([level, c]) => `${level}: ${c}`)
    .join(', ');

  const summaryText = parts || 'no findings';

  if (fatal > 0 || error > 0 || warn > 0) {
    return {
      id,
      status: STATUS_FAIL,
      details: `Dockle reported hardening issues (${summaryText})`,
    };
  }

  return {
    id,
    status: STATUS_PASS,
    details: `Dockle scan clean (${summaryText})`,
  };
}

function evaluateSec04(trivyFsArtifact, trivyImageArtifact, fsSummary, imageSummary) {
  const id = CONTROL_IDS.SEC04;

  const problems = [];
  if (!trivyFsArtifact.found || !trivyFsArtifact.parsed) {
    problems.push('Trivy FS scan missing or invalid');
  }
  if (!trivyImageArtifact.found || !trivyImageArtifact.parsed) {
    problems.push('Trivy image scan missing or invalid');
  }

  if (problems.length > 0) {
    return {
      id,
      status: STATUS_FAIL,
      details: problems.join('; '),
    };
  }

  if (!fsSummary || !imageSummary) {
    return {
      id,
      status: STATUS_FAIL,
      details: 'Unable to interpret Trivy JSON structure to count vulnerabilities',
    };
  }

  const fsCrit = fsSummary.counts.CRITICAL || 0;
  const imgCrit = imageSummary.counts.CRITICAL || 0;
  const totalCrit = fsCrit + imgCrit;

  const fsText = formatTrivySummary('FS', fsSummary);
  const imgText = formatTrivySummary('Image', imageSummary);

  if (totalCrit > 0) {
    return {
      id,
      status: STATUS_FAIL,
      details: `CRITICAL vulnerabilities detected. ${fsText}; ${imgText}`,
    };
  }

  return {
    id,
    status: STATUS_PASS,
    details: `No CRITICAL vulnerabilities in Trivy scans. ${fsText}; ${imgText}`,
  };
}

function evaluateSec05(sbomArtifact) {
  const id = CONTROL_IDS.SEC05;

  if (!sbomArtifact.found) {
    return {
      id,
      status: STATUS_FAIL,
      details: `${FILES.sbom} not found`,
    };
  }

  if (!sbomArtifact.parsed) {
    return {
      id,
      status: STATUS_FAIL,
      details: `${FILES.sbom} is not valid JSON (${sbomArtifact.error})`,
    };
  }

  return {
    id,
    status: STATUS_PASS,
    details: `${FILES.sbom} present and valid (SBOM generated)`,
  };
}

function inferGitleaksFindingCount(data) {
  if (Array.isArray(data)) {
    return { count: data.length, error: null };
  }

  if (data && typeof data === 'object') {
    if (Array.isArray(data.findings)) {
      return { count: data.findings.length, error: null };
    }
    if (Array.isArray(data.Leaks)) {
      return { count: data.Leaks.length, error: null };
    }
    if (Array.isArray(data.leaks)) {
      return { count: data.leaks.length, error: null };
    }
    if (Array.isArray(data.results)) {
      return { count: data.results.length, error: null };
    }
    if (typeof data.total === 'number') {
      return { count: data.total, error: null };
    }
  }

  return {
    count: null,
    error: 'Unknown Gitleaks JSON structure (no findings array found)',
  };
}

function summarizeTrivyVulns(data) {
  if (!data || typeof data !== 'object' || !Array.isArray(data.Results)) {
    return null;
  }

  const counts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    UNKNOWN: 0,
  };

  for (const result of data.Results) {
    if (!result || !Array.isArray(result.Vulnerabilities)) continue;

    for (const vuln of result.Vulnerabilities) {
      let sev = vuln && vuln.Severity ? String(vuln.Severity).toUpperCase() : 'UNKNOWN';
      if (!TRIVY_SEVERITIES.includes(sev)) {
        sev = 'UNKNOWN';
      }
      counts[sev] += 1;
    }
  }

  const total = TRIVY_SEVERITIES.reduce((acc, sev) => acc + counts[sev], 0);

  return { total, counts };
}

function formatTrivySummary(label, summary) {
  const parts = TRIVY_SEVERITIES.map(
    (sev) => `${sev}: ${summary.counts[sev] || 0}`,
  ).join(', ');

  return `Trivy ${label}: total ${summary.total}, ${parts}`;
}

function summarizeDockleFindings(data) {
  const counts = {};

  const bump = (level) => {
    if (!level) return;
    const key = String(level).toUpperCase();
    counts[key] = (counts[key] || 0) + 1;
  };

  if (Array.isArray(data)) {
    for (const item of data) {
      if (item && item.level) bump(item.level);
      if (item && Array.isArray(item.details)) {
        for (const d of item.details) {
          if (d && d.level) bump(d.level);
        }
      }
    }
  } else if (data && typeof data === 'object') {
    if (Array.isArray(data.details)) {
      for (const d of data.details) {
        if (d && d.level) bump(d.level);
      }
    }
    if (data.level) {
      bump(data.level);
    }
  } else {
    return null;
  }

  if (Object.keys(counts).length === 0) {
    return { counts: {} };
  }

  return { counts };
}

function computeOverallStatus(controls) {
  const allPass = controls.every((c) => c.status === STATUS_PASS);
  return allPass ? STATUS_PASS : STATUS_FAIL;
}

function renderMarkdown(controls, overallStatus, timestamp) {
  const lines = [];

  const gitSha = process.env.GITHUB_SHA || 'n/a';
  const gitRef = process.env.GITHUB_REF || 'n/a';
  const repo = process.env.GITHUB_REPOSITORY || 'n/a';
  const runId = process.env.GITHUB_RUN_ID || null;
  const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com';
  const runUrl =
    runId && repo ? `${serverUrl}/${repo}/actions/runs/${runId}` : 'n/a';

  lines.push('# Compliance Report');
  lines.push('');
  lines.push(`Generated at: \`${timestamp}\``);
  lines.push('');

  lines.push('## Pipeline Context');
  lines.push('');
  lines.push(`- Commit: \`${gitSha}\``);
  lines.push(`- Ref: \`${gitRef}\``);
  lines.push(`- Repository: \`${repo}\``);
  lines.push(`- Run URL: ${runUrl}`);
  lines.push('');

  lines.push('## Control Summary');
  lines.push('');
  lines.push('| Control | Status | Details |');
  lines.push('|---------|--------|---------|');

  for (const control of controls) {
    const safeDetails = escapeMarkdown(control.details || '');
    lines.push(
      `| ${control.id} | ${control.status} | ${safeDetails} |`,
    );
  }

  lines.push('');
  lines.push('## Overall Status');
  lines.push('');
  lines.push(`**${overallStatus}**`);
  lines.push('');

  const failingControls = controls.filter((c) => c.status === STATUS_FAIL);
  if (failingControls.length > 0) {
    lines.push('### Failing Controls');
    lines.push('');
    for (const c of failingControls) {
      lines.push(`- ${c.id}: ${c.details}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function escapeMarkdown(text) {
  return String(text).replace(/\|/g, '\\|');
}

main().catch((err) => {
  console.error('Unexpected error in generate-report.js:', err);
  process.exitCode = 1;
});