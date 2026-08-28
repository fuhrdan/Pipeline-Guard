(() => {
  "use strict";

  const VERSION = "0.7.0";
  const severityRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const sarifLevel = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };

  function text(el, selector) {
    return el.querySelector(selector)?.textContent?.trim() || "";
  }

  function collectFindings() {
    return [...document.querySelectorAll("#findings article.finding")].map(article => {
      const severity = text(article, ".sev-badge").toLowerCase();
      const meta = text(article, ".finding-meta");
      const parts = meta.split(" · ").map(v => v.trim());
      const linePart = parts.find(v => /^line \d+$/i.test(v));
      const line = linePart ? Number(linePart.replace(/\D+/g, "")) : null;
      const rule = parts[parts.length - 1] || "pipeline-guard";
      const fileParts = parts.filter(v => v !== linePart && v !== rule);
      const file = fileParts.join(" · ") || "repository";
      const fix = text(article, ".fix").replace(/^Recommended fix:\s*/i, "");
      return {
        severity,
        rule,
        title: text(article, "h3"),
        description: text(article, ".finding-desc"),
        evidence: text(article, ".evidence"),
        remediation: fix,
        file,
        line,
        suppressed: article.classList.contains("is-suppressed")
      };
    });
  }

  function sarifFromFindings(findings, source = "PipelineGuard browser scan") {
    const ruleMap = new Map();
    for (const f of findings) {
      if (!ruleMap.has(f.rule)) {
        ruleMap.set(f.rule, {
          id: f.rule,
          name: f.rule,
          shortDescription: { text: f.title || f.rule },
          fullDescription: { text: f.description || f.title || f.rule },
          help: {
            text: f.remediation || "Review this finding and remediate before production.",
            markdown: f.remediation || "Review this finding and remediate before production."
          },
          defaultConfiguration: { level: sarifLevel[f.severity] || "warning" },
          properties: {
            tags: ["security", "devsecops", "pipeline-guard"],
            "security-severity":
              f.severity === "critical" ? "9.5" :
              f.severity === "high" ? "8.0" :
              f.severity === "medium" ? "5.5" :
              f.severity === "low" ? "3.0" : "0.0"
          }
        });
      }
    }

    return {
      version: "2.1.0",
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [{
        tool: {
          driver: {
            name: "Pipeline Guard",
            fullName: `Pipeline Guard v${VERSION}`,
            semanticVersion: VERSION,
            informationUri: "https://github.com/fuhrdan/Pipeline-Guard",
            rules: [...ruleMap.values()]
          }
        },
        automationDetails: { description: { text: source } },
        results: findings.map(f => {
          const result = {
            ruleId: f.rule,
            level: sarifLevel[f.severity] || "warning",
            message: {
              text: [f.title, f.description, f.remediation ? `Remediation: ${f.remediation}` : ""]
                .filter(Boolean).join(" — ")
            },
            properties: {
              severity: f.severity,
              evidence: f.evidence || ""
            }
          };
          if (f.file && f.file !== "repository" && !/\.zip$/i.test(f.file)) {
            result.locations = [{
              physicalLocation: {
                artifactLocation: { uri: f.file.replace(/\\/g, "/") },
                region: f.line ? { startLine: Math.max(1, f.line) } : undefined
              }
            }];
          }
          return result;
        })
      }]
    };
  }

  function downloadSarif() {
    const findings = collectFindings().filter(f => !f.suppressed);
    const sarif = sarifFromFindings(findings);
    const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: "application/sarif+json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "pipeline-guard.sarif";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function addSarifButton() {
    const actions = document.querySelector(".report-actions");
    if (!actions || document.getElementById("sarifExportBtn")) return;
    const btn = document.createElement("button");
    btn.id = "sarifExportBtn";
    btn.className = "ghost-btn";
    btn.type = "button";
    btn.textContent = "Export SARIF";
    btn.title = "Export active findings as SARIF 2.1.0 for GitHub code scanning";
    btn.disabled = true;
    btn.addEventListener("click", downloadSarif);
    actions.appendChild(btn);

    const observer = new MutationObserver(() => {
      btn.disabled = document.querySelectorAll("#findings article.finding").length === 0 &&
        !/No findings from enabled/i.test(document.getElementById("findings")?.textContent || "");
    });
    observer.observe(document.getElementById("findings"), { childList: true, subtree: true });
  }

  function updateVersionLabels() {
    document.querySelectorAll("*").forEach(el => {
      if (el.children.length === 0 && typeof el.textContent === "string" && el.textContent.includes("0.6.1")) {
        el.textContent = el.textContent.replaceAll("0.6.1", VERSION);
      }
    });
  }

  window.PipelineGuard070 = {
    version: VERSION,
    collectFindings,
    sarifFromFindings,
    severityRank
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      addSarifButton();
      updateVersionLabels();
    });
  } else {
    addSarifButton();
    updateVersionLabels();
  }
})();