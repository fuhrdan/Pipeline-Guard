(() => {
  "use strict";

  const state = {
    files: [],
    findings: [],
    score: null,
    currentFilter: "all",
    scannedAt: null,
    livePackages: [],
    liveVulnerabilities: [],
    liveCheckedAt: null,
    repository: null,
    suppressions: [],
    liveSource: null
  };

  const $ = (id) => document.getElementById(id);
  const dropZone = $("dropZone");
  const fileInput = $("fileInput");
  const fileList = $("fileList");
  const scanBtn = $("scanBtn");

  const SEVERITY_WEIGHT = { critical: 25, high: 12, medium: 6, low: 2, info: 0 };
  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const APP_VERSION = "0.6.1";
  const RELAY_HEALTH_TIMEOUT_MS = 10000;


  const SUPPRESSION_KEY = "pipelineguardSuppressionsV1";
  const LIVE_CACHE_KEY = "pipelineguardLiveCacheV1";


  function storageGet(key) {
    try { return localStorage.getItem(key); } catch { return null; }
  }

  function storageSet(key, value) {
    try { localStorage.setItem(key, value); return true; } catch { return false; }
  }

  function todayIso() {
    const d = new Date();
    const local = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
    return local.toISOString().slice(0, 10);
  }

  function addDaysIso(days) {
    const d = new Date();
    d.setDate(d.getDate() + days);
    const local = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
    return local.toISOString().slice(0, 10);
  }

  function fnv1a(value) {
    let h = 0x811c9dc5;
    for (let i = 0; i < value.length; i++) {
      h ^= value.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0).toString(16).padStart(8, "0");
  }

  function findingFingerprintParts(file, finding) {
    const stableEvidence = String(finding.evidence || "").replace(/\s+/g, " ").trim().slice(0, 260);
    return [file.name || "", finding.rule || "", finding.title || "", stableEvidence].join("|");
  }

  function loadSuppressions() {
    try {
      const raw = JSON.parse(storageGet(SUPPRESSION_KEY) || "[]");
      state.suppressions = Array.isArray(raw) ? raw : [];
    } catch {
      state.suppressions = [];
    }
    updateSuppressionUI();
  }

  function saveSuppressions() {
    const persisted = storageSet(SUPPRESSION_KEY, JSON.stringify(state.suppressions));
    updateSuppressionUI();
    return persisted;
  }

  function activeSuppression(finding) {
    const today = todayIso();
    return state.suppressions.find(s => s.fingerprint === finding.fingerprint && s.expiresAt >= today) || null;
  }

  function suppressionRecord(finding) {
    return state.suppressions.find(s => s.fingerprint === finding.fingerprint) || null;
  }

  function activeSuppressionCount() {
    const today = todayIso();
    return state.suppressions.filter(s => s.expiresAt >= today).length;
  }

  function unsuppressedFindings() {
    return state.findings.filter(f => !activeSuppression(f));
  }

  function recomputeScore() {
    state.score = Math.max(0, 100 - unsuppressedFindings().reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0));
  }

  function updateSuppressionUI() {
    const count = activeSuppressionCount();
    if ($("suppressionTopCount")) $("suppressionTopCount").textContent = count;
    if ($("suppressedBadge")) $("suppressedBadge").textContent = state.findings.filter(f => activeSuppression(f)).length;
  }

  function showToast(title, message) {
    const old = document.querySelector(".toast");
    if (old) old.remove();
    const el = document.createElement("div");
    el.className = "toast";
    el.innerHTML = `<strong>${escapeHtml(title)}</strong><br>${escapeHtml(message)}`;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }

  function openSuppressionDialog(fingerprint) {
    const finding = state.findings.find(f => f.fingerprint === fingerprint);
    if (!finding) return;
    $("suppressFingerprint").value = fingerprint;
    $("suppressFindingTitle").textContent = `${finding.severity.toUpperCase()} · ${finding.title} · ${finding.file}${finding.line ? `:${finding.line}` : ""}`;
    const existing = suppressionRecord(finding);
    $("suppressReason").value = existing?.reason || "";
    $("suppressExpiry").min = addDaysIso(1);
    $("suppressExpiry").value = existing?.expiresAt && existing.expiresAt >= todayIso() ? existing.expiresAt : addDaysIso(30);
    $("suppressDialog").showModal();
  }

  function saveSuppressionFromDialog(event) {
    event.preventDefault();
    const fingerprint = $("suppressFingerprint").value;
    const finding = state.findings.find(f => f.fingerprint === fingerprint);
    if (!finding) return;
    const reason = $("suppressReason").value.trim();
    const expiresAt = $("suppressExpiry").value;
    if (reason.length < 5 || !expiresAt || expiresAt <= todayIso()) {
      alert("Provide a meaningful justification and a future expiration date.");
      return;
    }
    const record = {
      fingerprint,
      reason,
      expiresAt,
      createdAt: new Date().toISOString(),
      rule: finding.rule,
      title: finding.title,
      file: finding.file,
      severity: finding.severity
    };
    state.suppressions = state.suppressions.filter(s => s.fingerprint !== fingerprint);
    state.suppressions.push(record);
    const persisted = saveSuppressions();
    recomputeScore();
    $("suppressDialog").close();
    renderResults(false);
    showToast(persisted ? "Suppression saved" : "Suppression saved for this session", persisted
      ? `Excluded until ${expiresAt}. The justification remains in the exception register.`
      : `Browser storage is unavailable, so this exception will not survive a reload. It is excluded until ${expiresAt} for this session.`);
  }

  function restoreFinding(fingerprint) {
    state.suppressions = state.suppressions.filter(s => s.fingerprint !== fingerprint);
    saveSuppressions();
    recomputeScore();
    renderResults(false);
    renderSuppressionManager();
    showToast("Finding restored", "The finding is active again and included in the score.");
  }

  function renderSuppressionManager() {
    const box = $("suppressionList");
    if (!box) return;
    const today = todayIso();
    const rows = [...state.suppressions].sort((a,b) => a.expiresAt.localeCompare(b.expiresAt));
    if (!rows.length) {
      box.innerHTML = '<div class="results-empty"><strong>No suppressions yet</strong><p>Suppress a finding from the results list to create an auditable exception.</p></div>';
      return;
    }
    box.innerHTML = rows.map(s => {
      const expired = s.expiresAt < today;
      return `<div class="suppression-row ${expired ? "expired" : ""}">
        <div class="suppression-row-head"><strong>${escapeHtml(s.title)}</strong><small>${expired ? "Expired" : "Active until"} ${escapeHtml(s.expiresAt)}</small></div>
        <small>${escapeHtml(s.severity.toUpperCase())} · ${escapeHtml(s.file)} · ${escapeHtml(s.rule)}</small>
        <p class="suppression-reason"><b>Reason:</b> ${escapeHtml(s.reason)}</p>
        <div class="suppression-actions"><button class="restore-btn" type="button" data-delete-suppression="${escapeHtml(s.fingerprint)}">${expired ? "Delete record" : "Restore finding"}</button></div>
      </div>`;
    }).join("");
  }

  function openSuppressionManager() {
    renderSuppressionManager();
    $("suppressionsDialog").showModal();
  }

  function runFirstMinuteDemo() {
    clearAll();
    const demoWorkflow = `name: PR Review
on:
  pull_request_target:
    types: [opened, synchronize]
permissions: write-all
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci`;
    const demoDocker = `FROM node:20.11.1
WORKDIR /app
COPY . .
USER node
CMD ["node", "src/app.js"]`;
    const demoPackage = `{
  "name": "pipelineguard-demo",
  "version": "1.0.0",
  "packageManager": "npm@10.5.0",
  "dependencies": { "express": "4.18.2" }
}`;
    const demoSource = `const API_KEY = "demoCredential123456";\nconsole.log("PipelineGuard demo");`;
    const demoReadme = `# PipelineGuard 60-second demo\nThis intentionally risky repository demonstrates CI trust boundaries, secret detection, suppression workflow, and dependency hygiene.`;
    const demo = [
      {name:".github/workflows/review.yml", text:demoWorkflow},
      {name:"Dockerfile", text:demoDocker},
      {name:"package.json", text:demoPackage},
      {name:"src/app.js", text:demoSource},
      {name:"README.md", text:demoReadme}
    ];
    state.files = demo.map(f => ({
      id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()),
      name: f.name,
      text: f.text,
      size: new Blob([f.text]).size,
      type: classify(f.name, f.text),
      repositoryFile: true
    }));
    state.repository = {
      name:"PipelineGuard-60-second-demo.zip", totalEntries:6, scannedFiles:5, ignoredFiles:1,
      selectedBytes:state.files.reduce((n,f)=>n+f.size,0), encrypted:0, unsupported:0, oversized:0,
      categories:{"CI/CD":1,"Docker":1,"Dependencies":1,"Source":1,"Config":1},
      sensitiveNames:[]
    };
    renderRepository();
    renderFiles();
    runScan();
    storageSet("pipelineguardQuickstartSeen", "1");
    showToast("Demo complete", "A focused risky repository was scanned locally. Review the compound CI/credential risk, suppress a finding if appropriate, then export the report.");
    setTimeout(() => document.querySelector(".score-card")?.scrollIntoView({behavior:"smooth", block:"start"}), 120);
  }

  const SECRET_RULES = [
    {
      id: "secret-private-key",
      title: "Private key material detected",
      severity: "critical",
      regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
      description: "A private-key header appears in this file. Committing private key material can expose systems that trust the key.",
      remediation: "Remove the key from source control, rotate/revoke it if it may have been exposed, and provide it at runtime from an approved secret store."
    },
    {
      id: "secret-aws-key",
      title: "Possible AWS access key ID",
      severity: "critical",
      regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
      description: "Text matches a common AWS access-key identifier format.",
      remediation: "Remove the credential, rotate it if real, and use your CI/CD platform's secret storage or short-lived identity federation."
    },
    {
      id: "secret-github-token",
      title: "Possible GitHub token",
      severity: "critical",
      regex: /\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{40,255})\b/g,
      description: "Text resembles a GitHub authentication token.",
      remediation: "Remove and revoke/rotate the token if valid. Reference a repository, environment, or organization secret instead of embedding it."
    },
    {
      id: "secret-jwt",
      title: "Possible hardcoded JWT",
      severity: "high",
      regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
      description: "A three-part token resembles a JSON Web Token and may contain reusable credentials or sensitive claims.",
      remediation: "Avoid storing live bearer tokens in source. Inject short-lived tokens at runtime and rotate this token if it is active."
    },
    {
      id: "secret-generic-assignment",
      title: "Suspicious hardcoded secret assignment",
      severity: "high",
      regex: /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']?(?!\$\{\{|\$\(|\$[A-Za-z_]|<|changeme|example|sample|dummy|placeholder|your[_-])([A-Za-z0-9_+\/.=:@\-]{8,})["']?/gi,
      description: "A secret-like variable appears to be assigned a literal value.",
      remediation: "Replace the literal with a secret-store reference or runtime environment value. Rotate the value if it is a real credential."
    }
  ];

  const riskyWorkflow = `name: Build and Deploy
on:
  pull_request_target:
    types: [opened, synchronize]

permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - name: Build PR
        run: echo "\${{ github.event.pull_request.title }}" | bash
      - uses: acme/example-action@main
      - name: Deploy
        env:
          API_KEY: "supersecret123456"
        run: curl -s https://example.invalid/install.sh | bash`;

  const riskyDocker = `FROM node:latest
ARG API_TOKEN="dockerBuildSecret123"
ENV ADMIN_PASSWORD=hardcodedPassword123
WORKDIR /app
ADD https://example.invalid/helper.sh /usr/local/bin/helper.sh
COPY . .
RUN curl -fsSL https://example.invalid/install.sh | bash
EXPOSE 22
CMD ["node", "server.js"]`;


  const riskyKubernetes = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: risky-api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: risky-api
  template:
    metadata:
      labels:
        app: risky-api
    spec:
      hostNetwork: true
      hostPID: true
      automountServiceAccountToken: true
      containers:
        - name: api
          image: example/risky-api:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            runAsUser: 0
            readOnlyRootFilesystem: false
            seccompProfile:
              type: Unconfined
            capabilities:
              add:
                - SYS_ADMIN
          ports:
            - containerPort: 8080
              hostPort: 8080
          volumeMounts:
            - name: host-root
              mountPath: /host
      volumes:
        - name: host-root
          hostPath:
            path: /
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
type: Opaque
data:
  password: c3VwZXJzZWNyZXQ=`;

  const riskyTerraform = `resource "aws_security_group" "admin" {
  name = "admin-anywhere"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "prod" {
  identifier          = "prod-db"
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_iam_policy" "adminish" {
  name = "adminish"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_instance" "legacy" {
  ami                         = "ami-1234567890abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = true

  metadata_options {
    http_tokens = "optional"
  }
}`;


  const riskyNpm = `{
  "name": "risky-web-app",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "curl -fsSL http://downloads.example.invalid/bootstrap.sh | bash",
    "postinstall": "node scripts/postinstall.js"
  },
  "dependencies": {
    "express": "latest",
    "legacy-widget": "*",
    "internal-client": "git+http://git.example.invalid/internal/client.git#main",
    "local-helper": "file:../local-helper"
  },
  "devDependencies": {
    "build-helper": "github:example/build-helper#main"
  }
}`;

  const riskyPython = `--index-url http://packages.example.invalid/simple
--trusted-host packages.example.invalid
--extra-index-url https://pypi.org/simple
requests>=2.0
flask
git+http://git.example.invalid/team/internal-lib.git@main#egg=internal-lib
example-lib @ http://downloads.example.invalid/example-lib-1.0.tar.gz
Django==5.0.1`;

  function bytesLabel(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;" }[c]));
  }

  function redact(text) {
    if (!text) return "";
    if (text.length <= 12) return text.slice(0, 3) + "••••";
    return text.slice(0, 6) + "••••••" + text.slice(-4);
  }

  function classify(name, text) {
    const n = name.toLowerCase();
    const base = n.split(/[\\/]/).pop();

    if (base === "dockerfile" || n.endsWith(".dockerfile") || /^\s*from\s+\S+/mi.test(text)) return "docker";
    if (n.endsWith(".tf") || n.endsWith(".tfvars") || n.endsWith(".hcl") ||
        /^\s*(?:resource|provider|module|terraform)\s+"?/mi.test(text)) return "terraform";

    if (base === "package.json") return "npm";
    if (["package-lock.json", "npm-shrinkwrap.json"].includes(base)) return "npm-lock";
    if (["yarn.lock", "pnpm-lock.yaml", "pnpm-lock.yml"].includes(base)) return "js-lock";

    if (/^requirements(?:[-_.].*)?\.txt$/i.test(base)) return "python-requirements";
    if (base === "pyproject.toml") return "pyproject";
    if (["poetry.lock", "pipfile.lock", "uv.lock", "pdm.lock"].includes(base)) return "python-lock";
    if (base === "pipfile") return "pipfile";

    if (base === "nuget.config") return "nuget-config";
    if (base === "packages.config" || /\.(?:csproj|fsproj|vbproj|props)$/i.test(base)) return "nuget";

    if (base === "pom.xml") return "maven";
    if (/^(?:build|settings)\.gradle(?:\.kts)?$/i.test(base) || base === "gradle.properties") return "gradle";

    if (base === "composer.json") return "composer";
    if (base === "gemfile") return "ruby";
    if (base === "go.mod") return "gomod";

    if (n.endsWith(".yml") || n.endsWith(".yaml")) {
      if (/(?:^|\n)\s*(?:name|on|jobs|permissions)\s*:/m.test(text) && /(?:^|\n)\s*(?:jobs|steps|uses|runs-on)\s*:/m.test(text)) return "github";
      if (/(?:^|\n)\s*apiVersion\s*:/m.test(text) && /(?:^|\n)\s*kind\s*:/m.test(text)) return "kubernetes";
      return "yaml";
    }
    return "text";
  }

  const REPO_LIMITS = {
    maxZipBytes: 25 * 1024 * 1024,
    maxEntries: 1500,
    maxFileBytes: 1024 * 1024,
    maxTextBytes: 8 * 1024 * 1024
  };

  const REPO_SKIP_DIRS = new Set([
    ".git","node_modules","vendor","dist","build","out","target","coverage",".next",".nuxt",
    ".cache",".parcel-cache",".venv","venv","env","__pycache__","bin","obj","packages",".idea"
  ]);

  const REPO_TEXT_EXTENSIONS = new Set([
    "txt","md","rst","yml","yaml","json","xml","toml","ini","conf","cfg","properties","env",
    "tf","tfvars","hcl","js","mjs","cjs","jsx","ts","tsx","py","cs","fs","vb","java","kt","kts",
    "go","php","rb","rs","c","h","cpp","hpp","cc","sh","bash","zsh","ps1","psm1","cmd","bat",
    "sql","graphql","gql","gradle","props","csproj","fsproj","vbproj","lock","mod","sum","pem","key"
  ]);

  const REPO_SPECIAL_FILES = new Set([
    "dockerfile","containerfile","makefile","gemfile","rakefile","pipfile","procfile",
    "package.json","package-lock.json","npm-shrinkwrap.json","yarn.lock","pnpm-lock.yaml",
    "pnpm-lock.yml","requirements.txt","pyproject.toml","poetry.lock","pipfile.lock","uv.lock",
    "pdm.lock","nuget.config","packages.config","pom.xml","composer.json","composer.lock",
    "go.mod","go.sum",".npmrc",".pypirc",".env",".gitignore",".dockerignore"
  ]);

  function normalizeZipPath(path) {
    const raw = String(path || "").replace(/\\/g, "/").replace(/^\/+/, "");
    const parts = [];
    for (const part of raw.split("/")) {
      if (!part || part === ".") continue;
      if (part === "..") return null;
      parts.push(part);
    }
    return parts.join("/");
  }

  function shouldSkipRepositoryPath(path) {
    const lower = path.toLowerCase();
    const parts = lower.split("/");
    if (parts.some(p => REPO_SKIP_DIRS.has(p))) return true;
    if (lower.endsWith(".min.js") || lower.endsWith(".min.css") || lower.endsWith(".map")) return true;
    if (lower.includes("/.terraform/") || lower.includes("/.gradle/")) return true;
    return false;
  }

  function repositoryFileIsText(path) {
    const lower = path.toLowerCase();
    const base = lower.split("/").pop();
    if (REPO_SPECIAL_FILES.has(base)) return true;
    if (/^requirements(?:[-_.].*)?\.txt$/i.test(base)) return true;
    if (/^(?:build|settings)\.gradle(?:\.kts)?$/i.test(base)) return true;
    if (/^\.env(?:\..+)?$/i.test(base)) return true;
    const dot = base.lastIndexOf(".");
    const ext = dot >= 0 ? base.slice(dot + 1) : "";
    return REPO_TEXT_EXTENSIONS.has(ext);
  }

  function repositoryCategory(path, type) {
    const lower = path.toLowerCase();
    if (lower.includes("/.github/workflows/") || type === "github") return "CI/CD";
    if (type === "docker") return "Docker";
    if (type === "kubernetes") return "Kubernetes";
    if (type === "terraform") return "Terraform";
    if (["npm","npm-lock","js-lock","python-requirements","pyproject","python-lock","pipfile",
         "nuget","nuget-config","maven","gradle","composer","ruby","gomod"].includes(type)) return "Dependencies";
    if (/\.(?:js|mjs|cjs|jsx|ts|tsx|py|cs|fs|vb|java|kt|go|php|rb|rs|c|cpp|cc|h|hpp)$/i.test(lower)) return "Source";
    return "Config";
  }

  async function inflateRawBytes(bytes) {
    if (typeof DecompressionStream !== "function") {
      throw new Error("This browser does not provide the DecompressionStream API required for local ZIP extraction.");
    }
    const ds = new DecompressionStream("deflate-raw");
    const stream = new Blob([bytes]).stream().pipeThrough(ds);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  async function parseRepositoryZip(file) {
    if (file.size > REPO_LIMITS.maxZipBytes) {
      throw new Error(`Repository ZIP exceeds the ${Math.round(REPO_LIMITS.maxZipBytes / 1024 / 1024)} MB v0.6.1 limit.`);
    }

    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const view = new DataView(buffer);

    let eocd = -1;
    const min = Math.max(0, bytes.length - 65557);
    for (let i = bytes.length - 22; i >= min; i--) {
      if (view.getUint32(i, true) === 0x06054b50) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) throw new Error("Not a supported ZIP archive: end-of-central-directory record not found.");

    const entryCount = view.getUint16(eocd + 10, true);
    const cdSize = view.getUint32(eocd + 12, true);
    const cdOffset = view.getUint32(eocd + 16, true);
    if (entryCount === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      throw new Error("ZIP64 repositories are not supported in v0.6.1.");
    }
    if (entryCount > REPO_LIMITS.maxEntries) {
      throw new Error(`Repository contains ${entryCount} ZIP entries; v0.6.1 allows ${REPO_LIMITS.maxEntries}.`);
    }
    if (cdOffset + cdSize > bytes.length) throw new Error("ZIP central directory is outside the archive.");

    const decoder = new TextDecoder("utf-8", { fatal: false });
    const entries = [];
    let pos = cdOffset;

    for (let n = 0; n < entryCount; n++) {
      if (pos + 46 > bytes.length || view.getUint32(pos, true) !== 0x02014b50) {
        throw new Error("ZIP central directory is malformed.");
      }
      const flags = view.getUint16(pos + 8, true);
      const method = view.getUint16(pos + 10, true);
      const compressedSize = view.getUint32(pos + 20, true);
      const uncompressedSize = view.getUint32(pos + 24, true);
      const nameLen = view.getUint16(pos + 28, true);
      const extraLen = view.getUint16(pos + 30, true);
      const commentLen = view.getUint16(pos + 32, true);
      const localOffset = view.getUint32(pos + 42, true);
      const nameBytes = bytes.slice(pos + 46, pos + 46 + nameLen);
      const originalName = decoder.decode(nameBytes);
      const name = normalizeZipPath(originalName);

      if (name) {
        entries.push({ name, flags, method, compressedSize, uncompressedSize, localOffset });
      }
      pos += 46 + nameLen + extraLen + commentLen;
    }

    state.files = [];
    let selectedBytes = 0;
    let ignored = 0;
    let encrypted = 0;
    let unsupported = 0;
    let oversized = 0;
    const categories = {};
    const sensitiveNames = [];

    for (const entry of entries) {
      if (!entry.name || entry.name.endsWith("/")) {
        ignored++;
        continue;
      }
      if (shouldSkipRepositoryPath(entry.name) || !repositoryFileIsText(entry.name)) {
        ignored++;
        continue;
      }
      if (entry.flags & 1) {
        encrypted++;
        ignored++;
        continue;
      }
      if (![0, 8].includes(entry.method)) {
        unsupported++;
        ignored++;
        continue;
      }
      if (entry.uncompressedSize > REPO_LIMITS.maxFileBytes) {
        oversized++;
        ignored++;
        continue;
      }
      if (selectedBytes + entry.uncompressedSize > REPO_LIMITS.maxTextBytes) {
        ignored++;
        continue;
      }
      if (entry.localOffset + 30 > bytes.length || view.getUint32(entry.localOffset, true) !== 0x04034b50) {
        ignored++;
        continue;
      }

      const localNameLen = view.getUint16(entry.localOffset + 26, true);
      const localExtraLen = view.getUint16(entry.localOffset + 28, true);
      const dataStart = entry.localOffset + 30 + localNameLen + localExtraLen;
      const dataEnd = dataStart + entry.compressedSize;
      if (dataEnd > bytes.length) {
        ignored++;
        continue;
      }

      let contentBytes;
      try {
        const compressed = bytes.slice(dataStart, dataEnd);
        contentBytes = entry.method === 0 ? compressed : await inflateRawBytes(compressed);
      } catch {
        unsupported++;
        ignored++;
        continue;
      }

      if (contentBytes.length > REPO_LIMITS.maxFileBytes) {
        oversized++;
        ignored++;
        continue;
      }

      // Avoid treating obvious binary content as text even when the filename extension is text-like.
      const probe = contentBytes.slice(0, Math.min(contentBytes.length, 4096));
      let nulCount = 0;
      for (const b of probe) if (b === 0) nulCount++;
      if (nulCount > 0) {
        ignored++;
        continue;
      }

      const text = decoder.decode(contentBytes);
      const normalized = {
        id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()),
        name: entry.name,
        text,
        size: contentBytes.length,
        type: classify(entry.name, text),
        repositoryFile: true
      };
      state.files.push(normalized);
      selectedBytes += contentBytes.length;
      const cat = repositoryCategory(entry.name, normalized.type);
      categories[cat] = (categories[cat] || 0) + 1;

      const baseName = entry.name.toLowerCase().split("/").pop();
      if (/^\.env(?:\..+)?$/.test(baseName) ||
          /^(?:id_rsa|id_ed25519|id_ecdsa)$/.test(baseName) ||
          /\.(?:pem|key|p12|pfx)$/.test(baseName) ||
          /^(?:credentials|credentials\.json|service-account[^/]*\.json)$/.test(baseName)) {
        sensitiveNames.push(entry.name);
      }
    }

    state.repository = {
      name: file.name,
      totalEntries: entries.length,
      scannedFiles: state.files.length,
      ignoredFiles: ignored,
      selectedBytes,
      encrypted,
      unsupported,
      oversized,
      categories,
      sensitiveNames
    };
    renderRepository();
    renderFiles();
  }

  function renderRepository() {
    const card = $("repoCard");
    if (!state.repository) {
      card.hidden = true;
      return;
    }
    const r = state.repository;
    card.hidden = false;
    $("repoName").textContent = r.name;
    $("repoEntries").textContent = r.totalEntries;
    $("repoScanned").textContent = r.scannedFiles;
    $("repoIgnored").textContent = r.ignoredFiles;
    $("repoSize").textContent = bytesLabel(r.selectedBytes);
    const kinds = Object.entries(r.categories)
      .sort((a,b) => b[1] - a[1])
      .map(([name,count]) => `<span>${escapeHtml(name)} ${count}</span>`);
    if (r.encrypted) kinds.push(`<span>Encrypted skipped ${r.encrypted}</span>`);
    if (r.oversized) kinds.push(`<span>Oversized skipped ${r.oversized}</span>`);
    $("repoKinds").innerHTML = kinds.join("");
  }

  async function addBrowserFiles(fileObjects) {
    const zips = fileObjects.filter(f => /\.zip$/i.test(f.name));
    const normal = fileObjects.filter(f => !/\.zip$/i.test(f.name));

    if (zips.length) {
      if (zips.length > 1) {
        alert("PipelineGuard v0.6.1 audits one repository ZIP at a time. The first ZIP will be used.");
      }
      try {
        await parseRepositoryZip(zips[0]);
      } catch (err) {
        alert(`Repository ZIP audit could not start: ${err.message}`);
      }
    }

    for (const file of normal) {
      if (file.size > 1024 * 1024) {
        alert(`${file.name} is larger than 1 MB. PipelineGuard v0.6.1 skips oversized individual files.`);
        continue;
      }
      const text = await file.text();
      upsertFile({ name: file.name || "unnamed.txt", text, size: file.size });
    }
    renderFiles();
  }

  function upsertFile(file) {
    const existing = state.files.findIndex(f => f.name === file.name);
    const normalized = {
      id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()),
      name: file.name,
      text: file.text,
      size: file.size ?? new Blob([file.text]).size,
      type: classify(file.name, file.text)
    };
    if (existing >= 0) state.files.splice(existing, 1, normalized);
    else state.files.push(normalized);
  }

  function renderFiles() {
    $("fileCount").textContent = state.files.length;
    scanBtn.disabled = state.files.length === 0;
    if (!state.files.length) {
      fileList.innerHTML = '<p class="empty-state">No files added yet.</p>';
      return;
    }
    fileList.innerHTML = state.files.map((f, idx) => `
      <div class="file-item">
        <div class="file-icon">${f.type === "docker" ? "DK" : f.type === "github" ? "CI" : f.type === "kubernetes" ? "K8" : f.type === "terraform" ? "TF" : f.type === "npm" || f.type === "npm-lock" || f.type === "js-lock" ? "JS" : f.type.startsWith("python") || f.type === "pyproject" || f.type === "pipfile" ? "PY" : f.type.startsWith("nuget") ? "NU" : f.type === "maven" ? "MV" : f.type === "gradle" ? "GR" : f.type === "composer" ? "PH" : f.type === "ruby" ? "RB" : f.type === "gomod" ? "GO" : "TXT"}</div>
        <div class="file-meta">
          <strong title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</strong>
          <small>${escapeHtml(f.type.toUpperCase())} · ${bytesLabel(f.size)}</small>
        </div>
        <button class="remove-file" type="button" data-remove="${idx}" aria-label="Remove ${escapeHtml(f.name)}">×</button>
      </div>`).join("");
    fileList.querySelectorAll("[data-remove]").forEach(btn => {
      btn.addEventListener("click", () => {
        state.files.splice(Number(btn.dataset.remove), 1);
        renderFiles();
      });
    });
  }

  function lineNumberAt(text, offset) {
    return text.slice(0, offset).split("\n").length;
  }

  function lineAt(text, lineNo) {
    return text.split(/\r?\n/)[lineNo - 1] || "";
  }

  function addFinding(findings, file, finding) {
    const key = `${file.name}|${finding.rule}|${finding.line || 0}|${finding.title}`;
    if (findings.some(f => f.key === key)) return;
    const fingerprint = `pg-${fnv1a(findingFingerprintParts(file, finding))}`;
    findings.push({
      key,
      fingerprint,
      file: file.name,
      fileType: file.type,
      severity: finding.severity,
      rule: finding.rule,
      title: finding.title,
      description: finding.description,
      remediation: finding.remediation,
      line: finding.line || null,
      evidence: finding.evidence || "",
      category: finding.category || "General"
    });
  }

  function scanSecrets(file, findings) {
    for (const rule of SECRET_RULES) {
      const regex = new RegExp(rule.regex.source, rule.regex.flags);
      let match;
      while ((match = regex.exec(file.text)) !== null) {
        const line = lineNumberAt(file.text, match.index);
        const originalLine = lineAt(file.text, line).trim();
        let evidence = originalLine;
        if (rule.id !== "secret-private-key") {
          const token = match[1] || match[0];
          evidence = originalLine.replace(token, redact(token));
        }
        addFinding(findings, file, {
          severity: rule.severity, rule: rule.id, title: rule.title,
          description: rule.description, remediation: rule.remediation,
          line, evidence, category: "Secrets"
        });
        if (regex.lastIndex === match.index) regex.lastIndex++;
      }
    }
  }

  function scanGitHub(file, findings) {
    const lines = file.text.split(/\r?\n/);

    // Actions not pinned to an immutable 40-character SHA.
    lines.forEach((line, i) => {
      const m = line.match(/^\s*-\s*uses:\s*([^\s#]+)/i);
      if (!m) return;
      const ref = m[1];
      if (ref.startsWith("./") || ref.startsWith("docker://")) return;
      const at = ref.lastIndexOf("@");
      if (at < 0 || !/^[a-f0-9]{40}$/i.test(ref.slice(at + 1))) {
        addFinding(findings, file, {
          severity: "medium", rule: "gha-unpinned-action",
          title: "Action is not pinned to a full commit SHA",
          description: "This third-party action is referenced by a mutable tag, branch, abbreviated hash, or no explicit immutable ref.",
          remediation: "Pin the action to a verified full 40-character commit SHA. Keep the human-readable release tag in a comment for maintainability.",
          line: i + 1, evidence: line.trim(), category: "CI/CD"
        });
      }
    });

    const hasPermissions = /(?:^|\n)\s*permissions\s*:/m.test(file.text);
    if (!hasPermissions) {
      addFinding(findings, file, {
        severity: "low", rule: "gha-missing-permissions",
        title: "No explicit GITHUB_TOKEN permissions block",
        description: "The workflow does not visibly declare a top-level permissions policy, making least-privilege intent harder to verify from this file alone.",
        remediation: "Declare the minimum required permissions at workflow or job scope, such as `permissions: { contents: read }`, then grant write permissions only where needed.",
        evidence: "No top-level `permissions:` declaration detected.", category: "CI/CD"
      });
    }

    lines.forEach((line, i) => {
      if (/^\s*permissions:\s*write-all\s*(?:#.*)?$/i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "gha-write-all",
          title: "GITHUB_TOKEN permissions set to write-all",
          description: "The workflow grants broad write access to the workflow token.",
          remediation: "Replace `write-all` with an explicit least-privilege permissions map and scope elevated permissions to the specific job that requires them.",
          line: i + 1, evidence: line.trim(), category: "CI/CD"
        });
      }
    });

    const prTarget = /(?:^|\n)\s*pull_request_target\s*:/m.test(file.text);
    if (prTarget) {
      addFinding(findings, file, {
        severity: "high", rule: "gha-pr-target",
        title: "pull_request_target requires careful trust boundaries",
        description: "This trigger runs in the context of the base repository and can have access to repository secrets or write-capable tokens. Executing untrusted pull-request code can be dangerous.",
        remediation: "Avoid executing or checking out untrusted PR code in `pull_request_target`. Prefer `pull_request` for untrusted builds, or split privileged follow-up work into a separately trusted workflow.",
        evidence: "Trigger: pull_request_target", category: "CI/CD"
      });
    }

    if (prTarget && /actions\/checkout[^]*?ref:\s*\$\{\{\s*github\.event\.pull_request\.(?:head\.sha|head\.ref)/i.test(file.text)) {
      addFinding(findings, file, {
        severity: "critical", rule: "gha-pr-target-checkout",
        title: "Untrusted PR code checked out under pull_request_target",
        description: "The workflow combines a privileged trigger with checkout of pull-request-controlled code, which can expose privileged workflow context to attacker-controlled content.",
        remediation: "Do not check out untrusted PR head code in a privileged `pull_request_target` job. Use an unprivileged `pull_request` workflow for build/test execution.",
        evidence: "pull_request_target + checkout of github.event.pull_request.head.*", category: "CI/CD"
      });
    }

    lines.forEach((line, i) => {
      if (/^\s*run\s*:.*\$\{\{\s*github\.event\.pull_request\.(?:title|body|head\.ref)/i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "gha-untrusted-run",
          title: "Untrusted pull-request data interpolated into shell",
          description: "Pull-request metadata can be attacker-controlled. Direct expression interpolation inside a shell command can create command-injection risk.",
          remediation: "Assign the expression to an environment variable and treat it as data, quoting it appropriately in the shell. Avoid evaluating it as code.",
          line: i + 1, evidence: line.trim(), category: "CI/CD"
        });
      }
      if (/\b(?:curl|wget)\b[^|;\n]*\|\s*(?:sudo\s+)?(?:bash|sh)\b/i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "shell-pipe-exec",
          title: "Remote content piped directly to a shell",
          description: "The workflow downloads content and immediately executes it, reducing opportunities to verify integrity or inspect what will run.",
          remediation: "Download the artifact separately, verify its expected version and checksum/signature, then execute a reviewed local file.",
          line: i + 1, evidence: line.trim(), category: "Supply Chain"
        });
      }
    });

    if (/\b(?:id-token|contents|packages|issues|pull-requests|actions|checks|deployments)\s*:\s*write\b/i.test(file.text)) {
      const line = lines.findIndex(l => /\b(?:id-token|contents|packages|issues|pull-requests|actions|checks|deployments)\s*:\s*write\b/i.test(l)) + 1;
      addFinding(findings, file, {
        severity: "info", rule: "gha-write-permission-review",
        title: "Workflow requests write-capable token permissions",
        description: "At least one explicit write permission is present. It may be legitimate, but deserves review because write access increases impact if the job is compromised.",
        remediation: "Confirm each write permission is required and scope it to the narrowest job possible. Use read permissions elsewhere.",
        line, evidence: lineAt(file.text, line).trim(), category: "CI/CD"
      });
    }
  }

  function scanDocker(file, findings) {
    const lines = file.text.split(/\r?\n/);
    const fromLines = lines.map((l, i) => ({l, i})).filter(x => /^\s*FROM\s+/i.test(x.l));
    fromLines.forEach(({l, i}) => {
      const m = l.match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i);
      if (!m) return;
      const image = m[1];
      if (/:latest(?:@|$)/i.test(image) || (!image.includes(":") && !image.includes("@sha256:"))) {
        addFinding(findings, file, {
          severity: "medium", rule: "docker-floating-base",
          title: "Base image uses a floating/default tag",
          description: "A mutable base-image reference can resolve to different content over time, reducing build reproducibility.",
          remediation: "Use an intentional version tag and, for stronger reproducibility, pin the trusted image digest. Keep dependency update automation in place.",
          line: i + 1, evidence: l.trim(), category: "Container"
        });
      }
    });

    const userLines = lines.map((l, i) => ({l, i})).filter(x => /^\s*USER\s+/i.test(x.l));
    if (!userLines.length) {
      addFinding(findings, file, {
        severity: "medium", rule: "docker-no-user",
        title: "No non-root USER instruction detected",
        description: "Without an explicit USER instruction, the final container commonly runs with the image's default user, which is often root.",
        remediation: "Create or use a dedicated unprivileged account and set `USER` before the runtime `CMD` or `ENTRYPOINT`, where application requirements allow.",
        evidence: "No USER instruction detected.", category: "Container"
      });
    } else {
      const last = userLines[userLines.length - 1];
      if (/^\s*USER\s+(?:0|root)(?::\S+)?\s*(?:#.*)?$/i.test(last.l)) {
        addFinding(findings, file, {
          severity: "high", rule: "docker-root-user",
          title: "Final container user is root",
          description: "The final USER instruction explicitly selects root.",
          remediation: "Run the application as a dedicated unprivileged user unless root is strictly required, and document any unavoidable exception.",
          line: last.i + 1, evidence: last.l.trim(), category: "Container"
        });
      }
    }

    lines.forEach((line, i) => {
      if (/^\s*(?:ARG|ENV)\s+[^#\n]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)/i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "docker-secret-arg-env",
          title: "Secret-like value passed with ARG or ENV",
          description: "Docker build arguments and environment variables are not appropriate for persistent build secrets and can leak through image metadata or layers.",
          remediation: "Use BuildKit secret mounts or another ephemeral secret mechanism instead of ARG/ENV for sensitive values.",
          line: i + 1, evidence: redactDockerEvidence(line.trim()), category: "Container"
        });
      }
      if (/^\s*ADD\s+https?:\/\//i.test(line)) {
        addFinding(findings, file, {
          severity: "medium", rule: "docker-remote-add",
          title: "Remote URL used in ADD",
          description: "A remote resource is introduced during the image build without an obvious integrity check in this instruction.",
          remediation: "Prefer a controlled download step with explicit versioning and checksum/signature verification, or copy a trusted build-context artifact.",
          line: i + 1, evidence: line.trim(), category: "Supply Chain"
        });
      }
      if (/\b(?:curl|wget)\b[^|;\n]*\|\s*(?:sudo\s+)?(?:bash|sh)\b/i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "shell-pipe-exec",
          title: "Remote content piped directly to a shell",
          description: "The build downloads content and immediately executes it without an explicit integrity verification step.",
          remediation: "Download to a file, pin the expected version, verify checksum/signature, then run the verified artifact.",
          line: i + 1, evidence: line.trim(), category: "Supply Chain"
        });
      }
      if (/^\s*EXPOSE\s+.*\b22(?:\/tcp)?\b/i.test(line)) {
        addFinding(findings, file, {
          severity: "low", rule: "docker-expose-ssh",
          title: "SSH port exposed by image",
          description: "Port 22 is declared in the container image. Application containers usually do not need an SSH daemon.",
          remediation: "Confirm SSH is truly required. Prefer container exec/management mechanisms and remove the SSH service and EXPOSE instruction when unnecessary.",
          line: i + 1, evidence: line.trim(), category: "Container"
        });
      }
    });
  }

  function redactDockerEvidence(line) {
    return line.replace(/([=:]\s*["']?)([^"'\s]{5,})/g, (_, p, v) => p + redact(v));
  }

  function scanKubernetes(file, findings) {
    const lines = file.text.split(/\r?\n/);
    const workload = /(?:^|\n)\s*kind\s*:\s*(?:Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob)\s*(?:#.*)?$/mi.test(file.text);
    const hasContainers = /(?:^|\n)\s*(?:containers|initContainers)\s*:/m.test(file.text);

    lines.forEach((line, i) => {
      const evidence = line.trim();

      if (/^\s*privileged\s*:\s*true\b/i.test(line)) {
        addFinding(findings, file, {
          severity: "critical", rule: "k8s-privileged",
          title: "Privileged container enabled",
          description: "Privileged containers receive broad host-level capabilities and are disallowed by Kubernetes Baseline/Restricted pod security profiles.",
          remediation: "Set `privileged: false` and grant only narrowly required capabilities or device access. Treat any exception as a documented high-risk control.",
          line: i + 1, evidence, category: "Kubernetes"
        });
      }

      if (/^\s*allowPrivilegeEscalation\s*:\s*true\b/i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "k8s-privilege-escalation",
          title: "Privilege escalation is explicitly allowed",
          description: "The container permits a process to gain more privileges than its parent process.",
          remediation: "Set `allowPrivilegeEscalation: false` unless a narrowly justified workload requires escalation.",
          line: i + 1, evidence, category: "Kubernetes"
        });
      }

      if (/^\s*hostPID\s*:\s*true\b/i.test(line) || /^\s*hostIPC\s*:\s*true\b/i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "k8s-host-process-namespace",
          title: "Pod shares a host process namespace",
          description: "Sharing host PID or IPC namespaces reduces isolation between the pod and the node.",
          remediation: "Remove `hostPID: true` / `hostIPC: true` unless the workload is a specifically reviewed node-level agent.",
          line: i + 1, evidence, category: "Kubernetes"
        });
      }

      if (/^\s*hostNetwork\s*:\s*true\b/i.test(line)) {
        addFinding(findings, file, {
          severity: "medium", rule: "k8s-host-network",
          title: "Pod uses the host network namespace",
          description: "Host networking reduces network isolation and can expose node-local services or ports to the workload.",
          remediation: "Use the normal pod network unless host networking is required and explicitly threat-modeled.",
          line: i + 1, evidence, category: "Kubernetes"
        });
      }

      if (/^\s*hostPath\s*:/i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "k8s-hostpath",
          title: "hostPath volume accesses the node filesystem",
          description: "hostPath mounts can expose sensitive node files or let a compromised container modify host state.",
          remediation: "Prefer purpose-built volumes. If hostPath is unavoidable, restrict the exact path, use read-only mounts where possible, and isolate the workload.",
          line: i + 1, evidence, category: "Kubernetes"
        });
      }

      if (/^\s*runAsUser\s*:\s*0\b/i.test(line) || /^\s*runAsNonRoot\s*:\s*false\b/i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "k8s-root-user",
          title: "Workload permits or requests root execution",
          description: "The security context explicitly selects UID 0 or disables the non-root requirement.",
          remediation: "Set `runAsNonRoot: true` and configure a non-zero user compatible with the container image.",
          line: i + 1, evidence, category: "Kubernetes"
        });
      }

      if (/^\s*readOnlyRootFilesystem\s*:\s*false\b/i.test(line)) {
        addFinding(findings, file, {
          severity: "low", rule: "k8s-writable-rootfs",
          title: "Writable container root filesystem",
          description: "The container explicitly keeps its root filesystem writable, increasing persistence options after compromise.",
          remediation: "Set `readOnlyRootFilesystem: true` when the application supports it and mount writable paths explicitly.",
          line: i + 1, evidence, category: "Kubernetes"
        });
      }

      if (/^\s*type\s*:\s*Unconfined\b/i.test(line) && lines.slice(Math.max(0, i - 4), i + 1).join("\n").includes("seccompProfile")) {
        addFinding(findings, file, {
          severity: "high", rule: "k8s-seccomp-unconfined",
          title: "Seccomp profile explicitly unconfined",
          description: "An unconfined seccomp profile removes a syscall filtering layer from the container.",
          remediation: "Use `seccompProfile: { type: RuntimeDefault }` or a reviewed Localhost profile.",
          line: i + 1, evidence, category: "Kubernetes"
        });
      }

      if (/^\s*automountServiceAccountToken\s*:\s*true\b/i.test(line)) {
        addFinding(findings, file, {
          severity: "medium", rule: "k8s-service-account-token",
          title: "Service account token explicitly auto-mounted",
          description: "The pod explicitly requests a Kubernetes API credential, which increases impact if the container is compromised.",
          remediation: "Set `automountServiceAccountToken: false` for workloads that do not call the Kubernetes API. Use a dedicated least-privilege service account when API access is needed.",
          line: i + 1, evidence, category: "Kubernetes"
        });
      }

      if (/^\s*hostPort\s*:\s*(\d+)/i.test(line)) {
        addFinding(findings, file, {
          severity: "medium", rule: "k8s-host-port",
          title: "Container binds a host port",
          description: "hostPort couples the workload directly to a node port and reduces scheduling/network isolation.",
          remediation: "Prefer a Kubernetes Service or ingress layer unless direct node-port binding is specifically required.",
          line: i + 1, evidence, category: "Kubernetes"
        });
      }

      if (/^\s*image\s*:\s*["']?[^"'#\s]+:latest\b/i.test(line) || /^\s*image\s*:\s*["']?[^"'#\s]+["']?\s*(?:#.*)?$/i.test(line) && !/@sha256:/i.test(line) && !/:[A-Za-z0-9_.-]+/i.test(line.replace(/https?:\/\//i, ""))) {
        addFinding(findings, file, {
          severity: "medium", rule: "k8s-floating-image",
          title: "Container image uses a floating/default tag",
          description: "A mutable or implicit image tag can resolve to different content over time and weakens deployment reproducibility.",
          remediation: "Use an intentional version and preferably an immutable image digest for production workloads.",
          line: i + 1, evidence, category: "Supply Chain"
        });
      }

      if (/^\s*add\s*:/i.test(line) && lines.slice(Math.max(0, i - 4), i + 1).join("\n").includes("capabilities")) {
        const capabilityWindow = lines.slice(i, Math.min(lines.length, i + 8)).join("\n");
        if (/\b(?:SYS_ADMIN|SYS_PTRACE|NET_ADMIN|DAC_READ_SEARCH|ALL)\b/i.test(capabilityWindow)) {
          addFinding(findings, file, {
            severity: "high", rule: "k8s-dangerous-capability",
            title: "Dangerous Linux capability added",
            description: "The container adds a powerful Linux capability that materially expands what a compromise can do.",
            remediation: "Drop `ALL` capabilities by default and add back only the specific capability proven necessary.",
            line: i + 1, evidence: capabilityWindow.trim(), category: "Kubernetes"
          });
        }
      }
    });

    if (workload && hasContainers && !/\brunAsNonRoot\s*:\s*true\b/i.test(file.text)) {
      addFinding(findings, file, {
        severity: "low", rule: "k8s-missing-runasnonroot",
        title: "No explicit runAsNonRoot control detected",
        description: "The workload does not visibly require containers to run as non-root.",
        remediation: "Add `runAsNonRoot: true` at pod or container security-context scope where compatible.",
        evidence: "No `runAsNonRoot: true` detected.", category: "Kubernetes"
      });
    }

    if (workload && hasContainers && !/\ballowPrivilegeEscalation\s*:\s*false\b/i.test(file.text)) {
      addFinding(findings, file, {
        severity: "low", rule: "k8s-missing-no-priv-escalation",
        title: "No explicit privilege-escalation denial detected",
        description: "The manifest does not visibly set `allowPrivilegeEscalation: false`.",
        remediation: "Set `allowPrivilegeEscalation: false` on Linux containers unless an exception is required.",
        evidence: "No `allowPrivilegeEscalation: false` detected.", category: "Kubernetes"
      });
    }

    if (workload && hasContainers && !/\bseccompProfile\s*:/i.test(file.text)) {
      addFinding(findings, file, {
        severity: "low", rule: "k8s-missing-seccomp",
        title: "No seccomp profile declared",
        description: "The manifest does not visibly select a seccomp profile for the workload.",
        remediation: "Set `seccompProfile.type: RuntimeDefault` at pod or container scope where supported.",
        evidence: "No `seccompProfile:` detected.", category: "Kubernetes"
      });
    }

    if (workload && hasContainers && !/\bcapabilities\s*:[\s\S]{0,180}\bdrop\s*:[\s\S]{0,100}\bALL\b/i.test(file.text)) {
      addFinding(findings, file, {
        severity: "info", rule: "k8s-capabilities-review",
        title: "No explicit drop ALL capability policy detected",
        description: "The workload does not visibly drop all Linux capabilities before adding back only those required.",
        remediation: "For hardened Linux workloads, consider `capabilities: { drop: [\"ALL\"] }` and add only proven requirements.",
        evidence: "No `capabilities.drop: ALL` pattern detected.", category: "Kubernetes"
      });
    }

    if (workload && hasContainers && !/\bresources\s*:[\s\S]{0,180}\blimits\s*:/i.test(file.text)) {
      addFinding(findings, file, {
        severity: "low", rule: "k8s-missing-limits",
        title: "No container resource limits detected",
        description: "The manifest does not visibly define resource limits, which can increase resource-exhaustion impact.",
        remediation: "Define appropriate CPU and memory requests/limits based on measured workload behavior.",
        evidence: "No `resources.limits` pattern detected.", category: "Kubernetes"
      });
    }

    const kindSecret = lines.findIndex(l => /^\s*kind\s*:\s*Secret\s*(?:#.*)?$/i.test(l));
    if (kindSecret >= 0 && /(?:^|\n)\s*(?:data|stringData)\s*:/m.test(file.text)) {
      addFinding(findings, file, {
        severity: "high", rule: "k8s-secret-manifest",
        title: "Kubernetes Secret material stored in manifest",
        description: "This file contains a Kubernetes Secret resource. Base64-encoded Secret data is encoding, not encryption, and committed manifests can expose credentials.",
        remediation: "Avoid committing live secret values. Use an approved secret manager, external-secret controller, sealed/encrypted secret workflow, or deployment-time injection.",
        line: kindSecret + 1, evidence: lines[kindSecret].trim(), category: "Secrets"
      });
    }
  }

  function stripHclStrings(line) {
    return line
      .replace(/"(?:\\.|[^"\\])*"/g, '""')
      .replace(/#.*$/, "")
      .replace(/\/\/.*$/, "");
  }

  function parseTerraformResourceBlocks(text) {
    const lines = text.split(/\r?\n/);
    const blocks = [];
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/);
      if (!m) continue;
      let depth = 0;
      let end = i;
      for (let j = i; j < lines.length; j++) {
        const clean = stripHclStrings(lines[j]);
        depth += (clean.match(/\{/g) || []).length;
        depth -= (clean.match(/\}/g) || []).length;
        end = j;
        if (depth <= 0 && j > i) break;
      }
      blocks.push({
        type: m[1],
        name: m[2],
        startLine: i + 1,
        endLine: end + 1,
        lines: lines.slice(i, end + 1),
        body: lines.slice(i, end + 1).join("\n")
      });
      i = end;
    }
    return blocks;
  }

  function nearestTfDirection(lines, index) {
    for (let i = index; i >= Math.max(0, index - 16); i--) {
      if (/^\s*ingress\s*\{/i.test(lines[i])) return "ingress";
      if (/^\s*egress\s*\{/i.test(lines[i])) return "egress";
      const type = lines[i].match(/^\s*type\s*=\s*"([^"]+)"/i);
      if (type) return type[1].toLowerCase();
    }
    return "unknown";
  }

  function tfNearbyNumber(lines, index, key) {
    const rx = new RegExp("^\\s*" + key + "\\s*=\\s*(-?\\d+)", "i");
    for (let radius = 0; radius <= 14; radius++) {
      for (const idx of [index - radius, index + radius]) {
        if (idx < 0 || idx >= lines.length) continue;
        const m = lines[idx].match(rx);
        if (m) return Number(m[1]);
      }
    }
    return null;
  }

  function scanTerraform(file, findings) {
    const blocks = parseTerraformResourceBlocks(file.text);

    blocks.forEach(block => {
      const type = block.type.toLowerCase();

      if (type === "aws_security_group" || type === "aws_security_group_rule" ||
          type === "aws_vpc_security_group_ingress_rule") {
        block.lines.forEach((line, idx) => {
          if (!/(?:0\.0\.0\.0\/0|::\/0)/.test(line)) return;
          const direction = type.includes("ingress_rule") ? "ingress" : nearestTfDirection(block.lines, idx);
          if (direction === "egress") return;

          const fromPort = tfNearbyNumber(block.lines, idx, "from_port");
          const toPort = tfNearbyNumber(block.lines, idx, "to_port");
          const protocolAll = block.body.match(/\bprotocol\s*=\s*"(?:-1|all)"/i);
          const sensitive = fromPort === 22 || toPort === 22 || fromPort === 3389 || toPort === 3389;
          const severity = (sensitive || protocolAll) ? "critical" : "medium";
          const title = sensitive
            ? "Security group exposes administrative port to the internet"
            : protocolAll
              ? "Security group exposes all protocols to the internet"
              : "Security group allows internet-wide ingress";

          addFinding(findings, file, {
            severity, rule: sensitive ? "tf-public-admin-ingress" : protocolAll ? "tf-public-all-ingress" : "tf-public-ingress",
            title,
            description: "This Terraform rule allows inbound traffic from an internet-wide IPv4 or IPv6 CIDR. Public web ingress may be intentional, but administrative or broad protocol exposure is high risk.",
            remediation: "Restrict source CIDRs or reference trusted security groups. For public applications, expose only required frontend ports through an intentional load balancer/edge layer.",
            line: block.startLine + idx, evidence: line.trim(), category: "Terraform"
          });
        });
      }

      if (type === "aws_db_instance" || type === "aws_rds_cluster_instance") {
        const publicMatch = block.lines.findIndex(l => /^\s*publicly_accessible\s*=\s*true\b/i.test(l));
        if (publicMatch >= 0) {
          addFinding(findings, file, {
            severity: "high", rule: "tf-rds-public",
            title: "Database instance configured as publicly accessible",
            description: "The RDS-compatible database resource is explicitly configured for public accessibility.",
            remediation: "Keep production databases private where possible and allow application access through private networking and tightly scoped security groups.",
            line: block.startLine + publicMatch, evidence: block.lines[publicMatch].trim(), category: "Terraform"
          });
        }
        const encMatch = block.lines.findIndex(l => /^\s*storage_encrypted\s*=\s*false\b/i.test(l));
        if (encMatch >= 0) {
          addFinding(findings, file, {
            severity: "high", rule: "tf-rds-unencrypted",
            title: "Database storage encryption explicitly disabled",
            description: "The database resource explicitly disables storage encryption.",
            remediation: "Enable storage encryption and use an appropriate managed or customer-managed KMS key according to your data-classification requirements.",
            line: block.startLine + encMatch, evidence: block.lines[encMatch].trim(), category: "Terraform"
          });
        }
      }

      if (type === "aws_s3_bucket_public_access_block") {
        block.lines.forEach((line, idx) => {
          if (/^\s*(?:block_public_acls|ignore_public_acls|block_public_policy|restrict_public_buckets)\s*=\s*false\b/i.test(line)) {
            addFinding(findings, file, {
              severity: "high", rule: "tf-s3-public-block-disabled",
              title: "S3 public-access protection disabled",
              description: "A setting in the S3 Public Access Block resource is explicitly disabled.",
              remediation: "Enable all applicable S3 Block Public Access controls unless public access is an intentional, reviewed requirement.",
              line: block.startLine + idx, evidence: line.trim(), category: "Terraform"
            });
          }
        });
      }

      if (/\bacl\s*=\s*"(?:public-read|public-read-write|authenticated-read)"/i.test(block.body)) {
        const idx = block.lines.findIndex(l => /\bacl\s*=\s*"(?:public-read|public-read-write|authenticated-read)"/i.test(l));
        addFinding(findings, file, {
          severity: "high", rule: "tf-public-storage-acl",
          title: "Public or broad storage ACL configured",
          description: "The resource explicitly applies a broad/public ACL.",
          remediation: "Prefer private ACLs and grant access through narrowly scoped IAM/resource policies or signed delivery mechanisms.",
          line: block.startLine + idx, evidence: block.lines[idx].trim(), category: "Terraform"
        });
      }

      if (type === "aws_iam_policy" || type === "aws_iam_role_policy" || type === "aws_iam_user_policy") {
        const wildcardAction = /\bAction\s*[=:]\s*"\*"|\bactions?\s*=\s*\[\s*"\*"\s*\]/i.test(block.body);
        const wildcardResource = /\bResource\s*[=:]\s*"\*"|\bresources?\s*=\s*\[\s*"\*"\s*\]/i.test(block.body);
        if (wildcardAction && wildcardResource) {
          addFinding(findings, file, {
            severity: "critical", rule: "tf-iam-wildcard-admin",
            title: "IAM policy grants wildcard action on wildcard resource",
            description: "The policy appears to allow every action against every resource, creating administrator-like blast radius.",
            remediation: "Replace wildcard actions/resources with the minimum services, API actions, resource ARNs, and conditions required by the workload.",
            line: block.startLine, evidence: `resource "${block.type}" "${block.name}" { ... Action="*" ... Resource="*" ... }`, category: "Terraform"
          });
        } else if (wildcardAction || wildcardResource) {
          addFinding(findings, file, {
            severity: "medium", rule: "tf-iam-wildcard-review",
            title: "IAM policy contains a wildcard permission dimension",
            description: "The policy contains a wildcard action or resource. Some service APIs require wildcards, but the permission deserves least-privilege review.",
            remediation: "Narrow the wildcard where the service supports resource scoping and add conditions where appropriate.",
            line: block.startLine, evidence: `resource "${block.type}" "${block.name}" contains wildcard IAM scope`, category: "Terraform"
          });
        }
      }

      if (type === "aws_ebs_volume") {
        const idx = block.lines.findIndex(l => /^\s*encrypted\s*=\s*false\b/i.test(l));
        if (idx >= 0) {
          addFinding(findings, file, {
            severity: "high", rule: "tf-ebs-unencrypted",
            title: "EBS volume encryption explicitly disabled",
            description: "The EBS resource explicitly disables encryption at rest.",
            remediation: "Enable EBS encryption and select the appropriate KMS key policy for the workload.",
            line: block.startLine + idx, evidence: block.lines[idx].trim(), category: "Terraform"
          });
        }
      }

      if (type === "aws_instance") {
        const publicIdx = block.lines.findIndex(l => /^\s*associate_public_ip_address\s*=\s*true\b/i.test(l));
        if (publicIdx >= 0) {
          addFinding(findings, file, {
            severity: "info", rule: "tf-ec2-public-ip",
            title: "EC2 instance requests a public IP",
            description: "The instance is explicitly configured with a public IP address. This may be intentional, but increases the importance of security-group and host hardening.",
            remediation: "Prefer private subnets and managed ingress/egress paths when direct public addressing is unnecessary.",
            line: block.startLine + publicIdx, evidence: block.lines[publicIdx].trim(), category: "Terraform"
          });
        }
        const tokenIdx = block.lines.findIndex(l => /^\s*http_tokens\s*=\s*"optional"/i.test(l));
        if (tokenIdx >= 0) {
          addFinding(findings, file, {
            severity: "medium", rule: "tf-imdsv1-enabled",
            title: "EC2 metadata permits IMDSv1",
            description: "Setting `http_tokens = \"optional\"` permits metadata requests without an IMDSv2 session token.",
            remediation: "Require IMDSv2 with `http_tokens = \"required\"` unless a documented legacy dependency prevents it.",
            line: block.startLine + tokenIdx, evidence: block.lines[tokenIdx].trim(), category: "Terraform"
          });
        }
      }

      if (type === "azurerm_network_security_rule") {
        const body = block.body;
        const inbound = /\bdirection\s*=\s*"Inbound"/i.test(body);
        const allow = /\baccess\s*=\s*"Allow"/i.test(body);
        const publicSource = /\bsource_address_prefix(?:es)?\s*=\s*(?:"\*"|\[\s*"(?:\*|0\.0\.0\.0\/0)"\s*\])/i.test(body);
        if (inbound && allow && publicSource) {
          const sensitive = /\bdestination_port_range(?:s)?\s*=\s*(?:"(?:22|3389|\*)"|\[[^\]]*"(?:22|3389|\*)")/i.test(body);
          addFinding(findings, file, {
            severity: sensitive ? "critical" : "medium",
            rule: sensitive ? "tf-azure-public-admin" : "tf-azure-public-ingress",
            title: sensitive ? "Azure NSG exposes administrative/broad port publicly" : "Azure NSG allows public inbound access",
            description: "This network security rule allows inbound traffic from a public wildcard source.",
            remediation: "Restrict the source prefix and destination ports to the minimum required ranges, or front public applications with an intentional edge/load-balancing layer.",
            line: block.startLine, evidence: `resource "${block.type}" "${block.name}" permits public inbound traffic`, category: "Terraform"
          });
        }
      }

      if (type === "google_compute_firewall") {
        const publicSource = /\bsource_ranges\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"/i.test(block.body);
        const ingress = !/\bdirection\s*=\s*"EGRESS"/i.test(block.body);
        if (publicSource && ingress) {
          const sensitive = /\bports\s*=\s*\[[^\]]*"(?:22|3389)"/i.test(block.body) || /\bprotocol\s*=\s*"all"/i.test(block.body);
          addFinding(findings, file, {
            severity: sensitive ? "critical" : "medium",
            rule: sensitive ? "tf-gcp-public-admin" : "tf-gcp-public-ingress",
            title: sensitive ? "GCP firewall exposes administrative/broad traffic publicly" : "GCP firewall allows internet-wide ingress",
            description: "This firewall resource permits ingress from `0.0.0.0/0`.",
            remediation: "Restrict source ranges and allowed ports/protocols to the minimum required scope.",
            line: block.startLine, evidence: `resource "${block.type}" "${block.name}" includes source_ranges = ["0.0.0.0/0"]`, category: "Terraform"
          });
        }
      }
    });

    if (!blocks.length && /\b(?:0\.0\.0\.0\/0|::\/0)\b/.test(file.text)) {
      const lines = file.text.split(/\r?\n/);
      const idx = lines.findIndex(l => /(?:0\.0\.0\.0\/0|::\/0)/.test(l));
      addFinding(findings, file, {
        severity: "info", rule: "tf-public-cidr-review",
        title: "Internet-wide CIDR found outside a recognized resource block",
        description: "The Terraform/HCL text contains a public CIDR, but PipelineGuard could not confidently associate it with a supported resource type.",
        remediation: "Review whether the CIDR controls inbound exposure and restrict it if public access is not intended.",
        line: idx + 1, evidence: lines[idx].trim(), category: "Terraform"
      });
    }
  }

  function scanGenericYaml(file, findings) {
    // Generic YAML still receives secret scanning; deeper workload checks are only
    // applied when PipelineGuard recognizes a Kubernetes manifest.
  }


  function isExactSemverish(value) {
    return /^v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/.test(String(value || "").trim());
  }

  function isDynamicVersion(value) {
    const v = String(value || "").trim();
    return v === "*" || /^latest$/i.test(v) || /(?:^|[.xX*])(?:x|X|\*)$/.test(v) || /\+$/.test(v) || /latest\.(?:release|integration)/i.test(v);
  }

  function findJsonPropertyLine(text, key) {
    const lines = text.split(/\r?\n/);
    const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const rx = new RegExp('"' + escaped + '"\\s*:');
    const idx = lines.findIndex(l => rx.test(l));
    return idx >= 0 ? idx + 1 : null;
  }

  function scanNpm(file, findings) {
    let data;
    try {
      data = JSON.parse(file.text);
    } catch {
      addFinding(findings, file, {
        severity: "info", rule: "npm-json-parse",
        title: "package.json could not be parsed",
        description: "PipelineGuard recognized package.json but could not parse it as JSON, so dependency-specific analysis is incomplete.",
        remediation: "Validate the JSON syntax and rescan the manifest.",
        evidence: "Invalid JSON", category: "Supply Chain"
      });
      return;
    }

    const groups = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
    for (const group of groups) {
      const deps = data[group];
      if (!deps || typeof deps !== "object") continue;
      for (const [name, raw] of Object.entries(deps)) {
        const value = String(raw);
        const line = findJsonPropertyLine(file.text, name);

        if (isDynamicVersion(value)) {
          addFinding(findings, file, {
            severity: "high", rule: "npm-dynamic-version",
            title: "npm dependency uses a floating version",
            description: `Dependency ${name} uses \`${value}\`, allowing future installs to resolve to different package content without a manifest change.`,
            remediation: "Use an intentional version/range and commit a supported lockfile. For deployment builds, use the package manager's lockfile-respecting clean/frozen install mode.",
            line, evidence: `\"${name}\": \"${value}\"`, category: "Supply Chain"
          });
        }

        if (/^(?:http|git\+http):\/\//i.test(value)) {
          addFinding(findings, file, {
            severity: "high", rule: "npm-insecure-source",
            title: "npm dependency uses an insecure transport",
            description: "The dependency source uses unencrypted HTTP, allowing package or repository content to be modified in transit on an untrusted network path.",
            remediation: "Use HTTPS or SSH with host verification, and prefer a trusted package registry or immutable source reference.",
            line, evidence: `\"${name}\": \"${value}\"`, category: "Supply Chain"
          });
        }

        if (/^(?:git\+|github:|gitlab:|bitbucket:)/i.test(value) && !/@[a-f0-9]{40}(?:#|$)/i.test(value) && !/#[a-f0-9]{40}$/i.test(value)) {
          addFinding(findings, file, {
            severity: "medium", rule: "npm-mutable-git-ref",
            title: "npm dependency references a mutable VCS ref",
            description: "A Git/VCS dependency is not visibly pinned to an immutable full commit, so branch/tag movement can alter future installs.",
            remediation: "Pin trusted VCS dependencies to an immutable commit and review the source before updating that commit.",
            line, evidence: `\"${name}\": \"${value}\"`, category: "Supply Chain"
          });
        }

        if (/^file:/i.test(value)) {
          addFinding(findings, file, {
            severity: "low", rule: "npm-local-file-dependency",
            title: "npm dependency points to a local file path",
            description: "Local file dependencies can make CI and production resolution depend on files outside the package manifest's normal registry graph.",
            remediation: "Confirm the referenced artifact is included reproducibly in the build context or publish/version the shared package through a controlled registry.",
            line, evidence: `\"${name}\": \"${value}\"`, category: "Supply Chain"
          });
        }
      }
    }

    const scripts = data.scripts && typeof data.scripts === "object" ? data.scripts : {};
    for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
      if (!scripts[hook]) continue;
      const command = String(scripts[hook]);
      const line = findJsonPropertyLine(file.text, hook);
      const dangerous = /\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:bash|sh)\b/i.test(command) ||
                        /(?:Invoke-WebRequest|iwr|curl)\b[^\n]*(?:Invoke-Expression|iex)/i.test(command);
      addFinding(findings, file, {
        severity: dangerous ? "critical" : "info",
        rule: dangerous ? "npm-lifecycle-remote-exec" : "npm-lifecycle-hook",
        title: dangerous ? "npm lifecycle hook downloads and executes remote code" : `npm ${hook} lifecycle hook executes during install`,
        description: dangerous
          ? "The install lifecycle can retrieve remote content and execute it automatically when dependencies are installed."
          : "Lifecycle hooks execute code during common package installation workflows and expand supply-chain execution surface.",
        remediation: dangerous
          ? "Remove download-and-execute behavior. Vendor or separately retrieve a versioned artifact, verify its integrity/signature, and run reviewed local code."
          : "Keep lifecycle code minimal and reviewed. Consider install modes/policies that suppress scripts when consuming untrusted dependency trees.",
        line, evidence: `\"${hook}\": \"${command}\"`, category: "Supply Chain"
      });
    }

    if (!data.packageManager) {
      addFinding(findings, file, {
        severity: "info", rule: "npm-package-manager-unspecified",
        title: "Package manager version is not declared",
        description: "The manifest does not declare a package manager/version, which can make local and CI resolution behavior less explicit.",
        remediation: "Consider declaring the intended package manager/version (for example with the `packageManager` field) and enforce it in CI.",
        evidence: "No packageManager field detected.", category: "Supply Chain"
      });
    }
  }

  function scanPythonRequirements(file, findings) {
    const lines = file.text.split(/\r?\n/);
    let requirementCount = 0;
    let pinnedCount = 0;

    lines.forEach((raw, i) => {
      const line = raw.trim();
      if (!line || line.startsWith("#") || /^-r\s|^--requirement\s/i.test(line)) return;

      if (/^--(?:index-url|extra-index-url)\s+http:\/\//i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "pip-insecure-index",
          title: "Python package index uses insecure HTTP",
          description: "Package metadata or artifacts may be retrieved over an unencrypted package-index connection.",
          remediation: "Use an HTTPS package index with certificate validation and a controlled trusted repository.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
        return;
      }

      if (/^--trusted-host\b/i.test(line)) {
        addFinding(findings, file, {
          severity: "medium", rule: "pip-trusted-host",
          title: "pip trusted-host exception configured",
          description: "A trusted-host exception relaxes normal transport trust expectations for that package source.",
          remediation: "Remove the exception when possible and use a correctly configured HTTPS repository with valid certificates.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
        return;
      }

      if (/^--extra-index-url\b/i.test(line)) {
        addFinding(findings, file, {
          severity: "medium", rule: "pip-extra-index",
          title: "Additional Python package index configured",
          description: "Mixing multiple indexes can create dependency-confusion risk when private and public package names overlap.",
          remediation: "Ensure private package names cannot be resolved from an untrusted public index, or use repository controls that provide deterministic source priority.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
        return;
      }

      if (/^(?:git\+)?http:\/\//i.test(line) || /\s@\s*http:\/\//i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "pip-insecure-direct-source",
          title: "Python dependency uses insecure HTTP source",
          description: "The requirement retrieves dependency content over unencrypted HTTP.",
          remediation: "Use HTTPS/SSH from a trusted source and pin direct VCS/archive dependencies to immutable reviewed content.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }

      if (/^(?:-e\s+)?git\+/i.test(line) && !/@[a-f0-9]{40}(?:#|$)/i.test(line)) {
        addFinding(findings, file, {
          severity: "medium", rule: "pip-mutable-vcs-ref",
          title: "Python VCS dependency is not pinned to a full commit",
          description: "The Git dependency appears to use a branch, tag, or other mutable/non-immutable reference.",
          remediation: "Pin VCS requirements to a reviewed immutable commit and update it intentionally.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }

      if (line.startsWith("-")) return;
      if (/^(?:-e\s+)?(?:git\+|https?:\/\/)/i.test(line) || /\s@\s*(?:https?|git\+https|ssh):/i.test(line)) return;
      requirementCount++;
      if (/^[A-Za-z0-9_.-]+(?:\[[^\]]+\])?==[^;\s]+(?:\s*;.*)?$/.test(line)) {
        pinnedCount++;
      } else if (!/\s@\s*(?:https|git\+https|ssh):/i.test(line)) {
        addFinding(findings, file, {
          severity: "medium", rule: "pip-unpinned-requirement",
          title: "Python requirement is not exactly pinned",
          description: "The requirement can resolve to a different package version on a future install.",
          remediation: "For deployable applications, generate and review a locked/pinned dependency set. Use controlled update tooling rather than unconstrained production installs.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
    });

    if (requirementCount > 0 && pinnedCount === requirementCount && !/(?:^|\n)\s*--require-hashes\b/m.test(file.text) && !/--hash=sha256:/i.test(file.text)) {
      addFinding(findings, file, {
        severity: "info", rule: "pip-no-hashes",
        title: "Pinned Python requirements do not include integrity hashes",
        description: "Exact version pins improve reproducibility, but this requirements set does not visibly enforce artifact hashes.",
        remediation: "For higher-assurance deployments, consider a lock/export workflow that records and verifies approved package hashes.",
        evidence: `${requirementCount} pinned requirement(s), no hash enforcement detected.`, category: "Supply Chain"
      });
    }
  }

  function scanPyproject(file, findings) {
    const lines = file.text.split(/\r?\n/);
    lines.forEach((raw, i) => {
      const line = raw.trim();
      if (/\b(?:index|url)\s*=\s*["']http:\/\//i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "pyproject-insecure-index",
          title: "Python project declares an insecure package source",
          description: "The project configuration contains an HTTP package/source URL.",
          remediation: "Use an HTTPS repository with valid certificate verification.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
      if (/^[A-Za-z0-9_.-]+\s*=\s*["'](?:\*|latest)["']/i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "pyproject-dynamic-version",
          title: "Python project dependency uses a floating version",
          description: "The dependency declaration allows arbitrary/latest package resolution.",
          remediation: "Use intentional compatible constraints and commit the ecosystem's supported lockfile for deployable applications.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
      if (/\{[^}]*git\s*=\s*["'][^"']+["'][^}]*branch\s*=/i.test(line)) {
        addFinding(findings, file, {
          severity: "medium", rule: "pyproject-vcs-branch",
          title: "Python VCS dependency tracks a branch",
          description: "A branch-based VCS dependency can change without an application manifest change.",
          remediation: "Use a reviewed immutable revision/commit for production dependency resolution.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
    });
  }

  function scanNuget(file, findings) {
    const lines = file.text.split(/\r?\n/);
    lines.forEach((raw, i) => {
      const line = raw.trim();
      const pkg = line.match(/<PackageReference\b[^>]*Include=["']([^"']+)["'][^>]*>/i) ||
                  line.match(/<package\b[^>]*id=["']([^"']+)["'][^>]*>/i);
      if (pkg) {
        const ver = line.match(/\bVersion=["']([^"']+)["']/i) || line.match(/\bversion=["']([^"']+)["']/i);
        if (ver && (isDynamicVersion(ver[1]) || /[\[\(].*,.*[\]\)]/.test(ver[1]))) {
          addFinding(findings, file, {
            severity: isDynamicVersion(ver[1]) ? "high" : "medium", rule: "nuget-dynamic-version",
            title: "NuGet dependency uses a floating or ranged version",
            description: `Package ${pkg[1]} uses version expression \`${ver[1]}\`, which can change restore results over time.`,
            remediation: "Use an intentional version and, where appropriate, enable NuGet lock-file/locked restore behavior for application builds.",
            line: i + 1, evidence: line, category: "Supply Chain"
          });
        }
      }

      if (/<RestoreSources>[^<]*http:\/\//i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "nuget-insecure-source",
          title: "NuGet restore source uses insecure HTTP",
          description: "A project-level restore source is configured over unencrypted HTTP.",
          remediation: "Use HTTPS for package feeds and authenticated private sources where required.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
    });
  }

  function scanNugetConfig(file, findings) {
    const lines = file.text.split(/\r?\n/);
    lines.forEach((raw, i) => {
      const line = raw.trim();
      if (/<add\b[^>]*key=["'][^"']+["'][^>]*value=["']http:\/\//i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "nuget-insecure-feed",
          title: "NuGet package source uses insecure HTTP",
          description: "A NuGet package source is configured without transport encryption.",
          remediation: "Move the feed to HTTPS and validate its certificate/authentication configuration.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
    });
  }

  function scanMaven(file, findings) {
    const lines = file.text.split(/\r?\n/);
    lines.forEach((raw, i) => {
      const line = raw.trim();
      if (/<url>http:\/\//i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "maven-insecure-repository",
          title: "Maven repository uses insecure HTTP",
          description: "A Maven repository/plugin repository URL is configured over unencrypted HTTP.",
          remediation: "Use HTTPS and a trusted repository manager/source.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
      const version = line.match(/<version>([^<]+)<\/version>/i);
      if (version && (/SNAPSHOT$/i.test(version[1]) || /^(?:LATEST|RELEASE)$/i.test(version[1]))) {
        const context = lines.slice(Math.max(0, i - 12), i + 1).join("\n");
        const dependencyOpen = context.lastIndexOf("<dependency>") > context.lastIndexOf("</dependency>");
        const pluginOpen = context.lastIndexOf("<plugin>") > context.lastIndexOf("</plugin>");
        if (dependencyOpen || pluginOpen) {
          addFinding(findings, file, {
            severity: "medium", rule: "maven-dynamic-version",
            title: "Maven dependency/plugin uses a mutable version",
            description: `Version \`${version[1]}\` can resolve differently over time or represents a changing snapshot.`,
            remediation: "Use a reviewed release version for production builds and update it intentionally.",
            line: i + 1, evidence: line, category: "Supply Chain"
          });
        }
      }
    });
  }

  function scanGradle(file, findings) {
    const lines = file.text.split(/\r?\n/);
    lines.forEach((raw, i) => {
      const line = raw.trim();
      if (/\ballowInsecureProtocol\s*=\s*true\b/i.test(line) || /\burl\s*(?:=|\s)\s*["']http:\/\//i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "gradle-insecure-repository",
          title: "Gradle repository permits insecure HTTP",
          description: "The Gradle configuration uses or explicitly allows an HTTP repository.",
          remediation: "Use HTTPS with certificate verification and a trusted repository manager/source.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
      if (/\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\b[^\n]*["'][^"']+:[^"']+:(?:\+|latest\.(?:release|integration)|[^"']*\+)["']/i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "gradle-dynamic-version",
          title: "Gradle dependency uses a dynamic version",
          description: "The dependency selector can resolve to a different artifact/version on a future build.",
          remediation: "Use an intentional fixed/compatible version and consider Gradle dependency locking/verification for reproducible builds.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
      if (/\bmavenLocal\s*\(\s*\)/i.test(line)) {
        addFinding(findings, file, {
          severity: "info", rule: "gradle-maven-local",
          title: "Gradle build resolves from mavenLocal()",
          description: "Local Maven repository content can vary between developer and CI machines and may shadow expected artifacts.",
          remediation: "Avoid mavenLocal() in production resolution unless its precedence and contents are intentionally controlled.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
    });
  }

  function scanComposer(file, findings) {
    let data;
    try { data = JSON.parse(file.text); } catch { return; }
    for (const group of ["require", "require-dev"]) {
      const deps = data[group];
      if (!deps || typeof deps !== "object") continue;
      for (const [name, version] of Object.entries(deps)) {
        if (String(version) === "*" || /^dev-(?:main|master)$/i.test(String(version))) {
          addFinding(findings, file, {
            severity: "medium", rule: "composer-floating-version",
            title: "Composer dependency uses a floating development version",
            description: `Package ${name} uses \`${version}\`, which can change without a manifest update.`,
            remediation: "Use an intentional release/constraint and commit composer.lock for application deployments.",
            line: findJsonPropertyLine(file.text, name), evidence: `\"${name}\": \"${version}\"`, category: "Supply Chain"
          });
        }
      }
    }
    const scripts = data.scripts && typeof data.scripts === "object" ? JSON.stringify(data.scripts) : "";
    if (/\b(?:curl|wget)\b[^|;&]*\|\s*(?:bash|sh)\b/i.test(scripts)) {
      addFinding(findings, file, {
        severity: "critical", rule: "composer-script-remote-exec",
        title: "Composer lifecycle script downloads and executes remote code",
        description: "Composer script hooks can execute automatically during dependency workflows and this hook pipes downloaded content to a shell.",
        remediation: "Remove remote pipe-to-shell execution; retrieve versioned content separately and verify integrity before execution.",
        evidence: "composer.json scripts contain download-and-execute behavior", category: "Supply Chain"
      });
    }
  }

  function scanRuby(file, findings) {
    const lines = file.text.split(/\r?\n/);
    lines.forEach((raw, i) => {
      const line = raw.trim();
      if (/^source\s+["']http:\/\//i.test(line)) {
        addFinding(findings, file, {
          severity: "high", rule: "bundler-insecure-source",
          title: "RubyGems source uses insecure HTTP",
          description: "The Gemfile configures an unencrypted package source.",
          remediation: "Use HTTPS and a trusted gem source.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
      if (/^gem\s+["'][^"']+["']\s*,\s*git:\s*["'][^"']+["'][^#]*branch:/i.test(line)) {
        addFinding(findings, file, {
          severity: "medium", rule: "bundler-mutable-git-ref",
          title: "Gem dependency tracks a Git branch",
          description: "A branch-based Git dependency can change without a Gemfile change.",
          remediation: "Pin the Git dependency to a reviewed immutable revision for production use.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
    });
  }

  function scanGoMod(file, findings) {
    const lines = file.text.split(/\r?\n/);
    lines.forEach((raw, i) => {
      const line = raw.trim();
      if (/^replace\s+\S+\s+=>\s+(?:\.\.\/|\.\/|\/)/.test(line)) {
        addFinding(findings, file, {
          severity: "low", rule: "gomod-local-replace",
          title: "Go module uses a local replace directive",
          description: "A local filesystem replacement can make builds depend on content outside the normal module graph.",
          remediation: "Remove local replacements from production builds or ensure the replacement is vendored/versioned reproducibly.",
          line: i + 1, evidence: line, category: "Supply Chain"
        });
      }
    });
  }

  function scanSupplyChainCrossFile(findings) {
    const lowerNames = state.files.map(f => f.name.toLowerCase().split(/[\\/]/).pop());
    const hasName = (...names) => names.some(n => lowerNames.includes(n));

    for (const file of state.files.filter(f => f.type === "npm")) {
      let data = null;
      try { data = JSON.parse(file.text); } catch {}
      const hasDeps = data && ["dependencies", "devDependencies", "optionalDependencies"].some(k => data[k] && Object.keys(data[k]).length);
      const hasJsLock = hasName("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "pnpm-lock.yml");
      if (hasDeps && !hasJsLock) {
        addFinding(findings, file, {
          severity: "medium", rule: "npm-lockfile-missing",
          title: "JavaScript dependency manifest supplied without a lockfile",
          description: "No npm, Yarn, or pnpm lockfile was included in this scan, so transitive dependency resolution cannot be shown as locked/reproducible from the supplied files.",
          remediation: "Commit the package manager's lockfile and use a CI install mode that refuses unexpected lockfile drift.",
          evidence: "package.json present; no recognized JS lockfile supplied.", category: "Supply Chain"
        });
      }
    }

    for (const file of state.files.filter(f => f.type === "pyproject")) {
      const hasLock = hasName("poetry.lock", "uv.lock", "pdm.lock", "pipfile.lock");
      if (!hasLock && /\bdependencies\s*=|\[tool\.poetry\.dependencies\]/i.test(file.text)) {
        addFinding(findings, file, {
          severity: "low", rule: "python-lockfile-missing",
          title: "Python project manifest supplied without a recognized lockfile",
          description: "The scan includes a Python project dependency manifest but no Poetry/uv/PDM/Pipenv-style lockfile.",
          remediation: "For deployable applications, use the ecosystem's supported locking/export workflow and commit the resulting reproducible dependency metadata when appropriate.",
          evidence: "pyproject.toml present; no recognized Python lockfile supplied.", category: "Supply Chain"
        });
      }
    }

    for (const file of state.files.filter(f => f.type === "composer")) {
      if (!hasName("composer.lock")) {
        addFinding(findings, file, {
          severity: "medium", rule: "composer-lockfile-missing",
          title: "composer.json supplied without composer.lock",
          description: "Application dependency resolution is not demonstrated as locked by the files included in this scan.",
          remediation: "Commit composer.lock for applications and use lockfile-respecting install behavior in CI/deployment.",
          evidence: "composer.json present; composer.lock not supplied.", category: "Supply Chain"
        });
      }
    }
  }

  function scanSupplyChainFile(file, findings) {
    switch (file.type) {
      case "npm": scanNpm(file, findings); break;
      case "python-requirements": scanPythonRequirements(file, findings); break;
      case "pyproject": scanPyproject(file, findings); break;
      case "nuget": scanNuget(file, findings); break;
      case "nuget-config": scanNugetConfig(file, findings); break;
      case "maven": scanMaven(file, findings); break;
      case "gradle": scanGradle(file, findings); break;
      case "composer": scanComposer(file, findings); break;
      case "ruby": scanRuby(file, findings); break;
      case "gomod": scanGoMod(file, findings); break;
    }
  }


  function exactVersionFromNpmSpec(spec) {
    const v = String(spec || "").trim();
    if (/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(v)) return v;
    return null;
  }

  function collectLivePackages() {
    const out = [];
    const seen = new Set();
    const add = (ecosystem, name, version, sourceFile) => {
      if (!ecosystem || !name || !version) return;
      const key = `${ecosystem}|${name}|${version}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ ecosystem, name, version, sourceFile });
    };

    for (const file of state.files) {
      try {
        if (file.type === "npm") {
          const data = JSON.parse(file.text);
          for (const group of ["dependencies","devDependencies","optionalDependencies"]) {
            for (const [name, spec] of Object.entries(data[group] || {})) {
              const v = exactVersionFromNpmSpec(spec);
              if (v) add("npm", name, v, file.name);
            }
          }
        } else if (file.type === "npm-lock") {
          const data = JSON.parse(file.text);
          if (data.packages && typeof data.packages === "object") {
            for (const [path, info] of Object.entries(data.packages)) {
              if (!path || !info || !info.version) continue;
              let name = info.name;
              if (!name && path.startsWith("node_modules/")) name = path.slice("node_modules/".length);
              if (name) add("npm", name, String(info.version), file.name);
            }
          } else if (data.dependencies) {
            for (const [name, info] of Object.entries(data.dependencies)) {
              if (info && info.version) add("npm", name, String(info.version), file.name);
            }
          }
        } else if (file.type === "python-requirements") {
          for (const raw of file.text.split(/\r?\n/)) {
            const m = raw.trim().match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^;\s]+)/);
            if (m) add("PyPI", m[1], m[2], file.name);
          }
        } else if (file.type === "nuget") {
          for (const raw of file.text.split(/\r?\n/)) {
            const m = raw.match(/<(?:PackageReference\b[^>]*Include|package\b[^>]*id)=["']([^"']+)["'][^>]*(?:Version|version)=["']([^"']+)["']/i);
            if (m && /^\d+(?:\.\d+)+/.test(m[2]) && !/[\[\(\],*+]/.test(m[2])) add("NuGet", m[1], m[2], file.name);
          }
        } else if (file.type === "maven") {
          const depRx = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?<version>([^<]+)<\/version>[\s\S]*?<\/dependency>/gi;
          let m;
          while ((m = depRx.exec(file.text))) {
            if (!/\$\{/.test(m[3]) && !/SNAPSHOT|LATEST|RELEASE/i.test(m[3])) add("Maven", `${m[1]}:${m[2]}`, m[3], file.name);
          }
        } else if (file.type === "gradle") {
          for (const raw of file.text.split(/\r?\n/)) {
            const m = raw.match(/\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\b[^(]*\(?\s*["']([^:"']+):([^:"']+):([^"']+)["']/i);
            if (m && !/[+]/.test(m[3]) && !/latest\./i.test(m[3])) add("Maven", `${m[1]}:${m[2]}`, m[3], file.name);
          }
        } else if (file.type === "composer") {
          const data = JSON.parse(file.text);
          for (const group of ["require","require-dev"]) {
            for (const [name, spec] of Object.entries(data[group] || {})) {
              if (/^\d+(?:\.\d+){1,3}$/.test(String(spec))) add("Packagist", name, String(spec), file.name);
            }
          }
        } else if (file.type === "ruby") {
          for (const raw of file.text.split(/\r?\n/)) {
            const m = raw.match(/^\s*gem\s+["']([^"']+)["']\s*,\s*["']=?\s*([0-9][^"']*)["']/);
            if (m && /^\d+(?:\.\d+)+$/.test(m[2])) add("RubyGems", m[1], m[2], file.name);
          }
        } else if (file.type === "gomod") {
          for (const raw of file.text.split(/\r?\n/)) {
            const m = raw.trim().match(/^([A-Za-z0-9._~/-]+)\s+v([0-9][^\s]*)$/);
            if (m) add("Go", m[1], `v${m[2]}`, file.name);
          }
        }
      } catch {
        // Static scan already reports parse issues where applicable.
      }
    }

    state.livePackages = out.slice(0, 50);
    $("livePackages").textContent = state.livePackages.length;
    $("liveBtn").disabled = !state.livePackages.length;
    return state.livePackages;
  }

  function capabilityResult(idPrefix, supported, okText, badText) {
    const value = $(`status${idPrefix}`);
    const stateEl = $(`status${idPrefix}State`);
    if (value) value.textContent = supported ? okText : badText;
    if (stateEl) {
      stateEl.textContent = supported ? "Ready" : "Unavailable";
      stateEl.className = supported ? "status-ok" : "status-bad";
    }
  }

  function persistentStorageAvailable() {
    const key = "pipelineguardStatusProbe";
    try {
      localStorage.setItem(key, "1");
      const ok = localStorage.getItem(key) === "1";
      localStorage.removeItem(key);
      return ok;
    } catch { return false; }
  }

  function refreshSystemStatus() {
    capabilityResult("Zip", typeof DecompressionStream === "function", "Deflate ZIP supported", "DecompressionStream missing");
    capabilityResult("Storage", persistentStorageAvailable(), "localStorage writable", "Session-only exceptions/settings");
    capabilityResult("Clipboard", !!(window.isSecureContext && navigator.clipboard?.writeText), "Clipboard API available", "Clipboard API unavailable");
    capabilityResult("Download", !!(URL?.createObjectURL && "download" in document.createElement("a")), "HTML report export supported", "Download API unavailable");
    capabilityResult("Network", !!(window.fetch && window.AbortController), "fetch + timeout supported", "Required networking API missing");
    if ($("statusFrontend")) $("statusFrontend").textContent = APP_VERSION;
  }

  function setRelaySummary(text, kind="") {
    const summary = $("relaySummary");
    if (summary) summary.textContent = text;
    const status = $("statusRelayState");
    if (status && kind) status.className = kind === "ok" ? "status-ok" : kind === "warn" ? "status-warn" : "status-bad";
  }

  async function fetchRelayHealth(url, timeoutMs=RELAY_HEALTH_TIMEOUT_MS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const started = performance.now();
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "health", frontendVersion: APP_VERSION }),
        signal: controller.signal
      });
      const raw = await resp.text();
      let data;
      try { data = JSON.parse(raw); }
      catch { throw new Error(`Relay returned non-JSON data (HTTP ${resp.status}).`); }
      if (!resp.ok || !data.ok) {
        const e = new Error(data.error || `Relay health HTTP ${resp.status}`);
        e.code = data.code || `HTTP_${resp.status}`;
        throw e;
      }
      data.latencyMs = Math.round(performance.now() - started);
      return data;
    } finally { clearTimeout(timer); }
  }

  async function testRelayHealth() {
    const url = relayUrl();
    const liveStatus = $("liveStatus");
    const statusMessage = $("statusMessage");
    if (!url) {
      alert("Configure the PipelineGuard relay URL first.");
      return;
    }
    for (const id of ["testRelayBtn","statusTestRelayBtn"]) if ($(id)) $(id).disabled = true;
    setRelaySummary(`Frontend ${APP_VERSION} · Testing relay…`);
    if ($("statusRelay")) $("statusRelay").textContent = "Testing…";
    if ($("statusOsv")) $("statusOsv").textContent = "Testing…";
    if (statusMessage) {
      statusMessage.hidden = false;
      statusMessage.className = "live-message";
      statusMessage.textContent = "Testing the configured relay and OSV reachability. No repository content is sent.";
    }
    try {
      const data = await fetchRelayHealth(url);
      const version = data.version || "unknown";
      const versionMatch = version === APP_VERSION;
      const osvOk = data.osv?.reachable === true;
      const curlOk = data.curlAvailable !== false;
      if ($("statusRelay")) $("statusRelay").textContent = `${data.service || "PipelineGuard Relay"} ${version} · ${data.latencyMs} ms`;
      if ($("statusRelayState")) {
        $("statusRelayState").textContent = versionMatch && curlOk ? "Connected" : versionMatch ? "Degraded" : "Version mismatch";
        $("statusRelayState").className = versionMatch && curlOk ? "status-ok" : "status-warn";
      }
      if ($("statusOsv")) $("statusOsv").textContent = osvOk ? `Reachable${data.osv.http ? ` · HTTP ${data.osv.http}` : ""}` : (data.osv?.error || "Unavailable");
      if ($("statusOsvState")) {
        $("statusOsvState").textContent = osvOk ? "Reachable" : "Unavailable";
        $("statusOsvState").className = osvOk ? "status-ok" : "status-bad";
      }
      const summary = `Frontend ${APP_VERSION} · Relay ${version}${versionMatch ? "" : " (mismatch)"} · OSV ${osvOk ? "reachable" : "unavailable"} · ${data.latencyMs} ms`;
      setRelaySummary(summary, versionMatch && osvOk && curlOk ? "ok" : "warn");
      if (statusMessage) {
        statusMessage.className = versionMatch && osvOk && curlOk ? "live-message ok" : "live-message warn";
        statusMessage.textContent = versionMatch && osvOk && curlOk
          ? "Frontend, relay, and OSV connectivity are aligned."
          : `${versionMatch ? "" : `Frontend ${APP_VERSION} does not match relay ${version}. `}${curlOk ? "" : "PHP cURL is unavailable. "}${osvOk ? "" : "OSV could not be reached from the relay."}`.trim();
      }
      if (liveStatus && !state.liveCheckedAt) {
        liveStatus.textContent = versionMatch && osvOk && curlOk ? "Relay ready" : "Relay degraded";
        liveStatus.className = versionMatch && osvOk && curlOk ? "live-status ok" : "live-status warn";
      }
      showToast(versionMatch && osvOk && curlOk ? "Relay healthy" : "Relay needs attention", summary);
      return data;
    } catch (err) {
      const message = err.name === "AbortError" ? "Relay health test timed out." : liveFailureMessage(err);
      setRelaySummary(`Frontend ${APP_VERSION} · Relay unavailable`, "bad");
      if ($("statusRelay")) $("statusRelay").textContent = message;
      if ($("statusRelayState")) { $("statusRelayState").textContent = "Unavailable"; $("statusRelayState").className = "status-bad"; }
      if ($("statusOsv")) $("statusOsv").textContent = "Not testable";
      if ($("statusOsvState")) { $("statusOsvState").textContent = "Unknown"; $("statusOsvState").className = "status-warn"; }
      if (statusMessage) { statusMessage.hidden = false; statusMessage.className = "live-message bad"; statusMessage.textContent = `${message} Local scanning remains available.`; }
      if (liveStatus && !state.liveCheckedAt) { liveStatus.textContent = "Relay unavailable"; liveStatus.className = "live-status bad"; }
      showToast("Relay test failed", message);
      return null;
    } finally {
      for (const id of ["testRelayBtn","statusTestRelayBtn"]) if ($(id)) $(id).disabled = false;
    }
  }

  function openSystemStatus() {
    refreshSystemStatus();
    $("systemStatusDialog").showModal();
  }

  function relayUrl() {
    return storageGet("pipelineguardRelayUrl") || $("relayUrl").value.trim();
  }

  function saveRelayUrl() {
    const url = $("relayUrl").value.trim();
    const persisted = storageSet("pipelineguardRelayUrl", url);
    const s = $("liveStatus");
    s.textContent = persisted ? "Relay saved" : "Relay set for session";
    s.className = persisted ? "live-status ok" : "live-status warn";
  }

  function severityFromOsv(v) {
    const text = JSON.stringify(v).toLowerCase();
    if (/"severity"\s*:\s*"critical"/.test(text)) return "critical";
    if (/"severity"\s*:\s*"high"/.test(text)) return "high";
    if (/"severity"\s*:\s*"moderate"|"severity"\s*:\s*"medium"/.test(text)) return "medium";
    return "low";
  }

  function extractFixVersion(vuln) {
    for (const affected of (vuln.affected || [])) {
      for (const range of (affected.ranges || [])) {
        for (const ev of (range.events || [])) {
          if (ev.fixed) return ev.fixed;
        }
      }
    }
    return null;
  }

  function livePackageSetKey(packages) {
    return fnv1a(packages.map(p => `${p.ecosystem}|${p.name}|${p.version}`).sort().join("\n"));
  }

  function loadLiveCache(packages) {
    try {
      const cached = JSON.parse(storageGet(LIVE_CACHE_KEY) || "null");
      if (!cached || cached.key !== livePackageSetKey(packages) || !Array.isArray(cached.vulnerabilities)) return null;
      const ageMs = Date.now() - new Date(cached.checkedAt).getTime();
      if (!Number.isFinite(ageMs) || ageMs > 24 * 60 * 60 * 1000) return null;
      return cached;
    } catch { return null; }
  }

  function saveLiveCache(packages, vulnerabilities) {
    try {
      storageSet(LIVE_CACHE_KEY, JSON.stringify({
        key: livePackageSetKey(packages), checkedAt: new Date().toISOString(), vulnerabilities
      }));
    } catch {}
  }

  function clearPreviousLiveFindings() {
    state.findings = state.findings.filter(f => f.rule !== "osv-known-vulnerability");
  }

  function mergeLiveResults(items, sourceLabel, warnings=[]) {
    clearPreviousLiveFindings();
    state.liveVulnerabilities = Array.isArray(items) ? items : [];
    state.liveCheckedAt = new Date();
    state.liveSource = sourceLabel;
    let severe = 0, fixable = 0;
    for (const item of state.liveVulnerabilities) {
      const sev = severityFromOsv(item.vulnerability || {});
      if (sev === "critical" || sev === "high") severe++;
      if (extractFixVersion(item.vulnerability || {})) fixable++;
      const v = item.vulnerability || {};
      const fix = extractFixVersion(v);
      addFinding(state.findings, { name: item.sourceFile || "live advisory", type: "live" }, {
        severity: sev,
        rule: "osv-known-vulnerability",
        title: `Known vulnerability: ${v.id || "OSV advisory"} in ${item.name}@${item.version}`,
        description: v.summary || v.details || "OSV reports this exact package version as affected by a known vulnerability. Advisory detail may be partial.",
        remediation: fix ? `Upgrade to a non-affected version; OSV lists ${fix} as a fixed version in at least one affected range. Review the advisory before changing production dependencies.` : "Review the advisory's affected ranges and upgrade to a non-affected version or apply the vendor's mitigation.",
        evidence: `${item.ecosystem}:${item.name}@${item.version}${v.id ? ` · ${v.id}` : ""}${item.partial ? " · partial detail" : ""}`,
        category: "Live Intelligence"
      });
    }
    state.findings.sort((a,b) => SEVERITY_ORDER[a.severity]-SEVERITY_ORDER[b.severity] || a.file.localeCompare(b.file) || (a.line||0)-(b.line||0));
    recomputeScore();
    $("liveVulns").textContent = state.liveVulnerabilities.length;
    $("liveCritical").textContent = severe;
    $("liveFixable").textContent = fixable;
    const status = $("liveStatus");
    status.textContent = sourceLabel;
    status.className = state.liveVulnerabilities.length ? "live-status warn" : "live-status ok";
    const msg = $("liveMessage");
    if (warnings.length) {
      msg.hidden = false;
      msg.className = "live-message warn";
      msg.textContent = warnings.join(" ");
    } else {
      msg.hidden = true;
    }
    renderResults(false);
  }

  function liveFailureMessage(err) {
    if (err.name === "AbortError") return "The advisory relay timed out. Your local scan is unchanged; retry when connectivity improves.";
    if (/Failed to fetch|NetworkError|Load failed/i.test(err.message)) return "The relay could not be reached (network, DNS, TLS, or CORS). Your local scan is still valid.";
    return err.message || "The live advisory lookup failed. Your local scan is unchanged.";
  }

  async function fetchLiveWithTimeout(url, packages, timeoutMs=22000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "osv_query", packages }),
        signal: controller.signal
      });
      const raw = await resp.text();
      let data;
      try { data = JSON.parse(raw); }
      catch { throw new Error(`Relay returned non-JSON data (HTTP ${resp.status}).`); }
      if (!resp.ok || !data.ok) {
        const e = new Error(data.error || `Relay HTTP ${resp.status}`);
        e.retryable = data.retryable === true || resp.status === 408 || resp.status === 429 || resp.status >= 500;
        e.code = data.code || `HTTP_${resp.status}`;
        throw e;
      }
      if (!Array.isArray(data.vulnerabilities)) throw new Error("Relay response was missing the vulnerabilities array.");
      return data;
    } finally { clearTimeout(timer); }
  }

  async function checkLiveAdvisories() {
    const packages = collectLivePackages();
    if (!packages.length) {
      alert("No exact package versions were found. Include a lockfile or exact pinned dependency versions to use live advisory matching.");
      return;
    }
    const url = relayUrl();
    if (!url) {
      alert("Configure the PipelineGuard relay URL first.");
      return;
    }

    const status = $("liveStatus");
    const msg = $("liveMessage");
    const previousLiveCount = state.liveVulnerabilities.length;
    msg.hidden = false;
    msg.className = "live-message";
    msg.textContent = `Checking ${packages.length} exact package version(s)… local findings remain available if this fails.`;
    status.textContent = "Checking…";
    status.className = "live-status";
    $("liveBtn").disabled = true;

    let lastError = null;
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        const data = await fetchLiveWithTimeout(url, packages);
        const warnings = Array.isArray(data.warnings) ? data.warnings : [];
        if (data.partial) warnings.unshift("OSV returned partial advisory detail; known vulnerability IDs are still shown where available.");
        saveLiveCache(packages, data.vulnerabilities);
        mergeLiveResults(data.vulnerabilities, data.partial ? "Partial live results" : `${data.vulnerabilities.length} advisories`, warnings);
        $("liveBtn").disabled = false;
        return;
      } catch (err) {
        lastError = err;
        if (!(err.retryable || err.name === "AbortError" || /Failed to fetch|NetworkError|Load failed/i.test(err.message)) || attempt === 2) break;
        status.textContent = "Retrying…";
        msg.textContent = `Live lookup attempt ${attempt} failed; retrying once without affecting the local scan.`;
        await new Promise(resolve => setTimeout(resolve, 900 * attempt));
      }
    }

    const cached = loadLiveCache(packages);
    if (cached) {
      mergeLiveResults(cached.vulnerabilities, "Cached fallback", [
        `Live lookup failed: ${liveFailureMessage(lastError)} Showing the last successful result for this exact package set from ${new Date(cached.checkedAt).toLocaleString()}.`
      ]);
      status.className = "live-status warn";
    } else {
      status.textContent = "Live check unavailable";
      status.className = "live-status bad";
      msg.hidden = false;
      msg.className = "live-message bad";
      if (previousLiveCount > 0) {
        msg.textContent = `${liveFailureMessage(lastError)} The previously displayed live advisory results are retained; they were not refreshed.`;
        state.liveSource = "Previous live results";
      } else {
        msg.textContent = `${liveFailureMessage(lastError)} No cached result exists for this exact package set.`;
        state.liveSource = null;
        $("liveVulns").textContent = "0";
        $("liveCritical").textContent = "0";
        $("liveFixable").textContent = "0";
      }
    }
    $("liveBtn").disabled = false;
  }

  function hasRule(findings, ...rules) {
    const set = new Set(rules);
    return findings.some(f => set.has(f.rule));
  }

  function findingFiles(findings, ...rules) {
    const set = new Set(rules);
    return [...new Set(findings.filter(f => set.has(f.rule)).map(f => f.file))];
  }

  function scanRepositoryMetadata(findings) {
    if (!state.repository) return;
    const repoFile = { name: state.repository.name, type: "repository" };

    for (const path of state.repository.sensitiveNames || []) {
      const lower = path.toLowerCase();
      const base = lower.split("/").pop();
      const privateKeyLike = /^(?:id_rsa|id_ed25519|id_ecdsa)$/.test(base) || /\.(?:pem|key|p12|pfx)$/.test(base);
      addFinding(findings, repoFile, {
        severity: privateKeyLike ? "high" : "medium",
        rule: privateKeyLike ? "repo-sensitive-key-file" : "repo-sensitive-config-file",
        title: privateKeyLike ? "Sensitive key/certificate file included in repository ZIP" : "Sensitive configuration filename included in repository ZIP",
        description: `The repository archive contains ${path}. Filename alone does not prove it contains a live credential, but this class of file deserves explicit review before source distribution.`,
        remediation: privateKeyLike
          ? "Confirm this file contains no private credential material. Remove private keys from source control and rotate any credential that may have been committed."
          : "Confirm the file contains only safe example values. Keep live environment credentials in an approved secret store and exclude local secret files from source control.",
        evidence: path,
        category: "Repository"
      });
    }

    if (state.repository.encrypted > 0) {
      addFinding(findings, repoFile, {
        severity: "info",
        rule: "repo-encrypted-files-skipped",
        title: "Encrypted ZIP entries were not inspected",
        description: `${state.repository.encrypted} encrypted archive entr${state.repository.encrypted === 1 ? "y was" : "ies were"} skipped because PipelineGuard does not request archive passwords.`,
        remediation: "Review encrypted repository content separately if it is security-relevant.",
        evidence: `${state.repository.encrypted} encrypted entry/entries skipped`,
        category: "Repository"
      });
    }

    if (state.repository.scannedFiles === 0) {
      addFinding(findings, repoFile, {
        severity: "info",
        rule: "repo-no-scannable-files",
        title: "No supported text files were selected from repository ZIP",
        description: "The repository archive was opened, but no supported security-relevant text files passed the filtering and size limits.",
        remediation: "Check whether the ZIP primarily contains generated/binary content or add the important files individually.",
        evidence: `${state.repository.totalEntries} ZIP entries inspected`,
        category: "Repository"
      });
    }
  }

  function scanRepositoryCorrelations(findings) {
    if (!state.repository) return;
    const repoFile = { name: state.repository.name, type: "repository" };

    const privilegedCI = hasRule(findings, "gha-pr-target-checkout", "gha-write-all", "gha-untrusted-run");
    const credentialMaterial = hasRule(findings,
      "secret-private-key","secret-aws-key","secret-github-token","secret-generic-assignment",
      "k8s-secret-manifest","repo-sensitive-key-file");
    if (privilegedCI && credentialMaterial) {
      const ciFiles = findingFiles(findings, "gha-pr-target-checkout","gha-write-all","gha-untrusted-run");
      const secretFiles = findingFiles(findings,
        "secret-private-key","secret-aws-key","secret-github-token","secret-generic-assignment","k8s-secret-manifest","repo-sensitive-key-file");
      addFinding(findings, repoFile, {
        severity: "critical",
        rule: "repo-correlation-ci-credentials",
        title: "Compound risk: privileged CI behavior and credential material coexist",
        description: "This repository contains both privileged/high-risk CI behavior and credential-like material. If untrusted code reaches a privileged workflow, credential exposure can substantially increase blast radius.",
        remediation: "Treat the CI trust boundary as a release blocker: isolate untrusted builds, minimize token permissions, remove committed credential material, and rotate any exposed live secrets.",
        evidence: `CI: ${ciFiles.slice(0,3).join(", ")} · Credentials: ${secretFiles.slice(0,3).join(", ")}`,
        category: "Correlation"
      });
    }

    const installExec = hasRule(findings, "npm-lifecycle-remote-exec", "composer-script-remote-exec", "shell-pipe-exec");
    if (installExec && privilegedCI) {
      addFinding(findings, repoFile, {
        severity: "critical",
        rule: "repo-correlation-supply-ci",
        title: "Compound risk: automatic package/build execution under privileged CI",
        description: "The repository combines automatic download/execute behavior or dangerous install hooks with privileged CI characteristics. A compromised dependency or remote script could execute with elevated workflow access.",
        remediation: "Remove pipe-to-shell/install-time remote execution, pin and verify build inputs, and run dependency installation with the minimum token permissions required.",
        evidence: "Supply-chain execution finding + privileged CI finding detected in the same repository.",
        category: "Correlation"
      });
    }

    const publicInfra = hasRule(findings, "tf-public-admin-ingress","tf-public-all-ingress","tf-public-ingress","tf-azure-public-admin","tf-azure-public-ingress","tf-gcp-public-admin","tf-gcp-public-ingress");
    const privilegedWorkload = hasRule(findings, "k8s-privileged","k8s-hostpath","k8s-host-process-namespace","k8s-root-user");
    if (publicInfra && privilegedWorkload) {
      addFinding(findings, repoFile, {
        severity: "critical",
        rule: "repo-correlation-public-privileged-workload",
        title: "Compound risk: public infrastructure and highly privileged workload configuration",
        description: "The repository contains internet-facing infrastructure controls and Kubernetes workload settings that materially reduce isolation. They may belong to different components, but together warrant architectural review.",
        remediation: "Confirm whether the public path can reach the privileged workload. Restrict ingress, remove unnecessary host/privileged access, and enforce hardened workload security contexts.",
        evidence: "Public IaC exposure + privileged Kubernetes configuration detected.",
        category: "Correlation"
      });
    }

    const publicDb = hasRule(findings, "tf-rds-public");
    if (publicDb && credentialMaterial) {
      addFinding(findings, repoFile, {
        severity: "high",
        rule: "repo-correlation-public-db-credentials",
        title: "Compound risk: public database configuration and repository credential material",
        description: "A publicly accessible database configuration exists in a repository that also contains credential-like or secret-manifest material.",
        remediation: "Keep production databases private where possible, restrict network sources, remove live credentials from source, and rotate any database credential that may have been committed.",
        evidence: "Public database + credential material detected in repository.",
        category: "Correlation"
      });
    }

    const imageRoot = hasRule(findings, "docker-no-user","docker-root-user");
    const runtimeRoot = hasRule(findings, "k8s-root-user","k8s-privileged");
    if (imageRoot && runtimeRoot) {
      addFinding(findings, repoFile, {
        severity: "high",
        rule: "repo-correlation-root-defense-depth",
        title: "Container image and Kubernetes runtime both weaken non-root isolation",
        description: "The image and orchestration configuration both contain root/privilege findings, reducing defense in depth if the application is compromised.",
        remediation: "Create an unprivileged image user and enforce non-root execution in Kubernetes with `runAsNonRoot`, restricted capabilities, and no privilege escalation.",
        evidence: "Docker root/user finding + Kubernetes root/privilege finding detected.",
        category: "Correlation"
      });
    }

    const publicHost = hasRule(findings, "tf-ec2-public-ip");
    const publicAdmin = hasRule(findings, "tf-public-admin-ingress");
    if (publicHost && publicAdmin) {
      addFinding(findings, repoFile, {
        severity: "critical",
        rule: "repo-correlation-public-admin-host",
        title: "Compound risk: public host addressing plus internet-wide administrative ingress",
        description: "The Terraform configuration includes both a public host address request and internet-wide administrative-port exposure.",
        remediation: "Remove direct public administration where possible. Use private networking, a hardened bastion/managed access service, and tightly scoped source ranges.",
        evidence: "Public EC2 IP + public SSH/RDP ingress detected.",
        category: "Correlation"
      });
    }
  }

  function runScan() {
    setStages("input", "done");
    setStages("secrets", "active");
    const findings = [];
    scanRepositoryMetadata(findings);

    for (const file of state.files) {
      scanSecrets(file, findings);
    }

    setStages("secrets", "done");
    setStages("cicd", "active");

    for (const file of state.files) {
      if (file.type === "github") scanGitHub(file, findings);
    }

    setStages("cicd", "done");
    setStages("docker", "active");

    for (const file of state.files) {
      if (file.type === "docker") scanDocker(file, findings);
      else if (file.type === "kubernetes") scanKubernetes(file, findings);
      else if (file.type === "yaml") scanGenericYaml(file, findings);
    }

    setStages("docker", "done");
    setStages("iac", "active");

    for (const file of state.files) {
      if (file.type === "terraform") scanTerraform(file, findings);
    }

    setStages("iac", "done");
    setStages("supply", "active");

    for (const file of state.files) {
      scanSupplyChainFile(file, findings);
    }
    scanSupplyChainCrossFile(findings);

    setStages("supply", "done");
    setStages("correlate", "active");
    scanRepositoryCorrelations(findings);
    setStages("correlate", "done");
    setStages("report", "done");

    findings.sort((a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.file.localeCompare(b.file) ||
      (a.line || 0) - (b.line || 0)
    );

    state.findings = findings;
    recomputeScore();
    state.scannedAt = new Date();
    state.currentFilter = "all";
    state.liveVulnerabilities = [];
    state.liveCheckedAt = null;
    $("liveVulns").textContent = "0";
    $("liveCritical").textContent = "0";
    $("liveFixable").textContent = "0";
    $("liveStatus").textContent = "Not checked";
    $("liveStatus").className = "live-status";
    $("liveMessage").hidden = true;
    collectLivePackages();
    renderResults();
  }

  function setStages(stage, status) {
    const el = document.querySelector(`[data-stage="${stage}"]`);
    if (!el) return;
    el.classList.remove("active", "done");
    if (status) el.classList.add(status);
  }

  function scoreDescriptor(score) {
    if (score >= 90) return ["Strong posture", "No major static-analysis issues were found in the supplied files. Review informational items and continue with runtime/dependency scanning."];
    if (score >= 75) return ["Good with improvements", "The configuration is generally solid, but several findings should be reviewed before production deployment."];
    if (score >= 50) return ["Moderate risk", "Meaningful security weaknesses were detected. Address high-severity findings before promoting this pipeline."];
    if (score >= 25) return ["High risk", "Multiple serious weaknesses reduce confidence in this pipeline. Prioritize critical and high findings before deployment."];
    return ["Critical risk", "The supplied configuration contains severe security signals. Treat critical findings as release blockers until reviewed and remediated."];
  }

  function scoreColor(score) {
    if (score >= 85) return "#36e69a";
    if (score >= 65) return "#9ddd57";
    if (score >= 45) return "#ffc14a";
    if (score >= 25) return "#ff714c";
    return "#ff496b";
  }

  function counts() {
    const c = { critical:0, high:0, medium:0, low:0, info:0, suppressed:0 };
    state.findings.forEach(f => {
      if (activeSuppression(f)) c.suppressed++;
      else c[f.severity]++;
    });
    return c;
  }

  function renderResults(resetFilter=true) {
    recomputeScore();
    const c = counts();
    $("scoreValue").textContent = state.score;
    $("scoreGauge").style.setProperty("--score", state.score);
    $("scoreGauge").style.background = `conic-gradient(${scoreColor(state.score)} ${state.score}%, #17293a 0)`;
    const [label, text] = scoreDescriptor(state.score);
    $("scoreLabel").textContent = label;
    $("scoreText").textContent = text;
    const note = $("suppressionScoreNote");
    if (c.suppressed) {
      note.hidden = false;
      note.textContent = `${c.suppressed} active suppression${c.suppressed === 1 ? " is" : "s are"} excluded from this score. Expired suppressions automatically reactivate.`;
    } else note.hidden = true;
    $("criticalCount").textContent = c.critical;
    $("highCount").textContent = c.high;
    $("mediumCount").textContent = c.medium;
    $("lowCount").textContent = c.low;
    $("allBadge").textContent = unsuppressedFindings().length;
    $("suppressedBadge").textContent = c.suppressed;
    $("copyBtn").disabled = false;
    $("exportBtn").disabled = false;
    updateSuppressionUI();

    if (resetFilter) {
      state.currentFilter = "all";
      document.querySelectorAll(".filter").forEach(b => b.classList.toggle("active", b.dataset.filter === "all"));
    }
    renderFindings();
  }

  function renderFindings() {
    const container = $("findings");
    const list = state.currentFilter === "suppressed"
      ? state.findings.filter(f => activeSuppression(f))
      : state.currentFilter === "all"
        ? state.findings.filter(f => !activeSuppression(f))
        : state.findings.filter(f => f.severity === state.currentFilter && !activeSuppression(f));

    if (!state.findings.length && state.score !== null) {
      container.innerHTML = `<div class="results-empty"><div class="empty-shield" aria-hidden="true">✓</div><strong>No findings from enabled v0.6.1 rules</strong><p>This is a static preflight result, not proof that the pipeline is vulnerability-free.</p></div>`;
      return;
    }
    if (!list.length) {
      container.innerHTML = `<div class="results-empty"><strong>No ${escapeHtml(state.currentFilter)} findings</strong></div>`;
      return;
    }

    container.innerHTML = list.map(f => {
      const suppression = activeSuppression(f);
      return `<article class="finding ${suppression ? "is-suppressed" : ""}">
        <div class="severity-bar ${f.severity}"></div>
        <div>
          <div class="finding-head">
            <div class="finding-title-row">
              <span class="sev-badge ${f.severity}">${escapeHtml(f.severity)}</span>
              <h3>${escapeHtml(f.title)}</h3>
            </div>
            <span class="finding-meta">${escapeHtml(f.file)}${f.line ? ` · line ${f.line}` : ""} · ${escapeHtml(f.rule)}</span>
          </div>
          <p class="finding-desc">${escapeHtml(f.description)}</p>
          ${f.evidence ? `<div class="evidence">${escapeHtml(f.evidence)}</div>` : ""}
          <div class="fix"><strong>Recommended fix:</strong> ${escapeHtml(f.remediation)}</div>
          ${suppression ? `<div class="suppressed-note"><b>Suppressed until ${escapeHtml(suppression.expiresAt)}:</b> ${escapeHtml(suppression.reason)}</div>` : ""}
          <div class="finding-actions">
            ${suppression
              ? `<button class="restore-btn" type="button" data-restore-finding="${escapeHtml(f.fingerprint)}">Restore finding</button>`
              : `<button class="suppress-btn" type="button" data-suppress-finding="${escapeHtml(f.fingerprint)}">Suppress / false positive</button>`}
          </div>
        </div>
      </article>`;
    }).join("");
  }

  function summaryText() {
    const c = counts();
    const lines = [
      `PipelineGuard v0.6.1 Security Preflight`,
      `Score: ${state.score}/100`,
      ...(state.repository ? [
        `Repository: ${state.repository.name}`,
        `Repository entries: ${state.repository.totalEntries}`,
        `Repository files analyzed: ${state.repository.scannedFiles}`,
        `Repository entries ignored: ${state.repository.ignoredFiles}`
      ] : []),
      `Files scanned: ${state.files.length}`,
      `Findings: ${state.findings.length} (${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info)`,
      ``,
      ...state.findings.map((f, i) =>
        `${i + 1}. [${f.severity.toUpperCase()}] ${f.title} — ${f.file}${f.line ? `:${f.line}` : ""}\n   Fix: ${f.remediation}`)
    ];
    return lines.join("\n");
  }

  async function copySummary() {
    try {
      await navigator.clipboard.writeText(summaryText());
      const btn = $("copyBtn");
      const old = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(() => btn.textContent = old, 1200);
    } catch {
      alert("Clipboard access is unavailable in this browser context.");
    }
  }

  function exportReport() {
    const c = counts();
    const generated = state.scannedAt ? state.scannedAt.toLocaleString() : new Date().toLocaleString();
    const activeRows = unsuppressedFindings();
    const suppressedRows = state.findings.filter(f => activeSuppression(f));
    const rows = activeRows.length ? activeRows.map(f => `
      <section class="finding ${f.severity}">
        <div class="top"><span class="badge">${escapeHtml(f.severity.toUpperCase())}</span><strong>${escapeHtml(f.title)}</strong></div>
        <div class="meta">${escapeHtml(f.file)}${f.line ? ` · line ${f.line}` : ""} · ${escapeHtml(f.rule)}</div>
        <p>${escapeHtml(f.description)}</p>
        ${f.evidence ? `<pre>${escapeHtml(f.evidence)}</pre>` : ""}
        <p class="fix"><b>Recommended fix:</b> ${escapeHtml(f.remediation)}</p>
      </section>`).join("") : `<p>No active findings from the enabled v0.6.1 rules.</p>`;
    const suppressedHtml = suppressedRows.length ? `<h2>Suppressed findings / exception register</h2>` + suppressedRows.map(f => {
      const s = activeSuppression(f);
      return `<section class="finding"><div class="top"><span class="badge">SUPPRESSED</span><strong>${escapeHtml(f.title)}</strong></div><div class="meta">${escapeHtml(f.file)} · ${escapeHtml(f.rule)}</div><p><b>Reason:</b> ${escapeHtml(s.reason)}</p><p><b>Expires:</b> ${escapeHtml(s.expiresAt)}</p></section>`;
    }).join("") : "";

    const html = `<!doctype html><html><head><meta charset="utf-8"><title>PipelineGuard Report</title>
<style>
body{font-family:Arial,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#172331;line-height:1.5}
h1{margin-bottom:4px}.muted,.meta{color:#647487}.score{font-size:40px;font-weight:800;margin:20px 0}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}.grid div{border:1px solid #dde5eb;border-radius:8px;padding:10px}.finding{border:1px solid #dde5eb;border-left:5px solid #8fa6ba;border-radius:8px;padding:14px;margin:12px 0}.finding.critical{border-left-color:#df2348}.finding.high{border-left-color:#ec633d}.finding.medium{border-left-color:#d99d17}.finding.low{border-left-color:#3989d8}.badge{font-size:10px;font-weight:bold;background:#edf2f6;border-radius:4px;padding:3px 5px;margin-right:8px}.meta{font-size:11px;margin-top:5px}pre{white-space:pre-wrap;background:#f5f7f9;padding:9px;border-radius:6px}.fix{background:#edf9f4;padding:9px;border-radius:6px}.footer{margin-top:30px;border-top:1px solid #dde5eb;padding-top:15px;font-size:11px;color:#647487}@media print{body{margin:0}.finding{break-inside:avoid}}</style>
</head><body>
<h1>PipelineGuard Security Preflight</h1><div class="muted">v0.6.1 · Generated ${escapeHtml(generated)} · Local static analysis</div>
<div class="score">${state.score}/100</div>
${state.repository ? `<p><b>Repository:</b> ${escapeHtml(state.repository.name)} · ${state.repository.totalEntries} entries · ${state.repository.scannedFiles} analyzed · ${state.repository.ignoredFiles} ignored</p>` : ""}
<div class="grid"><div><b>${state.files.length}</b><br>Files</div><div><b>${c.critical}</b><br>Critical</div><div><b>${c.high}</b><br>High</div><div><b>${c.medium}</b><br>Medium</div><div><b>${c.low}</b><br>Low</div></div>
<h2>Active findings</h2>${rows}${suppressedHtml}
<div class="footer">PipelineGuard v0.6.1 is a repository-aware static preflight scanner. It does not execute code or replace a full security assessment. Optional live advisory checks use the configured relay.</div>
</body></html>`;
    const blob = new Blob([html], { type: "text/html" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "PipelineGuard-Security-Report.html";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  function clearAll() {
    state.files = [];
    state.findings = [];
    state.score = null;
    state.scannedAt = null;
    state.livePackages = [];
    state.liveVulnerabilities = [];
    state.liveCheckedAt = null;
    state.repository = null;
    renderRepository();
    $("livePackages").textContent = "0";
    $("liveVulns").textContent = "0";
    $("liveCritical").textContent = "0";
    $("liveFixable").textContent = "0";
    $("liveStatus").textContent = "Not checked";
    $("liveStatus").className = "live-status";
    $("pasteArea").value = "";
    $("scoreValue").textContent = "—";
    $("scoreLabel").textContent = "Ready to scan";
    $("scoreText").textContent = "Add one or more files to generate a local DevSecOps preflight assessment.";
    $("scoreGauge").style.setProperty("--score", 100);
    $("scoreGauge").style.background = "conic-gradient(#36e69a 100%, #17293a 0)";
    ["criticalCount","highCount","mediumCount","lowCount"].forEach(id => $(id).textContent = "0");
    $("allBadge").textContent = "0";
    $("suppressedBadge").textContent = "0";
    $("suppressionScoreNote").hidden = true;
    $("copyBtn").disabled = true; $("exportBtn").disabled = true;
    document.querySelectorAll(".stage").forEach(el => el.classList.remove("active","done"));
    $("findings").innerHTML = `<div class="results-empty"><div class="empty-shield" aria-hidden="true">◇</div><strong>No scan results yet</strong><p>Your files stay on this device. Add files and run a scan to see prioritized findings.</p></div>`;
    renderFiles();
  }

  dropZone.addEventListener("click", () => fileInput.click());
  dropZone.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); } });
  fileInput.addEventListener("change", async () => { await addBrowserFiles([...fileInput.files]); fileInput.value = ""; });
  ["dragenter","dragover"].forEach(ev => dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.classList.add("drag"); }));
  ["dragleave","drop"].forEach(ev => dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.classList.remove("drag"); }));
  dropZone.addEventListener("drop", async e => { await addBrowserFiles([...e.dataTransfer.files]); });

  $("addPasteBtn").addEventListener("click", () => {
    const text = $("pasteArea").value;
    const name = $("pasteName").value.trim() || "pasted.txt";
    if (!text.trim()) return;
    upsertFile({ name, text });
    renderFiles();
  });
  $("badSampleBtn").addEventListener("click", () => { $("pasteName").value = "workflow.yml"; $("pasteArea").value = riskyWorkflow; });
  $("dockerSampleBtn").addEventListener("click", () => { $("pasteName").value = "Dockerfile"; $("pasteArea").value = riskyDocker; });
  $("k8sSampleBtn").addEventListener("click", () => { $("pasteName").value = "deployment.yaml"; $("pasteArea").value = riskyKubernetes; });
  $("tfSampleBtn").addEventListener("click", () => { $("pasteName").value = "main.tf"; $("pasteArea").value = riskyTerraform; });
  $("npmSampleBtn").addEventListener("click", () => { $("pasteName").value = "package.json"; $("pasteArea").value = riskyNpm; });
  $("pythonSampleBtn").addEventListener("click", () => { $("pasteName").value = "requirements.txt"; $("pasteArea").value = riskyPython; });
  $("clearBtn").addEventListener("click", clearAll);
  scanBtn.addEventListener("click", runScan);
  $("copyBtn").addEventListener("click", copySummary);
  $("exportBtn").addEventListener("click", exportReport);
  $("suppressForm").addEventListener("submit", saveSuppressionFromDialog);
  $("manageSuppressionsBtn").addEventListener("click", openSuppressionManager);
  $("suppressionsBtn").addEventListener("click", openSuppressionManager);
  $("quickstartBtn").addEventListener("click", () => { $("quickstartCard").hidden = false; $("quickstartCard").scrollIntoView({behavior:"smooth", block:"center"}); });
  $("runDemoBtn").addEventListener("click", runFirstMinuteDemo);
  $("dismissQuickstartBtn").addEventListener("click", () => { $("quickstartCard").hidden = true; storageSet("pipelineguardQuickstartSeen", "1"); });
  document.addEventListener("click", e => {
    const suppress = e.target.closest("[data-suppress-finding]");
    if (suppress) openSuppressionDialog(suppress.dataset.suppressFinding);
    const restore = e.target.closest("[data-restore-finding]");
    if (restore) restoreFinding(restore.dataset.restoreFinding);
    const del = e.target.closest("[data-delete-suppression]");
    if (del) restoreFinding(del.dataset.deleteSuppression);
    const close = e.target.closest("[data-close-dialog]");
    if (close) $(close.dataset.closeDialog)?.close();
  });
  $("liveBtn").addEventListener("click", checkLiveAdvisories);
  $("saveRelayBtn").addEventListener("click", saveRelayUrl);
  $("testRelayBtn").addEventListener("click", testRelayHealth);
  $("systemStatusBtn").addEventListener("click", openSystemStatus);
  $("statusTestRelayBtn").addEventListener("click", testRelayHealth);
  $("statusRefreshBtn").addEventListener("click", refreshSystemStatus);
  const savedRelay = storageGet("pipelineguardRelayUrl");
  if (savedRelay) $("relayUrl").value = savedRelay;

  $("filters").addEventListener("click", e => {
    const btn = e.target.closest("[data-filter]");
    if (!btn) return;
    state.currentFilter = btn.dataset.filter;
    document.querySelectorAll(".filter").forEach(b => b.classList.toggle("active", b === btn));
    renderFindings();
  });

  const dlg = $("helpDialog");
  $("helpBtn").addEventListener("click", () => dlg.showModal());

  refreshSystemStatus();
  loadSuppressions();
  if (storageGet("pipelineguardQuickstartSeen") === "1") $("quickstartCard").hidden = true;
  renderRepository();
  renderFiles();
})();