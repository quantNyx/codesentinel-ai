const findings = [
  {
    id: "CS-1842",
    title: "Heap buffer overflow",
    type: "Buffer overflow",
    severity: "critical",
    repository: "quantnyx/api-server",
    file: "src/parser/input.c",
    line: 142,
    detected: "4 min ago",
    description: "The input length is not checked against the destination buffer capacity before data is copied. An attacker could provide an oversized payload to write beyond the bounds of the allocated buffer.",
    snippet: [
      { line: 140, code: "void parse_input(const char *input) {" },
      { line: 141, code: "    char buffer[256];" },
      { line: 142, code: "    strcpy(buffer, input);", highlighted: true },
      { line: 143, code: "    process(buffer);" },
      { line: 144, code: "}" },
    ],
    fix: "snprintf(buffer, sizeof(buffer), \"%s\", input);",
    cwe: "CWE-122",
  },
  {
    id: "CS-1838",
    title: "SQL injection vulnerability",
    type: "SQL injection",
    severity: "high",
    repository: "quantnyx/web-client",
    file: "app/api/search.py",
    line: 87,
    detected: "38 min ago",
    description: "User-controlled search text is concatenated into a SQL query. Use parameterized queries so the input is always treated as data rather than executable SQL.",
    snippet: [
      { line: 85, code: "def find_users(connection, query):" },
      { line: 86, code: `    sql = "SELECT * FROM users WHERE name = '"` },
      { line: 87, code: `    sql += query + "'"`, highlighted: true },
      { line: 88, code: "    return connection.execute(sql)" },
      { line: 89, code: "" },
    ],
    fix: 'connection.execute("SELECT * FROM users WHERE name = ?", (query,))',
    cwe: "CWE-89",
  },
  {
    id: "CS-1829",
    title: "Use-after-free in session handler",
    type: "Use after free",
    severity: "high",
    repository: "quantnyx/api-server",
    file: "src/session/manager.c",
    line: 209,
    detected: "2 hrs ago",
    description: "This pointer is accessed after its memory has been released. A subsequent allocation could reuse this region, leading to corrupted data or a crash.",
    snippet: [
      { line: 207, code: "void close_session(Session *session) {" },
      { line: 208, code: "    free(session->data);" },
      { line: 209, code: "    log_session(session->data);", highlighted: true },
      { line: 210, code: "    free(session);" },
      { line: 211, code: "}" },
    ],
    fix: "log_session(session->data);\n    free(session->data);",
    cwe: "CWE-416",
  },
  {
    id: "CS-1817",
    title: "Command injection via filename",
    type: "Command injection",
    severity: "high",
    repository: "quantnyx/worker",
    file: "worker/tasks.py",
    line: 56,
    detected: "5 hrs ago",
    description: "An unsanitized filename is interpolated into a shell command. A crafted filename could execute arbitrary shell commands in the worker process.",
    snippet: [
      { line: 54, code: "def convert_document(filename):" },
      { line: 55, code: '    command = f"convert {filename} output.pdf"' },
      { line: 56, code: "    subprocess.run(command, shell=True)", highlighted: true },
      { line: 57, code: "" },
      { line: 58, code: "    return Path('output.pdf')" },
    ],
    fix: "subprocess.run([\"convert\", filename, \"output.pdf\"], check=True)",
    cwe: "CWE-78",
  },
  {
    id: "CS-1805",
    title: "Null pointer dereference",
    type: "Null dereference",
    severity: "medium",
    repository: "quantnyx/api-server",
    file: "src/cache/lookup.c",
    line: 73,
    detected: "yesterday",
    description: "The result of the cache lookup may be null, but its fields are accessed without checking first. Missing cache entries can cause the service to crash.",
    snippet: [
      { line: 71, code: "CacheEntry *entry = cache_find(key);" },
      { line: 72, code: "" },
      { line: 73, code: "    return entry->value;", highlighted: true },
      { line: 74, code: "}" },
      { line: 75, code: "" },
    ],
    fix: 'return entry ? entry->value : NULL;',
    cwe: "CWE-476",
  },
  {
    id: "CS-1801",
    title: "Unsanitized HTML rendering",
    type: "Cross-site scripting",
    severity: "medium",
    repository: "quantnyx/web-client",
    file: "src/components/Preview.tsx",
    line: 118,
    detected: "yesterday",
    description: "Untrusted user content is rendered directly as HTML without sanitization, which could allow an attacker to inject executable markup into the page.",
    snippet: [
      { line: 116, code: "function CommentPreview({ content }) {" },
      { line: 117, code: "  return (" },
      { line: 118, code: "    <div dangerouslySetInnerHTML={{ __html: content }} />", highlighted: true },
      { line: 119, code: "  );" },
      { line: 120, code: "}" },
    ],
    fix: "Sanitize user-generated content with a trusted HTML sanitizer before rendering.",
    cwe: "CWE-79",
  },
  {
    id: "CS-1798",
    title: "Insecure temporary file",
    type: "Race condition",
    severity: "medium",
    repository: "quantnyx/worker",
    file: "worker/export.py",
    line: 94,
    detected: "2 days ago",
    description: "A predictable temporary filename is created without exclusive access or secure permissions. Another local process could create or replace the file first.",
    snippet: [
      { line: 92, code: "def export_report(data):" },
      { line: 93, code: '    path = "/tmp/report-output.csv"' },
      { line: 94, code: "    open(path, 'w').write(data)", highlighted: true },
      { line: 95, code: "    return path" },
      { line: 96, code: "" },
    ],
    fix: "Create a temporary file with tempfile.NamedTemporaryFile(mode=\"w\", delete=False).",
    cwe: "CWE-377",
  },
  {
    id: "CS-1785",
    title: "Weak cryptographic algorithm",
    type: "Weak cryptography",
    severity: "medium",
    repository: "quantnyx/auth-service",
    file: "auth/tokens.py",
    line: 31,
    detected: "3 days ago",
    description: "MD5 is not suitable for protecting security-sensitive data because it is vulnerable to collision attacks. Use a modern, purpose-built algorithm instead.",
    snippet: [
      { line: 29, code: "def hash_token(token):" },
      { line: 30, code: "    encoded = token.encode()" },
      { line: 31, code: "    return hashlib.md5(encoded).hexdigest()", highlighted: true },
      { line: 32, code: "" },
      { line: 33, code: "def verify_token(token, expected):" },
    ],
    fix: "hashlib.sha256(encoded).hexdigest()",
    cwe: "CWE-327",
  },
  {
    id: "CS-1772",
    title: "Missing authorization check",
    type: "Broken access control",
    severity: "medium",
    repository: "quantnyx/api-server",
    file: "app/routes/admin.py",
    line: 63,
    detected: "4 days ago",
    description: "This administrative endpoint is reachable without verifying that the requesting user has the required role.",
    snippet: [
      { line: 61, code: "@app.delete('/admin/users/<user_id>')" },
      { line: 62, code: "def delete_user(user_id):" },
      { line: 63, code: "    remove_user(user_id)", highlighted: true },
      { line: 64, code: "    return {'status': 'deleted'}" },
      { line: 65, code: "" },
    ],
    fix: "Check the authenticated user's admin role before performing the deletion.",
    cwe: "CWE-862",
  },
  {
    id: "CS-1761",
    title: "Integer overflow in size check",
    type: "Integer overflow",
    severity: "medium",
    repository: "quantnyx/worker",
    file: "src/buffer/allocate.cpp",
    line: 154,
    detected: "5 days ago",
    description: "Multiplying the unchecked element count can overflow before allocation, resulting in a smaller-than-requested buffer.",
    snippet: [
      { line: 152, code: "Buffer *allocate_items(size_t count) {" },
      { line: 153, code: "    size_t item_size = sizeof(Item);" },
      { line: 154, code: "    size_t size = count * item_size;", highlighted: true },
      { line: 155, code: "    return malloc(size);" },
      { line: 156, code: "}" },
    ],
    fix: "Check count <= SIZE_MAX / item_size before multiplication.",
    cwe: "CWE-190",
  },
  {
    id: "CS-1744",
    title: "Unbounded input accepted",
    type: "Resource exhaustion",
    severity: "low",
    repository: "quantnyx/web-client",
    file: "src/api/upload.ts",
    line: 44,
    detected: "1 week ago",
    description: "Uploaded data is accepted without an explicit size limit. Consider enforcing a maximum size before processing to prevent excessive resource use.",
    snippet: [
      { line: 42, code: "async function uploadDocument(file: File) {" },
      { line: 43, code: "  const formData = new FormData();" },
      { line: 44, code: "  formData.append('file', file);", highlighted: true },
      { line: 45, code: "  return fetch('/api/upload', {" },
      { line: 46, code: "    method: 'POST', body: formData," },
    ],
    fix: "if (file.size > MAX_UPLOAD_BYTES) throw new Error(\"File too large\");",
    cwe: "CWE-400",
  },
  {
    id: "CS-1720",
    title: "Debug information exposed",
    type: "Information disclosure",
    severity: "low",
    repository: "quantnyx/auth-service",
    file: "auth/config.py",
    line: 18,
    detected: "1 week ago",
    description: "Detailed debug errors are enabled in this configuration. Disable debug output in environments where responses may be exposed to end users.",
    snippet: [
      { line: 16, code: "app = create_app()" },
      { line: 17, code: "app.config['SECRET_KEY'] = secret" },
      { line: 18, code: "app.config['DEBUG'] = True", highlighted: true },
      { line: 19, code: "app.run(host='0.0.0.0')" },
      { line: 20, code: "" },
    ],
    fix: "Set DEBUG from a protected deployment environment variable.",
    cwe: "CWE-215",
  },
];

let repositories = [
  { name: "quantnyx/api-server", branch: "main", issues: 5, health: "review", scanned: "4m ago", initials: "A", language: "C · Python" },
  { name: "quantnyx/web-client", branch: "main", issues: 3, health: "review", scanned: "38m ago", initials: "W", language: "TypeScript" },
  { name: "quantnyx/worker", branch: "develop", issues: 2, health: "review", scanned: "2h ago", initials: "W", language: "C++ · Python" },
  { name: "quantnyx/auth-service", branch: "main", issues: 2, health: "clean", scanned: "1d ago", initials: "A", language: "Python" },
  { name: "quantnyx/docs", branch: "main", issues: 0, health: "clean", scanned: "2d ago", initials: "D", language: "Markdown" },
  { name: "quantnyx/infra", branch: "main", issues: 0, health: "clean", scanned: "3d ago", initials: "I", language: "Terraform" },
];

let activeFilter = "all";
let pageNumber = 1;
let toastTimer;
let scanTimer;
const findingsBody = document.querySelector("#findings-body");
const searchInput = document.querySelector("#finding-search");
const dialog = document.querySelector("#app-dialog");
const dialogContent = document.querySelector("#dialog-content");

function iconForFinding(severity) {
  if (severity === "critical") {
    return '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="m10 2.5 7.5 13h-15l7.5-13Z"/><path d="M10 7v4m0 2.2v.1"/></svg>';
  }
  if (severity === "medium") {
    return '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="7"/><path d="M10 6v4.2l2.8 1.5"/></svg>';
  }
  return '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 4.5h12v11H4zM7 8h6m-6 3h4"/></svg>';
}

function getVisibleFindings() {
  const query = searchInput.value.trim().toLowerCase();
  return findings.filter((finding) => {
    const matchesSeverity = activeFilter === "all" || finding.severity === activeFilter;
    const matchesQuery = !query || [
      finding.title, finding.type, finding.repository, finding.file, finding.id, finding.severity, finding.cwe,
    ].some((value) => value.toLowerCase().includes(query));
    return matchesSeverity && matchesQuery;
  });
}

function renderFindings() {
  const visibleFindings = getVisibleFindings();
  const pageSize = 5;
  const pages = Math.max(1, Math.ceil(visibleFindings.length / pageSize));
  pageNumber = Math.min(pageNumber, pages);
  const start = (pageNumber - 1) * pageSize;
  const shown = visibleFindings.slice(start, start + pageSize);
  findingsBody.innerHTML = shown.map((finding) => {
    const severityLabel = finding.severity[0].toUpperCase() + finding.severity.slice(1);
    return `<tr class="finding-row" tabindex="0" data-finding-id="${finding.id}" aria-label="${finding.title}, ${severityLabel}, ${finding.repository}">
      <td><div class="finding-title"><span class="finding-icon icon-${finding.severity}">${iconForFinding(finding.severity)}</span><span class="finding-copy"><strong>${finding.title}</strong><small>${finding.file}:${finding.line}</small></span></div></td>
      <td><span class="severity-badge severity-${finding.severity}">${severityLabel}</span></td>
      <td><span class="repo-cell"><span class="repo-avatar">${finding.repository.split("/")[1][0].toUpperCase()}</span><span>${finding.repository.split("/")[1]}</span></span></td>
      <td class="date-cell">${finding.detected}</td>
      <td class="row-arrow">›</td>
    </tr>`;
  }).join("");
  document.querySelector("#visible-count").textContent = visibleFindings.length;
  document.querySelector("#showing-range").textContent = visibleFindings.length
    ? `${start + 1}–${start + shown.length}`
    : "0";
  document.querySelector(".table-footer > span").innerHTML =
    `Showing <strong id="showing-range">${visibleFindings.length ? `${start + 1}–${start + shown.length}` : "0"}</strong> of <strong>${visibleFindings.length}</strong> findings`;
  document.querySelector(".empty-state").hidden = shown.length > 0;
  document.querySelector("#findings-panel .table-scroll").classList.toggle("has-empty", shown.length === 0);
  document.querySelector(".pagination .page-number.active")?.classList.remove("active");
  document.querySelectorAll(".pagination .page-number").forEach((button, index) => {
    button.hidden = index >= pages;
    button.setAttribute("aria-current", index + 1 === pageNumber ? "page" : "false");
    if (index + 1 === pageNumber) button.classList.add("active");
  });
  document.querySelector('.pagination button[aria-label="Previous page"]').disabled = pageNumber === 1;
  document.querySelector('.pagination button[aria-label="Next page"]').disabled = pageNumber === pages;
}

function renderRepositories() {
  const inner = document.createElement("div");
  inner.className = "repository-list-inner";
  inner.innerHTML = repositories.map((repository) => `
    <div class="repository-row">
      <div class="repository-identity"><span class="repository-avatar">${repository.initials}</span><span class="repository-name"><strong>${repository.name}</strong><small>${repository.language}</small></span></div>
      <span class="branch-badge">⑂ ${repository.branch}</span>
      <span class="repo-issue-count ${repository.issues ? "warn" : ""}">${repository.issues.toString().padStart(2, "0")} issues</span>
      <span class="scan-health ${repository.health === "review" ? "review" : ""}">${repository.health === "review" ? "Needs review" : "Protected"}</span>
      <span class="last-scan">${repository.scanned}</span>
    </div>
  `).join("");
  const list = document.querySelector("#repository-list");
  list.replaceChildren(inner);
  document.querySelector("#stat-repositories").textContent = repositories.length.toString().padStart(2, "0");
  document.querySelector(".nav-count").textContent = repositories.length.toString();
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

function showFinding(id) {
  const finding = findings.find((item) => item.id === id);
  if (!finding) return;
  const severityLabel = finding.severity[0].toUpperCase() + finding.severity.slice(1);
  const snippet = finding.snippet.map(({ line, code, highlighted }) => `
    <div class="code-line${highlighted ? " highlighted" : ""}"><span class="line-number">${line}</span><span>${escapeHtml(code)}</span></div>
  `).join("");
  dialogContent.innerHTML = `
    <div class="dialog-eyebrow">${finding.id} · ${finding.cwe}</div>
    <h2 id="dialog-title">${finding.title}</h2>
    <p>${finding.description}</p>
    <div class="finding-meta"><span class="severity-badge severity-${finding.severity}">${severityLabel}</span><span class="meta-text">${finding.repository}</span></div>
    <section class="detail-block"><h3>Vulnerable code <span class="meta-text">· ${finding.file}:${finding.line}</span></h3><div class="code-frame">${snippet}</div></section>
    <section class="detail-block"><h3>Why it matters</h3><div class="detail-note">${finding.description}</div></section>
    <section class="detail-block remediation-block"><h3>Suggested remediation</h3><div class="code-frame"><div class="code-line"><span class="line-number">+</span><span>${escapeHtml(finding.fix)}</span></div></div></section>
    <div class="dialog-action-row"><button class="dialog-button" data-action="close-dialog">Close</button><button class="dialog-button dialog-button-primary" data-action="dismiss-finding" data-finding-id="${finding.id}">Mark as resolved</button></div>
  `;
  dialog.showModal();
}

function showToast(message, isError = false) {
  const region = document.querySelector("#toast-region");
  region.replaceChildren();
  clearTimeout(toastTimer);
  const toast = document.createElement("div");
  toast.className = `toast${isError ? " toast-error" : ""}`;
  toast.innerHTML = `<span>${isError ? "!" : "✓"}</span><span>${escapeHtml(message)}</span><button class="toast-dismiss" aria-label="Dismiss notification">×</button>`;
  region.append(toast);
  toast.querySelector(".toast-dismiss").addEventListener("click", () => toast.remove());
  toastTimer = setTimeout(() => toast.remove(), 3600);
}

function openConnectDialog() {
  dialogContent.innerHTML = `
    <div class="dialog-eyebrow">REPOSITORY INTEGRATION</div>
    <h2 id="dialog-title">Connect a repository</h2>
    <p>Bring your code into CodeSentinel. Connect a GitHub repository to keep your team’s findings in one place.</p>
    <form id="connect-form">
      <label class="form-field"><span>Repository name</span><input name="repository" required pattern="[A-Za-z0-9_.\\-]+\\/[A-Za-z0-9_.\\-]+" placeholder="quantnyx/my-project" autocomplete="off"><span class="form-help">Enter your organization and repository, separated by a slash.</span></label>
      <div class="connect-options"><button class="connect-option" type="button" data-action="provider-github"><span class="option-icon">⌘</span> Connect GitHub</button><button class="connect-option" type="button" data-action="provider-gitlab"><span class="option-icon">◈</span> Connect GitLab</button></div>
      <div class="dialog-action-row"><button class="dialog-button" type="button" data-action="close-dialog">Cancel</button><button class="dialog-button dialog-button-primary" type="submit">Add repository</button></div>
    </form>
    <p class="demo-notice">Demo mode: repository names are stored in this page session only.</p>
  `;
  dialog.showModal();
}

function openScanDialog() {
  const suggestedRepository = repositories[0]?.name ?? "quantnyx/api-server";
  dialogContent.innerHTML = `
    <div class="dialog-eyebrow">ON-DEMAND SECURITY ANALYSIS</div>
    <h2 id="dialog-title">Run a security scan</h2>
    <p>Start a simulated scan to preview the CodeSentinel analysis workflow and PR-style findings.</p>
    <label class="form-field"><span>Repository</span><input id="scan-repository" list="repository-options" value="${escapeHtml(suggestedRepository)}" autocomplete="off"><datalist id="repository-options">${repositories.map((repository) => `<option value="${escapeHtml(repository.name)}"></option>`).join("")}</datalist></label>
    <div class="dialog-action-row"><button class="dialog-button" data-action="close-dialog">Cancel</button><button class="dialog-button dialog-button-primary" data-action="start-scan">Start demo scan</button></div>
    <p class="demo-notice">This UI demo does not connect to a repository or perform a real ML analysis.</p>
  `;
  dialog.showModal();
}

function finishDemoScan(repositoryName, button) {
  const repoName = repositoryName.split("/").pop();
  const repo = repositories.find((item) => item.name.toLowerCase() === repositoryName.toLowerCase());
  if (repo) repo.scanned = "just now";
  const status = dialogContent.querySelector(".scan-modal-status");
  if (status) {
    status.innerHTML = `<span class="step-check">✓</span><span><strong>Demo scan complete</strong><small>${escapeHtml(repoName)} · Previewed 3 sample findings</small></span>`;
  }
  if (button) {
    button.disabled = false;
    button.innerHTML = "Run again";
  }
  if (repo) renderRepositories();
  showToast("Demo scan complete — 3 sample findings reviewed");
}

function startDemoScan() {
  const input = document.querySelector("#scan-repository");
  const repositoryName = input?.value.trim();
  if (!repositoryName || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repositoryName)) {
    input?.setCustomValidity("Use the format organization/repository.");
    input?.reportValidity();
    return;
  }
  input.setCustomValidity("");
  const button = dialogContent.querySelector('[data-action="start-scan"]');
  if (button.disabled) return;
  button.disabled = true;
  button.innerHTML = '<span class="scan-spinner" aria-hidden="true"></span> Analyzing…';
  let status = dialogContent.querySelector(".scan-modal-status");
  if (!status) {
    status = document.createElement("div");
    status.className = "scan-modal-status";
    status.setAttribute("role", "status");
    button.closest(".dialog-action-row").before(status);
  }
  status.innerHTML = `<span class="scan-spinner" aria-hidden="true"></span><span><strong>Analyzing code structure…</strong><small>${escapeHtml(repositoryName)} · Parsing AST and mapping data flow</small></span>`;
  clearTimeout(scanTimer);
  scanTimer = setTimeout(() => finishDemoScan(repositoryName, button), 1600);
}

function updateNav(page) {
  const pages = {
    overview: ["Overview", "Here’s what’s happening across your codebase today."],
    repositories: ["Repositories", "Monitor security across all your connected repositories."],
    findings: ["Findings", "Review, prioritize, and resolve security issues across your codebase."],
    activity: ["Activity", "Track scans and security findings across your workspace."],
  };
  const [title, subtitle] = pages[page] ?? pages.overview;
  document.querySelector("#breadcrumb-current").textContent = title;
  document.querySelector("#page-title").innerHTML = page === "overview"
    ? 'Good morning, Sakib <span class="wave">✳</span>'
    : escapeHtml(title);
  document.querySelector("#page-subtitle").textContent = subtitle;
  document.querySelectorAll(".nav-item").forEach((item) => {
    const isActive = item.dataset.page === page;
    item.classList.toggle("active", isActive);
    if (isActive) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
  if (page === "findings") {
    document.querySelector("#findings-panel").scrollIntoView({ behavior: "smooth", block: "start" });
    searchInput.focus({ preventScroll: true });
  }
  if (page === "repositories") {
    document.querySelector("#repositories-panel").scrollIntoView({ behavior: "smooth", block: "start" });
  }
  if (page === "activity") {
    document.querySelector(".scan-panel").scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  const { action, page, filter, findingId } = button.dataset;
  if (page) {
    updateNav(page);
    if (button.classList.contains("text-button") && page === "findings") {
      activeFilter = "all";
      document.querySelectorAll(".filter-tab").forEach((tab) => {
        tab.classList.toggle("active", tab.dataset.filter === "all");
        tab.setAttribute("aria-selected", tab.dataset.filter === "all" ? "true" : "false");
      });
      renderFindings();
    }
    return;
  }
  if (filter) {
    activeFilter = filter;
    pageNumber = 1;
    document.querySelectorAll(".filter-tab").forEach((tab) => {
      const isActive = tab === button;
      tab.classList.toggle("active", isActive);
      tab.setAttribute("aria-selected", isActive ? "true" : "false");
    });
    renderFindings();
    return;
  }
  switch (action) {
    case "connect":
      openConnectDialog();
      break;
    case "upgrade":
      showToast("Plan options will be available soon.");
      break;
    case "profile":
      showToast("Signed in as Sakib Al Hasan.");
      break;
    case "help":
      showToast("CodeSentinel demo — security guidance is shown on each finding.");
      break;
    case "notifications":
      showToast("You have 4 high-priority findings to review.");
      break;
    case "close-dialog":
      clearTimeout(scanTimer);
      dialog.close();
      break;
    case "dismiss-tip":
      button.closest(".tip-card").remove();
      break;
    case "clear-filters":
      searchInput.value = "";
      activeFilter = "all";
      pageNumber = 1;
      document.querySelectorAll(".filter-tab").forEach((tab) => {
        tab.classList.toggle("active", tab.dataset.filter === "all");
        tab.setAttribute("aria-selected", tab.dataset.filter === "all" ? "true" : "false");
      });
      renderFindings();
      searchInput.focus();
      break;
    case "start-scan":
      startDemoScan();
      break;
    case "provider-github":
      showToast("GitHub OAuth is not connected in this demo.");
      break;
    case "provider-gitlab":
      showToast("GitLab OAuth is not connected in this demo.");
      break;
    case "settings":
      showToast("Workspace settings are not available in this demo.");
      break;
    case "dismiss-finding":
      if (findingId) {
        const index = findings.findIndex((finding) => finding.id === findingId);
        if (index !== -1) {
          const [resolved] = findings.splice(index, 1);
          document.querySelector("#stat-findings").textContent = findings.length.toString().padStart(2, "0");
          const repository = repositories.find((repo) => repo.name === resolved.repository);
          if (repository) repository.issues = Math.max(0, repository.issues - 1);
          const unresolvedCount = findings.filter((finding) => finding.severity === "critical" || finding.severity === "high").length;
          document.querySelector("#stat-critical").textContent = unresolvedCount.toString().padStart(2, "0");
          document.querySelector('.nav-item[data-page="findings"] .nav-count').textContent = findings.length.toString();
          document.querySelectorAll(".filter-tab").forEach((tab) => {
            const count = tab.dataset.filter === "all"
              ? findings.length
              : findings.filter((finding) => finding.severity === tab.dataset.filter).length;
            const countLabel = tab.querySelector("span:last-child");
            if (countLabel) countLabel.textContent = count.toString();
          });
          renderFindings();
          renderRepositories();
        }
      }
      dialog.close();
      showToast("Finding marked as resolved.");
      break;
    case "next-page": {
      const pages = Math.max(1, Math.ceil(getVisibleFindings().length / 5));
      if (button.getAttribute("aria-label") === "Previous page") pageNumber = Math.max(1, pageNumber - 1);
      else pageNumber = Math.min(pages, pageNumber + 1);
      renderFindings();
      break;
    }
    case undefined:
      if (button.id === "scan-button") openScanDialog();
      break;
  }
});

findingsBody.addEventListener("click", (event) => {
  const row = event.target.closest("[data-finding-id]");
  if (row) showFinding(row.dataset.findingId);
});

findingsBody.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const row = event.target.closest("[data-finding-id]");
  if (row) {
    event.preventDefault();
    showFinding(row.dataset.findingId);
  }
});

searchInput.addEventListener("input", () => {
  pageNumber = 1;
  renderFindings();
});

dialog.addEventListener("click", (event) => {
  if (event.target === dialog) dialog.close();
});

dialog.addEventListener("close", () => clearTimeout(scanTimer));

dialog.addEventListener("submit", (event) => {
  if (event.target.id !== "connect-form") return;
  event.preventDefault();
  const input = event.target.elements.repository;
  const name = input.value.trim();
  if (!event.target.reportValidity()) return;
  if (repositories.some((repository) => repository.name.toLowerCase() === name.toLowerCase())) {
    input.setCustomValidity("This repository is already connected.");
    input.reportValidity();
    return;
  }
  input.setCustomValidity("");
  repositories.unshift({
    name,
    branch: "main",
    issues: 0,
    health: "clean",
    scanned: "not yet",
    initials: name.split("/")[1][0].toUpperCase(),
    language: "Ready to scan",
  });
  renderRepositories();
  dialog.close();
  showToast(`${name} added to your workspace.`);
});

document.addEventListener("input", (event) => {
  if (event.target.id === "scan-repository" || event.target.name === "repository") {
    event.target.setCustomValidity("");
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && dialog.open) {
    clearTimeout(scanTimer);
  }
});

renderFindings();
renderRepositories();
