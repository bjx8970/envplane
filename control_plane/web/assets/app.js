import { mountTerminal } from "./terminal.js";

const main = document.querySelector("#main");
const nav = document.querySelector("#navigation");
const account = document.querySelector("#account");
const feedback = document.querySelector("#feedback");
const state = { user: null, csrf: null, screen: 0, onLeave: [] };

function el(tag, content = "", attrs = {}) {
  const node = document.createElement(tag);
  node.textContent = content;
  for (const [key, value] of Object.entries(attrs)) {
    if (value !== undefined && value !== null) node.setAttribute(key, value);
  }
  return node;
}

function announce(message) {
  feedback.textContent = message;
  clearTimeout(announce.timer);
  announce.timer = setTimeout(() => { feedback.textContent = ""; }, 5500);
}

async function api(path, method = "GET", data = {}) {
  const options = { method, credentials: "same-origin", cache: "no-store" };
  if (method !== "GET") {
    options.headers = { "Content-Type": "application/json", "X-CSRF-Token": state.csrf };
    options.body = JSON.stringify(data);
  }
  const result = await fetch("/api" + path, options);
  const body = await result.json();
  if (!result.ok) {
    if (result.status === 401 && state.user) {
      state.user = null;
      drawNavigation();
      await showLogin();
    }
    const error = new Error(body.message || "请求失败");
    error.status = result.status;
    throw error;
  }
  return body;
}

function section(parent, title) {
  const pane = el("section");
  pane.append(el("h2", title));
  parent.append(pane);
  return pane;
}

function button(label, run, primary = false) {
  const item = el("button", label, { type: "button", class: primary ? "primary" : undefined });
  item.addEventListener("click", async () => {
    item.disabled = true;
    try { await run(); } catch (error) { announce(error.message); }
    finally { item.disabled = false; }
  });
  return item;
}

function field(form, label, options = {}) {
  const wrapper = el("label", label);
  const input = el(options.tag || "input", "", options.attrs);
  if (options.value !== undefined) input.value = options.value;
  wrapper.append(input);
  form.append(wrapper);
  return input;
}

function select(form, label, choices, options = {}) {
  const input = field(form, label, { tag: "select", attrs: options.required ? { required: "" } : {} });
  if (options.empty !== undefined) input.append(el("option", options.empty, { value: "" }));
  choices.forEach(([value, label]) => input.append(el("option", label, { value })));
  if (options.value !== undefined) input.value = options.value;
  return input;
}

function submit(form, label, run) {
  const item = el("button", label, { type: "submit", class: "primary" });
  form.append(item);
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (item.disabled) return;
    item.disabled = true;
    try { await run(); } catch (error) { announce(error.message); }
    finally { item.disabled = false; }
  });
}

function formIn(parent) {
  const form = el("form");
  parent.append(form);
  return form;
}

function jsonField(form, title, initial, large = false) {
  const input = field(form, title, { tag: "textarea", value: JSON.stringify(initial, null, 2),
    attrs: { spellcheck: "false", class: large ? "code" : undefined } });
  return () => JSON.parse(input.value);
}

function changePage(title, name) {
  state.onLeave.splice(0).forEach(close => close());
  state.screen += 1;
  main.replaceChildren(el("h1", title));
  nav.querySelectorAll("button").forEach(item => {
    if (item.textContent === name) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
  const content = el("div");
  main.append(content);
  return content;
}

function drawNavigation() {
  account.textContent = state.user ? state.user.username : "";
  nav.replaceChildren();
  if (!state.user) return;
  nav.append(button("实验环境", showEnvironments));
  if (state.user.role !== "student") nav.append(button("课程与成员", showCourses));
  if (state.user.role === "admin") {
    nav.append(button("模板版本", showTemplates), button("插件实例", showPlugins),
      button("账户与配额", showAccounts), button("运维", () => showOperations()));
  }
  nav.append(button("个人资料", showProfile));
}

async function showLogin() {
  const area = changePage("登录");
  const session = await api("/session");
  state.csrf = session.csrf_token;
  const form = formIn(section(area, "平台账户"));
  const username = field(form, "用户名", { attrs: { required: "", autocomplete: "username" } });
  const password = field(form, "密码", { attrs: { required: "", type: "password", autocomplete: "current-password" } });
  submit(form, "登录", async () => {
    const session = await api("/login", "POST", { username: username.value, password: password.value });
    password.value = "";
    Object.assign(state, { user: session.user, csrf: session.csrf_token });
    drawNavigation();
    await showEnvironments();
  });
}

async function showProfile() {
  const area = changePage("个人资料", "个人资料");
  const profile = section(area, state.user.username);
  const form = formIn(profile);
  const name = field(form, "用户名", { value: state.user.username, attrs: { required: "" } });
  submit(form, "保存用户名", async () => {
    await api("/users/" + state.user.id, "PATCH", { username: name.value });
    state.user = (await api("/session")).user;
    drawNavigation();
    await showProfile();
  });
  const passwordForm = formIn(section(area, "修改密码"));
  const old = field(passwordForm, "当前密码", { attrs: { type: "password", required: "", autocomplete: "current-password" } });
  const current = field(passwordForm, "新密码", { attrs: { type: "password", required: "", autocomplete: "new-password" } });
  submit(passwordForm, "保存密码", async () => {
    await api("/me/password", "PUT", { current_password: old.value, new_password: current.value });
    state.user = null;
    drawNavigation();
    await showLogin();
  });
  profile.append(button("退出登录", async () => {
    await api("/logout", "POST");
    state.user = null;
    drawNavigation();
    await showLogin();
  }));
}

function parameterInputs(form, fields, candidates) {
  const getters = [];
  for (const [key, spec] of Object.entries(fields)) {
    const schema = spec.schema || spec.constraints || spec;
    const title = spec.label || key;
    const required = Boolean(spec.required && spec.default === undefined);
    const choices = spec.selector ? candidates[key] : schema.enum?.map(value => ({ value, label: String(value) }));
    let control, read;
    if (choices) {
      const defaultIndex = choices.findIndex(item => JSON.stringify(item.value) === JSON.stringify(spec.default));
      control = select(form, title, choices.map((item, index) => [index, item.label]),
        { required, empty: "请选择", value: defaultIndex >= 0 ? String(defaultIndex) : "" });
      read = () => control.value === "" ? undefined : choices[Number(control.value)].value;
    } else if (spec.type === "boolean") {
      control = select(form, title, [["true", "是"], ["false", "否"]], {
        required, empty: "请选择", value: spec.default === undefined ? "" : String(spec.default) });
      read = () => control.value === "" ? undefined : control.value === "true";
    } else if (["object", "array"].includes(spec.type)) {
      control = field(form, title, { tag: "textarea", attrs: { required: required ? "" : undefined },
        value: spec.default === undefined ? "" : JSON.stringify(spec.default) });
      read = () => control.value.trim() ? JSON.parse(control.value) : undefined;
    } else {
      const numeric = ["number", "integer"].includes(spec.type);
      control = field(form, title, { value: spec.default, attrs: {
        type: numeric ? "number" : "text", required: required ? "" : undefined,
        min: schema.minimum, max: schema.maximum, minlength: schema.minLength, maxlength: schema.maxLength,
        step: numeric ? (spec.type === "integer" ? 1 : "any") : undefined,
      } });
      read = () => control.value === "" && spec.default !== "" ? undefined :
        numeric ? control.valueAsNumber : control.value;
    }
    if (spec.description) control.parentElement.append(el("small", spec.description, { class: "muted" }));
    getters.push([key, read]);
  }
  return () => Object.fromEntries(getters.map(([key, read]) => [key, read()]).filter(([, value]) => value !== undefined));
}

function jobSubmitter(path) {
  let pending;
  return async data => {
    const signature = JSON.stringify(data);
    if (!pending || pending.signature !== signature) pending = { signature, key: crypto.randomUUID() };
    const result = await api(path, "POST", { ...data, request_key: pending.key });
    pending = null;
    await showJob(result.job_id);
  };
}

async function showJob(jobId) {
  const area = changePage("Job 执行结果", "实验环境");
  const screen = state.screen;
  const info = section(area, "执行状态");
  const output = el("output", "加载中");
  const steps = el("ul");
  info.append(output, steps);
  let navigation, cancel;
  const refresh = async () => {
    const job = await api("/jobs/" + jobId);
    if (state.screen !== screen) return;
    output.textContent = job.state;
    steps.replaceChildren(...job.steps.map(step => el("li", step.step_path + " · " + step.state)));
    if (!navigation) {
      navigation = button("返回环境", () => showEnvironment(job.environment_id));
      cancel = button("请求取消", async () => {
        await api("/jobs/" + jobId + "/cancel", "POST");
        announce("取消请求已提交");
      });
      info.append(navigation, cancel);
    }
    cancel.hidden = !["queued", "running"].includes(job.state);
    if (job.kind === "session_open" && job.state === "succeeded" && job.session_id) {
      const sessions = await api("/environments/" + job.environment_id + "/sessions");
      if (state.screen !== screen) return;
      const session = sessions.find(item => item.id === job.session_id);
      if (session?.state === "active") {
        showTerminal(job.environment_id, session);
        return;
      }
      info.append(el("p", "平台通道不可用 · " + (session?.state || "unknown")));
    }
    if (["queued", "running", "cancel_requested"].includes(job.state)) {
      const timer = setTimeout(() => refresh().catch(error => announce(error.message)), 800);
      state.onLeave[0] = () => clearTimeout(timer);
    }
  };
  await refresh();
  const logs = section(area, "Job 日志");
  logs.append(button("加载事件", async () => {
    const events = await api("/jobs/" + jobId + "/logs");
    logs.replaceChildren(logs.firstChild, el("pre", events.length ?
      events.map(item => item.sequence + " · " + item.code + " · " + item.created_at).join("\n") : "暂无日志事件"));
  }));
}

async function showOperations(before) {
  const area = changePage("运维", "运维");
  const screen = state.screen;
  const suffix = before ? "?before=" + encodeURIComponent(before) : "";
  const [status, page] = await Promise.all([
    api("/admin/operations/status"), api("/admin/blocked-jobs" + suffix),
  ]);
  if (state.screen !== screen) return;
  const overview = section(area, "控制面状态");
  const lease = status.coordinator;
  const quota = status.quarantined_quota;
  overview.append(el("p", status.status === "ready" ? "就绪" : "降级", { role: "status" }),
    el("p", `协调租约 ${lease.state} · 版本 ${lease.revision} · 上次续租 ${lease.heartbeat_at || "—"} · 到期 ${lease.expires_at || "—"}`),
    el("p", `隔离配额 · ${quota.affected_environments} 个受影响环境 · ${quota.environments} 环境额度 · ${quota.vms} VM · ${quota.vcpu} vCPU · ${quota.memory_mb} MiB`));
  if (status.capacity) {
    const table = el("table", "", { "aria-label": "执行池容量", class: "capacity-table" });
    const head = el("thead");
    const heading = el("tr");
    for (const label of ["执行池", "线程", "运行", "排队", "超期"]) {
      heading.append(el("th", label, { scope: "col" }));
    }
    head.append(heading);
    const body = el("tbody");
    const lanes = { ordinary: "普通操作", control: "控制调用", session: "交互会话" };
    for (const [lane, values] of Object.entries(status.capacity.lanes)) {
      const row = el("tr");
      row.append(el("th", lanes[lane] || lane, { scope: "row" }));
      for (const key of ["workers", "active", "queued", "overdue"]) row.append(el("td", values[key]));
      body.append(row);
    }
    table.append(head, body);
    overview.append(table);
    if (status.capacity.manual_restart_required) overview.append(el("p", "存在超期调用，需要人工重启。"));
  }
  overview.append(button("刷新运维状态", () => showOperations(before)));
  const jobs = section(area, "阻断 Job");
  if (!page.jobs.length) jobs.append(el("p", "暂无阻断 Job"));
  const list = el("ul", "", { class: "operations-list" });
  for (const job of page.jobs) {
    const item = el("li");
    item.append(button("查看 " + job.environment_name, () => showBlockedJob(job.job_id)),
      el("span", `${job.kind} · ${job.reason || job.state} · ${job.updated_at}`));
    list.append(item);
  }
  jobs.append(list);
  if (before) jobs.append(button("返回第一页", () => showOperations()));
  if (page.next_before) jobs.append(button("下一页", () => showOperations(page.next_before)));
}

const RECOVERY_ACTIONS = {
  review: "记录核对", poll: "查询原调用", apply_result: "应用已保存结果",
};
const RECOVERY_REASONS = {
  evidence_reviewed: "已阅览证据摘要", evidence_inconclusive: "证据不足，仍需核对",
  check_remote_status: "确认原调用的远端状态", apply_verified_result: "采用已保存的成功证据",
  external_success_declared: "管理员声明已独立核实外部成功",
};
const RECOVERY_STATES = {
  queued: "等待处理", running: "处置中", completed: "已完成", blocked: "仍阻断",
};
const RECOVERY_OUTCOMES = {
  reviewed: "已保存核对记录", result_applied: "已应用成功结果",
  remote_succeeded: "插件查询报告成功", remote_failed: "插件查询报告失败",
  external_verification_declared: "已保存外部核验声明",
  remote_still_pending: "远端仍在执行", unknown_external_result: "远端结果仍未知",
  protocol_error: "结果未通过协议验证", recovery_interrupted: "处置中断",
  recovery_could_not_proceed: "当前授权或依赖无法完成处置",
  request_no_longer_eligible: "原 Job 或授权条件已变化",
  call_deadline_exceeded: "查询超期", dispatch_capacity_unavailable: "查询容量不足",
};
const VERIFICATION_SOURCES = {
  provider_console: "供应商控制台", provider_api: "供应商 API", independent_record: "独立运维记录",
};
const VERIFICATION_METHODS = {
  matched_execution: "核对原调用记录", checked_resource_state: "检查外部资源状态",
  cross_checked_records: "交叉核对操作记录",
};

function externalVerificationForm(panel, save) {
  const form = formIn(panel);
  form.append(el("p", "请依据独立来源核实外部执行事实。平台将把以下内容记录为管理员声明。"));
  const source = select(form, "外部核验来源", Object.entries(VERIFICATION_SOURCES),
    { empty: "选择来源", required: true });
  const method = select(form, "外部核验方法", Object.entries(VERIFICATION_METHODS),
    { empty: "选择方法", required: true });
  const reference = field(form, "外部核验记录编号", { attrs: { required: "", maxlength: 128 } });
  const conclusion = select(form, "外部核验结论", [["confirmed_succeeded", "已独立核实原调用成功"]],
    { empty: "选择结论", required: true });
  submit(form, "保存外部核验声明", () => save({
    source: source.value, method: method.value, reference: reference.value, conclusion: conclusion.value,
  }));
}

function renderEvidenceSummary(panel, detail) {
  if (detail.outcome) panel.append(el("p", "插件报告 · " + detail.outcome));
  if (detail.protocol_error) panel.append(el("p", "结果未通过协议校验"));
  const labels = { target: "固定目标", current_reference: "当前续查引用",
    reported_reference: "返回的续查引用", evidence: "证据内容", output: "结果输出" };
  for (const [key, label] of Object.entries(labels)) {
    const value = detail[key];
    if (value) panel.append(el("p", `${label} · ${value.type} · ${value.bytes} 字节 · 指纹 ${value.fingerprint}`));
  }
  if (detail.method) panel.append(el("p", "来源方式 · " + detail.method));
  if (detail.external_reference_count !== undefined) {
    panel.append(el("p", `外部引用 ${detail.external_reference_count} 条 · 检查点 ${detail.checkpoint_count} 条`));
  }
}

async function showBlockedJob(jobId) {
  const area = changePage("阻断 Job", "运维");
  const screen = state.screen;
  const path = "/admin/blocked-jobs/" + jobId;
  const content = el("div");
  let timer;
  state.onLeave.push(() => clearTimeout(timer));
  area.append(button("返回运维", () => showOperations()), content);

  async function refresh() {
    clearTimeout(timer);
    const job = await api(path);
    if (state.screen !== screen) return;
    content.replaceChildren();
    const info = section(content, job.environment_name);
    info.append(el("p", `${job.kind} · ${job.state} · ${job.reason || job.group_state}`),
      el("p", "Job " + job.job_id), button("刷新处置状态", refresh));
    const busy = job.requests.some(request => ["queued", "running"].includes(request.state));

    function sendRecovery(action) {
      let pending;
      return async details => {
        const payload = { action, expected_revision: job.group_revision, ...details };
        const signature = JSON.stringify(payload);
        if (!pending || pending.signature !== signature) pending = { signature, key: crypto.randomUUID() };
        await api(path + "/recovery", "POST", { ...payload, request_key: pending.key });
        await refresh();
      };
    }

    const operations = section(content, "关联 Operation");
    if (!job.operations.length) operations.append(el("p", "暂无 Operation"));
    for (const operation of job.operations) {
      const item = el("div", "", { class: "operations-item" });
      item.append(el("h3", operation.step_path),
        el("p", `${operation.state} · ${operation.operation_id}`),
        el("p", operation.dispatch_intent_at ? "派发意图记录于 " + operation.dispatch_intent_at : "暂无派发意图"));
      if (job.recoverable && operation.can_poll && !busy) {
        const send = sendRecovery("poll");
        item.append(button("查询原调用", () => send({
          operation_id: operation.operation_id, reason: "check_remote_status",
        })));
      }
      operations.append(item);
    }

    const evidence = section(content, "证据");
    if (!job.evidence.length) evidence.append(el("p", "暂无执行证据"));
    for (const record of job.evidence) {
      const item = el("div", "", { class: "operations-item" });
      item.append(el("p", `${record.kind} · ${record.created_at}`), el("p", "证据 " + record.evidence_id),
        el("p", "Operation " + record.operation_id),
        el("p", record.call_attempt_id ? "来源调用 " + record.call_attempt_id : "来源调用未知"));
      const details = el("div");
      const attestation = job.requests.find(request => request.action === "review" &&
        request.actor_id === state.user.id && request.reason === "external_success_declared" &&
        request.evidence_id === record.evidence_id && request.expected_revision === job.group_revision);
      const review = sendRecovery("review");
      item.append(button("查看证据详情", async () => {
        const detail = await api(path + "/evidence/" + record.evidence_id);
        details.replaceChildren();
        renderEvidenceSummary(details, detail);
        if (job.state === "blocked" && !busy && detail.group_revision === job.group_revision) {
          details.append(button("记录已阅览摘要", () => review({
            operation_id: record.operation_id, evidence_id: record.evidence_id, reason: "evidence_reviewed",
          })));
          if (job.recoverable && record.can_apply && !attestation) {
            externalVerificationForm(details, verification => review({
              operation_id: record.operation_id, evidence_id: record.evidence_id,
              reason: "external_success_declared", verification,
            }));
          }
        }
      }), details);
      if (job.recoverable && record.can_apply && !busy) {
        if (attestation) {
          const send = sendRecovery("apply_result");
          item.append(button("应用已保存结果", () => send({
            operation_id: record.operation_id, evidence_id: record.evidence_id,
            confirmed_review_id: attestation.request_id, reason: "apply_verified_result",
          })));
        } else {
          item.append(el("p", "应用结果前请查看证据详情，并提交外部核验声明。"));
        }
      }
      evidence.append(item);
    }

    const history = section(content, "处置记录");
    if (!job.requests.length) history.append(el("p", "暂无处置记录"));
    for (const request of job.requests) {
      const record = el("div", "", { class: "operations-item" });
      const outcome = RECOVERY_OUTCOMES[request.outcome] || RECOVERY_STATES[request.state];
      record.append(el("p", `${RECOVERY_ACTIONS[request.action]} · ${outcome}`),
        el("p", `${RECOVERY_REASONS[request.reason]} · ${request.created_at}`),
        el("p", "管理员 " + request.actor_id));
      if (request.verification) {
        const verification = request.verification;
        record.append(el("p", `管理员外部核验 · ${VERIFICATION_SOURCES[verification.source]}` +
          ` · ${VERIFICATION_METHODS[verification.method]} · 原调用成功 · 记录指纹 ${verification.reference_fingerprint}`));
      }
      history.append(record);
    }
    if (job.state === "blocked" && !busy) {
      const form = formIn(history);
      const reason = select(form, "核对结论", ["evidence_reviewed", "evidence_inconclusive"]
        .map(key => [key, RECOVERY_REASONS[key]]));
      const send = sendRecovery("review");
      submit(form, "保存核对记录", () => send({ reason: reason.value }));
    }
    if (busy) timer = setTimeout(() => refresh().catch(error => announce(error.message)), 1200);
  }
  await refresh();
}

async function showEnvironments() {
  const area = changePage("实验环境", "实验环境");
  const records = await api("/environments");
  if (state.user.role !== "student") {
    const tools = el("div", "", { class: "actions" });
    tools.append(button("创建环境", showCreate, true));
    if (state.user.role === "teacher") tools.append(button("教师配额", showMyQuota));
    area.append(tools);
  }
  if (!records.length) area.append(el("p", "暂无可访问环境。", { class: "muted" }));
  for (const env of records) {
    const pane = section(area, env.name);
    pane.append(el("p", "环境就绪状态 · " + env.lifecycle), button("查看环境", () => showEnvironment(env.id)));
  }
}

async function showCreate() {
  const area = changePage("创建环境", "实验环境");
  const [courses, templates] = await Promise.all([api("/courses"), api("/templates")]);
  const pane = section(area, "课程和模板");
  if (!courses.length || !templates.some(v => v.status === "published")) {
    pane.append(el("p", "创建环境需要课程和已发布模板。"));
    return;
  }
  const form = formIn(pane);
  const course = select(form, "课程", courses.map(item => [item.id, item.name]));
  const template = select(form, "模板版本", templates.filter(v => v.status === "published")
    .map(item => [item.id, item.metadata.name + " · v" + item.version]));
  submit(form, "加载模板参数", async () => {
    const version = templates.find(item => item.id === template.value);
    const courseId = course.value;
    const candidates = Object.values(version.parameters || {}).some(spec => spec.selector)
      ? await api("/courses/" + courseId + "/templates/" + version.id + "/candidates") : {};
    const old = area.querySelector("[data-parameters]");
    if (old) old.remove();
    const params = section(area, version.metadata.name);
    params.dataset.parameters = "true";
    const input = formIn(params);
    const name = field(input, "环境名称", { attrs: { required: "", maxlength: 255 } });
    const read = parameterInputs(input, version.parameters || {}, candidates);
    const start = jobSubmitter("/environments");
    submit(input, "提交创建", () => start({
      course_id: courseId, template_version_id: version.id, name: name.value, parameters: read(),
    }));
  });
}

function renderActions(parent, entries, prefix) {
  for (const [key, spec] of Object.entries(entries)) {
    const box = el("details", "", { class: "card" });
    box.append(el("summary", spec.label));
    parent.append(box);
    box.addEventListener("toggle", async () => {
      if (!box.open || box.querySelector("form") || box.dataset.loading) return;
      box.dataset.loading = "true";
      try {
        const path = prefix + "/actions/" + encodeURIComponent(key);
        const candidates = Object.values(spec.parameters).some(field => field.selector)
          ? await api(path + "/candidates") : {};
        const form = formIn(box);
        const read = parameterInputs(form, spec.parameters, candidates);
        const start = jobSubmitter(path);
        submit(form, "执行「" + spec.label + "」", () => start({ parameters: read() }));
      } catch (error) { announce(error.message); }
      finally { delete box.dataset.loading; }
    });
  }
}

async function showEnvironment(id) {
  const area = changePage("环境详情", "实验环境");
  const base = "/environments/" + id;
  const env = await api(base);
  area.parentElement.querySelector("h1").textContent = env.name;
  const overview = section(area, "环境状态");
  overview.append(el("p", "环境就绪状态 · " + env.lifecycle), button("刷新状态", () => showEnvironment(id)));
  if (env.cleanup) {
    const cleanup = jobSubmitter(base + "/cleanup");
    overview.append(button("显式清理", () => {
      if (window.confirm("运行模板定义的清理流程？")) return cleanup({});
    }));
  }
  if (Object.keys(env.actions).length) renderActions(section(area, "环境动作"), env.actions, base);
  for (const resource of env.resources) {
    const card = section(area, resource.name + " · " + resource.type_label);
    card.append(el("p", "资源观测状态 · " + resource.state),
      el("p", "观测时间 · " + (resource.observed_at || "暂无") +
        (resource.observed_at && !resource.fresh ? "（已过期）" : ""), { class: "muted" }));
    if (Object.keys(resource.display).length) card.append(el("pre", JSON.stringify(resource.display, null, 2)));
    renderActions(card, resource.actions, "/resources/" + resource.id);
  }
  if (env.credentials.length) {
    const card = section(area, "环境凭据");
    for (const [index, credential] of env.credentials.entries()) {
      const slot = el("output");
      card.append(button("查看凭据 " + (index + 1), async () => {
        if (slot.textContent) { slot.textContent = ""; return; }
        const result = await api(base + "/credentials/" + credential.id, "POST");
        slot.textContent = result.encoding === "utf-8" ? result.value : "Base64 · " + result.value;
      }), slot);
    }
  }
  if (env.assignments && env.lifecycle !== "deleted") await renderAssignments(area, env, base);
  if (env.revocations?.length) {
    const card = section(area, "远端撤权");
    for (const rev of env.revocations) card.append(el("p", rev.status + " · " + rev.reason + " · " + rev.created_at));
  }
  if (env.jobs.length) {
    const card = section(area, "我的 Job");
    env.jobs.forEach(job => card.append(button(job.kind + " · " + job.state, () => showJob(job.id))));
  }
  await renderTerminalAccess(area, env, base);
}

async function renderAssignments(area, env, base) {
  const course = await api("/courses/" + env.course_id);
  const card = section(area, "环境分配");
  const group = new Map(course.groups.map(item => [item.id, item.name]));
  const student = new Map(course.members.map(item => [item.id, item.username]));
  for (const item of env.assignments) {
    const actions = el("p", group.get(item.group_id) || student.get(item.student_id) || "已离开课程的成员",
      { class: "actions" });
    actions.append(button("撤销分配", async () => {
      await api("/assignments/" + item.id, "DELETE");
      await showEnvironment(env.id);
    }));
    card.append(actions);
  }
  const form = formIn(card);
  const choices = [...course.groups.map(item => ["group_id:" + item.id, "小组 · " + item.name]),
    ...course.members.filter(item => item.active).map(item => ["student_id:" + item.id, "学生 · " + item.username])];
  const target = select(form, "分配对象", choices, { required: true, empty: "请选择" });
  submit(form, "添加分配", async () => {
    const [field, id] = target.value.split(":");
    await api(base + "/assignments", "POST", { [field]: id });
    await showEnvironment(env.id);
  });
}

async function showCourses() {
  const area = changePage("课程与成员", "课程与成员");
  const [courses, accounts] = await Promise.all([api("/courses"), api("/users")]);
  const pane = section(area, "新建课程");
  const form = formIn(pane);
  const name = field(form, "课程名称", { attrs: { required: "" } });
  const owner = state.user.role === "admin" ? select(form, "所属教师", accounts.filter(
    item => item.active && item.role === "teacher").map(item => [item.id, item.username]), { required: true }) : null;
  submit(form, "创建课程", async () => {
    await api("/courses", "POST", { name: name.value, owner_teacher_id: owner ? owner.value : state.user.id });
    await showCourses();
  });
  if (state.user.role === "teacher") {
    const students = section(area, "学生账户");
    students.append(button("管理学生账号", showAccounts));
  }
  for (const course of courses) section(area, course.name).append(button("查看课程", () => showCourse(course, accounts)));
}

async function showCourse(course, accounts) {
  const area = changePage(course.name, "课程与成员");
  const base = "/courses/" + course.id;
  const detail = await api(base);
  const groups = section(area, "小组");
  for (const group of detail.groups) {
    const actions = el("p", group.name, { class: "actions" });
    actions.append(button("删除小组", async () => {
      if (!window.confirm("删除此小组并撤销该组的分配路径？")) return;
      await api(base + "/groups/" + group.id, "DELETE");
      await showCourse(course, accounts);
    }));
    groups.append(actions);
  }
  const addGroup = formIn(groups);
  const groupName = field(addGroup, "小组名称", { attrs: { required: "" } });
  submit(addGroup, "创建小组", async () => {
    await api(base + "/groups", "POST", { name: groupName.value });
    await showCourse(course, accounts);
  });
  const members = section(area, "课程成员");
  const choices = detail.groups.map(item => [item.id, item.name]);
  for (const student of detail.members) {
    const item = formIn(members);
    item.append(el("strong", student.username));
    const group = select(item, "所属小组", choices, { empty: "未分组", value: student.group_id || "" });
    submit(item, "保存分组", async () => {
      await api(base + "/members/" + student.id, "PUT", { group_id: group.value || null });
      await showCourse(course, accounts);
    });
    item.append(button("移出课程", async () => {
      if (!window.confirm("将该学生移出课程？")) return;
      await api(base + "/members/" + student.id, "DELETE");
      await showCourse(course, accounts);
    }));
  }
  const enrollment = formIn(members);
  const enrolled = new Set(detail.members.map(item => item.id));
  const available = accounts.filter(item => item.role === "student" && item.active && !enrolled.has(item.id));
  const student = select(enrollment, "添加学生", available.map(item => [item.id, item.username]),
    { empty: "请选择", required: true });
  submit(enrollment, "添加成员", async () => {
    await api(base + "/members/" + student.value, "POST");
    await showCourse(course, accounts);
  });
  area.append(button("删除课程", async () => {
    if (!window.confirm("删除此课程？")) return;
    await api(base, "DELETE");
    await showCourses();
  }));
}

const quotaDimensions = { environments: "环境数", vms: "虚拟机数", vcpu: "vCPU", memory_mb: "内存（MB）" };

function quotaSummary(pane, quota) {
  pane.append(el("p", quota.limits ? "额度 · " + Object.entries(quotaDimensions)
    .map(([key, label]) => label + " " + quota.limits[key]).join(" · ") : "教师配额尚未配置。"));
  for (const [kind, usage] of Object.entries(quota.usage)) {
    pane.append(el("p", kind + " · " + Object.entries(quotaDimensions).map(
      ([key, label]) => label + " " + usage[key]).join(" · ")));
  }
}

async function showMyQuota() {
  const area = changePage("教师配额", "实验环境");
  quotaSummary(section(area, "用量与额度"), await api("/quota/" + state.user.id));
}

async function showAccounts() {
  const area = changePage("账户与配额", state.user.role === "admin" ? "账户与配额" : "课程与成员");
  const accounts = await api("/users");
  const form = formIn(section(area, "新建账户"));
  const name = field(form, "用户名", { attrs: { required: "" } });
  const password = field(form, "初始密码", { attrs: { type: "password", required: "", autocomplete: "new-password" } });
  const roles = [["student", "学生"], ["teacher", "教师"], ["admin", "管理员"]];
  const role = state.user.role === "admin" ? select(form, "角色", roles) : null;
  submit(form, "创建账户", async () => {
    await api("/users", "POST", { username: name.value, password: password.value, role: role?.value || "student" });
    password.value = "";
    await showAccounts();
  });
  for (const user of accounts.filter(item => item.manageable)) {
    const pane = section(area, user.username + " · " + user.role);
    const edit = formIn(pane);
    const username = field(edit, "用户名", { value: user.username, attrs: { required: "" } });
    submit(edit, "保存用户名", async () => {
      await api("/users/" + user.id, "PATCH", { username: username.value });
      await showAccounts();
    });
    const reset = formIn(pane);
    const passwordInput = field(reset, "新密码", { attrs: { required: "", type: "password", autocomplete: "new-password" } });
    submit(reset, "重置密码", async () => {
      await api("/users/" + user.id + "/password", "PUT", { password: passwordInput.value });
      passwordInput.value = "";
      announce("密码已更新");
    });
    pane.append(button(user.active ? "停用账户" : "启用账户", async () => {
      await api("/users/" + user.id + "/active", "PUT", { active: !user.active });
      await showAccounts();
    }), button("删除账户", async () => {
      if (!window.confirm("删除该平台账户？")) return;
      await api("/users/" + user.id, "DELETE");
      await showAccounts();
    }));
    if (state.user.role === "admin") {
      const assignRole = formIn(pane);
      const selected = select(assignRole, "角色", roles, { value: user.role });
      submit(assignRole, "保存角色", async () => {
        await api("/users/" + user.id + "/role", "PUT", { role: selected.value });
        await showAccounts();
      });
      if (user.role === "teacher" && user.active) {
        pane.append(button("管理配额", async () => {
          const path = "/quota/" + user.id;
          const quotas = section(pane, "教师配额");
          quotaSummary(quotas, await api(path));
          const editQuota = formIn(quotas);
          const quota = await api(path);
          const controls = Object.entries(quotaDimensions).map(([key, title]) => [
            key, field(editQuota, title, { value: quota.limits?.[key] || 0,
              attrs: { type: "number", min: 0, step: 1, required: "" } }),
          ]);
          submit(editQuota, "保存配额", async () => {
            await api(path, "PUT", { limits: Object.fromEntries(controls.map(([key, input]) => [key, input.valueAsNumber])) });
            await showAccounts();
          });
        }));
      }
    }
  }
}

async function showTemplates() {
  const area = changePage("模板版本", "模板版本");
  const versions = await api("/templates");
  const form = formIn(section(area, "新建草稿"));
  const templateIds = [...new Map(versions.map(v => [v.template_id, v.metadata.name])).entries()];
  const parent = select(form, "模板", templateIds, { empty: "新模板" });
  const draft = jsonField(form, "模板定义（JSON）", {
    schema_version: 1, metadata: { name: "" }, parameters: {},
    quota: { environments: 1, vms: 0, vcpu: 0, memory_mb: 0 }, create: { steps: [] },
    resources: [], actions: {}, cleanup: { steps: [], completion: { no_external_cleanup_required: true } },
    readiness: { require_steps: [] }, access: {},
  }, true);
  submit(form, "保存草稿", async () => {
    await api("/templates", "POST", { definition: draft(), ...(parent.value ? { template_id: parent.value } : {}) });
    await showTemplates();
  });
  for (const version of versions) {
    const pane = section(area, (version.metadata.name || "模板") + " · v" + version.version + " · " + version.status);
    const path = "/templates/" + version.id;
    if (version.status === "draft") {
      const edit = formIn(pane);
      const read = jsonField(edit, "草稿定义（JSON）", version.definition, true);
      submit(edit, "保存修改", async () => {
        await api(path, "PUT", { definition: read() });
        announce("草稿已保存");
      });
      pane.append(button("发布版本", async () => {
        await api(path, "PUT", { definition: read() });
        await api(path + "/publish", "POST");
        await showTemplates();
      }, true));
    } else {
      const details = el("details");
      details.append(el("summary", "查看固定定义"), el("pre", JSON.stringify(version.definition, null, 2)));
      pane.append(details);
      if (version.status === "published") pane.append(button("停用版本", async () => {
        await api(path + "/disable", "POST");
        await showTemplates();
      }));
    }
  }
}

async function showPlugins() {
  const area = changePage("插件实例", "插件实例");
  const { loaded, instances, unavailable } = await api("/admin/plugins");
  const manage = section(area, "新建插件实例");
  if (unavailable.length) manage.append(el("p", "未加载 · " + unavailable.join("、")));
  const form = formIn(manage);
  const key = select(form, "已加载插件", loaded.map(item => [item, item]), { required: true, empty: "请选择" });
  const alias = field(form, "实例别名", { attrs: { required: "" } });
  const configuration = jsonField(form, "配置及凭据引用（JSON）", { data: {}, allowed_secret_refs: [] });
  submit(form, "创建实例", async () => {
    await api("/admin/plugins", "POST", { plugin_key: key.value, instance_alias: alias.value, configuration: configuration() });
    await showPlugins();
  });
  const secretForm = formIn(section(area, "保存管理凭据"));
  const secret = field(secretForm, "凭据值", { attrs: { type: "password", required: "", autocomplete: "off" } });
  const ref = el("output");
  submit(secretForm, "加密保存", async () => {
    const result = await api("/admin/secrets", "POST", { value: secret.value });
    secret.value = "";
    ref.textContent = JSON.stringify(result);
  });
  secretForm.append(ref);
  for (const item of instances) {
    const pane = section(area, item.instance_alias + " · " + item.plugin_key);
    pane.append(el("p", item.available ? "可用" : "不可用"));
    const path = "/admin/plugins/" + item.id;
    if (item.needs_rebind) {
      pane.append(el("p", "当前配置版本绑定了旧插件代码。核对配置后可为新任务发布版本。"),
        button("为已加载插件发布配置", async () => {
          if (!window.confirm("确认将当前配置用于已加载插件？既有 Job 仍按各自的固定版本处理。")) return;
          await api(path + "/rebind", "POST", { expected_revision: item.configuration_revision });
          await showPlugins();
        }));
    }
    const edit = formIn(pane);
    const config = jsonField(edit, "当前配置（JSON）", item.configuration);
    submit(edit, "保存配置版本", async () => {
      await api(path, "PUT", { configuration: config(), expected_revision: item.configuration_revision });
      await showPlugins();
    });
    pane.append(button(item.enabled ? "停用实例" : "启用实例", async () => {
      await api(path + "/enabled", "PUT", { enabled: !item.enabled });
      await showPlugins();
    }), button("配置实例存储", () => showStorage(item, path)));
  }
}

async function showStorage(item, path) {
  const area = changePage(item.instance_alias, "插件实例");
  const data = await api(path + "/storage");
  const pane = section(area, "实例存储");
  const form = formIn(pane);
  const selected = select(form, "条目", data.map(record => [record.key, record.key]), { empty: "新条目" });
  const key = field(form, "存储键", { attrs: { required: "" } });
  const value = field(form, "存储内容（JSON）", { tag: "textarea", value: "{}", attrs: { class: "code" } });
  selected.addEventListener("change", () => {
    const existing = data.find(record => record.key === selected.value);
    key.value = existing?.key || "";
    key.readOnly = Boolean(existing);
    value.value = JSON.stringify(existing?.value || {}, null, 2);
  });
  submit(form, "保存存储版本", async () => {
    const existing = data.find(record => record.key === selected.value);
    await api(path + "/storage", "PUT", {
      key: key.value, value: JSON.parse(value.value), expected_version: existing?.version_id || null,
    });
    await showStorage(item, path);
  });
}

async function renderTerminalAccess(area, env, base) {
  const entries = [
    ...Object.entries(env.access).map(([key, spec]) => [base, key, spec]),
    ...env.resources.flatMap(resource => Object.entries(resource.access).map(
      ([key, spec]) => ["/resources/" + resource.id, key, { label: resource.name + " · " + spec.label }])),
  ];
  const manager = state.user.role !== "student";
  if (!entries.length && !manager) return;
  const sessions = await api(base + "/sessions");
  if (!entries.length && !sessions.length) return;
  const card = section(area, "浏览器终端");
  for (const [prefix, key, spec] of entries) {
    let requestKey;
    card.append(button("连接「" + spec.label + "」", async () => {
      requestKey ||= crypto.randomUUID();
      const result = await api(prefix + "/access/" + encodeURIComponent(key), "POST", { request_key: requestKey });
      requestKey = null;
      await showJob(result.job_id);
    }));
  }
  for (const session of sessions) {
    const line = el("p", session.username + " · " + session.template_entry + " · 平台状态 " + session.state,
      { class: "actions" });
    if (session.reason?.code) line.append(el("span", session.reason.code));
    if (session.state === "active") {
      line.append(button(manager && session.actor_id !== state.user.id ? "旁观终端" : "打开已连接终端",
        () => showTerminal(env.id, session)));
    }
    card.append(line);
  }
}

function showTerminal(environmentId, session) {
  const area = changePage("WebSSH", "实验环境");
  const pane = section(area, session.username + " · " + session.template_entry);
  mountTerminal(pane, { ...session, environment_id: environmentId, viewer_id: state.user.id }, {
    manager: state.user.role !== "student", api, el, button, announce,
    onLeave: close => state.onLeave.push(close),
  });
  pane.append(button("返回环境", () => showEnvironment(environmentId)));
}

async function start() {
  const session = await api("/session");
  Object.assign(state, { user: session.user, csrf: session.csrf_token });
  drawNavigation();
  if (state.user) await showEnvironments();
  else await showLogin();
}
start().catch(error => announce(error.message));
