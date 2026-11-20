/* Real-browser acceptance. Use only with the disposable p5_fixture server. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const [origin, fixturePath, executablePath, playwrightPath] = process.argv.slice(2);
const { chromium } = require(playwrightPath || "playwright-core");
const password = "p5-platform-test-only";
const { target } = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
const definition = JSON.parse(fs.readFileSync(path.join(__dirname, "p5_template.json"), "utf8"));

function btn(page, name) {
  return page.getByRole("button", { name, exact: true });
}
function heading(page, name) {
  return page.getByRole("heading", { name, exact: typeof name === "string" });
}
function panel(page, name) {
  return page.locator("section").filter({ has: heading(page, name) });
}
async function login(browser, user) {
  const page = await browser.newPage({ viewport: { width: 1250, height: 900 } });
  page.setDefaultTimeout(15000);
  page.on("pageerror", error => console.error("Browser error:", error.message));
  page.on("response", response => {
    if (response.status() >= 400) console.error("HTTP", response.status(), new URL(response.url()).pathname);
  });
  await page.goto(origin);
  await heading(page, "登录").waitFor();
  await page.getByLabel("用户名").fill(user);
  await page.getByLabel("密码", { exact: true }).fill(password);
  await btn(page, "登录").click();
  await heading(page, "实验环境").waitFor();
  return page;
}
function terminalFrames(page) {
  const frames = [];
  page.on("websocket", socket => {
    if (socket.url().includes("/realtime/sessions/")) {
      socket.on("framereceived", ({ payload }) => frames.push(JSON.parse(payload)));
    }
  });
  return frames;
}
async function echoed(frames, expected) {
  const end = Date.now() + 12000;
  while (Date.now() < end) {
    const output = frames.filter(frame => frame.type === "output").map(frame => frame.data).join("");
    if (output.includes(expected)) return;
    await new Promise(resolve => setTimeout(resolve, 80));
  }
  assert.fail("The expected test marker did not traverse the browser terminal.");
}
async function job(page) {
  await heading(page, "Job 执行结果").waitFor();
  await page.getByText("succeeded", { exact: true }).waitFor({ timeout: 15000 });
  await btn(page, "返回环境").click();
  await heading(page, "P5 browser environment").waitFor();
}

(async () => {
  const browser = await chromium.launch({ executablePath: executablePath || undefined, headless: true });
  try {
    const admin = await login(browser, "admin");
    await btn(admin, "插件实例").click();
    async function instance(plugin, alias, data) {
      await admin.getByLabel("已加载插件").selectOption(plugin);
      await admin.getByLabel("实例别名").fill(alias);
      await admin.getByLabel("配置及凭据引用（JSON）").fill(JSON.stringify({ data, allowed_secret_refs: [] }));
      await btn(admin, "创建实例").click();
      await heading(admin, `${alias} · ${plugin}`).waitFor();
    }
    await instance("p5_fixture", "fixture", { terminal: target });
    await instance("ssh_terminal", "terminal", {});
    await btn(admin, "模板版本").click();
    await admin.getByLabel("模板定义（JSON）").fill(JSON.stringify(definition));
    await btn(admin, "保存草稿").click();
    await btn(admin, "发布版本").click();
    await heading(admin, /P5 loopback lab.*published/).waitFor();
    console.log("PASS admin plugin instances, template draft and publication");

    const teacher = await login(browser, "teacher");
    await btn(teacher, "课程与成员").click();
    await teacher.getByLabel("课程名称").fill("P5 course");
    await btn(teacher, "创建课程").click();
    await btn(teacher, "查看课程").click();
    await teacher.getByLabel("小组名称").fill("Echo Group");
    await btn(teacher, "创建小组").click();
    await btn(teacher, "删除小组").waitFor();
    await teacher.getByLabel("添加学生").selectOption({ label: "student" });
    await btn(teacher, "添加成员").click();
    await teacher.getByLabel("所属小组").selectOption({ label: "Echo Group" });
    await btn(teacher, "保存分组").click();
    await teacher.waitForFunction(() => [...document.querySelectorAll("select")].some(
      item => item.selectedOptions[0]?.text === "Echo Group"));
    await btn(teacher, "实验环境").click();
    await btn(teacher, "创建环境").click();
    await btn(teacher, "加载模板参数").click();
    await teacher.getByLabel("环境名称").fill("P5 browser environment");
    await teacher.getByLabel("测试端点").selectOption({ label: "Loopback echo" });
    await teacher.getByLabel("实验备注").fill("Browser verified");
    await btn(teacher, "提交创建").click();
    await job(teacher);
    await teacher.getByText("环境就绪状态 · ready", { exact: true }).waitFor();
    await teacher.getByLabel("分配对象").selectOption({ label: "小组 · Echo Group" });
    await btn(teacher, "添加分配").click();
    await btn(teacher, "撤销分配").waitFor();
    console.log("PASS teacher course, group, selector, create Job, readiness and group assignment");

    const student = await login(browser, "student");
    assert.equal(await btn(student, "创建环境").count(), 0);
    await btn(student, "查看环境").click();
    await student.getByText("资源观测状态 · unknown", { exact: true }).waitFor();
    await student.getByText("探测状态", { exact: true }).click();
    await btn(student, "执行「探测状态」").click();
    await job(student);
    await student.getByText("资源观测状态 · online", { exact: true }).waitFor();
    await student.getByText(/^观测时间 · \d/).waitFor();
    const delivered = student.waitForResponse(response => response.url().includes("/credentials/"));
    await btn(student, "查看凭据 1").click();
    const credentialResponse = await delivered;
    assert.equal(credentialResponse.status(), 200);
    assert.equal(credentialResponse.headers()["cache-control"], "no-store");
    const credential = await credentialResponse.json();
    assert.equal(credential.value.length, 32);
    await panel(student, "环境凭据").locator("output").filter({ hasText: credential.value }).waitFor();
    await btn(student, "查看凭据 1").click();
    console.log("PASS student resource action, freshness and independently authorized no-store credential");

    const studentFrames = terminalFrames(student);
    await btn(student, "连接「实验终端」").click();
    await student.getByText("当前可输入", { exact: true }).waitFor();
    await echoed(studentFrames, "Ready for lab input");
    await student.locator(".xterm textarea").focus();
    await student.keyboard.type("student-line");
    await echoed(studentFrames, "student-line");

    await btn(teacher, "刷新状态").click();
    const teacherFrames = terminalFrames(teacher);
    await btn(teacher, "旁观终端").click();
    await teacher.getByText("只读旁观", { exact: true }).waitFor();
    await echoed(teacherFrames, "student-line");
    await btn(teacher, "接管输入").click();
    await teacher.getByText("当前可输入", { exact: true }).waitFor();
    await student.getByText("只读旁观", { exact: true }).waitFor();
    await teacher.locator(".xterm textarea").focus();
    await teacher.keyboard.type("teacher-line");
    await echoed(studentFrames, "teacher-line");
    await btn(teacher, "释放控制权").click();
    await student.getByText("当前可输入", { exact: true }).waitFor();
    await teacher.getByText("只读旁观", { exact: true }).waitFor();
    console.log("PASS Chrome WebSocket and SSH PTY echo, observer, takeover and release");

    await btn(teacher, "返回环境").click();
    await btn(teacher, "撤销分配").click();
    await student.getByText(/平台连接已断开/).waitFor();
    await teacher.getByText(/平台状态 disconnected/).waitFor();
    await teacher.getByText(/revocation_failed · unsupported/).waitFor();
    teacher.once("dialog", dialog => dialog.accept());
    await btn(teacher, "显式清理").click();
    await job(teacher);
    await teacher.getByText("环境就绪状态 · deleted", { exact: true }).waitFor();
    console.log("PASS platform disconnect, separate unsupported remote revocation, explicit cleanup");
    console.log("Chrome " + browser.version());
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
