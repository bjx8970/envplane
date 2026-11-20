export function mountTerminal(container, session, { manager, api, el, button, announce, onLeave }) {
  const bar = el("div", "", { class: "actions" });
  const status = el("output", "连接中", { role: "status", "data-terminal-status": "" });
  const screen = el("div", "", { class: "terminal", "aria-label": "WebSSH 终端" });
  container.append(bar, status, screen);

  const terminal = new window.Terminal({
    cursorBlink: true,
    disableStdin: true,
    scrollback: 500,
    theme: { background: "#131c2d", foreground: "#eef4ff" },
    fontSize: 14,
  });
  const fit = new window.FitAddon.FitAddon();
  terminal.loadAddon(fit);
  terminal.open(screen);

  let socket;
  let epoch = session.controller_revision;
  let canInput = false;
  let lastSequence = 0;
  let paused = false;
  let disposed = false;
  const closePath = "/terminal-sessions/" + session.id;
  const take = button("接管输入", () => api(closePath + "/takeover", "POST", { epoch }));
  const release = button("释放控制权", () => api(closePath + "/release", "POST", { epoch }));
  const end = button("关闭平台通道", async () => {
    await api(closePath + "/close", "POST");
    status.textContent = "平台通道正在关闭";
  });
  const replay = button("重新连接", () => connect(lastSequence));
  const live = button("从实时输出重新连接", () => connect(null));
  bar.append(take, release, end, replay, live);

  function controls(connected) {
    terminal.options.disableStdin = !canInput || !connected;
    take.hidden = !connected || !manager || canInput;
    release.hidden = !connected || !manager || !canInput || !paused;
    end.hidden = !connected;
    replay.hidden = connected;
    live.hidden = connected;
    if (connected) status.textContent = canInput ? "当前可输入" : "只读旁观";
  }

  function send(frame) {
    if (!canInput || socket?.readyState !== WebSocket.OPEN) return;
    if (socket.bufferedAmount > 65536) {
      announce("浏览器发送缓冲已满，输入已暂停。");
      socket.close(1000);
      return;
    }
    socket.send(JSON.stringify({ ...frame, epoch }));
  }

  function resize() {
    fit.fit();
    send({ type: "resize", cols: terminal.cols, rows: terminal.rows });
  }

  const observer = new ResizeObserver(resize);
  observer.observe(screen);
  terminal.onData(data => {
    const characters = Array.from(data);
    for (let index = 0; index < characters.length; index += 1024) {
      send({ type: "input", data: characters.slice(index, index + 1024).join("") });
    }
  });

  function connect(after) {
    if (disposed || socket?.readyState === WebSocket.CONNECTING || socket?.readyState === WebSocket.OPEN) return;
    status.textContent = "连接中";
    controls(false);
    const dest = new URL("/realtime/sessions/" + session.id, location.href);
    dest.protocol = location.protocol === "https:" ? "wss:" : "ws:";
    if (after !== null) dest.searchParams.set("after", String(after));
    const connection = new WebSocket(dest, "lab-terminal");
    socket = connection;
    connection.addEventListener("message", event => {
      if (disposed || connection !== socket) return;
      const frame = JSON.parse(event.data);
      if (frame.type === "control") {
        const wasInput = canInput;
        epoch = frame.epoch;
        canInput = frame.can_input;
        paused = canInput && frame.epoch > 0 && session.actor_id !== session.viewer_id;
        controls(true);
        if (canInput && !wasInput) { resize(); terminal.focus(); }
      } else if (frame.type === "output") {
        lastSequence = frame.seq;
        terminal.write(frame.data);
      } else if (frame.type === "transport_error") {
        announce({ read_only: "当前连接为只读", backpressure: "输入队列已满，请稍后再试",
          conflict: "控制权已更新" }[frame.code] || "终端帧被拒绝");
      }
    });
    connection.addEventListener("close", async () => {
      if (disposed || connection !== socket) return;
      canInput = false;
      controls(false);
      status.textContent = "平台连接已断开";
      try {
        const sessions = await api("/environments/" + session.environment_id + "/sessions");
        const current = sessions.find(item => item.id === session.id);
        if (!disposed && connection === socket && current && current.state !== "active") {
          status.textContent = "平台状态 · " + current.state + (current.reason?.code ? " · " + current.reason.code : "");
          replay.hidden = live.hidden = true;
        }
      } catch (error) {
        if (!disposed) status.textContent = "平台连接已断开 · 当前访问不可用";
      }
    });
  }

  onLeave(() => {
    disposed = true;
    observer.disconnect();
    socket?.close(1000);
    terminal.dispose();
  });
  controls(false);
  connect(0);
}
