/* PixelVault front-end: gallery, uploads, lightbox, share/delete dialogs. */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const meta = n => $(`meta[name="${n}"]`).content;
  const CSRF = meta("csrf");
  const MAX_MB = Number(meta("max-mb"));
  const MAX_BYTES = MAX_MB * 1024 * 1024;
  const TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp"];
  const MAX_QUEUE = 20;
  const NS = "http://www.w3.org/2000/svg";

  /* ---------- helpers ---------- */
  const fmtBytes = b => {
    if (b < 1024) return `${b} B`;
    const u = ["KB", "MB", "GB"]; let i = -1;
    do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
    return `${b.toFixed(1)} ${u[i]}`;
  };
  const svg = name => {
    const s = document.createElementNS(NS, "svg"); s.setAttribute("class", "icon");
    const u = document.createElementNS(NS, "use"); u.setAttribute("href", "#i-" + name);
    s.appendChild(u); return s;
  };
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const ago = ts => {
    const s = (ts * 1000 - Date.now()) / 1000;
    for (const [unit, sec] of [["year", 31536000], ["month", 2592000], ["day", 86400], ["hour", 3600], ["minute", 60]])
      if (Math.abs(s) >= sec) return rtf.format(Math.round(s / sec), unit);
    return "just now";
  };

  function toast(message, type = "info", ms = 4200) {
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.setAttribute("role", type === "error" ? "alert" : "status");
    const text = document.createElement("span"); text.textContent = message;
    const x = document.createElement("button");
    x.type = "button"; x.className = "toast-x"; x.setAttribute("aria-label", "Dismiss"); x.appendChild(svg("x"));
    el.append(svg({ success: "check", error: "alert", info: "shield" }[type] || "shield"), text, x);
    const close = () => { el.classList.add("out"); setTimeout(() => el.remove(), 200); };
    x.addEventListener("click", close);
    $("#toasts").appendChild(el);
    setTimeout(close, ms);
  }

  async function api(url, body) {
    const res = await fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
      body: JSON.stringify(body),
    });
    if (res.status === 401) { location.href = "/login"; throw new Error("Session expired"); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.ok === false) throw new Error(data.error || "Request failed");
    return data;
  }

  /* ---------- theme ---------- */
  $("#themeToggle").addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("theme", next); } catch (e) { /* ignore */ }
  });

  /* ---------- gallery: filter / sort / layout ---------- */
  const gallery = $("#gallery");
  const photos = () => $$(".photo", gallery);
  const visible = () => photos().filter(p => !p.hidden);

  function updateStats() {
    const l = photos();
    $("#statCount").textContent = l.length;
    $("#statSize").textContent = fmtBytes(l.reduce((s, p) => s + Number(p.dataset.size), 0));
  }

  function refresh() {
    const q = $("#search").value.trim().toLowerCase();
    const [field, dir] = $("#sort").value.split(":");
    const list = photos().sort((a, b) => {
      const r = field === "name"
        ? a.dataset.name.localeCompare(b.dataset.name, undefined, { numeric: true, sensitivity: "base" })
        : Number(a.dataset[field]) - Number(b.dataset[field]);
      return dir === "desc" ? -r : r;
    });
    list.forEach(p => { p.hidden = !!q && !p.dataset.name.toLowerCase().includes(q); gallery.appendChild(p); });
    const total = list.length, shown = list.filter(p => !p.hidden).length;
    $("#shownCount").textContent = q ? `${shown} of ${total}` : String(total);
    $("#emptyState").hidden = total !== 0;
    $("#noResults").hidden = !(total > 0 && shown === 0);
    $("#toolbar").hidden = total === 0;
    gallery.hidden = total === 0;
  }
  $("#search").addEventListener("input", refresh);
  $("#sort").addEventListener("change", refresh);

  function setView(v) {
    gallery.classList.toggle("view-list", v === "list");
    $$("[data-view]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.view === v)));
    try { localStorage.setItem("view", v); } catch (e) { /* ignore */ }
  }
  $$("[data-view]").forEach(b => b.addEventListener("click", () => setView(b.dataset.view)));
  try { setView(localStorage.getItem("view") || "grid"); } catch (e) { setView("grid"); }

  $$(".js-ago").forEach(el => {
    const ts = Number(el.dataset.ts);
    el.textContent = ago(ts);
    el.title = new Date(ts * 1000).toLocaleString();
  });

  photos().forEach(p => {
    const img = $("img", p);
    const ok = () => p.classList.add("loaded");
    img.addEventListener("load", ok, { once: true });
    img.addEventListener("error", () => p.classList.add("loaded", "broken"), { once: true });
    if (img.complete && img.naturalWidth > 0) ok();
  });

  /* ---------- dialogs ---------- */
  $$("dialog").forEach(d => {
    d.addEventListener("click", e => { if (e.target === d) d.close(); });
    $$("[data-close]", d).forEach(b => b.addEventListener("click", () => d.close()));
  });

  /* share */
  const shareDlg = $("#shareDialog");
  let shareCard = null, shareReq = 0;
  async function loadShare() {
    if (!shareCard) return;
    const req = ++shareReq;
    const minutes = Number($('input[name="minutes"]:checked').value);
    const urlEl = $("#shareUrl"), btn = $("#copyBtn");
    urlEl.value = "Generating link…"; btn.disabled = true; $("#shareHint").textContent = "";
    try {
      const d = await api("/share", { id: shareCard.dataset.id, minutes });
      if (req !== shareReq) return;
      urlEl.value = d.url; btn.disabled = false;
      const exp = new Date(Date.now() + d.expires_in_minutes * 60000);
      $("#shareHint").textContent = `Expires at ${exp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    } catch (e) {
      if (req !== shareReq) return;
      urlEl.value = ""; $("#shareHint").textContent = e.message;
    }
  }
  function openShare(card) {
    shareCard = card;
    $("#shareName").textContent = card.dataset.name;
    shareDlg.showModal();
    loadShare();
  }
  $$('input[name="minutes"]').forEach(r => r.addEventListener("change", loadShare));
  $("#copyBtn").addEventListener("click", async () => {
    const el = $("#shareUrl");
    try { await navigator.clipboard.writeText(el.value); }
    catch (e) { el.select(); document.execCommand("copy"); }   // fallback for plain-HTTP origins
    const label = $("#copyBtn span"); label.textContent = "Copied!";
    toast("Link copied to clipboard", "success", 2000);
    setTimeout(() => { label.textContent = "Copy"; }, 1800);
  });

  /* delete */
  const delDlg = $("#deleteDialog");
  let delCard = null;
  function openDelete(card) {
    delCard = card;
    $("#delName").textContent = card.dataset.name;
    $("#delConfirm").disabled = false;
    delDlg.showModal();
  }
  $("#delConfirm").addEventListener("click", async () => {
    if (!delCard) return;
    const card = delCard, btn = $("#delConfirm");
    btn.disabled = true;
    try {
      await api("/delete", { id: card.dataset.id });
      delDlg.close();
      card.classList.add("removing");
      setTimeout(() => {
        card.remove(); updateStats(); refresh();
        if (!lb.hidden) {
          lbList = visible();
          if (!lbList.length) closeLb(); else { lbIndex = Math.min(lbIndex, lbList.length - 1); showLb(); }
        }
      }, 250);
      toast(`Deleted ${card.dataset.name}`, "success");
    } catch (e) {
      btn.disabled = false; toast(e.message, "error");
    }
  });

  /* ---------- lightbox ---------- */
  const lb = $("#lightbox");
  let lbList = [], lbIndex = 0;
  function showLb() {
    const c = lbList[lbIndex];
    $("#lbImg").src = c.dataset.url; $("#lbImg").alt = c.dataset.name;
    $("#lbName").textContent = c.dataset.name;
    $("#lbMeta").textContent = `${fmtBytes(Number(c.dataset.size))} · ${new Date(c.dataset.ts * 1000).toLocaleString()}`;
    $("#lbCount").textContent = `${lbIndex + 1} / ${lbList.length}`;
    $("#lbPrev").hidden = $("#lbNext").hidden = lbList.length < 2;
  }
  function openLb(card) {
    lbList = visible(); lbIndex = Math.max(0, lbList.indexOf(card));
    showLb(); lb.hidden = false; document.body.classList.add("noscroll"); $("#lbClose").focus();
  }
  function closeLb() { lb.hidden = true; $("#lbImg").removeAttribute("src"); document.body.classList.remove("noscroll"); }
  const stepLb = d => { lbIndex = (lbIndex + d + lbList.length) % lbList.length; showLb(); };
  $("#lbClose").addEventListener("click", closeLb);
  $("#lbPrev").addEventListener("click", () => stepLb(-1));
  $("#lbNext").addEventListener("click", () => stepLb(1));
  $("#lbShare").addEventListener("click", () => openShare(lbList[lbIndex]));
  $("#lbDelete").addEventListener("click", () => openDelete(lbList[lbIndex]));
  lb.addEventListener("click", e => { if (e.target === lb || e.target.classList.contains("lb-stage")) closeLb(); });
  document.addEventListener("keydown", e => {
    if (lb.hidden || $("dialog[open]")) return;
    if (e.key === "Escape") closeLb();
    else if (e.key === "ArrowLeft") stepLb(-1);
    else if (e.key === "ArrowRight") stepLb(1);
  });

  gallery.addEventListener("click", e => {
    const btn = e.target.closest("[data-action]");
    if (!btn) return;
    const card = btn.closest(".photo");
    ({ open: openLb, share: openShare, delete: openDelete })[btn.dataset.action](card);
  });

  /* ---------- upload ---------- */
  const dz = $("#dropzone"), input = $("#fileInput"), queueEl = $("#queue");
  const upBtn = $("#uploadBtn"), clearBtn = $("#clearBtn"), upStatus = $("#uploadStatus");
  let queue = [], busy = false;

  function makeItem(item) {
    const li = document.createElement("li"); li.className = "q-item"; li.dataset.state = "ready";
    const img = document.createElement("img"); img.src = item.url; img.alt = "";
    const body = document.createElement("div"); body.className = "q-body";
    const name = document.createElement("div"); name.className = "q-name"; name.textContent = item.file.name;
    const metaEl = document.createElement("div"); metaEl.className = "q-meta"; metaEl.textContent = fmtBytes(item.file.size);
    const bar = document.createElement("div"); bar.className = "bar";
    const fill = document.createElement("i"); bar.appendChild(fill);
    body.append(name, metaEl, bar);
    const rm = document.createElement("button");
    rm.type = "button"; rm.className = "btn-icon sm"; rm.setAttribute("aria-label", `Remove ${item.file.name}`);
    rm.appendChild(svg("x"));
    rm.addEventListener("click", () => {
      if (busy) return;
      URL.revokeObjectURL(item.url);
      queue = queue.filter(q => q !== item); renderQueue();
    });
    li.append(img, body, rm);
    Object.assign(item, { li, metaEl, fill });
    return li;
  }
  function renderQueue() {
    queueEl.replaceChildren(...queue.map(makeItem));
    $("#queueActions").hidden = queue.length === 0;
    upBtn.querySelector("span").textContent = `Upload ${queue.length} image${queue.length === 1 ? "" : "s"}`;
    upStatus.textContent = "";
  }
  function addFiles(files) {
    for (const f of files) {
      if (!TYPES.includes(f.type)) { toast(`${f.name}: unsupported file type`, "error"); continue; }
      if (f.size > MAX_BYTES) { toast(`${f.name}: larger than ${MAX_MB} MB`, "error"); continue; }
      if (queue.some(q => q.file.name === f.name && q.file.size === f.size && q.file.lastModified === f.lastModified)) continue;
      if (queue.length >= MAX_QUEUE) { toast(`Up to ${MAX_QUEUE} images at a time`, "info"); break; }
      queue.push({ file: f, url: URL.createObjectURL(f) });
    }
    renderQueue();
  }
  const setProgress = (item, f) => {
    const pct = Math.round(f * 100);
    item.fill.style.width = pct + "%"; item.metaEl.textContent = `Uploading… ${pct}%`;
  };
  const mark = (item, state, text) => {
    item.li.dataset.state = state; item.metaEl.textContent = text;
    if (state === "done") item.fill.style.width = "100%";
  };

  function sendOne(item) {
    return new Promise(resolve => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/upload");
      xhr.setRequestHeader("X-CSRF-Token", CSRF);
      xhr.responseType = "json";
      xhr.upload.onprogress = e => { if (e.lengthComputable) setProgress(item, e.loaded / e.total); };
      xhr.onload = () => {
        if (xhr.status === 401) { location.href = "/login"; return resolve(false); }
        const d = xhr.response || {};
        if (xhr.status >= 200 && xhr.status < 300 && d.ok) { mark(item, "done", "Uploaded"); resolve(true); }
        else { mark(item, "error", d.error || "Upload failed"); resolve(false); }
      };
      xhr.onerror = () => { mark(item, "error", "Network error"); resolve(false); };
      const fd = new FormData(); fd.append("image", item.file);
      xhr.send(fd);
    });
  }

  upBtn.addEventListener("click", async () => {
    if (busy || !queue.length) return;
    busy = true; upBtn.disabled = clearBtn.disabled = true;
    const todo = queue.filter(q => q.li.dataset.state !== "done");
    let okCount = 0;
    for (let i = 0; i < todo.length; i++) {
      upStatus.textContent = `Uploading ${i + 1} of ${todo.length}…`;
      if (await sendOne(todo[i])) okCount++;
    }
    const failed = todo.length - okCount;
    if (okCount) toast(`${okCount} image${okCount === 1 ? "" : "s"} uploaded`, "success");
    if (failed) toast(`${failed} upload${failed === 1 ? "" : "s"} failed`, "error");
    if (okCount && !failed) { upStatus.textContent = "Done — refreshing gallery…"; setTimeout(() => location.reload(), 900); }
    else { busy = false; upBtn.disabled = clearBtn.disabled = false; upStatus.textContent = failed ? "Some files failed. Remove them or retry." : ""; }
  });
  clearBtn.addEventListener("click", () => { queue.forEach(q => URL.revokeObjectURL(q.url)); queue = []; renderQueue(); });

  ["dragenter", "dragover"].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.remove("drag"); }));
  dz.addEventListener("drop", e => { if (!busy) addFiles(e.dataTransfer.files); });
  input.addEventListener("change", () => { if (!busy) addFiles(input.files); input.value = ""; });
  ["dragover", "drop"].forEach(t => window.addEventListener(t, e => e.preventDefault()));  // don't navigate away on stray drops

  refresh();
})();
