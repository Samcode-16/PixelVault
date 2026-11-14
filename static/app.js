/* PixelVault v3 front-end: timeline, selection, albums, trash, sharing, uploads. */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const meta = n => $(`meta[name="${n}"]`).content;
  const CSRF = meta("csrf"), MAX_MB = Number(meta("max-mb")), MAX_BYTES = MAX_MB * 1048576, TRASH_DAYS = Number(meta("trash-days"));
  const TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp"], MAX_QUEUE = 20, NS = "http://www.w3.org/2000/svg";

  /* ---------- helpers ---------- */
  const fmtBytes = b => { if (b < 1024) return `${b} B`; const u = ["KB", "MB", "GB"]; let i = -1;
    do { b /= 1024; i++; } while (b >= 1024 && i < 2); return `${b.toFixed(1)} ${u[i]}`; };
  const svg = name => { const s = document.createElementNS(NS, "svg"); s.setAttribute("class", "icon");
    const u = document.createElementNS(NS, "use"); u.setAttribute("href", "#i-" + name); s.appendChild(u); return s; };
  function h(tag, attrs = {}, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) { if (v === false || v == null) continue; el.setAttribute(k, v === true ? "" : v); }
    el.append(...kids.filter(k => k != null)); return el;
  }
  function toast(message, type = "info", ms = 4200, action) {
    const el = h("div", { class: `toast ${type}`, role: type === "error" ? "alert" : "status" });
    const x = h("button", { type: "button", class: "toast-x", "aria-label": "Dismiss" }, svg("x"));
    el.append(svg({ success: "check", error: "alert" }[type] || "shield"), h("span", {}, message));
    const close = () => { el.classList.add("out"); setTimeout(() => el.remove(), 200); };
    if (action) { const a = h("button", { type: "button", class: "toast-act" }, action.label);
      a.addEventListener("click", () => { close(); action.fn(); }); el.append(a); }
    x.addEventListener("click", close); el.append(x); $("#toasts").appendChild(el); setTimeout(close, ms);
  }
  async function api(url, body) {
    const opts = body === undefined ? { credentials: "same-origin" } : { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF }, body: JSON.stringify(body) };
    const res = await fetch(url, opts);
    if (res.status === 401) { location.href = "/login"; throw new Error("Session expired"); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.ok === false) throw new Error(data.error || "Request failed");
    return data;
  }
  const startOfDay = d => new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const dayKey = ts => { const d = new Date(ts * 1000); return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`; };
  function dayLabel(ts) {
    const d = new Date(ts * 1000), n = new Date(), diff = Math.round((startOfDay(n) - startOfDay(d)) / 864e5);
    if (diff === 0) return "Today"; if (diff === 1) return "Yesterday";
    return d.toLocaleDateString(undefined, { weekday: diff < 7 ? "long" : "short", day: "numeric", month: "short", year: d.getFullYear() === n.getFullYear() ? undefined : "numeric" });
  }

  /* ---------- theme / mobile menu ---------- */
  $("#themeToggle").addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("theme", next); } catch (e) { /* ignore */ }
  });
  $("#menuBtn").addEventListener("click", () => $("#side").classList.toggle("open"));

  /* ---------- dialogs ---------- */
  $$("dialog").forEach(d => {
    d.addEventListener("click", e => { if (e.target === d) d.close(); });
    $$("[data-close]", d).forEach(b => b.addEventListener("click", () => d.close()));
  });
  function ask(dlg, setup) {                       // promise wrapper around <form method=dialog>
    return new Promise(res => { dlg.returnValue = ""; setup();
      dlg.addEventListener("close", () => res(dlg.returnValue === "ok"), { once: true }); dlg.showModal(); });
  }
  const confirmDlg = (title, text, button) => ask($("#confirmDialog"), () => {
    $("#confTitle").textContent = title; $("#confText").textContent = text; $("#confOk").textContent = button; });
  async function askName(title, value) {
    const ok = await ask($("#nameDialog"), () => { $("#nameTitle").textContent = title; $("#nameInput").value = value || ""; });
    return ok ? $("#nameInput").value.trim() : null;
  }

  /* ---------- state ---------- */
  const S = { view: "photos", album: null, items: [], sum: null, sel: new Set(), q: "", sort: "desc", loadedAt: 0, lb: -1 };
  const byId = id => S.items.find(i => i.id === id);
  const inTrash = () => S.view === "trash";

  function shown() {
    const q = S.q.toLowerCase();
    const list = S.items.filter(i => !q || i.name.toLowerCase().includes(q) || (i.camera || "").toLowerCase().includes(q));
    const cmp = { desc: (a, b) => b.taken - a.taken, asc: (a, b) => a.taken - b.taken,
      name: (a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" }), size: (a, b) => b.size - a.size }[S.sort];
    return list.sort(cmp);
  }

  async function loadAll() {
    const qs = new URLSearchParams({ view: S.view }); if (S.album) qs.set("album", S.album);
    try {
      const [p, s] = await Promise.all([api(`/api/photos?${qs}`), api("/api/summary")]);
      S.items = p.items; S.sum = s; S.loadedAt = Date.now(); $("#loadError").hidden = true;
    } catch (e) {
      if (S.view === "album") { location.hash = "#photos"; return; }
      $("#loadError span").textContent = e.message; $("#loadError").hidden = false;
    }
    S.sel = new Set([...S.sel].filter(id => byId(id)));
    render();
  }
  function route() {
    const hash = location.hash.slice(1) || "photos";
    if (hash.startsWith("album/")) { S.view = "album"; S.album = hash.slice(6); }
    else { S.view = ["photos", "favorites", "trash"].includes(hash) ? hash : "photos"; S.album = null; }
    S.sel.clear(); closeLb(); $("#side").classList.remove("open"); loadAll();
  }

  /* ---------- rendering ---------- */
  function render() { renderSide(); renderHead(); renderTimeline(); renderSelbar(); }

  function renderSide() {
    const s = S.sum; if (!s) return;
    $("#cPhotos").textContent = s.photos; $("#cFavs").textContent = s.favorites; $("#cTrash").textContent = s.trash;
    const list = $("#albumList"); list.replaceChildren(...s.albums.map(a =>
      h("a", { href: `#album/${a.id}`, "data-nav": `album/${a.id}` }, svg("folder"), h("span", {}, a.name), h("b", {}, String(a.count)))));
    $("#noAlbums").hidden = s.albums.length > 0;
    const key = S.view === "album" ? `album/${S.album}` : S.view;
    $$("[data-nav]").forEach(a => a.classList.toggle("active", a.dataset.nav === key));
    const pct = Math.min(100, Math.max(s.used_bytes / (s.quota_mb * 1048576), s.total / s.max_images) * 100);
    $("#usedBar").style.width = pct + "%"; $("#usedBar").parentElement.classList.toggle("warn", pct > 85);
    $("#usedText").textContent = `${s.used_label} of ${s.quota_mb} MB`; $("#countText").textContent = `${s.total} of ${s.max_images} photos`;
  }

  function renderHead() {
    const alb = S.view === "album" ? (S.sum?.albums.find(a => a.id === S.album)) : null;
    $("#viewTitle").textContent = { photos: "Photos", favorites: "Favorites", trash: "Trash" }[S.view] || alb?.name || "Album";
    $("#viewSub").textContent = inTrash() ? `Items are permanently deleted after ${TRASH_DAYS} days.` : `${S.items.length} item${S.items.length === 1 ? "" : "s"}`;
    $("#renameAlbum").hidden = $("#deleteAlbum").hidden = S.view !== "album";
    $("#emptyTrash").hidden = !(inTrash() && S.items.length);
    document.title = `${$("#viewTitle").textContent} · PixelVault`;
  }

  function renderTimeline() {
    const list = shown(), root = $("#timeline"), groups = [];
    for (const it of list) {
      const k = S.sort === "asc" || S.sort === "desc" ? dayKey(it.taken) : "all";
      let g = groups[groups.length - 1];
      if (!g || g.key !== k) { g = { key: k, label: k === "all" ? "" : dayLabel(it.taken), items: [] }; groups.push(g); }
      g.items.push(it);
    }
    root.replaceChildren(...groups.map(g => {
      const all = g.items.every(i => S.sel.has(i.id));
      const head = g.label ? h("div", { class: "group-head" },
        h("button", { class: "group-check" + (all ? " on" : ""), type: "button", "data-group": g.items.map(i => i.id).join(","), "aria-label": `Select ${g.label}` }, svg("check")),
        h("span", {}, g.label), h("small", { class: "muted" }, `${g.items.length}`)) : null;
      return h("section", { class: "group" }, head, h("div", { class: "grid" }, ...g.items.map(tile)));
    }));
    const empty = list.length === 0;
    $("#empty").hidden = !empty;
    if (empty) {
      const q = S.q, t = { photos: ["No photos yet", "Upload your first photo — it's stored privately in S3.", "photos"],
        favorites: ["No favorites", "Tap the star on a photo to find it here.", "star"], trash: ["Trash is empty", "Deleted photos wait here before they're gone for good.", "trash"],
        album: ["This album is empty", "Select photos in your library and choose “Add to album”.", "folder"] }[S.view];
      $("#emptyTitle").textContent = q ? "No matches" : t[0]; $("#emptyText").textContent = q ? "Try a different search." : t[1];
      $("#emptyIcon").replaceWith(Object.assign(svg(q ? "search" : t[2]), { id: "emptyIcon" }));
      $("#emptyUpload").hidden = !!q || S.view !== "photos";
    }
  }

  function tile(it) {
    const img = h("img", { src: it.thumb, alt: it.name, loading: "lazy", decoding: "async" });
    const el = h("div", { class: "tile" + (S.sel.has(it.id) ? " sel" : ""), "data-id": it.id },
      h("button", { class: "tile-open", type: "button", "aria-label": `Open ${it.name}` }, h("span", { class: "skeleton" }), img),
      h("button", { class: "tile-check", type: "button", "aria-label": `Select ${it.name}` }, svg("check")),
      it.favorite ? h("span", { class: "tile-fav", title: "Favorite" }, svg("star")) : null);
    img.addEventListener("load", () => el.classList.add("loaded"), { once: true });
    img.addEventListener("error", () => el.classList.add("loaded", "broken"), { once: true });
    return el;
  }

  function renderSelbar() {
    const n = S.sel.size;
    $("#selbar").hidden = n === 0; document.body.classList.toggle("selecting", n > 0);
    $("#selCount").textContent = `${n} selected`;
    $$("#selbar .n-only").forEach(b => b.hidden = inTrash());
    $$("#selbar .t-only").forEach(b => b.hidden = !inTrash());
    $$("#selbar .a-only").forEach(b => b.hidden = S.view !== "album");
    const ids = [...S.sel].map(byId).filter(Boolean);
    $("#selbar [data-act=fav] span").textContent = ids.length && ids.every(i => i.favorite) ? "Unfavorite" : "Favorite";
  }

  /* ---------- selection ---------- */
  function toggleSel(id) {
    S.sel.has(id) ? S.sel.delete(id) : S.sel.add(id);
    const t = $(`.tile[data-id="${id}"]`); if (t) t.classList.toggle("sel", S.sel.has(id));
    renderSelbar();
  }
  $("#timeline").addEventListener("click", e => {
    const grp = e.target.closest(".group-check");
    if (grp) { const ids = grp.dataset.group.split(","), all = ids.every(i => S.sel.has(i));
      ids.forEach(i => all ? S.sel.delete(i) : S.sel.add(i)); renderTimeline(); renderSelbar(); return; }
    const t = e.target.closest(".tile"); if (!t) return;
    if (e.target.closest(".tile-check") || S.sel.size || e.shiftKey || e.ctrlKey || e.metaKey) toggleSel(t.dataset.id);
    else openLb(t.dataset.id);
  });

  /* ---------- actions ---------- */
  async function run(name, ids, opts = {}) {
    const n = ids.length, s = n === 1 ? "" : "s";
    try {
      if (name === "fav") { const v = !ids.every(i => byId(i)?.favorite); await api("/api/favorite", { ids, value: v }); toast(v ? `Added ${n} to favorites` : "Removed from favorites", "success", 2200); }
      else if (name === "trash") await api("/api/trash", { ids }), toast(`${n} photo${s} moved to trash`, "success", 6000, { label: "Undo", fn: () => run("restore", ids, { silent: true }) });
      else if (name === "restore") { await api("/api/restore", { ids }); if (!opts.silent) toast(`Restored ${n} photo${s}`, "success"); else toast("Restored", "success", 2000); }
      else if (name === "purge") {
        if (!await confirmDlg(`Delete ${n} photo${s} forever?`, "This removes the files from S3. It can't be undone from the app.", "Delete forever")) return;
        await api("/api/purge", { ids }); toast(`Deleted ${n} photo${s} permanently`, "success");
      } else if (name === "unalbum") { await api("/api/albums/remove", { id: S.album, ids }); toast("Removed from album", "success", 2200); }
      else if (name === "album") { if (!await pickAlbum(ids)) return; }
    } catch (e) { toast(e.message, "error"); return; }
    S.sel.clear(); await loadAll();
  }
  $("#selbar").addEventListener("click", e => {
    const b = e.target.closest("[data-act]"); if (!b) return;
    if (b.dataset.act === "clear") { S.sel.clear(); render(); } else run(b.dataset.act, [...S.sel]);
  });
  document.addEventListener("keydown", e => {
    if (e.target.matches("input,textarea,select") || $("dialog[open]")) return;
    if (!$("#lightbox").hidden) return;
    if (e.key === "Escape" && S.sel.size) { S.sel.clear(); render(); }
    else if ((e.key === "Delete" || e.key === "Backspace") && S.sel.size && !inTrash()) run("trash", [...S.sel]);
    else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "a") { e.preventDefault(); shown().forEach(i => S.sel.add(i.id)); renderTimeline(); renderSelbar(); }
  });

  /* albums */
  function pickAlbum(ids) {
    return new Promise(resolve => {
      const dlg = $("#albumDialog"); let done = false;
      const finish = async (albumId, label) => {
        try { await api("/api/albums/add", { id: albumId, ids }); toast(`Added ${ids.length} to “${label}”`, "success"); done = true; dlg.close(); }
        catch (e) { toast(e.message, "error"); }
      };
      $("#pickList").replaceChildren(...(S.sum.albums.length ? S.sum.albums.map(a =>
        h("li", {}, (() => { const b = h("button", { type: "button", class: "pick" }, svg("folder"), h("span", {}, a.name), h("small", { class: "muted" }, String(a.count)));
          b.addEventListener("click", () => finish(a.id, a.name)); return b; })())) : [h("li", { class: "muted small pad" }, "No albums yet — create one below.")]));
      $("#pickNew").value = "";
      $("#pickCreate").onclick = async () => { const name = $("#pickNew").value.trim(); if (!name) return;
        try { const r = await api("/api/albums/create", { name }); await finish(r.id, r.name); } catch (e) { toast(e.message, "error"); } };
      dlg.addEventListener("close", () => resolve(done), { once: true }); dlg.showModal();
    });
  }
  $("#newAlbum").addEventListener("click", async () => {
    const name = await askName("New album", ""); if (!name) return;
    try { const r = await api("/api/albums/create", { name }); location.hash = `#album/${r.id}`; } catch (e) { toast(e.message, "error"); }
  });
  $("#renameAlbum").addEventListener("click", async () => {
    const cur = S.sum.albums.find(a => a.id === S.album), name = await askName("Rename album", cur?.name); if (!name) return;
    try { await api("/api/albums/rename", { id: S.album, name }); await loadAll(); } catch (e) { toast(e.message, "error"); }
  });
  $("#deleteAlbum").addEventListener("click", async () => {
    if (!await confirmDlg("Delete this album?", "The photos stay in your library — only the album is removed.", "Delete album")) return;
    try { await api("/api/albums/delete", { id: S.album }); location.hash = "#photos"; } catch (e) { toast(e.message, "error"); }
  });
  $("#emptyTrash").addEventListener("click", async () => {
    if (!await confirmDlg("Empty trash?", `${S.items.length} photo(s) will be permanently deleted from S3.`, "Empty trash")) return;
    try { await api("/api/purge", { all: true }); toast("Trash emptied", "success"); await loadAll(); } catch (e) { toast(e.message, "error"); }
  });

  /* ---------- share ---------- */
  const shareDlg = $("#shareDialog"); let shareId = null;
  const when = ts => new Date(ts * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); }
    catch (e) { const t = $("#shareUrl"); const old = t.value; t.value = text; t.select(); document.execCommand("copy"); t.value = old; }   // plain-HTTP fallback
    toast("Link copied", "success", 1800);
  }
  async function loadLinks() {
    try {
      const d = await api(`/api/shares?id=${shareId}`);
      $("#shareList").replaceChildren(...(d.links.length ? d.links.map(l => {
        const copy = h("button", { type: "button", class: "btn btn-ghost sm" }, "Copy"), rev = h("button", { type: "button", class: "btn btn-ghost sm danger-text" }, "Revoke");
        copy.addEventListener("click", () => copyText(l.url));
        rev.addEventListener("click", async () => { try { await api("/api/share/revoke", { token: l.token }); toast("Link revoked", "success", 2000); loadLinks(); } catch (e) { toast(e.message, "error"); } });
        return h("li", {}, h("div", {}, h("div", {}, `Expires ${when(l.expires_at)}`), h("small", { class: "muted" }, `${l.views} view${l.views === 1 ? "" : "s"}`)), h("div", { class: "row" }, copy, rev));
      }) : [h("li", { class: "muted small" }, "No active links.")]));
    } catch (e) { toast(e.message, "error"); }
  }
  function openShare(id) {
    shareId = id; $("#shareName").textContent = byId(id).name; $("#shareUrl").value = ""; shareDlg.showModal(); loadLinks();
  }
  $("#createLink").addEventListener("click", async () => {
    const btn = $("#createLink"); btn.disabled = true;
    try { const d = await api("/api/share/create", { id: shareId, minutes: Number($('input[name="minutes"]:checked').value) });
      $("#shareUrl").value = d.url; await copyText(d.url); loadLinks(); }
    catch (e) { toast(e.message, "error"); } finally { btn.disabled = false; }
  });

  /* ---------- lightbox ---------- */
  const lb = $("#lightbox"); let lbList = [], lbIndex = 0;
  const cur = () => lbList[lbIndex];
  function showLb() {
    const c = cur(); if (!c) return closeLb();
    $("#lbImg").src = c.url; $("#lbImg").alt = c.name; $("#lbName").textContent = c.name;
    const parts = [fmtBytes(c.size), new Date(c.taken * 1000).toLocaleString(), c.width ? `${c.width}×${c.height}` : null, c.camera].filter(Boolean);
    $("#lbMeta").textContent = parts.join(" · ");
    $("#lbCount").textContent = `${lbIndex + 1} / ${lbList.length}`;
    $("#lbPrev").hidden = $("#lbNext").hidden = lbList.length < 2;
    $("#lbFav").classList.toggle("on", c.favorite);
    $$(".lb-tools .n-only", lb).forEach(b => b.hidden = inTrash()); $$(".lb-tools .t-only", lb).forEach(b => b.hidden = !inTrash());
  }
  function openLb(id) {
    lbList = shown(); lbIndex = Math.max(0, lbList.findIndex(i => i.id === id));
    showLb(); lb.hidden = false; document.body.classList.add("noscroll"); $("#lbClose").focus();
  }
  function closeLb() { lb.hidden = true; $("#lbImg").removeAttribute("src"); document.body.classList.remove("noscroll"); }
  const stepLb = d => { if (!lbList.length) return; lbIndex = (lbIndex + d + lbList.length) % lbList.length; showLb(); };
  async function lbAct(name) {                     // run an action on the open photo, then keep the viewer on the next one
    const id = cur().id, keep = lbIndex;
    await run(name, [id]);
    lbList = shown(); lbIndex = Math.min(keep, lbList.length - 1);
    if (!lbList.length) closeLb(); else if (!lb.hidden) showLb();
  }
  $("#lbClose").addEventListener("click", closeLb);
  $("#lbPrev").addEventListener("click", () => stepLb(-1)); $("#lbNext").addEventListener("click", () => stepLb(1));
  $("#lbFav").addEventListener("click", async () => { const id = cur().id; await run("fav", [id]); lbList = shown(); lbIndex = Math.max(0, lbList.findIndex(i => i.id === id)); showLb(); });
  $("#lbTrash").addEventListener("click", () => lbAct("trash"));
  $("#lbRestore").addEventListener("click", () => lbAct("restore"));
  $("#lbPurge").addEventListener("click", () => lbAct("purge"));
  $("#lbAlbum").addEventListener("click", () => run("album", [cur().id]));
  $("#lbShare").addEventListener("click", () => openShare(cur().id));
  $("#lbDownload").addEventListener("click", () => { location.href = `/download/${cur().id}`; });
  lb.addEventListener("click", e => { if (e.target === lb || e.target.classList.contains("lb-stage")) closeLb(); });
  document.addEventListener("keydown", e => {
    if (lb.hidden || $("dialog[open]")) return;
    if (e.key === "Escape") closeLb(); else if (e.key === "ArrowLeft") stepLb(-1); else if (e.key === "ArrowRight") stepLb(1);
  });

  /* ---------- toolbar bits ---------- */
  $("#search").addEventListener("input", e => { S.q = e.target.value.trim(); renderTimeline(); });
  $("#sort").addEventListener("change", e => { S.sort = e.target.value; renderTimeline(); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && Date.now() - S.loadedAt > 600000) loadAll(); });  // pre-signed links expire after 15 min

  /* ---------- upload ---------- */
  const upDlg = $("#uploadDialog"), input = $("#fileInput"), queueEl = $("#queue"), upBtn = $("#uploadBtn"), clearBtn = $("#clearBtn"), upStatus = $("#uploadStatus"), dz = $("#dropzone");
  let queue = [], busy = false;
  const openUpload = () => { if (!upDlg.open) upDlg.showModal(); };
  $("#openUpload").addEventListener("click", openUpload); $("#emptyUpload").addEventListener("click", openUpload);
  function makeItem(item) {
    const li = h("li", { class: "q-item", "data-state": "ready" });
    const name = h("div", { class: "q-name" }, item.file.name), metaEl = h("div", { class: "q-meta" }, fmtBytes(item.file.size));
    const fill = h("i"), bar = h("div", { class: "bar" }, fill);
    const rm = h("button", { type: "button", class: "btn-icon sm", "aria-label": `Remove ${item.file.name}` }, svg("x"));
    rm.addEventListener("click", () => { if (busy) return; URL.revokeObjectURL(item.url); queue = queue.filter(q => q !== item); renderQueue(); });
    li.append(h("img", { src: item.url, alt: "" }), h("div", { class: "q-body" }, name, metaEl, bar), rm);
    Object.assign(item, { li, metaEl, fill }); return li;
  }
  function renderQueue() {
    queueEl.replaceChildren(...queue.map(makeItem)); $("#queueActions").hidden = queue.length === 0;
    upBtn.querySelector("span").textContent = `Upload ${queue.length} photo${queue.length === 1 ? "" : "s"}`; upStatus.textContent = "";
  }
  function addFiles(files) {
    for (const f of files) {
      if (!TYPES.includes(f.type)) { toast(`${f.name}: unsupported file type`, "error"); continue; }
      if (f.size > MAX_BYTES) { toast(`${f.name}: larger than ${MAX_MB} MB`, "error"); continue; }
      if (queue.some(q => q.file.name === f.name && q.file.size === f.size && q.file.lastModified === f.lastModified)) continue;
      if (queue.length >= MAX_QUEUE) { toast(`Up to ${MAX_QUEUE} photos at a time`, "info"); break; }
      queue.push({ file: f, url: URL.createObjectURL(f) });
    }
    renderQueue(); openUpload();
  }
  const mark = (item, state, text) => { item.li.dataset.state = state; item.metaEl.textContent = text; if (state === "done") item.fill.style.width = "100%"; };
  function sendOne(item) {
    return new Promise(resolve => {
      const xhr = new XMLHttpRequest(); xhr.open("POST", "/upload"); xhr.setRequestHeader("X-CSRF-Token", CSRF); xhr.responseType = "json";
      xhr.upload.onprogress = e => { if (e.lengthComputable) { const p = Math.round(e.loaded / e.total * 100); item.fill.style.width = p + "%"; item.metaEl.textContent = `Uploading… ${p}%`; } };
      xhr.onload = () => { if (xhr.status === 401) { location.href = "/login"; return resolve(false); }
        const d = xhr.response || {}; if (xhr.status < 300 && d.ok) { mark(item, "done", "Uploaded"); resolve(true); }
        else { mark(item, xhr.status === 409 ? "dup" : "error", d.error || "Upload failed"); resolve(xhr.status === 409 ? "dup" : false); } };
      xhr.onerror = () => { mark(item, "error", "Network error"); resolve(false); };
      const fd = new FormData(); fd.append("image", item.file); xhr.send(fd);
    });
  }
  upBtn.addEventListener("click", async () => {
    if (busy || !queue.length) return; busy = true; upBtn.disabled = clearBtn.disabled = true;
    const todo = queue.filter(q => !["done", "dup"].includes(q.li.dataset.state)); let okN = 0, dupN = 0, failN = 0;
    for (let i = 0; i < todo.length; i++) { upStatus.textContent = `Uploading ${i + 1} of ${todo.length}…`;
      const r = await sendOne(todo[i]); r === true ? okN++ : r === "dup" ? dupN++ : failN++; }
    if (okN) toast(`${okN} photo${okN === 1 ? "" : "s"} uploaded`, "success");
    if (dupN) toast(`${dupN} duplicate${dupN === 1 ? "" : "s"} skipped`, "info");
    if (failN) toast(`${failN} upload${failN === 1 ? "" : "s"} failed`, "error");
    busy = false; upBtn.disabled = clearBtn.disabled = false;
    if (okN) { if (location.hash !== "#photos" && S.view !== "photos") location.hash = "#photos"; await loadAll(); }
    if (!failN) setTimeout(() => { if (upDlg.open) upDlg.close(); queue.forEach(q => URL.revokeObjectURL(q.url)); queue = []; renderQueue(); }, 900);
    else upStatus.textContent = "Some files failed. Remove them or retry.";
  });
  clearBtn.addEventListener("click", () => { queue.forEach(q => URL.revokeObjectURL(q.url)); queue = []; renderQueue(); });
  input.addEventListener("change", () => { if (!busy) addFiles(input.files); input.value = ""; });
  [["dragenter", "dragover"], ["dragleave", "drop"]].forEach(([a, b], i) => [a, b].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.toggle("drag", i === 0 || t === "dragover"); if (i === 1) dz.classList.remove("drag"); })));
  let dragDepth = 0; const ov = $("#dropOverlay");               // drop anywhere on the page
  window.addEventListener("dragenter", e => { if (e.dataTransfer?.types?.includes("Files")) { dragDepth++; ov.hidden = false; } });
  window.addEventListener("dragleave", () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) ov.hidden = true; });
  window.addEventListener("dragover", e => e.preventDefault());
  window.addEventListener("drop", e => { e.preventDefault(); dragDepth = 0; ov.hidden = true; if (!busy && e.dataTransfer?.files?.length) addFiles(e.dataTransfer.files); });

  /* ---------- logout confirmation ---------- */
  $("#logoutBtn").addEventListener("click", async () => {
    if (await ask($("#logoutDialog"), () => {})) $("#logoutForm").submit();
  });

  window.addEventListener("hashchange", route); route();
})();
