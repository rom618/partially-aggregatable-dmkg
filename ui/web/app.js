"use strict";

// ---- DOM helpers ---------------------------------------------------------
const $ = (id) => document.getElementById(id);
const el = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
};

let latest = null; // last snapshot, for the inspector
let tManual = false; // has the user explicitly chosen the threshold t?

// ---- API -----------------------------------------------------------------
async function api(path, method = "GET", body) {
  const opts = { method };
  if (body !== undefined) {
    opts.headers = { "Content-Type": "application/json" };
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  return res.json();
}

async function getState() { render(await api("/api/state")); }
async function advance() { render(await api("/api/advance", "POST")); }
async function reset() { render(await api("/api/reset", "POST")); }

async function configure() {
  const n = parseInt($("nInput").value, 10);
  const degree = parseInt($("tInput").value, 10);
  const malice = {};
  document.querySelectorAll(".mal-boxes select").forEach((sel) => {
    if (sel.value !== "honest") malice[sel.dataset.pid] = sel.value;
  });
  const snap = await api("/api/configure", "POST", { n, degree, malice });
  if (snap.error) {
    $("configError").textContent = snap.error;
  } else {
    $("configError").textContent = "";
    render(snap);
  }
}

// ---- Configuration controls ---------------------------------------------
// Per-participant malice selector. `selected` maps participant id -> kind.
function rebuildMalBoxes(n, selected = {}) {
  const box = $("malBoxes");
  box.innerHTML = "";
  const kinds = [
    ["honest", "honest"],
    ["z", "z (→ Qagg)"],
    ["pedersen", "Pedersen (→ complaint)"],
    ["both", "both"],
  ];
  for (let i = 0; i < n; i++) {
    const row = el("label", "mal-row");
    row.appendChild(el("span", "mal-pid", "P" + i));
    const sel = el("select");
    sel.dataset.pid = i;
    for (const [val, text] of kinds) {
      const opt = el("option");
      opt.value = val;
      opt.textContent = text;
      if ((selected[i] || "honest") === val) opt.selected = true;
      sel.appendChild(opt);
    }
    sel.classList.toggle("mal-active", (selected[i] || "honest") !== "honest");
    sel.addEventListener("change", () =>
      sel.classList.toggle("mal-active", sel.value !== "honest")
    );
    row.appendChild(sel);
    box.appendChild(row);
  }
}

function syncConfigLabels() {
  const n = parseInt($("nInput").value, 10);
  $("nVal").textContent = n;
  const tInput = $("tInput");
  // t is the polynomial degree and must satisfy 1 <= t <= n-1.
  tInput.min = 1;
  tInput.max = n - 1;
  if (tManual) {
    // Respect a user-chosen t, but keep it inside the valid range.
    let t = parseInt(tInput.value, 10);
    t = Math.min(Math.max(t, 1), n - 1);
    tInput.value = t;
  } else {
    // Track the documented default t = floor(n/2) as n changes.
    tInput.value = Math.max(1, Math.floor(n / 2));
  }
  $("tVal").textContent = tInput.value;
  // Preserve the per-participant malice selections that are still in range.
  const selected = {};
  document.querySelectorAll(".mal-boxes select").forEach((sel) => {
    const pid = parseInt(sel.dataset.pid, 10);
    if (pid < n && sel.value !== "honest") selected[pid] = sel.value;
  });
  rebuildMalBoxes(n, selected);
}

// ---- z-aggregation tree rendering ----------------------------------------
function renderZTree(s) {
  const panel = $("zTreePanel");
  if (!s.zTree || s.zTree.length === 0) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");

  const body = $("zTreeBody");
  body.innerHTML = "";

  const totalLevels = s.zTotalLevels;
  const levelsDone = s.zLevelsDone;

  // Show levels from leaf (top) to root (bottom).
  for (let li = 0; li < s.zTree.length; li++) {
    const lv = s.zTree[li];
    const done = lv.level < levelsDone;

    const levelDiv = el("div", "ztree-level" + (done ? "" : " ztree-level-pending"));

    // Level header.
    const hdr = el("div", "ztree-level-hdr");
    const levelLabel = lv.isLeafLevel
      ? "Level 0 - Leaf verification"
      : lv.isRootLevel
      ? `Level ${lv.level} - Root`
      : `Level ${lv.level}`;
    hdr.innerHTML =
      `<span class="ztree-lnum">${escapeHtml(levelLabel)}</span>` +
      `<span class="ztree-ldesc">${escapeHtml(lv.description)}</span>` +
      (done
        ? '<span class="badge ok">done</span>'
        : '<span class="badge ztree-pending-badge">pending</span>');
    levelDiv.appendChild(hdr);

    // Node row.
    const nodesRow = el("div", "ztree-nodes");
    for (const nd of lv.nodes) {
      const partsLabel = nd.realParticipants.length
        ? nd.realParticipants.map((p) => "P" + p).join(" + ")
        : "∅";
      const aggLabel =
        nd.aggregator !== null && nd.aggregator !== undefined
          ? "agg: P" + nd.aggregator
          : "";

      // Determine node coloring.
      let nodeCls = "ztree-node";
      if (done) {
        if (lv.isLeafLevel) {
          if (nd.leafOk === true) nodeCls += " ztree-ok";
          else if (nd.leafOk === false) nodeCls += " ztree-fail";
          else nodeCls += " ztree-neutral";
        } else {
          // Internal node: highlight if any participant in it is in Qagg.
          const hasQagg = nd.realParticipants.some((p) => s.qagg.includes(p));
          const allQagg =
            nd.realParticipants.length > 0 &&
            nd.realParticipants.every((p) => s.qagg.includes(p));
          if (allQagg) nodeCls += " ztree-fail";
          else if (hasQagg) nodeCls += " ztree-mixed";
          else nodeCls += " ztree-ok";
        }
      }

      const nodeDiv = el("div", nodeCls);

      // Participants section.
      const partsDiv = el("div", "ztree-parts", escapeHtml(partsLabel));
      nodeDiv.appendChild(partsDiv);

      // Status / aggregator.
      if (lv.isLeafLevel && done) {
        const statusDiv = el(
          "div",
          "ztree-status",
          nd.leafOk === true
            ? "✓ ok"
            : nd.leafOk === false
            ? "✗ Qagg"
            : "?"
        );
        nodeDiv.appendChild(statusDiv);
      } else if (!lv.isLeafLevel && aggLabel) {
        const aggDiv = el("div", "ztree-agg", escapeHtml(aggLabel));
        nodeDiv.appendChild(aggDiv);
      }

      nodesRow.appendChild(nodeDiv);
    }
    levelDiv.appendChild(nodesRow);
    body.appendChild(levelDiv);

    // Connector arrow between levels (skip after root).
    if (li < s.zTree.length - 1) {
      body.appendChild(el("div", "ztree-arrow", "▼"));
    }
  }

  // Final transcript broadcast & approval step (after all levels are folded).
  const bcast = $("zTreeBroadcast");
  bcast.innerHTML = "";
  const treeFolded = levelsDone >= totalLevels && totalLevels > 0;
  if (treeFolded) {
    bcast.classList.remove("hidden");
    const rootLabel =
      s.zRoot !== null && s.zRoot !== undefined ? "P" + s.zRoot : "the root";
    if (s.zTranscriptBroadcast) {
      const head = el(
        "div",
        "ztree-bcast-head",
        `📡 Root ${rootLabel} broadcast the candidate transcript - each participant verified &amp; approved it:`
      );
      bcast.appendChild(head);
      const votes = el("div", "ztree-votes");
      for (const a of s.zApprovals || []) {
        const v = el(
          "span",
          "ztree-vote " + (a.approved ? "ztree-vote-ok" : "ztree-vote-bad"),
          `P${a.id} ${a.approved ? "✓" : "✗"}`
        );
        votes.appendChild(v);
      }
      bcast.appendChild(votes);
    } else {
      bcast.appendChild(
        el(
          "div",
          "ztree-bcast-head ztree-bcast-pending",
          `⏳ Root ${rootLabel} holds the candidate transcript - advance to broadcast it for approval.`
        )
      );
    }
  } else {
    bcast.classList.add("hidden");
  }

  // Progress bar / summary.
  const prog = $("zTreeProgress");
  if (levelsDone === 0) {
    prog.textContent = "Tree not yet started.";
  } else if (!treeFolded) {
    prog.textContent = `${levelsDone} of ${totalLevels} level${
      totalLevels !== 1 ? "s" : ""
    } processed.`;
  } else if (s.zTranscriptBroadcast) {
    prog.textContent = `All ${totalLevels} levels folded and the final transcript approved - z-layer complete.`;
  } else {
    prog.textContent = `All ${totalLevels} levels folded - transcript awaiting broadcast & approval.`;
  }
}

// ---- Setup / common reference --------------------------------------------
function renderCommon(s) {
  const c = s.common;
  if (!c) return;
  $("crsGg1").textContent = c.gG1;
  $("crsHg2").textContent = c.hG2;
  $("crsU1").textContent = c.u1;
  $("crsDegree").textContent = `t = ${s.degree}  (reconstruct from t+1 = ${s.reconstructionThreshold})`;
  $("crsPedG1").textContent = c.pedG1;
  $("crsPedG2").textContent = c.pedG2;
  $("crsPedH1").textContent = c.pedH1;
  $("crsPedH2").textContent = c.pedH2;
  $("crsElg").textContent = c.elgamalBase;
  $("crsDomain").textContent =
    `size ${c.domainSize}` + (c.domainSize !== s.n ? ` (n=${s.n} padded to a power of two)` : "");
}

// ---- Rendering -----------------------------------------------------------
function render(s) {
  if (!s || s.error) return;
  latest = s;

  renderCommon(s);

  // Phases.
  document.querySelectorAll("#phaseList li").forEach((li) => {
    const idx = parseInt(li.dataset.phase, 10);
    li.classList.toggle("done", idx < s.phaseIndex);
    li.classList.toggle("active", idx === s.phaseIndex);
  });
  const adv = $("advanceBtn");
  adv.disabled = !s.canAdvance;
  adv.textContent = s.canAdvance ? `Advance to ${s.nextPhase} »` : "Protocol complete";

  // Global state.
  $("qaggVal").textContent = s.qagg.length ? s.qagg.map((i) => "P" + i).join(", ") : "∅";
  $("qualVal").textContent = s.qual.length ? s.qual.map((i) => "P" + i).join(", ") : "-";
  $("complaintsVal").textContent = s.complaints.length
    ? s.complaints.map((c) => `P${c.complainer}→P${c.dealer}`).join(", ")
    : "none";

  // Public key.
  const pkBox = $("pkBox");
  if (s.publicKey) {
    pkBox.classList.remove("hidden");
    $("pkC1").textContent = s.publicKey.c1;
    $("pkC2").textContent = s.publicKey.c2;
    $("pkC3").textContent = s.publicKey.c3;
    const r = $("pkRecon");
    if (s.publicKey.reconstructedOk === true) {
      r.className = "badge ok";
      r.textContent = "reconstructed from t+1 ✓";
    } else if (s.publicKey.reconstructedOk === false) {
      r.className = "badge bad";
      r.textContent = "reconstruction mismatch ✗";
    } else {
      r.className = "badge";
      r.textContent = "";
    }
  } else {
    pkBox.classList.add("hidden");
  }

  // Participants.
  const grid = $("participants");
  grid.innerHTML = "";
  s.participants.forEach((p) => grid.appendChild(participantCard(p)));

  // z-aggregation tree.
  renderZTree(s);

  // Log (latest at bottom, auto-scroll).
  const log = $("log");
  log.innerHTML = "";
  s.log.forEach((line) => log.appendChild(el("div", null, escapeHtml(line))));
  log.scrollTop = log.scrollHeight;

  // Keep the inspector in sync if open.
  const insp = $("inspector");
  if (!insp.classList.contains("hidden") && insp.dataset.pid !== undefined) {
    openInspector(parseInt(insp.dataset.pid, 10));
  }
}

function participantCard(p) {
  const card = el("div", "pcard");
  card.classList.toggle("malicious", p.malicious);
  card.classList.toggle("disqualified", !!p.disqualifiedReason);

  const avatar = el("div", "avatar", "P" + p.id);
  card.appendChild(avatar);

  card.appendChild(el("div", "pid", `Participant ${p.id} <span class="who">${p.malicious ? "corrupted" : "honest"}</span>`));

  const badges = el("div", "pbadges");
  if (p.malicious) badges.appendChild(el("span", "badge mal", escapeHtml(p.maliceLabel || "malicious")));
  if (p.inQagg) badges.appendChild(el("span", "badge qagg", "Q<sub>agg</sub>"));
  if (p.inQual) badges.appendChild(el("span", "badge qual", "QUAL"));
  card.appendChild(badges);

  const bits = [];
  if (p.complaintsAgainst > 0) bits.push(`${p.complaintsAgainst} complaint(s)`);
  if (p.disqualifiedReason) bits.push(`DQ: ${p.disqualifiedReason}`);
  bits.push(`${p.public.length} public · ${p.private.length} private`);
  if (p.communication && p.communication.length)
    bits.push(`${p.communication.length} comm`);
  card.appendChild(el("div", "pstatus", bits.join(" · ")));

  card.addEventListener("click", () => openInspector(p.id));
  return card;
}

// ---- Inspector -----------------------------------------------------------
function openInspector(id) {
  const p = latest.participants.find((x) => x.id === id);
  if (!p) return;
  const insp = $("inspector");
  insp.dataset.pid = id;
  insp.classList.remove("hidden");

  $("inspTitle").innerHTML = `Participant ${p.id} <small style="color:var(--muted)">(${p.malicious ? "corrupted" : "honest"})</small>`;

  const badges = $("inspBadges");
  badges.innerHTML = "";
  if (p.malicious) badges.appendChild(el("span", "badge mal", escapeHtml(p.maliceLabel || "malicious")));
  if (p.inQagg) badges.appendChild(el("span", "badge qagg", "in Q<sub>agg</sub>"));
  if (p.inQual) badges.appendChild(el("span", "badge qual", "in QUAL"));
  if (p.disqualifiedReason) badges.appendChild(el("span", "badge bad", "disqualified: " + p.disqualifiedReason));
  if (p.complaintsAgainst > 0) badges.appendChild(el("span", "badge", p.complaintsAgainst + " complaint(s) against"));

  fillFields($("inspPublic"), p.public);
  fillFields($("inspPrivate"), p.private);
  fillFields($("inspComm"), p.communication || []);
}

function fillFields(dl, fields) {
  dl.innerHTML = "";
  if (!fields.length) {
    dl.appendChild(el("dd", null, "<i>(nothing yet - advance the protocol)</i>"));
    return;
  }
  fields.forEach((f) => {
    dl.appendChild(el("dt", null, escapeHtml(f.label)));
    dl.appendChild(el("dd", null, escapeHtml(f.value)));
  });
}

function closeInspector() {
  const insp = $("inspector");
  insp.classList.add("hidden");
  delete insp.dataset.pid;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ---- Wiring --------------------------------------------------------------
$("nInput").addEventListener("input", syncConfigLabels);
$("tInput").addEventListener("input", () => {
  // The user is explicitly choosing t - stop auto-tracking n/2.
  tManual = true;
  $("tVal").textContent = $("tInput").value;
});
$("configureBtn").addEventListener("click", configure);
$("resetBtn").addEventListener("click", reset);
$("advanceBtn").addEventListener("click", advance);
$("inspClose").addEventListener("click", closeInspector);
$("inspector").addEventListener("click", (e) => {
  if (e.target.id === "inspector") closeInspector();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeInspector();
});

// Initialise controls from the current (default) session, then load state.
syncConfigLabels();
getState().then(() => {
  if (latest) {
    $("nInput").value = latest.n;
    syncConfigLabels(); // sets the t range + default for this n
    // Reflect the server's actual degree without flipping into "manual" mode.
    if (latest.degree !== parseInt($("tInput").value, 10)) {
      $("tInput").value = latest.degree;
      $("tVal").textContent = latest.degree;
    }
    const selected = {};
    (latest.malice || []).forEach((m) => (selected[m.id] = m.kind));
    rebuildMalBoxes(latest.n, selected);
  }
});
