/* ── CWE Graph Explorer (standalone) ─────────────────────── */
(function () {
  "use strict";

  const DATA = window.CWE_DATA;
  const NODES = DATA.nodes;
  // Deprecated weaknesses aren't graph nodes, but the model, CVE records and old links still
  // name them: { id: { n, d, to: [MITRE's suggested replacements] } }.
  const DEPRECATED = DATA.deprecated || {};
  // MITRE's observed examples, loaded after start from data/cwe-examples.js:
  // EXAMPLES cwe → [[CVE id, description]], EXAMPLE_OF CVE id → [cwe ids].
  let EXAMPLES = null;
  const EXAMPLE_OF = {};

  /* ── Encodings ───────────────────────────────────────────
     MITRE's own CWE-site icons: a lettered circle per abstraction (P/C/B/V),
     a column for Pillars, and spheres / linked rings for Composite / Chain
     compounds. The letter or glyph is the secondary encoding, so identity
     never rides on colour alone. Colours are MITRE's, except Variant's purple,
     lightened from #944093 so it stays apart from Base's blue under protan
     CVD (validated all-pairs on the light surface). Keep in sync with
     css/app.css. */
  const KINDS = {
    Pillar:    { color: "#919191", letter: "P", shape: "round-rectangle" },
    Class:     { color: "#358d33", letter: "C", shape: "ellipse" },
    Base:      { color: "#3c5292", letter: "B", shape: "ellipse" },
    Variant:   { color: "#c06abd", letter: "V", shape: "ellipse" },
    Composite: { color: "#3c5292", shape: "ellipse" },
    Chain:     { color: "#3c5292", shape: "ellipse" },
  };
  const DEFAULT_KIND = { color: "#8c8c88", letter: "?", shape: "ellipse" };

  // Compounds split by MITRE's Structure attribute; everything else by abstraction.
  function kindOf(d) { return d.a === "Compound" ? (d.t === "Chain" ? "Chain" : "Composite") : d.a; }
  function kindStyle(kind) { return KINDS[kind] || DEFAULT_KIND; }

  function iconSvg(kind) {
    const k = kindStyle(kind), c = k.color;
    let body;
    if (kind === "Pillar") {
      body = `<rect x="3" y="2.5" width="34" height="6" rx="1.5" fill="#6e6e6e"/>` +
        `<rect x="3" y="31.5" width="34" height="6" rx="1.5" fill="#6e6e6e"/>` +
        `<rect x="7.5" y="8.5" width="25" height="23" fill="${c}"/>` +
        `<text x="20" y="27" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-weight="700" font-size="18" fill="#fff">P</text>`;
    } else if (kind === "Composite") {
      body = [[20, 13], [12.5, 26], [27.5, 26]].map(([x, y]) =>
        `<circle cx="${x}" cy="${y}" r="9" fill="${c}" stroke="#fff" stroke-width="1.5"/>` +
        `<circle cx="${x - 2.5}" cy="${y - 2.5}" r="2.5" fill="#fff" fill-opacity=".35"/>`).join("");
    } else if (kind === "Chain") {
      body = `<circle cx="20" cy="20" r="19" fill="#fff"/>` +
        `<rect x="4" y="13" width="17" height="14" rx="7" fill="none" stroke="${c}" stroke-width="4"/>` +
        `<rect x="19" y="13" width="17" height="14" rx="7" fill="none" stroke="${c}" stroke-width="4"/>`;
    } else {
      body = `<circle cx="20" cy="20" r="19" fill="${c}"/>` +
        `<text x="20" y="27.5" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-weight="700" font-size="21" fill="#fff">${k.letter}</text>`;
    }
    // Explicit width/height: without an intrinsic size Cytoscape mis-scales the image on resized nodes.
    return `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 40 40">${body}</svg>`;
  }
  const ICON_URI = {};
  function iconUri(kind) {
    return ICON_URI[kind] || (ICON_URI[kind] = "data:image/svg+xml;utf8," + encodeURIComponent(iconSvg(kind)));
  }
  function iconImg(kind, size = 14) {
    return `<img class="kind-icon" src="${iconUri(kind)}" width="${size}" height="${size}" alt="${escHtml(kind)}" title="${escHtml(kind)}">`;
  }

  // ChildOf has no arrowhead: tree-diagram convention, parents always sit
  // above their children.
  const EDGE_STYLE = {
    ChildOf:    { label: "ChildOf",    color: "#4d4d4d", line: "solid",  arrow: "none",     dash: "" },
    PeerOf:     { label: "PeerOf",     color: "#2f78c4", line: "dashed", arrow: "none",     dash: "5 3" },
    CanAlsoBe:  { label: "CanAlsoBe",  color: "#8c8c88", line: "dashed", arrow: "none",     dash: "2 3" },
    CanPrecede: { label: "CanPrecede", color: "#c0392b", line: "dotted", arrow: "vee",      dash: "1 3" },
    Requires:   { label: "Requires",   color: "#2a9d6f", line: "solid",  arrow: "vee",      dash: "" },
  };

  /* ── DOM ─────────────────────────────────────────────── */
  const $ = (id) => document.getElementById(id);
  const sInput = $("s");
  const qInput = $("q");
  const qBtn = $("q-btn");
  const searchResults = $("search-results");
  const viewSelect = $("view-select");
  const depthSelect = $("depth-select");
  const infoPanel = $("info-panel");
  const statusEl = $("status");
  const modeButtons = {
    neighbors: $("btn-neighbors"),
    ancestors: $("btn-ancestors"),
    descendants: $("btn-descendants"),
  };

  /* ── State ───────────────────────────────────────────── */
  const state = {
    center: null,
    mode: "neighbors",
    depth: 3,
    view: "all", // ChildOf from every MITRE view, merged
    dir: "TB", // "TB": parents on top · "LR": parents on the left, siblings stacked
    types: new Set(["ChildOf"]), // the hierarchy only; the other relationships are opt-in
  };
  let index = null; // { out: {id: [edge]}, in: {id: [edge]} } for the active filters

  /* ── Helpers ─────────────────────────────────────────── */
  function escHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function normId(raw) { return String(raw).trim().replace(/^cwe-?/i, ""); }

  // MITRE mapping usage as a coloured badge: green = Allowed / Allowed-with-Review,
  // yellow = Discouraged, red = Prohibited. The label is always spelled out too.
  const USAGE_CLASS = { "Allowed": "ok", "Allowed-with-Review": "ok", "Discouraged": "warn", "Prohibited": "bad" };
  // The same colours for the graph's tags (keep in sync with .badge.usage-* in css/app.css).
  const USAGE_COLORS = {
    ok:   { bg: "#eef7ee", border: "#b9dcb8", text: "#1e5a20" },
    warn: { bg: "#fdf5e3", border: "#ecd9a8", text: "#7a4f00" },
    bad:  { bg: "#fbeeed", border: "#ebbcb8", text: "#a3221b" },
    none: { bg: "#ffffff", border: "#c9c9c4", text: "#5c5c58" },
  };
  function usageBadge(u, prefix = "") {
    return `<span class="badge usage usage-${USAGE_CLASS[u] || "none"}" title="MITRE mapping usage">${prefix}${escHtml(u)}</span>`;
  }

  // "Deprecated in CWE 5.0", with links to what MITRE suggests instead.
  function deprecatedNote(id) {
    const d = DEPRECATED[normId(id)];
    if (!d) return "";
    const to = d.to.length ? `; MITRE suggests ${d.to.map((t) => cweLink(t)).join("")}` : "; MITRE names no replacement";
    return `<span class="dep-note" title="${escHtml(d.d)}">${usageBadge("Deprecated")} in CWE ${escHtml(DATA.version)}${to}</span>`;
  }

  // MITRE's mapping suggestions for a CWE (mostly on Discouraged ones), as compact links.
  function suggestNote(id) {
    const d = NODES[normId(id)];
    if (!d || !d.sg) return "";
    const links = d.sg.map(([s, why]) => `<span class="cmp-cwe" data-id="${s}" ` +
      `title="${escHtml(NODES[s].n + (why ? ": " + why : ""))}"><span class="cls-id">CWE-${s}</span></span>`).join(" ");
    return `<span class="dep-note sg">MITRE suggests ${links}</span>`;
  }

  /* ── Edge index for the active view ─────────────────────
     Holds every relationship type. The Relationships toggles filter only what
     the graph draws (outEdges/inEdges); the details panel always lists all. */
  function buildIndex() {
    const out = {}, inn = {}, seen = new Set();
    for (const [s, t, type, view] of DATA.edges) {
      if (type === "ChildOf" && state.view !== "all" && view !== state.view) continue;
      const id = `${type}:${s}>${t}`;
      if (seen.has(id)) continue; // same ChildOf pair in several views
      seen.add(id);
      const e = { id, s, t, type };
      (out[s] = out[s] || []).push(e);
      (inn[t] = inn[t] || []).push(e);
    }
    index = { out, in: inn };
  }
  const allOut = (id) => index.out[id] || [];
  const allIn = (id) => index.in[id] || [];
  const outEdges = (id) => allOut(id).filter((e) => state.types.has(e.type)); // what the graph shows
  const inEdges = (id) => allIn(id).filter((e) => state.types.has(e.type));

  /* ── Graph queries ───────────────────────────────────── */
  function collect(center, mode, depth) {
    const visited = new Set([center]);
    let frontier = [center];
    const maxSteps = mode === "neighbors" ? depth : Infinity;
    for (let step = 0; step < maxSteps && frontier.length; step++) {
      const next = [];
      for (const n of frontier) {
        let hops;
        if (mode === "ancestors") {
          hops = outEdges(n).filter((e) => e.type === "ChildOf").map((e) => e.t);
        } else if (mode === "descendants") {
          hops = inEdges(n).filter((e) => e.type === "ChildOf").map((e) => e.s);
        } else {
          hops = outEdges(n).map((e) => e.t).concat(inEdges(n).map((e) => e.s));
        }
        for (const h of hops) {
          if (!visited.has(h)) { visited.add(h); next.push(h); }
        }
      }
      frontier = next;
    }

    // A Cytoscape label is one block in one font, so each node's visible text is
    // drawn by two caption elements: the ID (bold, bigger) and the title (plus
    // the description, for the focused CWE). The node itself keeps the same text
    // as an invisible label, so the layout still reserves room for it.
    const nodes = [];
    for (const id of visited) {
      const d = NODES[id], focus = id === center;
      const title = focus && d.d ? `${d.n}\n\n${d.d}` : d.n;
      const capOpts = { classes: "cap", selectable: false, grabbable: false };
      nodes.push(
        // The invisible label's first line includes the usage text, so the layout reserves room for the tag.
        { data: { id, label: `CWE-${id}${d.u ? "   " + d.u : ""}\n${title}`, kind: kindOf(d), isCenter: focus } },
        { data: { id: `cap:${id}:id`, cap: "id", owner: id, focus, label: `CWE-${id}` }, ...capOpts },
        { data: { id: `cap:${id}:t`, cap: "t", owner: id, focus, label: title }, ...capOpts },
      );
      // MITRE mapping usage as a coloured tag after the ID (same colours as the right panel).
      if (d.u) nodes.push({ data: { id: `cap:${id}:u`, cap: "u", owner: id, focus, label: d.u, usage: USAGE_CLASS[d.u] || "none" }, ...capOpts });
    }
    const edges = [];
    for (const id of visited) {
      for (const e of outEdges(id)) {
        if (visited.has(e.t)) edges.push({ data: { id: e.id, source: e.s, target: e.t, type: e.type } });
      }
    }
    return { nodes, edges };
  }

  /* ── Cytoscape ───────────────────────────────────────── */
  const cy = cytoscape({
    container: $("cy"),
    minZoom: 0.05,
    maxZoom: 3,
    style: [
      {
        selector: "node",
        style: {
          shape: (el) => kindStyle(el.data("kind")).shape,
          "background-opacity": 0,
          "background-image": (el) => iconUri(el.data("kind")),
          "background-fit": "contain",
          width: 30,
          height: 30,
          "border-width": 0,
          "border-color": "#ffffff",
          label: "data(label)",
          "text-wrap": "wrap",
          // Top-down: a wrapped label under the node. Left-to-right: a wider
          // label beside it, so each sibling takes one short row.
          "text-max-width": () => (state.dir === "LR" ? "200px" : "110px"),
          "text-valign": () => (state.dir === "LR" ? "center" : "bottom"),
          "text-halign": () => (state.dir === "LR" ? "right" : "center"),
          "text-justification": () => (state.dir === "LR" ? "left" : "center"),
          "text-margin-y": () => (state.dir === "LR" ? 0 : 4),
          "text-margin-x": () => (state.dir === "LR" ? 6 : 0),
          "font-size": "8px",
          "font-family": "Helvetica Neue, Helvetica, Arial, sans-serif",
          color: "#1f1f1f",
          // Opaque label backing so edges pass behind, not through, the text.
          "text-background-color": "#ffffff",
          "text-background-opacity": 0.92,
          "text-background-padding": "2px",
          "min-zoomed-font-size": 5,
        },
      },
      {
        selector: "node[?isCenter]",
        // Wider label (it holds the description too); normal weight so a
        // paragraph doesn't render as a bold block.
        style: {
          width: 40, height: 40, "border-width": 3, "border-color": "#1f1f1f",
          "text-max-width": () => (state.dir === "LR" ? "200px" : "220px"),
          "text-justification": "left",
          "text-background-opacity": 0.95,
        },
      },
      {
        selector: "node:selected",
        style: { "border-width": 3, "border-color": "#0b57a4", "overlay-color": "#0b57a4", "overlay-opacity": 0.12, "overlay-padding": 4 },
      },
      {
        selector: "edge",
        style: {
          width: 1.5,
          "line-color": (el) => EDGE_STYLE[el.data("type")].color,
          "line-style": (el) => EDGE_STYLE[el.data("type")].line,
          "target-arrow-color": (el) => EDGE_STYLE[el.data("type")].color,
          "target-arrow-shape": (el) => EDGE_STYLE[el.data("type")].arrow,
          "arrow-scale": 0.9,
          "curve-style": "bezier",
          opacity: 0.85,
        },
      },
      {
        selector: "edge[type = 'ChildOf']",
        // Left-to-right turns close to the child (outline-style connectors), so
        // the run toward the parent passes behind the parent's label, not through
        // the children's.
        style: {
          "curve-style": "taxi",
          "taxi-direction": () => (state.dir === "LR" ? "leftward" : "upward"),
          "taxi-turn": () => (state.dir === "LR" ? 18 : "50%"),
        },
      },
      {
        // A CWE in the classifier's current top 3.
        selector: "node.candidate",
        style: { "underlay-color": "#0b57a4", "underlay-opacity": 0.18, "underlay-padding": 7, "underlay-shape": "ellipse" },
      },
      { selector: ".faded", style: { opacity: 0.15, "text-opacity": 0.25 } },
      {
        // Caption elements (see collect()): text only, placed over the space the
        // node's invisible label reserves. Left-aligned in left-to-right mode and
        // for the focused CWE's paragraph; centred under the node otherwise.
        selector: "node.cap",
        style: {
          width: 1, height: 1, "background-image": "none", "overlay-opacity": 0, events: "no",
          "text-valign": "bottom",
          "text-halign": (el) => (state.dir === "LR" || el.data("focus") ? "right" : "center"),
          "text-justification": (el) => (state.dir === "LR" || el.data("focus") ? "left" : "center"),
          "text-margin-x": 0, "text-margin-y": 0,
          "text-max-width": (el) => (el.data("cap") === "id" ? "400px"
            : state.dir === "LR" ? "200px" : el.data("focus") ? "220px" : "110px"),
        },
      },
      { selector: "node[cap = 'id']", style: { "font-size": "10px", "font-weight": "bold" } },
      {
        // Mapping-usage tag: always starts at its point (placed right after the ID).
        selector: "node[cap = 'u']",
        style: {
          "font-size": "7px", "font-weight": 600, "text-halign": "right", "text-justification": "left",
          "text-background-shape": "round-rectangle", "text-background-opacity": 1, "text-background-padding": "1.5px",
          "text-border-width": 0.6, "text-border-opacity": 1,
          "text-background-color": (el) => USAGE_COLORS[el.data("usage")].bg,
          "text-border-color": (el) => USAGE_COLORS[el.data("usage")].border,
          color: (el) => USAGE_COLORS[el.data("usage")].text,
        },
      },
      // The node's own label only reserves space; it's never drawn (even when faded).
      { selector: "node[!cap]", style: { "text-opacity": 0, "text-background-opacity": 0 } },
    ],
  });

  // Put each node's captions over the space its invisible label reserves.
  const ID_LINE = 12; // height of the 10px bold ID line, in graph units
  // Width of an ID as drawn (10px bold), to put the usage tag right after it.
  const measureCtx = document.createElement("canvas").getContext("2d");
  measureCtx.font = 'bold 10px "Helvetica Neue", Helvetica, Arial, sans-serif';
  const idWidth = (text) => measureCtx.measureText(text).width;

  function placeCaptions(nodes) {
    cy.batch(() => nodes.forEach((n) => {
      const bb = n.boundingBox({ includeNodes: false, includeEdges: false, includeLabels: true, includeOverlays: false });
      const left = state.dir === "LR" || n.data("isCenter");
      const x = left ? bb.x1 + 2 : n.position("x"), y = bb.y1 + 2;
      cy.getElementById(`cap:${n.id()}:id`).position({ x, y });
      cy.getElementById(`cap:${n.id()}:t`).position({ x, y: y + ID_LINE });
      const w = idWidth(`CWE-${n.id()}`);
      cy.getElementById(`cap:${n.id()}:u`).position({ x: (left ? x + w : x + w / 2) + 5, y: y + 2 });
    }));
  }
  cy.on("position", "node[!cap]", (e) => placeCaptions(e.target)); // layout, animation, dragging

  const ZOOM_MAX_FIT = 1.6;   // largest zoom an automatic fit may use
  const ZOOM_READABLE = 1.25; // smallest zoom an automatic fit may use (8px labels → 10px)

  function runLayout(animate) {
    // Rank by ChildOf only, so lateral relationships (PeerOf, CanPrecede …)
    // never distort the hierarchy.
    const n = cy.nodes("[!cap]").length;
    cy.elements("node[!cap], edge[type = 'ChildOf']").layout({
      name: "dagre",
      // Edges run child → parent, so "BT" puts parents on top and "RL" puts them on the left.
      rankDir: state.dir === "LR" ? "RL" : "BT",
      nodeSep: state.dir === "LR" ? 6 : 16,
      rankSep: state.dir === "LR" ? 60 : 50,
      edgeSep: 20,
      nodeDimensionsIncludeLabels: true,
      animate: animate !== false && n <= 150,
      animationDuration: 350,
      fit: true,
      padding: 40,
      stop: () => {
        placeCaptions(cy.nodes("[!cap]"));
        // Don't blow tiny graphs (e.g. a short ancestor chain) up to poster size,
        // and don't shrink wide ones past readable: centre on the focus CWE
        // instead and let the user pan (or press Fit for the whole picture).
        if (cy.zoom() > ZOOM_MAX_FIT) { cy.zoom(ZOOM_MAX_FIT); cy.center(); }
        else if (cy.zoom() < ZOOM_READABLE) {
          cy.zoom(ZOOM_READABLE);
          const focus = cy.getElementById(state.center);
          if (state.dir === "LR") {
            // A left-to-right tree reads from its left edge: pin that edge, and
            // centre the focus CWE vertically.
            const bb = cy.elements().boundingBox(), z = cy.zoom();
            cy.pan({ x: 20 - bb.x1 * z, y: cy.height() / 2 - focus.position("y") * z });
          } else {
            cy.center(focus);
          }
        }
      },
    }).run();
  }

  /* ── Rendering ───────────────────────────────────────── */
  function render() {
    const { center, mode, depth } = state;
    if (!center || !NODES[center]) return;
    const els = collect(center, mode, depth);
    cy.batch(() => {
      cy.elements().remove();
      cy.add(els.nodes);
      cy.add(els.edges);
    });
    runLayout(false);

    const node = cy.getElementById(center);
    node.select();
    markCandidates();
    updateInfo(center);

    for (const [m, btn] of Object.entries(modeButtons)) btn.classList.toggle("active", m === mode);
    for (const d of ["TB", "LR"]) $(`dir-${d}`).classList.toggle("active", d === state.dir);
    const what = mode === "neighbors" ? `neighborhood, depth ${depth}` : mode;
    const viewName = state.view === "all" ? "all views" : `view ${state.view}`;
    statusEl.textContent =
      `CWE-${center} · ${what} · ${els.nodes.filter((n) => !n.data.cap).length} nodes, ${els.edges.length} edges · ${viewName}`;
    document.title = `CWE-${center} – CWE Graph Explorer`;
  }

  /* ── Navigation (URL hash: #79, #79/ancestors, #79/descendants) ── */
  function parseHash() {
    const [raw, mode] = decodeURIComponent(location.hash.slice(1)).split("/");
    let id = normId(raw || "");
    if (!NODES[id] && DEPRECATED[id] && DEPRECATED[id].to.length) id = DEPRECATED[id].to[0];
    return { id, mode: modeButtons[mode] ? mode : "neighbors" };
  }
  function navigate(id, mode) {
    id = normId(id);
    if (!NODES[id]) return;
    mode = mode || "neighbors";
    const hash = mode === "neighbors" ? `#${id}` : `#${id}/${mode}`;
    if (location.hash === hash) {
      state.center = id; state.mode = mode; render();
    } else {
      location.hash = hash; // → hashchange → render
    }
  }
  window.addEventListener("hashchange", () => {
    const { id, mode } = parseHash();
    if (!NODES[id]) return;
    state.center = id; state.mode = mode; render();
  });

  /* ── Info panel ──────────────────────────────────────── */
  function relList(title, ids) {
    if (!ids.length) return "";
    const items = [...new Set(ids)]
      .sort((a, b) => a - b)
      .map((id) => `<li><a href="#${id}" class="info-nav" data-id="${id}">CWE-${id}</a> ` +
        `<span class="rel-name">${escHtml(NODES[id].n)}</span></li>`)
      .join("");
    return `<h3>${title} (${new Set(ids).size})</h3><ul class="rel">${items}</ul>`;
  }

  let infoId = null;
  function updateInfo(id) {
    infoId = id;
    const d = NODES[id];
    const kind = kindOf(d);
    const out = allOut(id), inn = allIn(id); // every relation, whatever the graph toggles show
    const pick = (list, type, end) => list.filter((e) => e.type === type).map((e) => e[end]);
    const both = (type) => pick(out, type, "t").concat(pick(inn, type, "s"));

    let html = `<h2>CWE-${escHtml(id)}</h2><div class="cwe-name">${escHtml(d.n)}</div>`;
    html += `<div class="badges">`;
    html += `<span class="badge">${iconImg(kind, 12)}${escHtml(d.a === "Compound" ? `Compound (${kind})` : d.a)}</span>`;
    html += `<span class="badge">Status: ${escHtml(d.s)}</span>`;
    if (d.u) html += usageBadge(d.u, "Mapping: ");
    html += `</div>`;
    if (d.d) html += `<p class="desc">${escHtml(d.d)}</p>`;
    if (d.sg) {
      // MITRE's comment, unless it only repeats the suggested CWE's name ("Specified Quantity").
      const note = (s, why) => why && !NODES[s].n.toLowerCase().includes(why.toLowerCase())
        ? `<span class="sg-why">${escHtml(why)}</span>` : "";
      html += `<h3>MITRE mapping suggestions (${d.sg.length})</h3><ul class="rel">` + d.sg.map(([s, why]) =>
        `<li><a href="#${s}" class="info-nav" data-id="${s}">CWE-${s}</a> <span class="rel-name">${escHtml(NODES[s].n)}` +
        `${note(s, why)}</span></li>`).join("") + `</ul>`;
    }

    html += relList("Parents", pick(out, "ChildOf", "t"));
    html += relList("Children", pick(inn, "ChildOf", "s"));
    html += relList("Peers", both("PeerOf"));
    html += relList("Can also be", both("CanAlsoBe"));
    html += relList("Can precede", pick(out, "CanPrecede", "t"));
    html += relList("Can follow", pick(inn, "CanPrecede", "s"));
    html += relList("Requires", pick(out, "Requires", "t"));
    html += relList("Required by", pick(inn, "Requires", "s"));
    const ex = EXAMPLES && EXAMPLES[id];
    if (ex) {
      html += `<details class="examples"><summary>Observed examples (${ex.length})</summary><ul class="rel">` +
        ex.map(([ref, desc]) => `<li>${/^CVE-/.test(ref)
          ? `<a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(ref)}" target="_blank" rel="noopener">${escHtml(ref)}</a>`
          : `<span>${escHtml(ref)}</span>`} <span class="rel-name">${escHtml(desc)}</span></li>`).join("") + `</ul></details>`;
    }

    html += `<a class="mitre" href="https://cwe.mitre.org/data/definitions/${encodeURIComponent(id)}.html" ` +
      `target="_blank" rel="noopener">View CWE-${escHtml(id)} on MITRE →</a>`;
    // MITRE's diagram of the weakness (84 CWEs have one), loaded from cwe.mitre.org.
    if (d.g) {
      const src = "https://cwe.mitre.org" + d.g;
      html += `<figure class="cwe-diagram"><a href="${escHtml(src)}" target="_blank" rel="noopener" title="Open full size">` +
        `<img src="${escHtml(src)}" alt="MITRE diagram of CWE-${escHtml(id)}" loading="lazy"></a>` +
        `<figcaption>Diagram: MITRE CWE</figcaption></figure>`;
    }
    infoPanel.innerHTML = html;
  }

  infoPanel.addEventListener("click", (e) => {
    const link = e.target.closest(".info-nav");
    if (!link) return;
    e.preventDefault();
    const id = link.dataset.id;
    const existing = cy.getElementById(id);
    if (existing.length) {
      cy.nodes().unselect();
      existing.select();
      cy.animate({ center: { eles: existing }, duration: 300 });
      updateInfo(id);
    } else {
      navigate(id, "neighbors");
    }
  });

  /* ── Search ──────────────────────────────────────────── */
  // Free-text search: words are lowercased and lightly stemmed ("responses", "response" →
  // "respons"; "disclosure", "disclosed" → "disclos"), then scored against the name, MITRE's
  // alternate terms and the description, weighted by how rare each word is.
  const STOP = new Set(("a an and are as at be by can due for from has in into is it its of on or " +
    "that the this to via when where which while with without").split(" "));
  const SUFFIXES = ["ational", "ations", "ation", "ating", "ated", "ates", "ate", "ings", "ing", "ions", "ion",
    "ures", "ure", "ments", "ment", "ness", "ers", "er", "ed", "es", "ly", "s"];
  function stem(w) {
    for (const s of SUFFIXES) {
      if (w.endsWith(s) && w.length - s.length >= 3) { w = w.slice(0, -s.length); break; }
    }
    return w.length > 3 && w.endsWith("e") ? w.slice(0, -1) : w;
  }
  function words(s) {
    s = String(s).toLowerCase().replace(/\b([a-z0-9]+)-([a-z0-9]+)\b/g, "$1 $2 $1$2"); // "hard-coded" also as "hardcoded"
    return s.split(/[^a-z0-9]+/).filter((w) => w && !STOP.has(w)).map(stem);
  }

  const SEARCH_LIST = Object.entries(NODES).map(([id, d]) => ({
    id, name: d.n, lname: d.n.toLowerCase(), terms: d.k || [],
    fields: [new Set(words(d.n)), new Set(words((d.k || []).join(" "))), new Set(words(d.d))],
  }));
  const FIELD_WEIGHT = [3, 2.5, 1]; // name, alternate terms, description
  const DF = {};
  for (const it of SEARCH_LIST) for (const w of new Set(it.fields.flatMap((f) => [...f]))) DF[w] = (DF[w] || 0) + 1;
  let activeIdx = -1;

  function textSearch(q) {
    const lq = q.toLowerCase().trim();
    // Each word matches exactly (by stem) or, scored lower, as a prefix: an unfinished word
    // while typing, or an abbreviation ("auth" → authorization, "info" → information).
    const raw = [...new Set(lq.split(/[^a-z0-9]+/).filter((w) => w && !STOP.has(w)))];
    if (!raw.length) return [];
    const qw = raw.map((r) => ({ stem: stem(r), pre: r.length >= 3 ? r : null }));
    const match = (f, w) => f.has(w.stem) ? 1 : w.pre && [...f].some((t) => t.startsWith(w.pre)) ? 0.6 : 0;
    for (const w of qw) {
      const df = w.pre ? SEARCH_LIST.filter((it) => it.fields.some((f) => match(f, w))).length : DF[w.stem] || 0;
      w.idf = Math.log(1 + SEARCH_LIST.length / (1 + df));
    }
    const scored = [];
    for (const it of SEARCH_LIST) {
      let score = 0, matched = 0;
      for (const w of qw) {
        const s = it.fields.reduce((acc, f, i) => acc + match(f, w) * FIELD_WEIGHT[i], 0);
        if (s) { score += s * w.idf; matched++; }
      }
      if (!matched) continue;
      score *= (matched / qw.length) ** 2; // matching every word beats matching one word well
      const term = it.terms.find((t) => t.toLowerCase() === lq) ||
        it.terms.find((t) => t.toLowerCase().includes(lq) || lq.includes(t.toLowerCase()));
      if (term && term.toLowerCase() === lq) score *= 4; // "XSS" is CWE-79's own alternate term
      else if (it.lname.includes(lq)) score *= 2;
      else if (term) score *= 1.8;
      scored.push({ ...it, score, aka: term || "" });
    }
    scored.sort((a, b) => b.score - a.score || +a.id - +b.id);
    return scored;
  }

  function search(q) {
    q = q.trim();
    if (!q) return [];
    const id = normId(q);
    if (/^\d+$/.test(id)) {
      const scored = [];
      for (const it of SEARCH_LIST) {
        const score = it.id === id ? 0 : it.id.startsWith(id) ? 1 : it.id.includes(id) ? 2 : -1;
        if (score >= 0) scored.push([score, +it.id, it]);
      }
      scored.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
      return scored.slice(0, 40).map((s) => s[2]);
    }
    return textSearch(q).slice(0, 40);
  }

  function showResults(items) {
    activeIdx = items.length ? 0 : -1;
    searchResults.innerHTML = items.map((it, i) =>
      `<li data-id="${it.id}" class="${i === 0 ? "active" : ""}" title="${escHtml(NODES[it.id].d || it.name)}">` +
      `${iconImg(kindOf(NODES[it.id]), 12)}<span class="sr-id">CWE-${it.id}</span>${escHtml(it.name)}` +
      `${it.aka ? ` <span class="sr-aka">aka ${escHtml(it.aka)}</span>` : ""}</li>`).join("");
  }
  function pickResult(li) {
    if (!li) return;
    searchResults.innerHTML = "";
    sInput.value = "";
    navigate(li.dataset.id, "neighbors");
    sInput.blur();
  }

  /* ── CWE search box ──────────────────────────────────── */
  sInput.addEventListener("input", () => showResults(search(sInput.value)));
  sInput.addEventListener("focus", () => showResults(search(sInput.value)));
  sInput.addEventListener("blur", () => setTimeout(() => { searchResults.innerHTML = ""; }, 150));
  sInput.addEventListener("keydown", (e) => {
    const lis = searchResults.querySelectorAll("li");
    if ((e.key === "ArrowDown" || e.key === "ArrowUp") && lis.length) {
      e.preventDefault();
      lis[activeIdx]?.classList.remove("active");
      activeIdx = (activeIdx + (e.key === "ArrowDown" ? 1 : -1) + lis.length) % lis.length;
      lis[activeIdx].classList.add("active");
      lis[activeIdx].scrollIntoView({ block: "nearest" });
    } else if (e.key === "Escape") {
      if (searchResults.children.length) searchResults.innerHTML = "";
      else sInput.blur();
    }
  });
  // mousedown, not click: pick the result before the input's blur clears the list.
  searchResults.addEventListener("mousedown", (e) => { e.preventDefault(); pickResult(e.target.closest("li")); });
  $("s-form").addEventListener("submit", (e) => {  // Enter
    e.preventDefault();
    pickResult(searchResults.querySelectorAll("li")[activeIdx]);
  });

  /* ── Description box: always the classifier ──────────── */
  const Q_HEIGHT = 46; // two rows; matches #q in css/app.css
  function growInput() {
    qInput.style.height = Q_HEIGHT + "px";
    const h = Math.min(Math.max(qInput.scrollHeight + 2, Q_HEIGHT), 220);
    qInput.style.height = h + "px";
    qInput.classList.toggle("grown", h > Q_HEIGHT);
  }

  function updateInput() {
    qBtn.textContent = "Find CWE";
    qBtn.disabled = !modelReady || !qInput.value.trim();
    qBtn.title = !modelReady ? modelStatus.textContent
      : noModel ? "Look up the CVE and its assigned CWEs; kernel text runs /linux-cwe (Enter)"
      : "Classify with vc-weakling (Enter)";
    if (document.activeElement === qInput) growInput();
  }

  qInput.addEventListener("input", updateInput);
  qInput.addEventListener("focus", growInput);
  qInput.addEventListener("blur", () => {
    qInput.style.height = Q_HEIGHT + "px";
    qInput.classList.remove("grown");
    qInput.scrollTop = 0;
  });
  qInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {  // Shift+Enter adds a line
      e.preventDefault();
      runClassify();
    } else if (e.key === "Escape") {
      qInput.blur();
    }
  });
  $("q-form").addEventListener("submit", (e) => { e.preventDefault(); runClassify(); });

  /* ── Classifier (vc-weakling via server.py) ──────────── */
  const resultPanel = $("result-panel");
  const clsResults = $("classify-results");
  const modelStatus = $("model-status");
  let candidates = []; // CWE ids (no prefix) in the latest top 3
  let modelReady = false;
  let noModel = null; // why the server has no vc-weakling; CVE lookup and /linux-cwe still work

  function markCandidates() {
    cy.nodes().removeClass("candidate");
    for (const id of candidates) cy.getElementById(id).addClass("candidate");
    clsResults.querySelectorAll("li[data-id]").forEach((li) =>
      li.classList.toggle("current", li.dataset.id === state.center));
  }

  function setModelStatus(text, ready) {
    modelReady = ready;
    modelStatus.textContent = text;
    modelStatus.classList.toggle("ready", ready);
    updateInput();
  }

  function showResultPanel(html) {
    clsResults.innerHTML = html;
    resultPanel.hidden = false;
    resultPanel.parentElement.scrollTop = 0;
  }

  const SERVER = "http://127.0.0.1:8800/";

  async function checkModel() {
    if (location.origin + "/" !== SERVER) {
      // Opened as a file (or from another dev server): if server.py is running, switch to it,
      // keeping the current CWE; otherwise say how to start it.
      try {
        const r = await fetch(SERVER + "api/health", { cache: "no-store" });
        if (r.ok) { location.replace(SERVER + location.hash); return; }
      } catch (e) { /* not running */ }
      setModelStatus("Model offline: run server.py, open 127.0.0.1:8800", false);
      return;
    }
    try {
      const h = await (await fetch("api/health", { cache: "no-store" })).json();
      if (h.error) {
        setModelStatus("Model failed to load", false);
        showError(h.error);
      } else if (h.no_model) {
        noModel = h.no_model;
        setModelStatus("No model: CVE lookup and /linux-cwe only", true);
        modelStatus.title = h.no_model;
      } else if (h.ready) setModelStatus(h.model, true);
      else { setModelStatus(`Loading ${h.model} …`, false); setTimeout(checkModel, 2000); }
    } catch (e) {
      setModelStatus("Model offline: run server.py", false);
    }
  }

  function showError(msg) {
    showResultPanel(`<p class="cls-error">${escHtml(msg)}</p>`);
  }

  const VERDICT = {
    auto: (r) => `<strong>High confidence</strong> <span class="cls-note">(≥ 0.90, auto)</span>`,
    review: (r) => `<strong>Needs review</strong> <span class="cls-note">(confidence below 0.90)</span>`,
    noinfo: (r) => r.route === "noinfo"
      ? `<strong>noinfo</strong> <span class="cls-note">Oracle CPU text names no root cause, so vc-weakling routes it to NVD-CWE-noinfo.</span>`
      : `<strong>noinfo</strong> <span class="cls-note">The model reads no specific weakness in this description.</span>`,
    nomodel: () => `<strong>No model</strong> <span class="cls-note">vc-weakling isn't installed with this server (${escHtml(noModel || "")}), so there's no top 3.</span>`,
    "linux-cwe": () => `<strong>Linux kernel</strong> <span class="cls-note">Out of vc-weakling's scope; running the /linux-cwe skill on the fix commit.</span>`,
    missing: () => `<span class="cls-note">No description to classify.</span>`,
  };

  /* ── Assigned (cve.org) vs model ─────────────────────── */
  let currentCve = null; // the "cve" block of the latest /api/classify response

  // Is `a` an ancestor of `b` through ChildOf, in any view?
  const PARENTS = {};
  for (const [s, t, type] of DATA.edges) if (type === "ChildOf") (PARENTS[s] = PARENTS[s] || new Set()).add(t);
  function isAncestor(a, b) {
    const seen = new Set(), todo = [b];
    while (todo.length) {
      for (const p of PARENTS[todo.pop()] || []) {
        if (p === a) return true;
        if (!seen.has(p)) { seen.add(p); todo.push(p); }
      }
    }
    return false;
  }

  // A CWE's description, in full.
  function descHtml(cwe, tag = "p") {
    const d = NODES[normId(cwe)];
    return d && d.d ? `<${tag} class="cwe-desc">${escHtml(d.d)}</${tag}>` : "";
  }

  function cweLink(cwe, extra = "") {
    const id = normId(cwe), d = NODES[id];
    if (!d && DEPRECATED[id]) {
      return `<span class="cmp-cwe static"><span class="cls-id">CWE-${escHtml(id)}</span>` +
        `<span class="cls-name">${escHtml(DEPRECATED[id].n)}</span>${extra} ${deprecatedNote(id)}</span>`;
    }
    if (!d) return `<span class="cmp-cwe static"><span class="cls-id">${escHtml(cwe)}</span>${extra}</span>`;
    const usage = d.u && d.u !== "Allowed" ? " " + usageBadge(d.u) : "";
    return `<span class="cmp-cwe" data-id="${id}" title="${escHtml(d.n)}">${iconImg(kindOf(d), 12)}` +
      `<span class="cls-id">CWE-${id}</span><span class="cls-name">${escHtml(d.n)}</span>${usage}${extra}</span>` +
      suggestNote(id);
  }

  // modelIds: the model's picks in rank order (top 3, or the skill's one CWE).
  function verdict(assignedIds, modelIds, who) {
    if (!assignedIds.length) {
      return ["none", "○", `The record has no CWE yet, so ${who}'s pick would fill the gap.`];
    }
    if (!modelIds.length) return ["none", "○", `${who} named no CWE.`];
    const top = modelIds[0];
    if (assignedIds.includes(top)) return ["agree", "✓", `Agrees: ${who}'s top pick is the assigned CWE.`];
    const rank = modelIds.findIndex((m) => assignedIds.includes(m));
    if (rank > 0) return ["partial", "≈", `Close: the assigned CWE-${modelIds[rank]} is #${rank + 1} in ${who}'s top ${modelIds.length}.`];
    for (const a of assignedIds) {
      if (NODES[a] && (NODES[a].sg || []).some(([s]) => s === top)) {
        return ["partial", "≈", `Related: MITRE suggests ${who}'s CWE-${top} in place of the assigned CWE-${a} (${NODES[a].u}).`];
      }
    }
    for (const a of assignedIds) {
      if (isAncestor(a, top)) return ["partial", "≈", `Related: ${who}'s CWE-${top} is a more specific child of the assigned CWE-${a}.`];
      if (isAncestor(top, a)) return ["partial", "≈", `Related: ${who}'s CWE-${top} is a broader parent of the assigned CWE-${a}.`];
    }
    const replaces = (old, now) => DEPRECATED[old] && DEPRECATED[old].to.includes(now);
    for (const a of assignedIds) {
      if (replaces(a, top)) return ["partial", "≈", `Related: the assigned CWE-${a} is deprecated, and MITRE suggests ${who}'s CWE-${top} in its place.`];
      if (replaces(top, a)) return ["partial", "≈", `Related: ${who}'s CWE-${top} is deprecated, and MITRE suggests the assigned CWE-${a} in its place.`];
    }
    return ["differ", "✗", `Differs: ${who}'s pick is not among the assigned CWEs or their parents/children.`];
  }

  let lastCompare = null; // re-rendered once the observed examples arrive
  function renderCompare(modelIds, who, pending) {
    lastCompare = [modelIds, who, pending];
    const box = $("cmp");
    const c = currentCve;
    if (!box || !c) return;
    if (!c.cve_id) {
      box.innerHTML = `<p class="cls-note">Assigned CWE: not compared, since ${escHtml(c.how)}.</p>`;
      return;
    }
    let html = `<div class="cmp-head"><a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(c.cve_id)}" ` +
      `target="_blank" rel="noopener">${escHtml(c.cve_id)}</a> <span class="cls-note">${escHtml(c.how)}` +
      `${c.others && c.others.length ? ` (also ${c.others.map(escHtml).join(", ")})` : ""}</span></div>`;
    if (!c.found) {
      box.innerHTML = html + `<p class="cls-note">${escHtml(c.how)}</p>`;
      return;
    }
    const assignedIds = [];
    let rows = "";
    for (const grp of c.assigned || []) {
      for (const w of grp.cwes) {
        if (/^CWE-\d+$/.test(w.cwe)) assignedIds.push(normId(w.cwe));
        rows += `<li>${cweLink(w.cwe, ` <span class="cmp-by">${escHtml(grp.by)}</span>`)}${descHtml(w.cwe)}</li>`;
      }
    }
    html += `<div class="cmp-grid"><div class="cmp-label">Assigned<br><span class="cls-note">${escHtml(c.source)}</span></div>` +
      `<ul class="cmp-list">${rows || `<li class="cls-note">No CWE on the record${c.state && c.state !== "PUBLISHED" ? ` (${escHtml(c.state)})` : ""}</li>`}</ul>`;
    html += `<div class="cmp-label">${escHtml(who)}</div><ul class="cmp-list">` +
      (pending ? `<li class="cls-note">${escHtml(pending)}</li>`
        : modelIds.length
          // Skip the description when it's one of the assigned CWEs: it's already shown above.
          ? `<li>${cweLink("CWE-" + modelIds[0])}${assignedIds.includes(modelIds[0]) ? "" : descHtml("CWE-" + modelIds[0])}</li>`
          : `<li class="cls-note">No CWE</li>`) +
      `</ul></div>`;
    const exOf = EXAMPLE_OF[c.cve_id] || [];
    if (exOf.length) {
      html += `<p class="cmp-example">MITRE lists ${escHtml(c.cve_id)} as an observed example of ` +
        `${exOf.map((x) => `<span class="cmp-cwe" data-id="${x}" title="${escHtml(NODES[x].n)}"><span class="cls-id">CWE-${x}</span></span>`).join(" ")}</p>`;
    }
    if (!pending) {
      const [cls, mark, text] = verdict([...new Set(assignedIds)], modelIds, who);
      html += `<p class="cmp-verdict ${cls}"><span class="mark" aria-hidden="true">${mark}</span>${escHtml(text)}</p>`;
    }
    box.innerHTML = html;
  }

  $("result-panel").addEventListener("click", (e) => {
    const el = e.target.closest(".cmp-cwe[data-id]");
    if (el) navigate(el.dataset.id, "neighbors");
  });

  function showPrediction(r, text) {
    const top3 = r.top3 || [];
    candidates = top3.map(([c]) => normId(c)).filter((id) => NODES[id]);
    currentCve = r.cve || null;
    // The exact text the model classified: the CVE's description from the mirror
    // for a bare CVE ID, otherwise what was pasted.
    const analyzed = r.looked_up ? r.looked_up.text : text;
    const source = r.looked_up ? `${escHtml(r.looked_up.cve_id)} description, from its CVE record` : "as entered";
    let html = `<div class="analyzed"><div class="analyzed-head">Analyzed description <span class="cls-note">(${source})</span></div>` +
      `<p class="analyzed-text">${escHtml(analyzed)}</p></div>`;
    html += `<div id="cmp" class="cmp"></div>`;
    html += `<p class="cls-verdict">${(VERDICT[r.status] || (() => escHtml(r.status)))(r)}</p>`;
    if (top3.length) {
      // The comparison block above already describes the top pick when there's a CVE record.
      const compared = !!(currentCve && currentCve.found);
      html += `<ul class="cls-list">` + top3.map(([label, conf], i) => {
        const id = normId(label), known = !!NODES[id];
        const pct = Math.round(conf * 100);
        const dep = !known && DEPRECATED[id];
        const name = known ? NODES[id].n : dep ? dep.n : label === "noinfo" ? "No weakness named" : "";
        return `<li ${known ? `data-id="${id}"` : `class="static"`} title="${escHtml(name)}">` +
          `<span class="cls-label">${known ? `${iconImg(kindOf(NODES[id]), 12)}<span class="cls-id">CWE-${id}</span>` : `<span class="cls-id">${dep ? `CWE-${escHtml(id)}` : escHtml(label)}</span>`}` +
          `<span class="cls-name">${escHtml(name)}</span></span>` +
          `<span class="cls-conf"><span class="cls-bar"><span style="width:${pct}%"></span></span>${pct}%</span>` +
          (i === 0 && known && !compared ? descHtml(label, "span") : "") + (dep ? deprecatedNote(id) : "") + `</li>`;
      }).join("") + `</ul>`;
    }
    if (r.status === "linux-cwe") html += `<div id="lcwe"></div>`;
    showResultPanel(html);
    if (r.status === "linux-cwe") renderCompare([], "/linux-cwe", "running …");
    else if (r.status === "nomodel") renderCompare([], "vc-weakling", "not installed");
    else renderCompare(top3.map(([c]) => normId(c)).filter((id) => /^\d+$/.test(id)), "vc-weakling");
    if (candidates.length && normId(r.pred || "") === candidates[0]) navigate(candidates[0], "neighbors");
    markCandidates();
    if (r.status === "linux-cwe") startLinuxCwe(text);
  }

  /* ── Kernel text → /linux-cwe skill job (linux_cwe.py) ── */
  let lcweJob = null;

  let lcweText = "";

  async function startLinuxCwe(text, fresh = false) {
    lcweText = text;
    try {
      const resp = await fetch(fresh ? "api/linux-cwe?fresh=1" : "api/linux-cwe", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }),
      });
      const job = await resp.json();
      if (!resp.ok) return showLinuxCwe({ state: "error", error: job.error || `HTTP ${resp.status}` });
      lcweJob = job.id;
      pollLinuxCwe(job.id);
    } catch (e) {
      showLinuxCwe({ state: "error", error: "Could not reach server.py." });
    }
  }

  async function pollLinuxCwe(id) {
    if (lcweJob !== id) return; // superseded by a newer lookup
    let job;
    try {
      job = await (await fetch(`api/linux-cwe/${id}`, { cache: "no-store" })).json();
    } catch (e) {
      job = { state: "error", error: "Lost contact with server.py." };
    }
    if (lcweJob !== id) return;
    showLinuxCwe(job);
    if (["queued", "resolving", "running"].includes(job.state)) setTimeout(() => pollLinuxCwe(id), 1500);
  }

  function evidenceLine(res) {
    if (!res) return "";
    const what = res.kind === "cve" ? escHtml(res.target)
      : res.kind === "commit" ? `commit <code>${escHtml(res.target.slice(0, 12))}</code>` : "";
    const others = res.others && res.others.length ? ` (also matches ${res.others.map(escHtml).join(", ")})` : "";
    return res.kind === "text"
      ? `<p class="cls-warn">No CVE or commit found for this text, so the skill worked from the text alone: no diff, weaker evidence.</p>`
      : `<p class="cls-note">Evidence: ${what}, ${escHtml(res.how)}${others}.</p>`;
  }

  function showLinuxCwe(job) {
    const box = $("lcwe");
    if (!box) return;
    let html = evidenceLine(job.resolution);
    if (["queued", "resolving", "running"].includes(job.state)) {
      const step = job.state === "running" ? (job.progress.slice(-1)[0] || "Starting Claude Code") :
        job.state === "resolving" ? "Finding the CVE and fix commit" : "Waiting for an earlier run to finish";
      html += `<p class="lcwe-run"><span class="spinner" aria-hidden="true"></span>${escHtml(step)} … ` +
        `<span class="cls-note">${job.elapsed_s || 0}s</span> <button type="button" id="lcwe-cancel">Cancel</button></p>`;
      box.innerHTML = html;
      $("lcwe-cancel").onclick = () => fetch(`api/linux-cwe/${job.id}/cancel`, { method: "POST" });
      return;
    }
    if (job.state === "cancelled") { box.innerHTML = html + `<p class="cls-note">Cancelled.</p>`; return; }
    if (job.state === "error") { box.innerHTML = html + `<p class="cls-error">${escHtml(job.error)}</p>`; return; }

    const r = job.result || {};
    const id = normId(r.cwe || "");
    if (r.status === "UNDETERMINED" || !id) {
      html += `<p class="cls-verdict"><strong>Undetermined</strong></p>`;
      if (r.root_cause) html += `<p>${escHtml(r.root_cause)}</p>`;
    } else {
      const name = NODES[id] ? NODES[id].n : DEPRECATED[id] ? DEPRECATED[id].n : r.cwe_name || "";
      html += `<ul class="cls-list"><li ${NODES[id] ? `data-id="${id}"` : `class="static"`}>` +
        `<span class="cls-label">${NODES[id] ? iconImg(kindOf(NODES[id]), 12) : ""}<span class="cls-id">CWE-${escHtml(id)}</span><span class="cls-name">${escHtml(name)}</span></span>` +
        `<span class="badge">${escHtml(r.confidence || "?")}</span>${deprecatedNote(id)}</li></ul>`;
      if (r.root_cause) html += `<p class="lcwe-field"><span class="info-label">Root cause:</span> ${escHtml(r.root_cause)}</p>`;
      if (r.considered) html += `<p class="lcwe-field"><span class="info-label">Considered:</span> ${escHtml(r.considered)}</p>`;
      if (r.impact_cwe) html += `<p class="lcwe-field"><span class="info-label">Impact CWE:</span> ${escHtml(r.impact_cwe)}</p>`;
      if (r.adp_cwe) html += `<p class="lcwe-field"><span class="info-label">ADP CWE:</span> ${escHtml(r.adp_cwe)} <span class="cls-note">(comparison only, often the symptom)</span></p>`;
    }
    const cost = job.cost_usd != null ? ` · $${job.cost_usd.toFixed(2)}` : "";
    html += job.cached
      ? `<p class="cls-note">/linux-cwe · from linux-cwe-results, decided ${escHtml(job.cached.replace("T", " "))} ` +
        `<button type="button" id="lcwe-rerun">Run again</button></p>`
      : `<p class="cls-note">/linux-cwe · ${job.elapsed_s}s${cost} · recorded to linux-cwe-results</p>`;
    box.innerHTML = html;
    if (job.cached) $("lcwe-rerun").onclick = () => startLinuxCwe(lcweText, true);
    renderCompare(id && r.status !== "UNDETERMINED" ? [id] : [], "/linux-cwe");
    if (NODES[id]) {
      candidates = [id];
      navigate(id, "neighbors");
      markCandidates();
    }
  }

  async function runClassify() {
    const text = qInput.value.trim();
    if (!text || !modelReady) return;
    qInput.blur();
    qBtn.disabled = true;
    qBtn.textContent = "Classifying …";
    try {
      const resp = await fetch("api/classify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      const r = await resp.json();
      lcweJob = null; // a new lookup supersedes any running skill job's display
      if (!resp.ok) showError(r.error || `HTTP ${resp.status}`);
      else showPrediction(r, text);
    } catch (e) {
      showError("Could not reach server.py. Is it still running?");
    } finally {
      updateInput();
    }
  }

  $("result-close").addEventListener("click", () => {
    lcweJob = null;
    candidates = [];
    markCandidates();
    resultPanel.hidden = true;
    clsResults.innerHTML = "";
  });
  clsResults.addEventListener("click", (e) => {
    const li = e.target.closest("li[data-id]");
    if (li) navigate(li.dataset.id, "neighbors");
  });

  /* ── Controls ────────────────────────────────────────── */
  function initViews() {
    const opts = Object.entries(DATA.views).map(([id, name]) =>
      `<option value="${id}">${escHtml(name)} (CWE-${id})</option>`);
    opts.push(`<option value="all">All views (merged)</option>`);
    viewSelect.innerHTML = opts.join("");
    viewSelect.value = state.view;
    viewSelect.addEventListener("change", () => {
      state.view = viewSelect.value;
      buildIndex();
      render();
    });
  }

  function initLegend() {
    $("node-legend").innerHTML = Object.keys(KINDS).map((kind) =>
      `<li title="${kind === "Composite" || kind === "Chain" ? `Compound (${kind})` : kind}">${iconImg(kind, 14)}<span class="k-label">${kind}</span></li>`).join("");

    $("edge-legend").innerHTML = Object.entries(EDGE_STYLE).map(([type, st]) => {
      const arrow = st.arrow === "none" ? "" :
        `<polygon points="26,4 20,1 20,7" fill="${st.color}"/>`;
      return `<li><label><input type="checkbox" data-type="${type}"${state.types.has(type) ? " checked" : ""}>` +
        `<svg width="28" height="8" aria-hidden="true"><line x1="1" y1="4" x2="${arrow ? 21 : 27}" y2="4" ` +
        `stroke="${st.color}" stroke-width="2" stroke-dasharray="${st.dash}"/>${arrow}</svg>` +
        `${st.label}</label></li>`;
    }).join("");

    $("edge-legend").addEventListener("change", (e) => {
      const t = e.target.dataset.type;
      if (!t) return;
      e.target.checked ? state.types.add(t) : state.types.delete(t);
      buildIndex();
      render();
    });
  }

  // Relationships popover: open/close, and close on any click outside it.
  const edgeBtn = $("btn-edges"), edgePop = $("edge-pop");
  function setEdgePop(open) {
    edgePop.hidden = !open;
    edgeBtn.setAttribute("aria-expanded", String(open));
  }
  edgeBtn.addEventListener("click", () => setEdgePop(edgePop.hidden));
  document.addEventListener("mousedown", (e) => {
    if (!edgePop.hidden && !e.target.closest(".pop-wrap")) setEdgePop(false);
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") setEdgePop(false); });

  // Side panel width: drag the handle on its left border (or focus it and use the
  // arrow keys); double-click resets. Remembered per browser.
  const side = document.querySelector(".side"), resizer = $("resizer");
  const SIDE_DEFAULT = 380, SIDE_MIN = 280;
  const sideMax = () => Math.max(SIDE_MIN, Math.round(window.innerWidth * 0.7));
  let resizeFrame = 0;
  function setSideWidth(w, save) {
    w = Math.round(Math.min(Math.max(w, SIDE_MIN), sideMax()));
    side.style.width = w + "px";
    resizer.setAttribute("aria-valuenow", String(w));
    // Cytoscape doesn't watch its container; tell it once per frame.
    cancelAnimationFrame(resizeFrame);
    resizeFrame = requestAnimationFrame(() => cy.resize());
    if (save) try { localStorage.setItem("cwe-graph.side", String(w)); } catch (e) { /* ignore */ }
  }
  try { const w = +localStorage.getItem("cwe-graph.side"); if (w) setSideWidth(w, false); } catch (e) { /* ignore */ }

  resizer.addEventListener("pointerdown", (e) => {
    e.preventDefault();
    resizer.setPointerCapture(e.pointerId);
    resizer.classList.add("dragging");
    document.body.classList.add("resizing");
  });
  resizer.addEventListener("pointermove", (e) => {
    if (resizer.hasPointerCapture(e.pointerId)) setSideWidth(window.innerWidth - e.clientX, false);
  });
  resizer.addEventListener("pointerup", (e) => {
    resizer.releasePointerCapture(e.pointerId);
    resizer.classList.remove("dragging");
    document.body.classList.remove("resizing");
    setSideWidth(side.getBoundingClientRect().width, true);
  });
  resizer.addEventListener("dblclick", () => setSideWidth(SIDE_DEFAULT, true));
  resizer.addEventListener("keydown", (e) => {
    const step = e.shiftKey ? 60 : 20, w = side.getBoundingClientRect().width;
    if (e.key === "ArrowLeft") { e.preventDefault(); setSideWidth(w + step, true); }
    if (e.key === "ArrowRight") { e.preventDefault(); setSideWidth(w - step, true); }
  });
  window.addEventListener("resize", () => setSideWidth(side.getBoundingClientRect().width, false));

  // Layout direction, remembered per browser (a convenience; it's fine if storage is unavailable).
  try { if (["TB", "LR"].includes(localStorage.getItem("cwe-graph.dir"))) state.dir = localStorage.getItem("cwe-graph.dir"); } catch (e) { /* ignore */ }
  for (const d of ["TB", "LR"]) {
    $(`dir-${d}`).addEventListener("click", () => {
      if (state.dir === d) return;
      state.dir = d;
      try { localStorage.setItem("cwe-graph.dir", d); } catch (e) { /* ignore */ }
      cy.style().update(); // label placement and edge routing read state.dir
      render();
    });
  }

  depthSelect.addEventListener("change", () => {
    state.depth = +depthSelect.value;
    if (!state.center) return;
    if (state.mode === "neighbors") render();
    else navigate(state.center, "neighbors");
  });

  for (const [mode, btn] of Object.entries(modeButtons)) {
    btn.addEventListener("click", () => state.center && navigate(state.center, mode));
  }
  $("btn-fit").addEventListener("click", () => cy.fit(undefined, 40));
  $("btn-layout").addEventListener("click", () => runLayout(true));
  $("btn-png").addEventListener("click", () => {
    const a = document.createElement("a");
    a.href = cy.png({ full: true, scale: 2, bg: "#ffffff" });
    a.download = `cwe-${state.center || "graph"}-${state.mode}.png`;
    a.click();
  });

  /* ── Graph interaction ───────────────────────────────── */
  // Clicking a CWE redraws the graph around it, in the current mode
  // (neighborhood, ancestors or descendants).
  cy.on("tap", "node", (evt) => {
    const id = evt.target.id();
    if (id !== state.center) navigate(id, state.mode);
  });
  // Hovering a CWE shows its description in a card beside the node. The focused CWE
  // already draws its description in the graph, so it gets no card.
  const hoverCard = $("hover-card");
  function showHoverCard(node) {
    const id = node.id(), d = NODES[id];
    if (!d || id === state.center || !d.d) return;
    hoverCard.innerHTML =
      `<div class="hc-head">${iconImg(kindOf(d), 12)}<span class="hc-id">CWE-${id}</span>${d.u ? usageBadge(d.u) : ""}</div>` +
      `<div class="hc-name">${escHtml(d.n)}</div><p class="hc-desc">${escHtml(d.d)}</p>`;
    hoverCard.hidden = false;
    // Beside the node, on whichever side has room, kept inside the canvas.
    const p = node.renderedPosition(), r = node.renderedOuterWidth() / 2 + 12;
    const W = hoverCard.parentElement.clientWidth, H = hoverCard.parentElement.clientHeight;
    const w = hoverCard.offsetWidth, h = hoverCard.offsetHeight;
    const x = p.x + r + w <= W ? p.x + r : p.x - r - w;
    hoverCard.style.left = Math.max(8, Math.min(x, W - w - 8)) + "px";
    hoverCard.style.top = Math.max(8, Math.min(p.y - h / 2, H - h - 8)) + "px";
  }
  const hideHoverCard = () => { hoverCard.hidden = true; };

  cy.on("mouseover", "node", (evt) => {
    const hood = evt.target.closedNeighborhood();
    const keep = new Set(hood.nodes().map((n) => n.id()));
    // Fade everything else, captions included, except the captions of the kept nodes.
    cy.elements().not(hood).filter((el) => !(el.data("cap") && keep.has(el.data("owner")))).addClass("faded");
    $("cy").style.cursor = "pointer";
    showHoverCard(evt.target);
  });
  cy.on("mouseout", "node", () => {
    cy.elements().removeClass("faded");
    $("cy").style.cursor = "";
    hideHoverCard();
  });
  cy.on("viewport tap drag", hideHoverCard); // panning, zooming, clicking or dragging leaves it stale
  // Leaving the canvas straight from a node fires no mouseout, so clear the hover here too.
  $("cy").addEventListener("mouseleave", () => {
    cy.elements().removeClass("faded");
    $("cy").style.cursor = "";
    hideHoverCard();
  });

  /* ── Boot ────────────────────────────────────────────── */
  $("catalog-version").textContent =
    `CWE ${DATA.version} · ${DATA.date} · ${Object.keys(NODES).length} weaknesses`;
  // The full placeholder wraps (and spills out of the one-line box) on phones.
  const narrow = window.matchMedia("(max-width: 860px)");
  const setPlaceholder = () => {
    qInput.placeholder = narrow.matches ? "Paste a description or CVE ID"
      : "Paste a vulnerability description or CVE ID to find its CWE";
  };
  narrow.addEventListener("change", setPlaceholder);
  setPlaceholder();
  initViews();
  initLegend();
  checkModel();
  buildIndex();
  const exScript = document.createElement("script");
  exScript.src = "data/cwe-examples.js";
  exScript.onload = () => {
    EXAMPLES = window.CWE_EXAMPLES || {};
    for (const [cwe, list] of Object.entries(EXAMPLES)) {
      for (const [ref] of list) (EXAMPLE_OF[ref.toUpperCase()] ||= []).push(cwe);
    }
    if (infoId) updateInfo(infoId);
    if (lastCompare) renderCompare(...lastCompare);
  };
  document.body.appendChild(exScript);
  const start = parseHash();
  state.center = NODES[start.id] ? start.id : "79";
  state.mode = start.mode;
  render();
})();
