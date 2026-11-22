const state = {
  tab: "stats",
  channel: "",
  rawKind: "",
  nodeSearch: "",
  nodeRole: "",
  nodeVia: "",
  nodeHardware: "",
  nodeChannel: "",
  nodeSort: "last_heard",
  nodeSortDir: "desc",
  nodes: [],
  nodeFamily: "mt",
  nodeNames: new Map(),
  packetFamily: "mt",
  packetProtocol: "",
  packetChannel: "",
  packetGateway: "",
  packetSource: "",
  packetDecrypted: "",
  nodeNamesAt: 0,
  nodeNamesSignature: "",
  nodeNamesVersion: 0,
  uiConfig: null,
  mapMeshtastic: true,
  mapMeshCore: true,
  mapMaxAge: "",
  statsFamily: "mt",
  jrawPayload: "",
  jrawRoute: "",
  jrawChannel: "",
  jrawDecrypted: "",
  jrawRegion: "",
  jrawSearch: "",
  jrawNodes: [],
  jrawSort: "last_heard",
  jrawSortDir: "desc",
};

const $ = (id) => document.getElementById(id);

const POLL_INTERVAL_MS = 3000;
const FETCH_TIMEOUT_MS = 15000;
const NODE_NAMES_MAX_AGE_MS = 30000;
const SEARCH_DEBOUNCE_MS = 150;
/** Timestamps further ahead of the browser clock than this are flagged. */
const FUTURE_SLACK_SECS = 120;
/** 2020-01-01T00:00:00Z; radio clocks reporting earlier times have no valid RTC. */
const MIN_PLAUSIBLE_TIME = 1577836800;
/** A radio rx_time this far from the server receive time is flagged in chat. */
const RX_TIME_SKEW_SECS = 3600;
const TRACE_UNKNOWN_NODE = 0xffffffff;
const TRACE_UNKNOWN_SNR = -128;

/** Bidi embedding/override/isolate controls; mesh names must not reorder the UI. */
const BIDI_CONTROLS = /[‪-‮⁦-⁩]/g;

function clean(value) {
  return String(value ?? "").replace(BIDI_CONTROLS, "");
}

const ROLE_NAMES = {
  0: "Client",
  1: "Client mute",
  2: "Router",
  3: "Router client",
  4: "Repeater",
  5: "Tracker",
  6: "Sensor",
  7: "TAK",
  8: "Client hidden",
  9: "Lost & found",
  10: "TAK tracker",
  11: "Router late",
  12: "Client base",
};

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = clean(text);
  return node;
}

function textNode(value) {
  return document.createTextNode(clean(value));
}

/** Last rendered payload per DOM target, so identical polls do not rebuild it. */
const renderSignatures = new Map();

/**
 * Run `render` only when `data` (plus `extra` render inputs) differs from what
 * this target last rendered. Keeps text selection, focus and open elements
 * alive across polls that returned nothing new.
 */
function renderIfChanged(key, data, extra, render) {
  const signature = `${extra}\u0000${JSON.stringify(data)}`;
  if (renderSignatures.get(key) === signature) return false;
  renderSignatures.delete(key);
  render();
  renderSignatures.set(key, signature);
  return true;
}

function fmtNum(value) {
  return Number(value ?? 0).toLocaleString();
}

function fmtPercent(value) {
  return `${Number(value ?? 0).toFixed(1)}%`;
}

function fmtBytes(value) {
  const bytes = Number(value ?? 0);
  if (bytes < 1024) {
    const rounded = bytes >= 10 ? Math.round(bytes) : Number(bytes.toFixed(1));
    return `${rounded} B`;
  }
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GiB`;
}

function fmtHourly(value) {
  return `${fmtNum(Math.round(Number(value ?? 0)))}/h`;
}

function fmtTime(seconds) {
  if (!seconds) return "—";
  return new Date(Number(seconds) * 1000).toLocaleString();
}

function fmtDuration(seconds) {
  const total = Math.max(0, Math.floor(Number(seconds ?? 0)));
  if (total < 60) return `${total}s`;
  const minutes = Math.floor(total / 60);
  if (minutes < 60) return `${minutes}m ${total % 60}s`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
}

/** Why a unix timestamp is suspect, or null when it looks sane. */
function timeProblem(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value)) return "not a valid time";
  if (value - Date.now() / 1000 > FUTURE_SLACK_SECS) return "in the future";
  if (value < MIN_PLAUSIBLE_TIME) return "implausibly old";
  return null;
}

function fmtAgo(seconds) {
  if (!seconds) return "—";
  const value = Number(seconds);
  if (!Number.isFinite(value)) return "invalid time";
  const ahead = value - Date.now() / 1000;
  if (ahead > FUTURE_SLACK_SECS) return `in ${fmtDuration(ahead)} (future)`;
  const diff = Math.max(0, -ahead);
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function updateTimeElement(node) {
  const raw = node.dataset.ago;
  const seconds = raw === "" ? 0 : Number(raw);
  const text = fmtAgo(seconds);
  if (node.textContent !== text) node.textContent = text;
  const problem = seconds ? timeProblem(seconds) : null;
  node.classList.toggle("bad-value", Boolean(problem));
  const suffix = node.dataset.titleSuffix || "";
  const title = `${fmtTime(seconds)}${problem ? ` · timestamp ${problem}` : ""}${suffix}`;
  if (node.title !== title) node.title = title;
}

/**
 * Relative-time element. Suspect timestamps are shown in red instead of being
 * clamped, and the label is kept fresh by `refreshAgoLabels` without a rebuild.
 */
function timeElement(tag, className, seconds, titleSuffix = "") {
  const node = element(tag, className);
  node.dataset.ago = seconds == null ? "" : String(seconds);
  if (titleSuffix) node.dataset.titleSuffix = titleSuffix;
  updateTimeElement(node);
  return node;
}

function refreshAgoLabels() {
  for (const node of document.querySelectorAll(".panel.active [data-ago]")) updateTimeElement(node);
}

/** Flag a radio-supplied rx_time that is garbage or far from the server clock. */
function rxTimeProblem(rxTime, receivedAt) {
  if (!rxTime) return null;
  const problem = timeProblem(rxTime);
  if (problem) return problem;
  if (receivedAt) {
    const skew = Math.abs(Number(rxTime) - Number(receivedAt));
    if (skew > RX_TIME_SKEW_SECS) return `radio clock differs from server by ${fmtDuration(skew)}`;
  }
  return null;
}

/** Hop usage; inconsistent hop fields are flagged instead of going negative. */
function hopsInfo(hopStart, hopLimit) {
  if (hopStart == null || hopLimit == null) return null;
  const start = Number(hopStart);
  const limit = Number(hopLimit);
  if (!Number.isFinite(start) || !Number.isFinite(limit) || start < 0 || limit < 0 || limit > start) {
    return { text: `?/${hopStart}`, bad: true, title: `inconsistent hop fields: hop_start ${hopStart}, hop_limit ${hopLimit}` };
  }
  return { text: `${start - limit}/${start}`, bad: false, title: "" };
}

function hopsElement(tag, className, info, prefix = "") {
  const node = element(tag, info.bad ? `${className} bad-value`.trim() : className, `${prefix}${info.text}`);
  if (info.title) node.title = info.title;
  return node;
}

/** Classify a node position: usable, absent, no GPS fix (0, 0) or out of range. */
function nodePosition(node) {
  if (node.latitude_i == null || node.longitude_i == null) return { state: "none" };
  const latitude = Number(node.latitude_i) * 1e-7;
  const longitude = Number(node.longitude_i) * 1e-7;
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
    return { state: "invalid", text: `${node.latitude_i}, ${node.longitude_i}` };
  }
  if (Number(node.latitude_i) === 0 && Number(node.longitude_i) === 0) return { state: "nofix" };
  const text = `${latitude.toFixed(5)}, ${longitude.toFixed(5)}`;
  if (Math.abs(latitude) > 90 || Math.abs(longitude) > 180) return { state: "invalid", text };
  return { state: "ok", text, latitude: latitude.toFixed(5), longitude: longitude.toFixed(5) };
}

function positionContent(node) {
  const position = nodePosition(node);
  if (position.state === "ok") {
    const link = element("a", "", position.text);
    link.href = `https://www.openstreetmap.org/?mlat=${position.latitude}&mlon=${position.longitude}#map=15/${position.latitude}/${position.longitude}`;
    link.target = "_blank";
    link.rel = "noreferrer";
    return link;
  }
  if (position.state === "invalid") {
    const bad = element("span", "bad-value", `invalid: ${position.text}`);
    bad.title = "coordinates out of range";
    return bad;
  }
  if (position.state === "nofix") {
    const noFix = element("span", "muted", "no fix");
    noFix.title = "node reported 0, 0 (no GPS fix)";
    return noFix;
  }
  return document.createTextNode("—");
}

function percentile(values, fraction) {
  if (!values.length) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const position = (sorted.length - 1) * fraction;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower];
  const weight = position - lower;
  return sorted[lower] * (1 - weight) + sorted[upper] * weight;
}

function fmtOneDecimal(value) {
  if (value == null) return "—";
  const text = Number(value).toFixed(1);
  return text.endsWith(".0") ? text.slice(0, -2) : text;
}

function fmtSnr(value) {
  return value == null ? "—" : `${fmtOneDecimal(value)} dB`;
}

function fmtRssi(value) {
  return value == null ? "—" : `${fmtOneDecimal(value)} dBm`;
}

function channelLabel(channel, name) {
  const id = Number(channel);
  if (id === 512) return "PKI";
  if (id >= 256 && id < 512) return `Opaque 0x${(id - 256).toString(16).padStart(2, "0")}`;
  return name && name.length ? name : `Channel ${id}`;
}

function channelKey(channel, name) {
  return name && name.length ? name : `#${Number(channel)}`;
}

function nodeLabel(node) {
  return node.long_name || node.short_name || node.node_id || `!${Number(node.num).toString(16).padStart(8, "0")}`;
}

function shortId(num) {
  return `!${Number(num).toString(16).padStart(8, "0")}`;
}

function nodeNumFromId(value) {
  if (value === null || value === undefined) return null;
  const text = String(value).trim();
  if (!text) return null;
  const hex = text.startsWith("!") ? text.slice(1) : text;
  if (!/^[0-9a-fA-F]{1,8}$/.test(hex)) return null;
  return parseInt(hex, 16);
}

/** Resolve a gateway id to its known node name, falling back to the id. */
function gatewayLabel(value) {
  const num = nodeNumFromId(value);
  if (num !== null) {
    const name = state.nodeNames.get(num);
    if (name) return name;
  }
  return value || "unknown";
}

/** Resolve a comma-separated gateway list from the Nodes query. */
function gatewayLabels(value) {
  const parts = String(value || "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  return parts.length ? parts.map(gatewayLabel).join(", ") : "";
}

function relayId(value) {
  const node = Number(value ?? 0);
  if (!node) return null;
  return `0x${(node & 0xff).toString(16).padStart(2, "0")}`;
}

/**
 * Fetch JSON with a hard timeout. `signal` (optional) cancels the request from
 * outside; a cancelled request rejects with an AbortError.
 */
async function getJson(url, signal) {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, FETCH_TIMEOUT_MS);
  const onAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener("abort", onAbort, { once: true });
  }
  try {
    const response = await fetch(url, { cache: "no-store", signal: controller.signal });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return await response.json();
  } catch (error) {
    if (timedOut) throw new Error(`request timed out after ${FETCH_TIMEOUT_MS / 1000}s`);
    throw error;
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener("abort", onAbort);
  }
}

/**
 * getJson for one refresh run: rejects if the run was superseded while the
 * request was in flight, so a stale response can never be rendered.
 */
async function fetchJson(run, url) {
  const data = await getJson(url, run ? run.signal : undefined);
  if (run && run.signal.aborted) throw new DOMException("superseded", "AbortError");
  return data;
}

function empty(text) {
  return element("div", "empty", text);
}

function decryptedTag() {
  return element("span", "decrypted", "decrypted");
}

function contrastText(hex) {
  if (!/^#[0-9a-f]{6}$/i.test(hex || "")) return "#fff";
  const red = parseInt(hex.slice(1, 3), 16);
  const green = parseInt(hex.slice(3, 5), 16);
  const blue = parseInt(hex.slice(5, 7), 16);
  return 0.299 * red + 0.587 * green + 0.114 * blue > 150 ? "#000" : "#fff";
}

function renderNodeStrips(nodes) {
  const container = $("node-strips");
  container.innerHTML = "";
  if (!nodes || !nodes.length) return;

  for (const status of nodes) {
    const node = status.node;
    const strip = element("section", "node-strip");
    const badge = element("div", "node-badge");
    badge.textContent = node?.short_name || "??";
    badge.style.background = node?.color || "#45475a";
    badge.style.color = contrastText(node?.color);

    const details = element("div", "node-details");
    const title = element("div", "node-title");
    const nodeName = node?.long_name || status.name || "Node";
    title.title = nodeName;
    title.appendChild(element("strong", "", nodeName));
    const stateLabel = !status.connected
      ? "offline"
      : node
        ? "connected"
        : "waiting for node info";
    const stateClass = !status.connected ? "off" : node ? "ok" : "warn";
    details.appendChild(title);

    const state = element("div", "node-status");
    state.appendChild(element("span", `pill ${stateClass}`, stateLabel));
    details.appendChild(state);

    strip.appendChild(badge);
    strip.appendChild(details);
    container.appendChild(strip);
  }
}

function renderStatus(status) {
  const strips = status.nodes || [];
  renderIfChanged("node-strips", strips, "", () => renderNodeStrips(strips));
  $("version").textContent = `v${status.version} · up ${status.uptime_secs}s`;
  const pills = $("status-pills");
  pills.innerHTML = "";
  const pill = (text, className) => {
    const node = element("span", `pill ${className || ""}`, text);
    pills.appendChild(node);
  };
  pill(status.physical_connected ? "node online" : "node offline", status.physical_connected ? "ok" : "off");
  if (status.mqtt_enabled) {
    pill(status.mqtt_connected ? "mqtt online" : "mqtt reconnecting", status.mqtt_connected ? "ok" : "warn");
  } else {
    pill("mqtt off", "off");
  }
  pill(`${status.active_clients} clients`);
  $("db-note").textContent = status.database ? `database: ${status.database}` : "";
}

function renderHourly(buckets, containerId = "hourly", totalId = "hourly-total", unit = "packets") {
  const container = $(containerId);
  container.innerHTML = "";
  const max = Math.max(1, ...buckets.map((bucket) => bucket.count));
  const total = buckets.reduce((sum, bucket) => sum + bucket.count, 0);
  $(totalId).textContent = `${fmtNum(total)} ${unit}`;

  const row = element("div", "bars-row");
  for (const bucket of buckets) {
    const bar = element("div", "bar");
    const fill = element("span");
    fill.style.height = `${Math.max(2, (bucket.count / max) * 100)}%`;
    const label = `${fmtNum(bucket.count)} ${unit} · ${new Date(bucket.hour_start * 1000).toLocaleString()}`;
    bar.title = label;
    bar.appendChild(fill);
    row.appendChild(bar);
  }
  container.appendChild(row);

  const labels = element("div", "bar-labels");
  for (let index = 0; index < buckets.length; index += 1) {
    const cell = element("div", "", index % 4 === 0 ? new Date(buckets[index].hour_start * 1000).toLocaleTimeString([], { hour: "2-digit" }) : "");
    labels.appendChild(cell);
  }
  container.appendChild(labels);
}

function renderCounts(tbodyId, buckets) {
  const body = $(tbodyId);
  body.innerHTML = "";
  if (!buckets.length) {
    const row = document.createElement("tr");
    const cell = element("td", "muted", "No data yet");
    cell.colSpan = 3;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  for (const bucket of buckets) {
    const row = document.createElement("tr");
    row.appendChild(element("td", "", bucket.label));
    row.appendChild(element("td", "num", fmtNum(bucket.count)));
    row.appendChild(element("td", "num", fmtPercent(bucket.percent)));
    body.appendChild(row);
  }
}

function renderStatChannels(channels) {
  const body = $("stat-channels");
  body.innerHTML = "";
  if (!channels.length) {
    const row = document.createElement("tr");
    const cell = element("td", "muted", "No data yet");
    cell.colSpan = 3;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  for (const channel of channels) {
    const row = document.createElement("tr");
    row.appendChild(element("td", "", channelLabel(channel.channel, channel.name)));
    row.appendChild(element("td", "num", fmtNum(channel.count)));
    row.appendChild(element("td", "num", fmtPercent(channel.percent)));
    body.appendChild(row);
  }
}

function renderTopNodes(nodes) {
  const body = $("top-nodes");
  body.innerHTML = "";
  if (!nodes.length) {
    const row = document.createElement("tr");
    const cell = element("td", "muted", "No data yet");
    cell.colSpan = 3;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  for (const node of nodes) {
    const row = document.createElement("tr");
    row.appendChild(element("td", "", node.name || shortId(node.num)));
    row.appendChild(element("td", "num", fmtNum(node.count)));
    row.appendChild(element("td", "num", fmtPercent(node.percent)));
    body.appendChild(row);
  }
}

/** Distinct slice colours; anything beyond these is folded into the remainder slice. */
const PIE_COLORS = [
  "#b4befe", "#89b4fa", "#f9e2af", "#cba6f7", "#f38ba8", "#74c7ec", "#fab387",
  "#89dceb", "#a6e3a1", "#f5c2e7", "#94e2d5", "#eba0ac", "#f2cdcd", "#f5e0dc",
];
const PIE_REMAINDER_COLOR = "#585b70";

/**
 * Draw a pie of `buckets` out of `total` packets. Whatever the buckets do not
 * cover (and any bucket beyond the colour palette) becomes an explicit
 * remainder slice, so no slice is ever stretched to fill the circle.
 */
function renderPie(pieId, legendId, totalId, buckets, labelFor, total, emptyText, showCount = true, remainderLabel = "other") {
  // Either element ids or the elements themselves.
  const pie = typeof pieId === "string" ? $(pieId) : pieId;
  const legend = typeof legendId === "string" ? $(legendId) : legendId;
  legend.innerHTML = "";
  if (totalId) $(totalId).textContent = `${fmtNum(total)} packets`;

  const data = buckets.filter((bucket) => bucket.count > 0);
  if (!data.length) {
    pie.style.background = "var(--panel-2)";
    legend.appendChild(empty(emptyText));
    return;
  }

  const slices = data.slice(0, PIE_COLORS.length).map((bucket, index) => ({
    label: labelFor(bucket),
    count: Number(bucket.count),
    color: PIE_COLORS[index],
  }));
  const drawn = slices.reduce((sum, slice) => sum + slice.count, 0);
  const whole = Math.max(Number(total ?? 0), drawn);
  if (whole > drawn) {
    slices.push({ label: remainderLabel, count: whole - drawn, color: PIE_REMAINDER_COLOR });
  }

  const stops = [];
  let angle = 0;
  slices.forEach((slice, index) => {
    const start = angle;
    angle = index === slices.length - 1 ? 360 : angle + (slice.count / whole) * 360;
    stops.push(`${slice.color} ${start.toFixed(2)}deg ${angle.toFixed(2)}deg`);
  });
  pie.style.background = `conic-gradient(${stops.join(",")})`;

  for (const slice of slices) {
    const entry = element("div", "entry");
    const swatch = element("span", "swatch");
    swatch.style.background = slice.color;
    entry.appendChild(swatch);
    entry.appendChild(element("span", "", slice.label));
    entry.appendChild(element("b", "", fmtPercent((slice.count / whole) * 100)));
    if (showCount) entry.appendChild(element("span", "", `${fmtNum(slice.count)} pkts`));
    legend.appendChild(entry);
  }
}

function renderChannelPie(channels, total) {
  renderPie(
    "channel-pie",
    "pie-legend",
    "pie-total",
    channels,
    (channel) => channelLabel(channel.channel, channel.name),
    total,
    "No packets yet.",
  );
}

function renderPortnumPie(portnums, totalPackets) {
  // Portnum counts only cover decoded packets; the rest of `totalPackets` is
  // drawn as its own slice instead of inflating the last portnum.
  renderPie(
    "portnum-pie",
    "portnum-pie-legend",
    "portnum-pie-total",
    portnums,
    (bucket) => bucket.label,
    totalPackets,
    "No decoded packets yet.",
    false,
    "encrypted / other",
  );
}

/** Render the Mesh Stats tab body from the `stats` half of /api/stats. */
function renderStats(stats) {
  const data = { stats };
  const totals = stats.totals;
  const cards = [
    ["Packets", totals.packets, `${fmtNum(totals.packets_24h)} in 24h · ${fmtHourly(data.stats.packets_per_hour)}`],
    ["Messages", totals.messages, `${fmtNum(totals.messages_24h)} in 24h`],
    ["Data", fmtBytes(totals.bytes), `${fmtBytes(data.stats.bytes_per_hour)}/h · last hour`],
    ["Decoded", totals.decoded_packets, "readable packets"],
    ["Opaque", totals.opaque_packets, "still encrypted"],
    ["Decrypted", totals.decrypted, "via extra channel keys"],
    ["PKI", totals.pki_packets, "direct encrypted"],
    ["Nodes", totals.nodes, "known"],
    ["JenCore raw", totals.jencore_frames, "MeshCore frames"],
    ["JenRNode raw", totals.jenrnode_frames, "Reticulum payloads"],
    ["Meshtastic raw", totals.meshtastic_frames, "packet protobufs"],
    ["Via MQTT", totals.via_mqtt, "via_mqtt flag"],
    ["MQTT source", totals.mqtt_source, "ingested from broker"],
    ["Receptions", totals.receptions, "gateway observations"],
    ["Multi-heard", totals.multi_heard, "heard by >1 gateway"],
  ];
  const container = $("stat-cards");
  container.innerHTML = "";
  for (const [label, value, sub] of cards) {
    const card = element("div", "card");
    card.appendChild(element("div", "label", label));
    card.appendChild(element("div", "value", typeof value === "string" ? value : fmtNum(value)));
    card.appendChild(element("div", "sub", sub));
    container.appendChild(card);
  }

  renderHourly(data.stats.hourly);
  renderChannelPie(data.stats.channels, totals.packets);
  renderPortnumPie(data.stats.portnums, totals.packets);
  renderCounts("portnums", data.stats.portnums);
  renderCounts("transports", data.stats.transports);
  renderStatChannels(data.stats.channels);
  renderTopNodes(data.stats.top_nodes);
}

const JRAW_PIE_SLICES = 8;

function statCardValue(card) {
  if (card.unit === "bytes") return fmtBytes(card.value);
  if (card.unit === "decimal") return Number(card.value).toFixed(1);
  return fmtNum(card.value);
}

/** Mesh Stats for a raw feed (MeshCore or Reticulum). */
function renderJrawStats(stats) {
  const cards = $("jraw-stat-cards");
  cards.innerHTML = "";
  for (const item of stats.cards) {
    const card = element("div", "card");
    card.appendChild(element("div", "label", item.label));
    card.appendChild(element("div", "value", statCardValue(item)));
    card.appendChild(element("div", "sub", item.sub));
    cards.appendChild(card);
  }
  renderHourly(stats.hourly, "jraw-hourly", "jraw-hourly-total", "frames");

  const tables = $("jraw-stat-tables");
  tables.innerHTML = "";
  for (const table of stats.tables) {
    const block = element("section", "block");
    const head = element("div", "block-head");
    head.appendChild(element("h2", "", table.title));
    head.appendChild(element("span", "muted", table.note));
    block.appendChild(head);
    if (table.pie) {
      const wrap = element("div", "pie-wrap compact");
      const pie = element("div", "pie compact");
      const legend = element("div", "pie-legend");
      wrap.appendChild(pie);
      wrap.appendChild(legend);
      block.appendChild(wrap);
      // The largest slices by name; everything else is one "other" slice.
      renderPie(pie, legend, null, table.rows.slice(0, JRAW_PIE_SLICES), (bucket) => bucket.label, table.total, "No data yet.", false);
    }
    const grid = document.createElement("table");
    const headRow = document.createElement("tr");
    headRow.appendChild(element("th", "", "Name"));
    headRow.appendChild(element("th", "num", "Count"));
    headRow.appendChild(element("th", "num", "%"));
    const thead = document.createElement("thead");
    thead.appendChild(headRow);
    grid.appendChild(thead);
    const body = document.createElement("tbody");
    if (!table.rows.length) {
      const row = document.createElement("tr");
      const cell = element("td", "muted", "No data yet");
      cell.colSpan = 3;
      row.appendChild(cell);
      body.appendChild(row);
    }
    for (const bucket of table.rows) {
      const row = document.createElement("tr");
      const unknown = /\((unknown|no key|\d+ candidates)\)$/.test(bucket.label);
      row.appendChild(element("td", unknown ? "muted" : "", bucket.label));
      row.appendChild(element("td", "num", fmtNum(bucket.count)));
      row.appendChild(element("td", "num", fmtPercent(bucket.percent)));
      body.appendChild(row);
    }
    grid.appendChild(body);
    block.appendChild(grid);
    tables.appendChild(block);
  }
}

async function loadJrawStats(run) {
  const family = state.statsFamily;
  const stats = await fetchJson(run, `/api/jraw-stats?kind=${family === "mc" ? 1 : 2}`);
  renderIfChanged("jraw-stats", stats, family, () => renderJrawStats(stats));
}

function showStatsFamily() {
  const meshtastic = state.statsFamily === "mt";
  $("stats-mt").hidden = !meshtastic;
  $("stats-jraw").hidden = meshtastic;
  for (const button of document.querySelectorAll("#stats-family button")) {
    const active = button.dataset.family === state.statsFamily;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  }
}

function renderChannels(channels) {
  const list = $("channels-list");
  list.innerHTML = "";
  const total = channels.reduce((sum, channel) => sum + channel.count, 0);
  const lastHour = channels.reduce((sum, channel) => sum + Number(channel.packets_per_hour ?? 0), 0);
  $("channels-summary").textContent =
    `${channels.length} channels · ${fmtNum(total)} packets total · ${fmtNum(Math.round(lastHour))} in the last hour`;

  if (!channels.length) {
    list.appendChild(empty("No channel traffic yet."));
    return;
  }

  for (const channel of channels) {
    const card = element("div", "channel-card");
    const head = element("div", "channel-head");
    head.appendChild(element("span", "channel-name", channelLabel(channel.channel, channel.name)));
    const stats = element("div", "channel-stats");
    const stat = (label, value) => {
      const item = element("span");
      item.appendChild(element("b", "", value));
      item.appendChild(document.createTextNode(` ${label}`));
      stats.appendChild(item);
    };
    stat("packets", fmtNum(channel.count));
    stat("share", fmtPercent(channel.percent));
    stat("bytes", fmtBytes(channel.bytes));
    stat("pkts/h", fmtHourly(channel.packets_per_hour));
    stat("bytes/h", fmtBytes(channel.bytes_per_hour));
    head.appendChild(stats);
    card.appendChild(head);

    const details = document.createElement("details");
    details.appendChild(element("summary", "", `Nodes (${channel.nodes.length})`));
    if (!channel.nodes.length) {
      details.appendChild(empty("No node traffic in this channel."));
    } else {
      const table = element("table");
      const thead = document.createElement("thead");
      const headRow = document.createElement("tr");
      for (const [label, className] of [["Node", ""], ["Packets", "num"], ["%", "num"], ["Bytes", "num"]]) {
        headRow.appendChild(element("th", className, label));
      }
      thead.appendChild(headRow);
      table.appendChild(thead);
      const tbody = document.createElement("tbody");
      for (const node of channel.nodes) {
        const row = document.createElement("tr");
        row.appendChild(element("td", "", node.name || shortId(node.num)));
        row.appendChild(element("td", "num", fmtNum(node.count)));
        row.appendChild(element("td", "num", fmtPercent(node.percent)));
        row.appendChild(element("td", "num", fmtBytes(node.bytes)));
        tbody.appendChild(row);
      }
      table.appendChild(tbody);
      details.appendChild(table);
    }
    card.appendChild(details);
    list.appendChild(card);
  }
}

function traceSnr(value) {
  return `${(Number(value) / 4).toFixed(1)} dB`;
}

function traceNodeUnknown(num) {
  return Number(num) === TRACE_UNKNOWN_NODE;
}

function traceNodeLabel(num) {
  if (traceNodeUnknown(num)) return "unknown";
  return state.nodeNames.get(Number(num)) || shortId(num);
}

/**
 * A traceroute reply travels target → requester, while its `route` and
 * `snr_towards` are ordered requester → target. Replies carry a request_id.
 */
function traceEndpoints(trace) {
  const isReply = Number(trace.request_id ?? 0) !== 0;
  return isReply
    ? { isReply, requester: trace.to_num, target: trace.from_num }
    : { isReply, requester: trace.from_num, target: trace.to_num };
}

/**
 * Collapse a hop that repeats the previous node, keeping every remaining link
 * paired with its own SNR entry (entry i belongs to the link into hop i + 1).
 * Unknown hops are distinct nodes and are never collapsed.
 */
function traceHops(start, route, end, snrs) {
  const all = [start, ...route, end];
  const hops = [];
  all.forEach((node, index) => {
    const previous = hops.length ? hops[hops.length - 1].node : null;
    if (index > 0 && Number(node) === Number(previous) && !traceNodeUnknown(node)) return;
    hops.push({ node, snr: index > 0 && snrs ? snrs[index - 1] : null });
  });
  return hops;
}

function renderTraceGraph(container, title, start, route, end, snrs) {
  const block = element("div");
  block.appendChild(element("div", "trace-graph-title", title));
  const graph = element("div", "trace-graph");
  const hops = traceHops(start, route, end, snrs);
  hops.forEach((hop, index) => {
    if (index > 0) {
      const link = element("div", "trace-link");
      link.appendChild(element("span", "arrow", "→"));
      if (hop.snr != null) {
        if (Number(hop.snr) === TRACE_UNKNOWN_SNR) {
          const unknown = element("span", "bad-value", "SNR ?");
          unknown.title = "SNR not reported for this hop";
          link.appendChild(unknown);
        } else {
          link.appendChild(element("span", "", traceSnr(hop.snr)));
        }
      }
      graph.appendChild(link);
    }
    const classes = ["trace-node"];
    if (index === 0) classes.push("start");
    if (index === hops.length - 1) classes.push("end");
    const unknown = traceNodeUnknown(hop.node);
    if (unknown) classes.push("unknown");
    const box = element("div", classes.join(" "), traceNodeLabel(hop.node));
    box.title = unknown ? "hop did not identify itself (0xffffffff)" : shortId(hop.node);
    graph.appendChild(box);
  });
  block.appendChild(graph);
  container.appendChild(block);
}

function renderTraces(traces) {
  const list = $("traces-list");
  list.innerHTML = "";
  $("traces-count").textContent = `${traces.length} traces`;
  if (!traces.length) {
    list.appendChild(empty("No traceroutes recorded yet."));
    return;
  }

  for (const trace of traces) {
    const details = document.createElement("details");
    details.className = "trace";
    const summary = element("summary");
    const { isReply, requester, target } = traceEndpoints(trace);
    summary.appendChild(element("b", "", `${traceNodeLabel(requester)} → ${traceNodeLabel(target)}`));
    const kind = element("span", "", isReply ? "reply" : "request");
    kind.title = isReply
      ? "reply from the target: complete route"
      : "request overheard on its way to the target: route so far";
    summary.appendChild(kind);
    summary.appendChild(timeElement("span", "", trace.received_at));
    summary.appendChild(element("span", "", `direct ${trace.route.length} hop${trace.route.length === 1 ? "" : "s"}`));
    summary.appendChild(element("span", "", `back ${trace.route_back.length} hop${trace.route_back.length === 1 ? "" : "s"}`));
    if (trace.source) summary.appendChild(element("span", "", trace.source));
    if (trace.decrypted) summary.appendChild(decryptedTag());
    if (trace.receiver) {
      const receiver = element("span", "", gatewayLabel(trace.receiver));
      receiver.title = trace.receiver;
      summary.appendChild(receiver);
    }
    details.appendChild(summary);

    const graphs = element("div", "trace-graphs");
    renderTraceGraph(
      graphs,
      isReply ? "Direct route" : "Direct route (so far)",
      requester,
      trace.route,
      target,
      trace.snr_towards,
    );
    if (trace.route_back.length) {
      renderTraceGraph(graphs, "Back route", target, trace.route_back, requester, trace.snr_back);
    } else {
      const emptyBack = element("div");
      emptyBack.appendChild(element("div", "trace-graph-title", "Back route"));
      emptyBack.appendChild(element("div", "trace-empty", "No back route in this traceroute."));
      graphs.appendChild(emptyBack);
    }
    details.appendChild(graphs);
    list.appendChild(details);
  }
}

/** Replace the node-name map; bumps the version only when a name changed. */
function setNodeNames(nodes) {
  const entries = nodes.map((node) => [Number(node.num), nodeLabel(node)]);
  const signature = JSON.stringify(entries);
  if (signature !== state.nodeNamesSignature) {
    state.nodeNames = new Map(entries);
    state.nodeNamesSignature = signature;
    state.nodeNamesVersion += 1;
  }
  state.nodeNamesAt = Date.now();
}

/** Node names change rarely: refetch at most every NODE_NAMES_MAX_AGE_MS. */
async function loadNodeNames(run) {
  if (state.nodeNamesAt && Date.now() - state.nodeNamesAt < NODE_NAMES_MAX_AGE_MS) return;
  setNodeNames(await fetchJson(run, "/api/node-names"));
}

async function loadTraces(run) {
  await loadNodeNames(run);
  const traces = await fetchJson(run, "/api/traceroutes?limit=200");
  renderIfChanged("traces", traces, String(state.nodeNamesVersion), () => renderTraces(traces));
}

function renderSources(sources) {
  const list = $("sources-list");
  list.innerHTML = "";
  $("sources-count").textContent = `${sources.length} sources`;
  if (!sources.length) {
    list.appendChild(empty("No sources configured."));
    return;
  }

  for (const source of sources) {
    const node = source.node;
    const card = element("div", "source-card");

    const badge = element("div", "node-badge");
    badge.textContent = node?.short_name || (source.kind === "mqtt" ? "MQ" : "PHY");
    badge.style.background = node?.color || "#45475a";
    badge.style.color = contrastText(node?.color);

    const details = element("div", "node-details");
    const title = element("div", "node-title");
    const titleText = node?.long_name || source.name;
    title.appendChild(element("strong", "", titleText));
    if (node?.short_name) title.appendChild(element("span", "muted", `(${node.short_name})`));
    if (node?.node_num) title.appendChild(element("span", "mono", shortId(node.node_num)));
    if (source.name !== titleText) title.appendChild(element("span", "muted", source.name));
    details.appendChild(title);

    const meta = element("div", "node-meta");
    details.appendChild(meta);
    const add = (label, value) => {
      if (value === null || value === undefined || value === "" || value === "unknown") return;
      const item = element("span");
      item.appendChild(element("b", "", `${label}: `));
      item.appendChild(value instanceof Node ? value : textNode(value));
      meta.appendChild(item);
    };
    add("Kind", source.kind.toUpperCase());
    add("Endpoint", source.endpoint);
    add("Virtual endpoint", source.virtual_endpoint);
    const status = element(
      "span",
      `pill ${source.connected ? "ok" : "off"}`,
      source.connected ? "connected" : "offline",
    );
    meta.appendChild(status);
    add("Details", source.details);
    if (node) {
      add("Firmware", node.firmware_version);
      if (node.lora) add("LoRa", node.lora.summary);
      if (node.lora) add("Region", node.lora.region);
      add("Hardware", node.hw_model);
      add("PlatformIO", node.pio_env);
    }
    if (source.topics && source.topics.length) add("Topics", source.topics.join(", "));

    if (source.kind === "physical") {
      const clients = Array.isArray(source.clients) ? source.clients : [];
      const block = document.createElement("details");
      block.className = "source-direct";
      block.appendChild(element("summary", "", `Clients (${clients.length})`));
      const body = element("div");
      if (clients.length) body.appendChild(renderClients(clients));
      else body.appendChild(empty("No clients connected."));
      block.appendChild(body);
      details.appendChild(block);
    }

    if (source.kind === "physical" && source.receiver) {
      const relays = document.createElement("details");
      relays.className = "source-direct";
      relays.appendChild(element("summary", "", "Relay stats"));
      const relayBody = element("div");
      relays.appendChild(relayBody);
      let relaysLoaded = false;
      relays.addEventListener("toggle", async () => {
        if (!relays.open || relaysLoaded) return;
        relaysLoaded = true;
        relayBody.appendChild(empty("loading…"));
        try {
          const receiver = encodeURIComponent(source.receiver);
          const [stats, directNodes, series] = await Promise.all([
            getJson(`/api/relay-stats?receiver=${receiver}&limit=100`),
            getJson(`/api/direct-nodes?receiver=${receiver}&limit=100`).catch(() => []),
            getJson(`/api/relay-series?receiver=${receiver}&limit=2000`).catch(() => []),
          ]);
          relayBody.innerHTML = "";
          relayBody.appendChild(renderRelayStats(stats, directNodes, series));
        } catch (error) {
          relayBody.innerHTML = "";
          relayBody.appendChild(empty(`could not load relay stats: ${error.message}`));
        }
      });
      details.appendChild(relays);

      const direct = document.createElement("details");
      direct.className = "source-direct";
      direct.appendChild(element("summary", "", "Direct nodes (zero hop)"));
      const directBody = element("div");
      direct.appendChild(directBody);
      let loaded = false;
      direct.addEventListener("toggle", async () => {
        if (!direct.open || loaded) return;
        loaded = true;
        directBody.appendChild(empty("loading…"));
        try {
          const query = `receiver=${encodeURIComponent(source.receiver)}&limit=200`;
          const nodes = await getJson(`/api/direct-nodes?${query}`);
          renderDirectNodes(directBody, nodes);
        } catch (error) {
          directBody.innerHTML = "";
          directBody.appendChild(empty(`could not load direct nodes: ${error.message}`));
        }
      });
      details.appendChild(direct);
    }

    if (source.kind === "mqtt") {
      const localGateways = source.gateways || [];
      const gateways = document.createElement("details");
      gateways.className = "source-direct";
      const summary = element("summary", "", `Gateways (${localGateways.length})`);
      gateways.appendChild(summary);
      const gatewayBody = element("div");
      gateways.appendChild(gatewayBody);
      const renderGateways = (list) => {
        gatewayBody.innerHTML = "";
        if (list.length) {
          gatewayBody.appendChild(renderMqttGateways(list));
        } else {
          gatewayBody.appendChild(empty("No MQTT gateways seen yet."));
        }
        summary.textContent = `Gateways (${list.length})`;
      };
      if (localGateways.length) {
        renderGateways(localGateways);
      }
      let loaded = false;
      gateways.addEventListener("toggle", async () => {
        if (!gateways.open || loaded) return;
        loaded = true;
        if (!localGateways.length) {
          gatewayBody.innerHTML = "";
          gatewayBody.appendChild(empty("loading…"));
        }
        try {
          const remote = await getJson("/api/mqtt-gateways?limit=500");
          renderGateways(mergeMqttGateways(localGateways, remote));
        } catch (error) {
          gatewayBody.innerHTML = "";
          gatewayBody.appendChild(empty(`could not load MQTT gateways: ${error.message}`));
        }
      });
      details.appendChild(gateways);
    }

    card.appendChild(badge);
    card.appendChild(details);
    list.appendChild(card);
  }
}

function mergeMqttGateways(localGateways, remoteGateways) {
  const merged = new Map();
  for (const gateway of localGateways) {
    const key =
      gateway.receiver ||
      (gateway.node?.node_num != null ? shortId(gateway.node.node_num) : gateway.name);
    if (key) merged.set(key, { ...gateway });
  }
  for (const gateway of remoteGateways) {
    const key = gateway.receiver;
    if (!key) continue;
    const node = {
      node_num: gateway.num,
      long_name: gateway.long_name,
      short_name: gateway.short_name,
      hardware: gateway.hardware,
      color:
        gateway.num == null
          ? undefined
          : `#${(Number(gateway.num) & 0xffffff).toString(16).padStart(6, "0")}`,
    };
    const details =
      gateway.packets == null
        ? ""
        : `${fmtNum(gateway.packets)} MQTT packet${gateway.packets === 1 ? "" : "s"} · ${fmtAgo(gateway.last_heard)}`;
    const existing = merged.get(key);
    if (existing) {
      const combinedDetails =
        existing.details && details ? `${existing.details} · ${details}` : existing.details || details;
      merged.set(key, {
        ...existing,
        node: existing.node || node,
        packets: gateway.packets,
        last_heard: gateway.last_heard,
        details: combinedDetails,
      });
    } else {
      merged.set(key, {
        name: gateway.long_name || gateway.short_name || key,
        receiver: key,
        node,
        connected: null,
        packets: gateway.packets,
        last_heard: gateway.last_heard,
        details,
      });
    }
  }
  return [...merged.values()].sort((left, right) => {
    const byPackets = Number(right.packets ?? 0) - Number(left.packets ?? 0);
    if (byPackets !== 0) return byPackets;
    return gatewayDisplayName(left).localeCompare(gatewayDisplayName(right));
  });
}

function gatewayDisplayName(gateway) {
  return gateway.node?.long_name || gateway.name || gateway.receiver || "unknown";
}

function renderMqttGateways(gateways) {
  const table = element("table", "detail-table");
  const thead = document.createElement("thead");
  const head = document.createElement("tr");
  for (const [label, className] of [["Gateway", ""], ["Status", ""], ["Details", ""]]) {
    head.appendChild(element("th", className, label));
  }
  thead.appendChild(head);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const gateway of gateways) {
    const row = document.createElement("tr");
    const nameCell = element("td", "", gatewayDisplayName(gateway));
    if (gateway.receiver) nameCell.title = gateway.receiver;
    row.appendChild(nameCell);
    const status = element("td");
    const connected = gateway.connected === true;
    const offline = gateway.connected === false;
    status.appendChild(
      element(
        "span",
        `pill ${connected ? "ok" : offline ? "off" : "warn"}`,
        connected ? "connected" : offline ? "offline" : "seen",
      ),
    );
    row.appendChild(status);
    row.appendChild(element("td", "muted", gateway.details || "—"));
    tbody.appendChild(row);
  }
  table.appendChild(tbody);
  return table;
}

function fmtFreqError(value) {
  return value == null ? "—" : `${fmtOneDecimal(value)} Hz`;
}

const RELAY_METRICS = [
  { key: "rssi", label: "RSSI", color: "#89b4fa", format: (value) => fmtRssi(value) },
  { key: "snr", label: "SNR", color: "#a6e3a1", format: (value) => fmtSnr(value) },
  { key: "frequency_error", label: "Δf", color: "#f9e2af", format: fmtFreqError, centerZero: true },
];

const SIGNAL_METRICS = [
  { key: "rx_rssi", label: "RSSI", color: "#89b4fa", format: (value) => fmtRssi(value) },
  { key: "rx_snr", label: "SNR", color: "#a6e3a1", format: (value) => fmtSnr(value) },
  { key: "rx_frequency_error", label: "Δf", color: "#f9e2af", format: fmtFreqError, centerZero: true },
];

function directNodeLabel(node) {
  return node.long_name || node.short_name || node.node_id || shortId(node.num);
}

function relayMatches(relay, directNodes) {
  const byte = Number(relay.relay_node) & 0xff;
  return directNodes.filter((node) => (Number(node.num) & 0xff) === byte);
}

function relayLabel(relay, directNodes) {
  const names = relayMatches(relay, directNodes).map(directNodeLabel);
  return names.length ? `${relayId(relay.relay_node) || "0x00"} ${names.join(", ")}` : relayId(relay.relay_node) || "0x00";
}

function relayMetricValue(metric, relay, field) {
  const stats = relay[metric.key];
  return stats && stats.count ? metric.format(stats[field]) : "—";
}

function renderRelayTable(stats, directNodes) {
  const table = element("table", "detail-table relay-table");
  const thead = document.createElement("thead");
  const head = document.createElement("tr");
  for (const [label, className] of [
    ["Relay", ""], ["Packets", "num"], ["Metric", ""],
    ["Avg", "num"], ["Min", "num"], ["Max", "num"], ["σ", "num"],
  ]) {
    head.appendChild(element("th", className, label));
  }
  thead.appendChild(head);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const relay of stats) {
    RELAY_METRICS.forEach((metric, index) => {
      const row = document.createElement("tr");
      if (index === 0) {
        const relayCell = element("td");
        relayCell.rowSpan = RELAY_METRICS.length;
        relayCell.appendChild(element("span", "mono", relayId(relay.relay_node) || "0x00"));
        const matches = relayMatches(relay, directNodes).map(directNodeLabel);
        relayCell.appendChild(
          element(
            "div",
            matches.length ? "relay-candidates" : "relay-candidates muted",
            matches.length ? matches.join(", ") : "unknown",
          ),
        );
        row.appendChild(relayCell);
        const packetCell = element("td", "num", fmtNum(relay.packets));
        packetCell.rowSpan = RELAY_METRICS.length;
        row.appendChild(packetCell);
      }
      const metricCell = element("td", "relay-metric", metric.label);
      metricCell.style.color = metric.color;
      row.appendChild(metricCell);
      for (const field of ["avg", "min", "max", "stddev"]) {
        row.appendChild(element("td", "num", relayMetricValue(metric, relay, field)));
      }
      tbody.appendChild(row);
    });
  }
  table.appendChild(tbody);
  return table;
}

function renderRelayChart(stats, metric, directNodes) {
  const data = stats.filter((relay) => relay[metric.key] && relay[metric.key].count);
  if (!data.length) return null;
  let globalMin = Math.min(...data.map((relay) => Number(relay[metric.key].min)));
  let globalMax = Math.max(...data.map((relay) => Number(relay[metric.key].max)));
  let clipped = false;
  if (metric.centerZero) {
    const values = data
      .flatMap((relay) => [relay[metric.key].min, relay[metric.key].max])
      .filter((value) => value != null)
      .map((value) => Math.abs(Number(value)));
    const bound = Math.max(1, percentile(values, 0.9));
    clipped = values.some((value) => value > bound);
    globalMin = -bound;
    globalMax = bound;
  } else if (globalMin === globalMax) {
    globalMin -= 1;
    globalMax += 1;
  }
  const range = globalMax - globalMin;
  const block = element("div", "relay-chart");
  block.appendChild(
    element(
      "div",
      "relay-chart-title",
      `${metric.label} · ${metric.format(globalMin)} … ${metric.format(globalMax)}${clipped ? " · clipped" : ""}`,
    ),
  );
  for (const relay of data) {
    const statsForMetric = relay[metric.key];
    const row = element("div", "relay-chart-row");
    const label = element("span", "relay-chart-label", relayLabel(relay, directNodes));
    label.title = relayLabel(relay, directNodes);
    row.appendChild(label);
    const track = element("div", "relay-range-track");
    const minPct = Math.max(0, Math.min(100, ((Number(statsForMetric.min) - globalMin) / range) * 100));
    const maxPct = Math.max(0, Math.min(100, ((Number(statsForMetric.max) - globalMin) / range) * 100));
    const avgPct = Math.max(0, Math.min(100, ((Number(statsForMetric.avg) - globalMin) / range) * 100));
    const fill = element("div", "relay-range-fill");
    fill.style.left = `${minPct}%`;
    fill.style.width = `${Math.max(2, maxPct - minPct)}%`;
    fill.style.background = metric.color;
    track.appendChild(fill);
    const marker = element("div", "relay-range-marker");
    marker.style.left = `${avgPct}%`;
    track.appendChild(marker);
    track.title = `min ${metric.format(statsForMetric.min)} · max ${metric.format(statsForMetric.max)} · avg ${metric.format(statsForMetric.avg)} · σ ${metric.format(statsForMetric.stddev)}`;
    row.appendChild(track);
    row.appendChild(element("span", "num", metric.format(statsForMetric.avg)));
    block.appendChild(row);
  }
  const legend = element("div", "relay-chart-legend");
  const rangeSwatch = element("span", "relay-legend-swatch range");
  rangeSwatch.style.background = metric.color;
  legend.appendChild(rangeSwatch);
  legend.appendChild(element("span", "", "min–max"));
  legend.appendChild(element("span", "relay-legend-swatch marker"));
  legend.appendChild(element("span", "", "average"));
  block.appendChild(legend);
  return block;
}

function renderRelayTimelines(series, stats, directNodes) {
  if (!series || !series.length) return null;
  const groups = new Map();
  for (const sample of series) {
    const key = Number(sample.relay_node);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(sample);
  }
  if (!groups.size) return null;
  const wrap = element("div", "relay-timelines");
  wrap.appendChild(element("div", "relay-chart-title", "Relay timelines"));
  const relayByByte = new Map(stats.map((relay) => [Number(relay.relay_node), relay]));
  for (const relay of stats) {
    const samples = groups.get(Number(relay.relay_node));
    if (!samples || !samples.length) continue;
    samples.sort((left, right) => left.received_at - right.received_at);
    const details = document.createElement("details");
    details.className = "relay-timeline";
    details.appendChild(
      element(
        "summary",
        "",
        `${relayLabel(relayByByte.get(Number(relay.relay_node)) || relay, directNodes)} · ${samples.length} samples`,
      ),
    );
    const metrics = SIGNAL_METRICS.map((metric) => ({ ...metric }));
    const svg = svgElement("svg", { class: "signal-chart", viewBox: "0 0 520 150" });
    metrics.forEach((metric, index) => {
      renderSignalTrack(svg, samples, metric, metric.label, metric.color, 8 + index * 50);
    });
    details.appendChild(svg);
    const legend = renderSignalLegend(samples, metrics);
    if (legend.childElementCount) details.appendChild(legend);
    wrap.appendChild(details);
  }
  return wrap;
}

function renderRelayStats(stats, directNodes, series) {
  if (!stats.length) return empty("No relay observations for this source.");
  const wrap = element("div", "relay-stats");
  wrap.appendChild(renderRelayTable(stats, directNodes));
  const charts = element("div", "relay-charts");
  for (const metric of RELAY_METRICS) {
    const chart = renderRelayChart(stats, metric, directNodes);
    if (chart) charts.appendChild(chart);
  }
  if (charts.childElementCount) wrap.appendChild(charts);
  const timelines = renderRelayTimelines(series, stats, directNodes);
  if (timelines) wrap.appendChild(timelines);
  return wrap;
}

function renderClients(clients) {
  const table = element("table", "detail-table");
  const thead = document.createElement("thead");
  const head = document.createElement("tr");
  for (const [label, className] of [["Client", ""], ["Connected", ""], ["Idle", ""], ["RX", "num"], ["TX", "num"]]) {
    head.appendChild(element("th", className, label));
  }
  thead.appendChild(head);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const client of clients) {
    const row = document.createElement("tr");
    const peer = element("td", "mono", client.peer);
    peer.title = `client #${client.id}`;
    row.appendChild(peer);
    row.appendChild(element("td", "", fmtDuration(client.connected_secs)));
    row.appendChild(element("td", "", fmtDuration(client.idle_secs)));
    row.appendChild(
      element("td", "num", `${fmtBytes(client.rx_bytes)} · ${fmtNum(client.rx_frames)} frames`),
    );
    row.appendChild(
      element("td", "num", `${fmtBytes(client.tx_bytes)} · ${fmtNum(client.tx_frames)} frames`),
    );
    tbody.appendChild(row);
  }
  table.appendChild(tbody);
  return table;
}

function renderDirectNodes(container, nodes) {
  container.innerHTML = "";
  if (!nodes.length) {
    container.appendChild(empty("No direct nodes heard by this source."));
    return;
  }
  const table = element("table", "detail-table");
  const thead = document.createElement("thead");
  const head = document.createElement("tr");
  for (const [label, className] of [["Node", ""], ["Hardware", ""], ["SNR", "num"], ["RSSI", "num"], ["Packets", "num"], ["Last heard", ""]]) {
    head.appendChild(element("th", className, label));
  }
  thead.appendChild(head);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const node of nodes) {
    const row = document.createElement("tr");
    row.appendChild(element("td", "", node.long_name || node.short_name || node.node_id || shortId(node.num)));
    row.appendChild(element("td", "muted", node.hardware || "—"));
    row.appendChild(element("td", "num", fmtSnr(node.snr)));
    row.appendChild(element("td", "num", fmtRssi(node.rssi)));
    row.appendChild(element("td", "num", fmtNum(node.packets)));
    row.appendChild(timeElement("td", "", node.last_heard));
    tbody.appendChild(row);
  }
  table.appendChild(tbody);
  container.appendChild(table);
}

function renderMessages(messages) {
  const list = $("chat-list");
  list.innerHTML = "";
  $("chat-count").textContent = `${messages.length} shown`;
  if (!messages.length) {
    list.appendChild(empty("No messages yet."));
    return;
  }
  for (const message of messages) {
    const card = element("div", "message");
    const head = element("div", "head");
    const meshCore = message.network === "meshcore";
    head.appendChild(element("span", "sender", message.sender || (meshCore ? "unknown sender" : shortId(message.from_num))));
    head.appendChild(element("span", "chan", channelLabel(message.channel, message.channel_name)));
    // The server receive time orders the list; rx_time is the radio's own clock.
    head.appendChild(timeElement("span", "time", message.received_at || message.rx_time));
    card.appendChild(head);
    card.appendChild(element("div", "text", message.text));

    const meta = element("div", "meta");
    meta.appendChild(element("span", "", `SNR ${fmtSnr(message.rx_snr)}`));
    meta.appendChild(element("span", "", `RSSI ${fmtRssi(message.rx_rssi)}`));
    if (message.rx_frequency_error != null) {
      meta.appendChild(element("span", "", `Δf ${Math.round(Number(message.rx_frequency_error))} Hz`));
    }
    if (message.rx_coding_rate != null) {
      meta.appendChild(element("span", "", `CR ${Number(message.rx_coding_rate) + 4}`));
    }
    if (meshCore) {
      // MeshCore has no hop limit: the path length is the number of hops used.
      if (message.hop_start != null) meta.appendChild(element("span", "", `hops ${message.hop_start}`));
      const sentProblem = message.sent_at == null ? null : rxTimeProblem(message.sent_at, message.received_at);
      if (sentProblem) meta.appendChild(element("span", "bad-value", `sender clock ${fmtTime(message.sent_at)} · ${sentProblem}`));
    } else {
      const messageHops = hopsInfo(message.hop_start, message.hop_limit);
      if (messageHops) meta.appendChild(hopsElement("span", "", messageHops, "hops "));
    }
    const rxProblem = rxTimeProblem(message.rx_time, message.received_at);
    if (rxProblem) {
      meta.appendChild(element("span", "bad-value", `rx time ${fmtTime(message.rx_time)} · ${rxProblem}`));
    }
    if (message.relay_node) meta.appendChild(element("span", "", `relay ${relayId(message.relay_node)}`));
    if (message.source === "mqtt") meta.appendChild(element("span", "", "source MQTT"));
    if (message.source === "client") meta.appendChild(element("span", "", "source client"));
    if (message.via_mqtt) meta.appendChild(element("span", "", "via MQTT"));
    if (message.decrypted) meta.appendChild(decryptedTag());
    if (message.reception_count > 0) {
      const best = message.best_snr == null ? "" : ` · best ${fmtSnr(message.best_snr)}`;
      meta.appendChild(
        element(
          "span",
          "",
          `heard ${message.reception_count} time${message.reception_count === 1 ? "" : "s"} · ${message.gateway_count} gateway${message.gateway_count === 1 ? "" : "s"}${best}`,
        ),
      );
    }
    card.appendChild(meta);

    // The path the MeshCore frame took: the first copy heard inline, every
    // copy (a flood arrives over several paths) in an expandable list.
    const heard = message.meshcore_receptions || [];
    if (heard.length) {
      const line = element("div", "chat-path");
      line.appendChild(element("span", "muted", "path "));
      line.appendChild(meshCorePathElement(heard[0]));
      card.appendChild(line);
    }
    if (heard.length > 1) {
      const details = document.createElement("details");
      details.className = "receptions";
      details.appendChild(element("summary", "", `MeshCore: heard ${heard.length} times over ${new Set(heard.map((copy) => copy.path.map((hop) => hop.hash).join(">"))).size} paths`));
      const container = element("div", "reception-list");
      for (const copy of heard) {
        const row = element("div", "chat-path");
        row.appendChild(timeElement("span", "muted", copy.received_at));
        row.appendChild(element("span", "muted", ` · ${gatewayLabel(copy.gateway_id)} · SNR ${fmtSnr(copy.rx_snr)} · RSSI ${fmtRssi(copy.rx_rssi)} · `));
        row.appendChild(meshCorePathElement(copy));
        container.appendChild(row);
      }
      details.appendChild(container);
      card.appendChild(details);
    }

    // Per-reception details exist for Meshtastic packets only.
    if (message.reception_count > 0 && !meshCore) {
      const details = document.createElement("details");
      details.className = "receptions";
      details.appendChild(
        element(
          "summary",
          "",
          `heard ${message.reception_count} time${message.reception_count === 1 ? "" : "s"} by ${message.gateway_count} gateway${message.gateway_count === 1 ? "" : "s"}`,
        ),
      );
      const container = element("div", "reception-list");
      details.appendChild(container);
      let loaded = false;
      details.addEventListener("toggle", async () => {
        if (!details.open || loaded) return;
        loaded = true;
        container.appendChild(empty("loading…"));
        try {
          const query = `from_num=${encodeURIComponent(message.from_num)}&packet_id=${encodeURIComponent(message.packet_id)}`;
          const receptions = await getJson(`/api/receptions?${query}`);
          renderReceptions(container, receptions);
        } catch (error) {
          container.innerHTML = "";
          container.appendChild(empty(`could not load receptions: ${error.message}`));
        }
      });
      card.appendChild(details);
    }

    list.appendChild(card);
  }
}

function renderReceptions(container, receptions) {
  container.innerHTML = "";
  if (!receptions.length) {
    container.appendChild(empty("No reception records."));
    return;
  }
  for (const reception of receptions) {
    const row = element("div", "reception");
    const head = element("div", "reception-head");
    const receiver = element("span", "", gatewayLabel(reception.receiver));
    if (reception.receiver) receiver.title = reception.receiver;
    head.appendChild(receiver);
    head.appendChild(element("span", "muted", reception.source));
    if (reception.decrypted) head.appendChild(decryptedTag());
    head.appendChild(timeElement("span", "time", reception.received_at));
    row.appendChild(head);

    const meta = element("div", "reception-meta");
    meta.appendChild(element("span", "", channelLabel(reception.channel, reception.channel_name)));
    meta.appendChild(element("span", "", `SNR ${fmtSnr(reception.rx_snr)}`));
    meta.appendChild(element("span", "", `RSSI ${fmtRssi(reception.rx_rssi)}`));
    if (reception.rx_frequency_error != null) {
      meta.appendChild(element("span", "", `Δf ${Math.round(Number(reception.rx_frequency_error))} Hz`));
    }
    if (reception.rx_coding_rate != null) {
      meta.appendChild(element("span", "", `CR ${Number(reception.rx_coding_rate) + 4}`));
    }
    const receptionHops = hopsInfo(reception.hop_start, reception.hop_limit);
    if (receptionHops) meta.appendChild(hopsElement("span", "", receptionHops, "hops "));
    if (reception.relay_node) meta.appendChild(element("span", "", `relay ${relayId(reception.relay_node)}`));
    row.appendChild(meta);
    container.appendChild(row);
  }
}

/**
 * Make `select` show `options` ([{ value, label }]) after an "all" entry.
 * The DOM is only touched where something differs, so a poll never closes or
 * resets a dropdown the user has open. A selected value that is no longer
 * offered stays visible instead of silently blanking the control.
 */
function syncSelect(select, allLabel, options, current) {
  const wanted = [{ value: "", label: allLabel }, ...options.map((option) => ({
    value: String(option.value),
    label: clean(option.label),
  }))];
  if (current !== "" && !wanted.some((option) => option.value === current)) {
    wanted.push({ value: current, label: `${clean(current)} (no longer present)` });
  }
  const existing = select.options;
  let sameValues = existing.length === wanted.length;
  for (let index = 0; sameValues && index < wanted.length; index += 1) {
    if (existing[index].value !== wanted[index].value) sameValues = false;
  }
  if (sameValues) {
    wanted.forEach((option, index) => {
      if (existing[index].textContent !== option.label) existing[index].textContent = option.label;
    });
  } else {
    select.replaceChildren(
      ...wanted.map((option) => {
        const item = element("option", "", option.label);
        item.value = option.value;
        return item;
      }),
    );
  }
  if (select.value !== current) select.value = current;
}

function fillChannelSelect(select, current, channels) {
  syncSelect(
    select,
    "All channels",
    channels.map((channel) => ({
      value: channel.key || channelKey(channel.channel, channel.name),
      label: channelLabel(channel.channel, channel.name),
    })),
    current,
  );
}

async function loadChannels(run) {
  const channels = await fetchJson(run, "/api/channels");
  fillChannelSelect(
    $("chat-channel"),
    state.channel,
    channels.filter((channel) => channel.channel < 256),
  );
  // MeshCore (JC:) channels carry a negative index; they are chat-only here.
  fillChannelSelect($("packet-channel"), state.packetChannel, channels.filter((channel) => channel.channel >= 0));
}

function fillFilterSelect(select, current, allLabel, options) {
  syncSelect(
    select,
    allLabel,
    options.map((option) => ({
      value: option.value,
      label: `${option.label} (${fmtNum(option.count)})`,
    })),
    current,
  );
}

const PACKET_FILTER_IDS = [
  "packet-protocol",
  "packet-channel",
  "packet-gateway",
  "packet-source",
  "packet-decrypted",
];

/** Filters shown for the MeshCore and Reticulum packet lists. */
const JRAW_FILTER_IDS = ["jraw-payload", "jraw-route", "jraw-search"];
/** Filters that only mean something for MeshCore. */
const MESHCORE_FILTER_IDS = ["jraw-channel", "jraw-decrypted", "jraw-region"];

function meshCoreNodeTypeLabel(type) {
  switch (Number(type)) {
    case 1: return "Companion";
    case 2: return "Repeater";
    case 3: return "Room Server";
    case 4: return "Sensor";
    default: return type == null ? "—" : `Type ${type}`;
  }
}

function fmtHexByte(value) {
  return `0x${Number(value).toString(16).padStart(2, "0")}`;
}

/**
 * A short MeshCore hash with the node(s) it could be. Short hashes collide, so
 * several candidates are listed instead of guessing one.
 */
function hashMatchElement(match) {
  const node = element("span", "hash-match");
  if (!match.candidates) {
    node.classList.add("unknown");
    node.appendChild(element("span", "mono", match.hash));
    node.title = `${match.hash}: no known node has this hash`;
    return node;
  }
  const more = match.candidates - match.names.length;
  node.appendChild(textNode(`${match.names.join(" | ")}${more > 0 ? ` +${more}` : ""} `));
  node.appendChild(element("span", "mono muted", match.hash));
  if (match.candidates > 1) {
    node.classList.add("ambiguous");
    node.title = `${match.hash} matches ${match.candidates} known nodes`;
  } else {
    node.title = `${match.hash} matches only this known node`;
  }
  return node;
}

/** The path of a MeshCore frame: repeaters passed (flood) or still ahead (direct). */
function meshCorePathElement(frame, tag = "span") {
  const container = element(tag, "mc-path");
  const direct = /direct/.test(frame.route_name || "");
  if (frame.trace && frame.trace.length) {
    container.title = "requested trace route; SNR is what each hop measured so far";
    frame.trace.forEach((hop, index) => {
      if (index) container.appendChild(textNode(" → "));
      container.appendChild(hashMatchElement(hop.node));
      if (hop.snr != null) container.appendChild(element("span", "muted", ` ${fmtSnr(hop.snr)}`));
    });
    return container;
  }
  const path = frame.path || [];
  if (!path.length) {
    container.appendChild(textNode(frame.path_hash_size == null ? "—" : direct ? "no hops left" : "no hops yet"));
    container.classList.add("muted");
    return container;
  }
  container.title = direct
    ? `route still ahead (${frame.path_hash_size ?? "?"}-byte hashes)`
    : `repeaters passed, in order (${frame.path_hash_size ?? "?"}-byte hashes)`;
  container.appendChild(element("span", "muted", direct ? "next: " : `${path.length} hop${path.length === 1 ? "" : "s"}: `));
  path.forEach((hop, index) => {
    if (index) container.appendChild(textNode(" → "));
    container.appendChild(hashMatchElement(hop));
  });
  return container;
}

function meshCoreChannelElement(frame, tag = "span") {
  if (frame.channel_hash == null) return element(tag, "", "—");
  const node = element(tag, "");
  node.appendChild(element("span", "mono", fmtHexByte(frame.channel_hash)));
  if (frame.channel_name) {
    node.appendChild(textNode(` JC:${frame.channel_name}`));
    node.title = "decrypted with this channel's key";
  } else if (frame.channel_candidates && frame.channel_candidates.length) {
    node.appendChild(element("span", "muted", ` ${frame.channel_candidates.map((name) => `JC:${name}`).join(" | ")}?`));
    node.title = "a known channel has this hash, but its key did not decrypt the frame";
  } else {
    node.title = "no known channel key has this hash";
  }
  return node;
}

function meshCoreRegionElement(frame, tag = "span") {
  if (frame.region_code == null) {
    const node = element(tag, "muted", "—");
    node.title = "not region-scoped";
    return node;
  }
  const code = `0x${Number(frame.region_code).toString(16).padStart(4, "0")}`;
  if (frame.region) {
    const node = element(tag, "", frame.region);
    node.title = `scope code ${code}`;
    return node;
  }
  const node = element(tag, "mono muted", code);
  node.title = "region-scoped, but no configured region produces this code (see web.meshcore_regions)";
  return node;
}

/** Position of a MeshCore advert or node, in degrees; out-of-range values are flagged. */
function degreesPosition(latitude, longitude) {
  if (latitude == null || longitude == null) return { state: "none" };
  const lat = Number(latitude);
  const lon = Number(longitude);
  if (lat === 0 && lon === 0) return { state: "nofix" };
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) {
    return { state: "invalid", text: `${latitude}, ${longitude}` };
  }
  const text = `${lat.toFixed(5)}, ${lon.toFixed(5)}`;
  return { state: "ok", text, latitude: lat.toFixed(5), longitude: lon.toFixed(5) };
}

function degreesPositionContent(latitude, longitude) {
  const position = degreesPosition(latitude, longitude);
  if (position.state === "ok") {
    const link = element("a", "", position.text);
    link.href = `https://www.openstreetmap.org/?mlat=${position.latitude}&mlon=${position.longitude}#map=15/${position.latitude}/${position.longitude}`;
    link.target = "_blank";
    link.rel = "noreferrer";
    return link;
  }
  if (position.state === "invalid") {
    const bad = element("span", "bad-value", `invalid: ${position.text}`);
    bad.title = "coordinates out of range";
    return bad;
  }
  if (position.state === "nofix") {
    const unset = element("span", "muted", "not set");
    unset.title = "node advertised 0, 0 (no position set)";
    return unset;
  }
  return document.createTextNode("—");
}

const JRAW_PACKET_COLUMNS = {
  mc: ["Time", "Payload", "Channel", "Contents", "From", "To", "Region", "Path", "Route", "Gateway", "Bytes", "SNR", "RSSI", "Source"],
  rnode: ["Time", "Packet type", "Context", "Name", "Destination", "Gateway", "Bytes", "SNR", "RSSI", "Source"],
};

function renderPacketHead(family) {
  const row = $("packets-head").querySelector("tr");
  row.innerHTML = "";
  const labels =
    family === "mt"
      ? ["Time", "From", "To", "Protocol", "Contents", "Channel", "Gateways", "Bytes", "SNR", "RSSI", "Source"]
      : JRAW_PACKET_COLUMNS[family];
  labels.forEach((label, index) => {
    const numeric = ["Bytes", "SNR", "RSSI"].includes(label) ? "num" : "";
    row.appendChild(element("th", numeric, label));
  });
}

async function loadPackets(run) {
  const family = state.packetFamily;
  const isMeshtastic = family === "mt";
  for (const id of PACKET_FILTER_IDS) $(id).hidden = !isMeshtastic;
  await loadNodeNames(run);

  for (const id of JRAW_FILTER_IDS) $(id).hidden = isMeshtastic;
  for (const id of MESHCORE_FILTER_IDS) $(id).hidden = family !== "mc";

  if (!isMeshtastic) {
    const kind = family === "mc" ? 1 : 2;
    const options = await fetchJson(run, `/api/raw-filters?kind=${kind}`);
    const meshCore = family === "mc";
    fillFilterSelect($("jraw-payload"), state.jrawPayload, meshCore ? "All payload types" : "All contexts", options.payloads);
    fillFilterSelect($("jraw-route"), state.jrawRoute, meshCore ? "All routes" : "All packet types", options.routes);
    fillFilterSelect($("jraw-channel"), state.jrawChannel, "All channels", options.channels);
    syncSelect(
      $("jraw-region"),
      "Any region or none",
      // Only the "any region-scoped" entry has a count.
      options.regions.map((region) => ({ value: region.value, label: region.count >= 0 ? `${region.label} (${fmtNum(region.count)})` : region.label })),
      state.jrawRegion,
    );

    const params = new URLSearchParams({ kind: String(kind), limit: "500" });
    if (state.jrawPayload) params.set("payload", state.jrawPayload);
    if (state.jrawRoute) params.set("route", state.jrawRoute);
    if (meshCore && state.jrawChannel) params.set("channel", state.jrawChannel);
    if (meshCore && state.jrawDecrypted) params.set("decrypted", state.jrawDecrypted);
    if (meshCore && state.jrawRegion) params.set("region", state.jrawRegion);
    if (state.jrawSearch.trim()) params.set("q", state.jrawSearch.trim());
    const filtered = [...params.keys()].length > 2;
    const frames = await fetchJson(run, `/api/raw?${params}`);
    renderIfChanged("packets", frames, `${family}|${params}|${state.nodeNamesVersion}`, () => {
      renderPacketHead(family);
      renderJrawPackets(frames, family, filtered);
    });
    return;
  }

  await loadChannels(run);
  const filters = await fetchJson(run, "/api/packet-filters");
  fillFilterSelect($("packet-protocol"), state.packetProtocol, "All protocols", filters.portnums);
  fillFilterSelect($("packet-gateway"), state.packetGateway, "All gateways", filters.gateways);

  const params = new URLSearchParams({ limit: "500" });
  if (state.packetProtocol) params.set("portnum", state.packetProtocol);
  if (state.packetChannel) params.set("channel", state.packetChannel);
  if (state.packetGateway) params.set("gateway", state.packetGateway);
  if (state.packetSource) params.set("source", state.packetSource);
  if (state.packetDecrypted) params.set("decrypted", state.packetDecrypted);
  const packets = await fetchJson(run, `/api/packets?${params}`);
  renderIfChanged("packets", packets, `mt|${params}|${state.nodeNamesVersion}`, () => {
    renderPacketHead("mt");
    renderPackets(packets);
  });
}

function renderJrawPackets(frames, family, filtered) {
  const body = $("packets-body");
  body.innerHTML = "";
  $("packet-count").textContent = `${frames.length} shown${frames.length >= 500 ? " (newest 500)" : ""}`;
  if (!frames.length) {
    const row = document.createElement("tr");
    const cell = element("td", "muted", filtered ? "No frames match these filters." : "No frames yet.");
    cell.colSpan = JRAW_PACKET_COLUMNS[family].length;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  for (const frame of frames) {
    const row = document.createElement("tr");
    const add = (cell) => row.appendChild(cell);
    add(timeElement("td", "", frame.received_at, ` · seq ${frame.sequence}`));
    if (family === "mc") {
      add(element("td", "", frame.payload_name || frame.kind_name));
      add(meshCoreChannelElement(frame, "td"));
      // Decrypted text is the point of the row: let it wrap instead of cutting it.
      const text = jrawContents(frame);
      const contents = element("td", frame.decrypted ? "packet-contents readable" : text === "encrypted" || text === "—" ? "packet-contents muted" : "packet-contents", text);
      contents.title = text;
      if (frame.decrypted) contents.appendChild(decryptedTag());
      add(contents);
      const from = element("td", "");
      if (frame.node_name) from.appendChild(textNode(frame.node_name));
      else if (frame.sender) from.appendChild(hashMatchElement(frame.sender));
      else from.appendChild(element("span", "mono", frame.sender_hash || "—"));
      add(from);
      const to = element("td", "");
      if (frame.destination) to.appendChild(hashMatchElement(frame.destination));
      else to.appendChild(element("span", "mono", frame.destination_hash || "—"));
      add(to);
      add(meshCoreRegionElement(frame, "td"));
      add(meshCorePathElement(frame, "td"));
      add(element("td", "", frame.route_name || "—"));
    } else {
      add(element("td", "", frame.route_name || "—"));
      add(element("td", "", frame.payload_name || frame.kind_name));
      add(element("td", "", frame.node_name || "—"));
      const destination = element("td", "mono", frame.destination_hash ? `${frame.destination_hash.slice(0, 16)}…` : "—");
      if (frame.destination_hash) destination.title = frame.destination_hash;
      add(destination);
    }
    add(element("td", "", gatewayLabel(frame.gateway_id)));
    add(element("td", "num", fmtBytes(frame.frame_len)));
    add(element("td", "num", fmtSnr(frame.rx_snr)));
    add(element("td", "num", fmtRssi(frame.rx_rssi)));
    add(element("td", "muted", frame.source === "mqtt" ? "MQTT" : "PHY"));
    body.appendChild(row);
  }
}

function jrawContents(frame) {
  if (frame.payload_text) return frame.payload_text;
  if (frame.node_type != null) {
    const position = degreesPosition(frame.latitude, frame.longitude);
    const where = position.state === "ok" ? ` at ${position.text}` : position.state === "invalid" ? ` at invalid position ${position.text}` : "";
    return `${meshCoreNodeTypeLabel(frame.node_type)}${where}`;
  }
  if (frame.trace_tag != null) return `trace #${Number(frame.trace_tag).toString(16).padStart(8, "0")}`;
  if (frame.payload_name === "TXT_MSG" || frame.payload_name === "GRP_TXT") return "encrypted";
  return "—";
}

function renderPackets(packets) {
  const body = $("packets-body");
  body.innerHTML = "";
  $("packet-count").textContent = `${packets.length} shown`;
  if (!packets.length) {
    const row = document.createElement("tr");
    const cell = element("td", "muted", "No matching packets.");
    cell.colSpan = 11;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  for (const packet of packets) {
    const row = document.createElement("tr");
    row.appendChild(timeElement("td", "", packet.received_at, ` · #${packet.packet_id}`));

    const from = element("td", "", packet.from_name || shortId(packet.from_num));
    from.title = shortId(packet.from_num);
    row.appendChild(from);
    row.appendChild(element("td", "", packet.to_name || shortId(packet.to_num)));
    row.appendChild(element("td", "", packet.portnum_name));
    const contents = element("td", "packet-contents", packet.contents || "—");
    contents.title = packet.contents || "";
    row.appendChild(contents);
    row.appendChild(element("td", "", channelLabel(packet.channel, packet.channel_name)));
    row.appendChild(
      element("td", "", gatewayLabels(packet.gateways) || (packet.via_mqtt ? "MQTT" : "—")),
    );
    row.appendChild(element("td", "num", fmtBytes(packet.bytes)));
    row.appendChild(element("td", "num", fmtSnr(packet.rx_snr)));
    row.appendChild(element("td", "num", fmtRssi(packet.rx_rssi)));

    const source = element("td", "muted");
    source.appendChild(
      document.createTextNode(
        packet.source === "mqtt" ? "MQTT" : packet.source === "client" ? "Client" : "LoRa",
      ),
    );
    if (packet.via_mqtt && packet.source !== "mqtt") source.appendChild(document.createTextNode(" · via MQTT"));
    if (packet.decrypted) source.appendChild(decryptedTag());
    row.appendChild(source);
    body.appendChild(row);
  }
}

async function loadChat(run) {
  await loadNodeNames(run);
  await loadChannels(run);
  const channel = state.channel;
  const query = channel === "" ? "" : `?channel=${encodeURIComponent(channel)}`;
  const messages = await fetchJson(run, `/api/messages${query}`);
  renderIfChanged("chat", messages, channel, () => renderMessages(messages));
}

function nodeRoleLabel(role) {
  return ROLE_NAMES[role] || (role == null ? "—" : `Role ${role}`);
}

function usedHops(node) {
  if (node.hop_start == null || node.hop_limit == null) return null;
  return Math.max(0, Number(node.hop_start) - Number(node.hop_limit));
}

/** Number for sorting; missing or non-numeric values sort below every real one. */
function sortNumber(value) {
  if (value == null) return Number.NEGATIVE_INFINITY;
  const number = Number(value);
  return Number.isNaN(number) ? Number.NEGATIVE_INFINITY : number;
}

function nodeSortValue(node, key) {
  switch (key) {
    case "name": return nodeLabel(node).toLowerCase();
    case "id": return (node.node_id || shortId(node.num)).toLowerCase();
    case "last_heard": {
      // last_heard is a radio clock; a future value must not pin a node on top.
      const heard = sortNumber(node.last_heard ?? 0);
      return timeProblem(heard) === "in the future" ? sortNumber(node.updated_at ?? 0) : heard;
    }
    case "snr": return sortNumber(node.snr);
    case "hops": return sortNumber(usedHops(node));
    case "battery": return sortNumber(node.battery_level);
    case "role": return nodeRoleLabel(node.role).toLowerCase();
    case "hardware": return (node.hardware || "").toLowerCase();
    case "channel": return sortNumber(node.channel);
    case "position": return nodePosition(node).state === "ok" ? 1 : 0;
    case "via": return (node.gateways || "").toLowerCase();
    default: return 0;
  }
}

/** Total order over sort values: never NaN, even for two infinities. */
function compareSortValues(a, b) {
  if (typeof a === "string" || typeof b === "string") return String(a).localeCompare(String(b));
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function updateNodeSortHeaders() {
  for (const th of document.querySelectorAll("th[data-sort]")) {
    const sorted = th.dataset.sort === state.nodeSort;
    th.classList.toggle("sorted", sorted);
    th.classList.toggle("asc", sorted && state.nodeSortDir === "asc");
    th.setAttribute("aria-sort", !sorted ? "none" : state.nodeSortDir === "asc" ? "ascending" : "descending");
  }
}

function populateNodeFilters() {
  const roles = [...new Set(state.nodes.map((node) => node.role).filter((role) => role != null))]
    .sort((a, b) => compareSortValues(sortNumber(a), sortNumber(b)));
  syncSelect(
    $("node-role-filter"),
    "All roles",
    roles.map((role) => ({ value: String(role), label: nodeRoleLabel(role) })),
    state.nodeRole,
  );

  const hardware = [...new Set(state.nodes.map((node) => node.hardware).filter((value) => value && value !== "UNKNOWN"))].sort();
  syncSelect(
    $("node-hardware-filter"),
    "All hardware",
    hardware.map((value) => ({ value, label: value })),
    state.nodeHardware,
  );

  const channels = new Map();
  for (const node of state.nodes) {
    if (node.channel == null) continue;
    const key = channelKey(node.channel, node.channel_name);
    if (!channels.has(key)) channels.set(key, channelLabel(node.channel, node.channel_name));
  }
  const channelOptions = [...channels.entries()]
    .map(([value, label]) => ({ value, label }))
    .sort(
      (left, right) =>
        left.label.localeCompare(right.label, undefined, { numeric: true }) ||
        left.value.localeCompare(right.value),
    );
  syncSelect($("node-channel-filter"), "All channels", channelOptions, state.nodeChannel);
}

function renderNodes() {
  const body = $("nodes-body");
  const active = document.activeElement;
  const focusedNum = active && body.contains(active) ? active.closest("tr")?.dataset.num : undefined;
  body.innerHTML = "";
  const search = state.nodeSearch.trim().toLowerCase();
  const nodes = state.nodes.filter((node) => {
    if (search) {
      const haystack = `${nodeLabel(node)} ${node.node_id || ""} ${shortId(node.num)} ${node.hardware || ""}`.toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    if (state.nodeRole !== "" && String(node.role ?? "") !== state.nodeRole) return false;
    if (state.nodeVia === "mqtt" && !node.via_mqtt) return false;
    if (state.nodeVia === "lora" && node.via_mqtt) return false;
    if (state.nodeHardware !== "" && node.hardware !== state.nodeHardware) return false;
    if (state.nodeChannel !== "" && channelKey(node.channel, node.channel_name) !== state.nodeChannel) return false;
    return true;
  });

  nodes.sort((left, right) => {
    const result = compareSortValues(
      nodeSortValue(left, state.nodeSort),
      nodeSortValue(right, state.nodeSort),
    );
    if (result !== 0) return state.nodeSortDir === "asc" ? result : -result;
    // Ties keep a fixed order by node number, whatever the direction.
    return compareSortValues(sortNumber(left.num), sortNumber(right.num));
  });

  $("nodes-count").textContent = `${nodes.length} / ${state.nodes.length} nodes`;
  updateNodeSortHeaders();
  if (!nodes.length) {
    const row = document.createElement("tr");
    const cell = element("td", "muted", state.nodes.length ? "No matching nodes." : "No nodes heard yet.");
    cell.colSpan = 11;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  for (const node of nodes) {
    const row = document.createElement("tr");
    row.dataset.num = String(node.num);
    row.tabIndex = 0;
    row.setAttribute("aria-haspopup", "dialog");
    row.setAttribute("aria-label", `Open details for ${clean(nodeLabel(node))}`);
    row.addEventListener("click", (event) => {
      if (event.target.closest("a")) return;
      openNodeDialog(node.num);
    });
    row.addEventListener("keydown", (event) => {
      if (event.target !== row || (event.key !== "Enter" && event.key !== " ")) return;
      event.preventDefault();
      openNodeDialog(node.num);
    });
    row.appendChild(element("td", "", nodeLabel(node)));
    row.appendChild(element("td", "mono", node.node_id || shortId(node.num)));
    row.appendChild(timeElement("td", "", node.last_heard));
    row.appendChild(element("td", "num", fmtSnr(node.snr)));
    const hops = hopsInfo(node.hop_start, node.hop_limit);
    row.appendChild(hops ? hopsElement("td", "num", hops) : element("td", "num", "—"));
    row.appendChild(element("td", "num", node.battery_level == null ? "—" : `${node.battery_level}%`));
    row.appendChild(element("td", "", nodeRoleLabel(node.role)));
    row.appendChild(element("td", "muted", node.hardware || "—"));
    row.appendChild(element("td", "", node.channel == null ? "—" : channelLabel(node.channel, node.channel_name)));

    const position = element("td", "");
    position.appendChild(positionContent(node));
    row.appendChild(position);
    row.appendChild(
      element("td", "", gatewayLabels(node.gateways) || (node.via_mqtt ? "MQTT" : "LoRa")),
    );
    body.appendChild(row);
    if (focusedNum !== undefined && row.dataset.num === focusedNum) row.focus({ preventScroll: true });
  }
}

const NODE_MT_FILTER_IDS = [
  "node-search",
  "node-role-filter",
  "node-via-filter",
  "node-hardware-filter",
  "node-channel-filter",
];

async function loadNodes(run) {
  const family = state.nodeFamily;
  const isMeshtastic = family === "mt";
  for (const id of NODE_MT_FILTER_IDS) $(id).hidden = !isMeshtastic;
  $("nodes-mt-table").hidden = !isMeshtastic;
  $("nodes-jraw-table").hidden = isMeshtastic;

  if (!isMeshtastic) {
    const kind = family === "mc" ? 1 : 2;
    const nodes = await fetchJson(run, `/api/jraw-nodes?kind=${kind}&limit=2000`);
    renderIfChanged("nodes", nodes, family, () => {
      state.jrawNodes = nodes;
      renderJrawNodes();
    });
    return;
  }

  const nodes = await fetchJson(run, "/api/nodes");
  renderIfChanged("nodes", nodes, "mt", () => {
    state.nodes = nodes;
    setNodeNames(nodes);
    populateNodeFilters();
    renderNodes();
  });
}

function jrawNodeTypeLabel(node) {
  if (node.kind === 1) return meshCoreNodeTypeLabel(node.node_type);
  return node.node_type == null ? node.kind_name : `${node.kind_name} type ${node.node_type}`;
}

/** Sort key for a MeshCore/Reticulum node; null sorts last in either direction. */
function jrawSortValue(node, key) {
  switch (key) {
    case "name": return node.name ? node.name.toLowerCase() : null;
    case "hash": return node.node_hash;
    case "type": return node.kind === 1 && node.node_type == null ? null : jrawNodeTypeLabel(node).toLowerCase();
    case "gateway": return (node.gateway_name || node.gateway_id || "").toLowerCase();
    case "frames": return Number(node.frames);
    case "first_heard": return Number(node.first_heard);
    case "position": return degreesPosition(node.latitude, node.longitude).state === "ok" ? Number(node.latitude) : null;
    case "key": return node.public_key || null;
    default: return Number(node.last_heard);
  }
}

function updateJrawSortHeaders() {
  for (const th of document.querySelectorAll("th[data-jsort]")) {
    const sorted = th.dataset.jsort === state.jrawSort;
    th.classList.toggle("sorted", sorted);
    th.classList.toggle("asc", sorted && state.jrawSortDir === "asc");
    th.setAttribute("aria-sort", !sorted ? "none" : state.jrawSortDir === "asc" ? "ascending" : "descending");
  }
}

function renderJrawNodes() {
  const direction = state.jrawSortDir === "asc" ? 1 : -1;
  const nodes = state.jrawNodes.slice().sort((left, right) => {
    const a = jrawSortValue(left, state.jrawSort);
    const b = jrawSortValue(right, state.jrawSort);
    if (a == null || b == null) return a == null && b == null ? 0 : a == null ? 1 : -1;
    return compareSortValues(a, b) * direction || Number(right.last_heard) - Number(left.last_heard);
  });
  updateJrawSortHeaders();
  const body = $("nodes-jraw-body");
  body.innerHTML = "";
  $("nodes-count").textContent = `${nodes.length} nodes`;
  if (!nodes.length) {
    const row = document.createElement("tr");
    const cell = element("td", "muted", "No nodes heard yet.");
    cell.colSpan = 9;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  for (const node of nodes) {
    const row = document.createElement("tr");
    // Advertised MeshCore nodes are keyed by their full public key.
    const shortHash = node.node_hash.length > 16 ? `${node.node_hash.slice(0, 8)}…` : node.node_hash;
    row.appendChild(element("td", "", node.name || shortHash));
    const hash = element("td", "mono", shortHash);
    hash.title = node.node_hash;
    row.appendChild(hash);
    row.appendChild(element("td", "", jrawNodeTypeLabel(node)));
    row.appendChild(element("td", "", node.gateway_name || node.gateway_id));
    row.appendChild(element("td", "num", fmtNum(node.frames)));
    row.appendChild(timeElement("td", "", node.first_heard));
    row.appendChild(timeElement("td", "", node.last_heard));
    const position = element("td", "");
    position.appendChild(degreesPositionContent(node.latitude, node.longitude));
    row.appendChild(position);
    row.appendChild(element("td", "mono", node.public_key ? `${node.public_key.slice(0, 16)}…` : "—"));
    body.appendChild(row);
  }
}

async function loadUiConfig(run) {
  if (!state.uiConfig) state.uiConfig = await fetchJson(run, "/api/config");
  return state.uiConfig;
}

let leafletLoading = null;

/** Load the vendored Leaflet only when the map is first opened. */
function loadLeaflet() {
  if (window.L) return Promise.resolve();
  if (!leafletLoading) {
    leafletLoading = new Promise((resolve, reject) => {
      const style = document.createElement("link");
      style.rel = "stylesheet";
      style.href = "/static/leaflet.css";
      document.head.appendChild(style);
      const script = document.createElement("script");
      script.src = "/static/leaflet.js";
      script.onload = () => resolve();
      script.onerror = () => {
        leafletLoading = null;
        reject(new Error("could not load the map library"));
      };
      document.head.appendChild(script);
    });
  }
  return leafletLoading;
}

const MAP_COLORS = { meshtastic: "#a6e3a1", repeater: "#89b4fa", room: "#cba6f7", meshcore: "#fab387" };
const mapView = { map: null, markers: null, entries: new Map(), fitted: false };

function mapEntryColor(entry) {
  if (entry.network === "meshtastic") return MAP_COLORS.meshtastic;
  if (entry.type === 2) return MAP_COLORS.repeater;
  if (entry.type === 3) return MAP_COLORS.room;
  return MAP_COLORS.meshcore;
}

/** Everything with a position, plus what could not be placed and why. */
function mapEntries(nodes, meshCoreNodes) {
  const placed = [];
  const invalid = [];
  let without = 0;
  const cutoff = state.mapMaxAge ? Date.now() / 1000 - Number(state.mapMaxAge) : 0;
  const consider = (entry, position) => {
    if (cutoff && Number(entry.lastHeard) < cutoff) return;
    if (position.state === "ok") placed.push({ ...entry, lat: Number(position.latitude), lon: Number(position.longitude), text: position.text });
    else if (position.state === "invalid") invalid.push(`${entry.name} (${position.text})`);
    else without += 1;
  };
  if (state.mapMeshtastic) {
    for (const node of nodes) {
      consider(
        { key: `mt:${node.num}`, network: "meshtastic", name: nodeLabel(node), id: shortId(node.num), num: node.num, lastHeard: node.last_heard, snr: node.snr, hops: node.hops_away, viaMqtt: node.via_mqtt },
        nodePosition(node),
      );
    }
  }
  if (state.mapMeshCore) {
    for (const node of meshCoreNodes) {
      // Rows without a public key are bare one-byte hashes, not known nodes.
      if (!node.public_key) continue;
      consider(
        { key: `mc:${node.node_hash}`, network: "meshcore", name: node.name || `${node.node_hash.slice(0, 8)}…`, id: `${node.public_key.slice(0, 8)}…`, type: node.node_type, lastHeard: node.last_heard },
        degreesPosition(node.latitude, node.longitude),
      );
    }
  }
  return { placed, invalid, without };
}

function mapPopup(entry) {
  const box = element("div", "map-popup");
  box.appendChild(element("strong", "", entry.name));
  const line = (label, value) => {
    const row = element("div", "");
    row.appendChild(element("span", "muted", `${label} `));
    row.appendChild(value instanceof Node ? value : textNode(value));
    box.appendChild(row);
  };
  line("network", entry.network === "meshtastic" ? "Meshtastic" : `MeshCore · ${meshCoreNodeTypeLabel(entry.type)}`);
  line("id", element("span", "mono", entry.id));
  line("position", entry.text);
  line("last heard", timeElement("span", "", entry.lastHeard));
  if (entry.network === "meshtastic") {
    if (entry.snr != null) line("SNR", fmtSnr(entry.snr));
    if (entry.hops != null) line("hops away", String(entry.hops));
    if (entry.viaMqtt) line("via", "MQTT");
    const details = element("button", "button", "Node details");
    details.type = "button";
    details.addEventListener("click", () => openNodeDialog(entry.num));
    box.appendChild(details);
  }
  return box;
}

/**
 * Zoom to where the nodes are. A few far-away positions (MQTT strays, typos)
 * would otherwise zoom the view out to a continent, so with enough nodes the
 * outermost 5% on each side are left outside the initial view; they stay on
 * the map.
 */
function fitMap() {
  const entries = [...mapView.entries.values()];
  if (!mapView.map || !entries.length) return;
  const range = (values) => {
    const sorted = values.slice().sort((a, b) => a - b);
    return entries.length < 20
      ? [sorted[0], sorted[sorted.length - 1]]
      : [percentile(sorted, 0.05), percentile(sorted, 0.95)];
  };
  const [south, north] = range(entries.map((entry) => entry.lat));
  const [west, east] = range(entries.map((entry) => entry.lon));
  mapView.map.fitBounds([[south, west], [north, east]], { padding: [30, 30], maxZoom: 13 });
  mapView.fitted = true;
}

function renderMap(entries) {
  const L = window.L;
  if (!mapView.map) {
    const config = state.uiConfig || {};
    mapView.map = L.map("map", { preferCanvas: true, worldCopyJump: true }).setView([20, 0], 2);
    if (config.map_tile_url) {
      L.tileLayer(config.map_tile_url, { attribution: clean(config.map_attribution || ""), maxZoom: 19 }).addTo(mapView.map);
    } else {
      $("map-note").textContent = "No tile source configured (web.map_tile_url): markers only.";
    }
    mapView.markers = L.layerGroup().addTo(mapView.map);
  }
  mapView.markers.clearLayers();
  mapView.entries = new Map(entries.map((entry) => [entry.key, entry]));
  for (const entry of entries) {
    const forwards = entry.network === "meshcore" && (entry.type === 2 || entry.type === 3);
    const marker = L.circleMarker([entry.lat, entry.lon], {
      radius: forwards ? 7 : 6,
      color: "#11111b",
      weight: 1,
      fillColor: mapEntryColor(entry),
      fillOpacity: 0.9,
    });
    marker.bindTooltip(clean(entry.name));
    // Built when opened, so it always shows the latest data for this node.
    marker.bindPopup(() => mapPopup(mapView.entries.get(entry.key) || entry));
    marker.addTo(mapView.markers);
  }
  if (!mapView.fitted) fitMap();
}

async function loadMap(run) {
  await loadUiConfig(run);
  await loadLeaflet();
  const [nodes, meshCoreNodes] = await Promise.all([
    state.mapMeshtastic ? fetchJson(run, "/api/nodes") : [],
    state.mapMeshCore ? fetchJson(run, "/api/jraw-nodes?kind=1&limit=2000") : [],
  ]);
  if (nodes.length) setNodeNames(nodes);
  const { placed, invalid, without } = mapEntries(nodes, meshCoreNodes);
  // Markers are only rebuilt when a node appears, disappears, moves or is
  // renamed, so an open popup survives ordinary polls.
  const shape = placed.map((entry) => [entry.key, entry.lat, entry.lon, entry.name, entry.type ?? null]);
  const rebuilt = renderIfChanged("map", shape, "", () => renderMap(placed));
  if (!rebuilt) mapView.entries = new Map(placed.map((entry) => [entry.key, entry]));
  mapView.map.invalidateSize();

  $("map-count").textContent = `${placed.length} on the map · ${without} without a position`;
  const bad = $("map-invalid");
  bad.hidden = !invalid.length;
  bad.textContent = `${invalid.length} with an invalid position`;
  bad.title = invalid.join("\n");
}

function fact(label, value) {
  const item = element("div", "fact");
  item.appendChild(document.createTextNode(label));
  item.appendChild(element("b", "", value));
  return item;
}

function renderNodeDetail(body, data) {
  const node = data.node;
  const facts = element("div", "node-facts");
  facts.appendChild(fact("Node ID", shortId(node.num)));
  facts.appendChild(fact("Long name", node.long_name || "—"));
  facts.appendChild(fact("Short name", node.short_name || "—"));
  facts.appendChild(fact("Hardware", node.hardware || "—"));
  facts.appendChild(fact("Role", nodeRoleLabel(node.role)));
  const heardFact = fact("Last heard", `${fmtAgo(node.last_heard)} · ${fmtTime(node.last_heard)}`);
  const heardProblem = node.last_heard ? timeProblem(node.last_heard) : null;
  if (heardProblem) {
    heardFact.lastChild.classList.add("bad-value");
    heardFact.title = `timestamp ${heardProblem}`;
  }
  facts.appendChild(heardFact);
  facts.appendChild(fact("SNR", fmtSnr(node.snr)));
  const detailHops = hopsInfo(node.hop_start, node.hop_limit);
  const hopsFact = fact("Hops", detailHops ? detailHops.text : "—");
  if (detailHops && detailHops.bad) {
    hopsFact.lastChild.classList.add("bad-value");
    hopsFact.title = detailHops.title;
  }
  facts.appendChild(hopsFact);
  facts.appendChild(fact("Channel", node.channel == null ? "—" : channelLabel(node.channel, node.channel_name)));
  facts.appendChild(fact("Gateways", gatewayLabels(node.gateways) || "—"));
  facts.appendChild(fact("Battery", node.battery_level == null ? "—" : `${node.battery_level}%`));
  facts.appendChild(fact("Voltage", node.voltage == null ? "—" : `${Number(node.voltage).toFixed(2)} V`));
  facts.appendChild(fact("Channel util", node.channel_utilization == null ? "—" : `${Number(node.channel_utilization).toFixed(1)}%`));
  facts.appendChild(fact("Air util TX", node.air_util_tx == null ? "—" : `${Number(node.air_util_tx).toFixed(1)}%`));
  facts.appendChild(fact("Via", node.via_mqtt ? "MQTT" : "LoRa"));
  facts.appendChild(fact("Source", node.source || "—"));
  facts.appendChild(fact("Public key", node.public_key ? `${node.public_key.slice(0, 16)}…` : "—"));
  const positionFact = element("div", "fact");
  positionFact.appendChild(document.createTextNode("Position"));
  const positionValue = element("b");
  positionValue.appendChild(positionContent(node));
  positionFact.appendChild(positionValue);
  facts.appendChild(positionFact);
  body.appendChild(facts);

  const signalHeading = element("h3", "", "Signal by source");
  signalHeading.style.fontSize = "14px";
  body.appendChild(signalHeading);
  const signalBody = element("div", "signal-body");
  body.appendChild(signalBody);
  loadNodeSignalGraph(signalBody, node.num);

  const heading = element("h3", "", `Packets sent (${data.packets.length})`);
  heading.style.fontSize = "14px";
  body.appendChild(heading);
  if (!data.packets.length) {
    body.appendChild(empty("No packets recorded for this node."));
    return;
  }
  const wrap = element("div", "table-wrap");
  const table = element("table", "detail-table");
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  for (const [label, className] of [
    ["Packet", ""], ["Port", ""], ["Contents", ""], ["Transport", ""], ["Channel", ""],
    ["Bytes", "num"], ["Hops", "num"], ["SNR", "num"], ["RSSI", "num"], ["Relay", ""], ["Via", ""], ["Time", ""],
  ]) {
    headRow.appendChild(element("th", className, label));
  }
  thead.appendChild(headRow);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const packet of data.packets) {
    const row = document.createElement("tr");
    row.appendChild(element("td", "mono", `#${packet.packet_id}`));
    const port = element("td", "", packet.portnum_name);
    if (packet.decrypted) port.appendChild(document.createTextNode(" · decrypted"));
    row.appendChild(port);
    const contents = element("td", packet.contents ? "packet-contents readable" : "packet-contents muted", packet.contents || "—");
    if (packet.contents) contents.title = packet.contents;
    row.appendChild(contents);
    row.appendChild(element("td", "", packet.transport_name));
    row.appendChild(element("td", "", channelLabel(packet.channel, packet.channel_name)));
    row.appendChild(element("td", "num", fmtBytes(packet.bytes)));
    // Hops used out of the hop limit the packet started with.
    const packetHops = hopsInfo(packet.hop_start, packet.hop_limit);
    row.appendChild(packetHops ? hopsElement("td", "num", packetHops) : element("td", "num muted", "—"));
    row.appendChild(element("td", "num", fmtSnr(packet.rx_snr)));
    row.appendChild(element("td", "num", fmtRssi(packet.rx_rssi)));
    row.appendChild(element("td", "mono", relayId(packet.relay_node) || "—"));
    row.appendChild(element("td", "", packet.via_mqtt ? "MQTT" : "LoRa"));
    row.appendChild(timeElement("td", "", packet.received_at));
    tbody.appendChild(row);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
  body.appendChild(wrap);
}

function svgElement(tag, attributes = {}) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
  return node;
}

function renderSignalTrack(svg, receptions, metric, label, color, top) {
  const chartLeft = 50;
  const chartRight = 510;
  const height = 38;
  const values = receptions.filter((reception) => reception[metric.key] != null);
  svg.appendChild(
    svgElement("text", { x: 8, y: top + 14, fill: color, "font-size": "10" }),
  ).textContent = label;
  if (!values.length) {
    svg.appendChild(
      svgElement("text", { x: chartLeft, y: top + 18, "font-size": "10" }),
    ).textContent = "no data";
    return;
  }

  const numericValues = values.map((reception) => Number(reception[metric.key]));
  let min;
  let max;
  let clipped = false;
  if (metric.centerZero) {
    const bound = Math.max(1, percentile(numericValues.map((value) => Math.abs(value)), 0.9));
    min = -bound;
    max = bound;
    clipped = numericValues.some((value) => Math.abs(value) > bound);
    metric.scaleBounds = { min, max, clipped };
  } else {
    min = Math.min(...numericValues);
    max = Math.max(...numericValues);
    if (min === max) {
      min -= 1;
      max += 1;
    }
  }
  const first = receptions[0].received_at;
  const last = receptions[receptions.length - 1].received_at;
  const span = Math.max(1, last - first);
  const points = values.map((reception) => {
    const x = chartLeft + ((reception.received_at - first) / span) * (chartRight - chartLeft);
    const value = Math.max(min, Math.min(max, Number(reception[metric.key])));
    const y = top + height - ((value - min) / (max - min)) * height;
    return [x, y, reception];
  });
  const path = points
    .map(([x, y], index) => `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`)
    .join(" ");
  svg.appendChild(
    svgElement("path", { d: path, fill: "none", stroke: color, "stroke-width": "1.8" }),
  );
  for (const [x, y, reception] of points) {
    const circle = svgElement("circle", { cx: x, cy: y, r: 2.4, fill: color });
    const title = svgElement("title");
    title.textContent = `${fmtTime(reception.received_at)} · ${metric.format(reception[metric.key])}`;
    circle.appendChild(title);
    svg.appendChild(circle);
  }
  svg.appendChild(
    svgElement("text", { x: chartLeft, y: top + 10, "font-size": "9" }),
  ).textContent = metric.format(max);
  svg.appendChild(
    svgElement("text", { x: chartLeft, y: top + height + 2, "font-size": "9" }),
  ).textContent = metric.format(min);
}

function renderSignalLegend(samples, metrics) {
  const legend = element("div", "signal-legend");
  for (const metric of metrics) {
    const values = samples
      .map((sample) => sample[metric.key])
      .filter((value) => value != null)
      .map(Number);
    if (!values.length) continue;
    const min = Math.min(...values);
    const max = Math.max(...values);
    const avg = values.reduce((sum, value) => sum + value, 0) / values.length;
    const stddev = Math.sqrt(
      values.reduce((sum, value) => sum + (value - avg) ** 2, 0) / values.length,
    );
    const last = values[values.length - 1];
    const entry = element("div", "legend-entry");
    const swatch = element("span", "legend-swatch");
    swatch.style.background = metric.color;
    entry.appendChild(swatch);
    entry.appendChild(element("span", "", metric.label));
    entry.appendChild(
      element(
        "span",
        "muted",
        `last ${metric.format(last)} · min ${metric.format(min)} · max ${metric.format(max)} · avg ${metric.format(avg)} · σ ${metric.format(stddev)}${metric.scaleBounds?.clipped ? ` · scale ±${metric.format(metric.scaleBounds.max)}` : ""}`,
      ),
    );
    legend.appendChild(entry);
  }
  return legend;
}

function renderNodeSignalGraph(container, receptions) {
  const groups = new Map();
  for (const reception of receptions) {
    const key = reception.receiver || "unknown";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(reception);
  }
  if (!groups.size) {
    container.appendChild(empty("No per-source signal history yet."));
    return;
  }

  for (const [receiver, sourceReceptions] of groups) {
    sourceReceptions.sort((left, right) => left.received_at - right.received_at);
    const block = element("div", "signal-source");
    const title = element("div", "signal-source-title");
    title.appendChild(element("strong", "", gatewayLabel(receiver)));
    title.appendChild(element("span", "muted", `${sourceReceptions.length} receptions`));
    block.appendChild(title);
    const svg = svgElement("svg", { class: "signal-chart", viewBox: "0 0 520 150" });
    const signalMetrics = SIGNAL_METRICS.map((metric) => ({ ...metric }));
    signalMetrics.forEach((metric, index) => {
      renderSignalTrack(svg, sourceReceptions, metric, metric.label, metric.color, 8 + index * 50);
    });
    block.appendChild(svg);
    const legend = renderSignalLegend(sourceReceptions, signalMetrics);
    if (legend.childElementCount) block.appendChild(legend);
    container.appendChild(block);
  }
}

async function loadNodeSignalGraph(container, nodeNum) {
  container.appendChild(empty("loading signal history…"));
  try {
    const receptions = await getJson(`/api/receptions?from_num=${encodeURIComponent(nodeNum)}&limit=1000`);
    container.innerHTML = "";
    renderNodeSignalGraph(container, receptions);
  } catch (error) {
    container.innerHTML = "";
    container.appendChild(empty(`could not load signal history: ${error.message}`));
  }
}

function renderNodeDialog(data) {
  $("node-dialog-title").textContent = nodeLabel(data.node);
  const body = $("node-dialog-body");
  body.innerHTML = "";
  renderNodeDetail(body, data);
}

/** The node-dialog request in flight; a newer click supersedes it. */
let nodeDialogRequest = null;

async function openNodeDialog(num) {
  if (nodeDialogRequest) nodeDialogRequest.abort();
  const controller = new AbortController();
  nodeDialogRequest = controller;
  const dialog = $("node-dialog");
  $("node-dialog-open").href = `/node/${encodeURIComponent(num)}`;
  try {
    const data = await getJson(`/api/nodes/${encodeURIComponent(num)}`, controller.signal);
    if (controller.signal.aborted) return;
    renderNodeDialog(data);
  } catch (error) {
    if (controller.signal.aborted) return;
    console.error(error);
    $("node-dialog-title").textContent = shortId(num);
    const body = $("node-dialog-body");
    body.innerHTML = "";
    const message = empty(`Could not load node ${shortId(num)}: ${error.message}`);
    message.classList.add("bad-value");
    message.setAttribute("role", "alert");
    body.appendChild(message);
  } finally {
    if (nodeDialogRequest === controller) nodeDialogRequest = null;
  }
  if (!dialog.open) dialog.showModal();
}

async function initNodePage(num) {
  document.body.classList.add("node-page");
  $("version").textContent = "node details";
  const main = document.querySelector("main");
  main.innerHTML = "";
  const section = element("section", "node-page-view");
  const head = element("div", "node-page-head");
  const title = element("h1", "", "Node details");
  const back = element("a", "button", "← Back to dashboard");
  back.href = "/";
  head.appendChild(title);
  head.appendChild(back);
  section.appendChild(head);
  const body = element("div");
  section.appendChild(body);
  main.appendChild(section);

  try {
    await loadNodeNames();
    const data = await getJson(`/api/nodes/${encodeURIComponent(num)}`);
    title.textContent = nodeLabel(data.node);
    renderNodeDetail(body, data);
  } catch (error) {
    body.appendChild(empty(`Could not load node: ${error.message}`));
  }
}

function renderRaw(frames) {
  const list = $("raw-list");
  list.innerHTML = "";
  $("raw-count").textContent = `${frames.length} shown`;
  if (!frames.length) {
    list.appendChild(empty("No raw frames yet."));
    return;
  }

  for (const frame of frames) {
    const card = element("div", "raw");
    const head = element("div", "head");
    head.appendChild(element("span", `kind ${frame.kind_name}`, frame.kind_name.toUpperCase()));
    const gateway = element("span", "", gatewayLabel(frame.gateway_id));
    gateway.title = frame.gateway_id;
    head.appendChild(gateway);
    head.appendChild(element("span", "muted", frame.source === "mqtt" ? "source MQTT" : "source PHY"));
    if (frame.decrypted) head.appendChild(decryptedTag());
    if (frame.source !== "mqtt" && frame.kind_name !== "meshtastic") {
      head.appendChild(element("span", "muted", `seq ${frame.sequence}`));
    }
    head.appendChild(timeElement("span", "time", frame.received_at));
    card.appendChild(head);

    const grid = element("div", "grid");
    const add = (label, value, problem = null) => {
      if (value === null || value === undefined || value === "") return;
      const item = element("div", problem ? "bad-value" : "");
      item.appendChild(element("b", "", `${label}: `));
      item.appendChild(value instanceof Node ? value : textNode(value));
      if (problem) item.title = problem;
      grid.appendChild(item);
    };
    add("length", `${frame.frame_len} B`);
    add("route", frame.route_name);
    add("payload", frame.payload_name);
    add("node", frame.node_name);
    const tracing = Boolean(frame.trace && frame.trace.length);
    if (tracing || (frame.path && frame.path.length)) {
      add(tracing ? "trace route" : "path", meshCorePathElement(frame));
    } else {
      add("path", frame.path_hex);
    }
    add("path hash size", frame.path_hash_size == null ? null : `${frame.path_hash_size} B`);
    add("node type", frame.node_type == null ? null : meshCoreNodeTypeLabel(frame.node_type));
    add("text", frame.payload_text);
    add("sender", frame.sender ? hashMatchElement(frame.sender) : frame.sender_hash);
    add("destination", frame.destination ? hashMatchElement(frame.destination) : frame.destination_hash);
    add("channel", frame.channel_hash == null ? null : meshCoreChannelElement(frame));
    if (frame.region_code != null) add("region", meshCoreRegionElement(frame));
    if (frame.latitude != null && frame.longitude != null) {
      const position = degreesPosition(frame.latitude, frame.longitude);
      add("position", degreesPositionContent(frame.latitude, frame.longitude), position.state === "invalid" ? "coordinates out of range" : null);
    }
    if (frame.sent_at != null) {
      const sentProblem = rxTimeProblem(frame.sent_at, frame.received_at);
      add("sender clock", fmtTime(frame.sent_at), sentProblem ? `timestamp ${sentProblem}` : null);
    }
    add("RSSI", fmtRssi(frame.rx_rssi));
    add("SNR", fmtSnr(frame.rx_snr));
    add("Δf", frame.frequency_error == null ? null : `${Math.round(Number(frame.frequency_error))} Hz`);
    add("CR", frame.coding_rate == null ? null : Number(frame.coding_rate) + 4);
    const frameRxProblem = rxTimeProblem(frame.rx_time, null);
    add("rx time", fmtTime(frame.rx_time), frameRxProblem ? `timestamp ${frameRxProblem}` : null);
    if (frame.public_key) add("public key", `${frame.public_key.slice(0, 16)}…`);
    card.appendChild(grid);

    const details = document.createElement("details");
    details.appendChild(element("summary", "", "raw hex"));
    details.appendChild(element("code", "hex", frame.frame_hex));
    card.appendChild(details);
    list.appendChild(card);
  }
}

async function loadRaw(run) {
  await loadNodeNames(run);
  const kind = state.rawKind;
  const query = kind === "" ? "" : `?kind=${encodeURIComponent(kind)}`;
  const frames = await fetchJson(run, `/api/raw${query}`);
  renderIfChanged("raw", frames, `${kind}|${state.nodeNamesVersion}`, () => renderRaw(frames));
}

function renderRecentReceptions(receptions) {
  const list = $("receptions-list");
  list.innerHTML = "";
  $("receptions-count").textContent = `${receptions.length} shown`;
  if (!receptions.length) {
    list.appendChild(empty("No packet receptions yet."));
    return;
  }
  for (const reception of receptions) {
    const card = element("div", "raw");
    const head = element("div", "head");
    head.appendChild(element("span", "kind jencore", `#${reception.packet_id}`));
    head.appendChild(element("span", "mono", shortId(reception.from_num)));
    const receiver = element("span", "muted", gatewayLabel(reception.receiver));
    if (reception.receiver) receiver.title = reception.receiver;
    head.appendChild(receiver);
    head.appendChild(element("span", "muted", reception.source));
    if (reception.decrypted) head.appendChild(decryptedTag());
    head.appendChild(timeElement("span", "time", reception.received_at));
    card.appendChild(head);

    const grid = element("div", "grid");
    const add = (label, value, problem = null) => {
      if (value === null || value === undefined || value === "") return;
      const item = element("div", problem ? "bad-value" : "");
      item.appendChild(element("b", "", `${label}: `));
      item.appendChild(value instanceof Node ? value : textNode(value));
      if (problem) item.title = problem;
      grid.appendChild(item);
    };
    add("channel", channelLabel(reception.channel, reception.channel_name));
    add("relay", reception.relay_node ? relayId(reception.relay_node) : null);
    add("SNR", fmtSnr(reception.rx_snr));
    add("RSSI", fmtRssi(reception.rx_rssi));
    add("Δf", reception.rx_frequency_error == null ? null : `${Math.round(Number(reception.rx_frequency_error))} Hz`);
    add("CR", reception.rx_coding_rate == null ? null : Number(reception.rx_coding_rate) + 4);
    const receptionHops = hopsInfo(reception.hop_start, reception.hop_limit);
    if (receptionHops) add("hops", receptionHops.text, receptionHops.bad ? receptionHops.title : null);
    const receptionRxProblem = rxTimeProblem(reception.rx_time, reception.received_at);
    add("rx time", fmtTime(reception.rx_time), receptionRxProblem ? `timestamp ${receptionRxProblem}` : null);
    card.appendChild(grid);
    list.appendChild(card);
  }
}

async function loadReceptions(run) {
  await loadNodeNames(run);
  const receptions = await fetchJson(run, "/api/receptions?limit=200");
  renderIfChanged("receptions", receptions, String(state.nodeNamesVersion), () =>
    renderRecentReceptions(receptions),
  );
}

/**
 * The refresh in flight, if any: { tab, controller, signal, promise }.
 * Every load for the dashboard goes through one run at a time. A forced
 * refresh (tab switch, filter change, Refresh button) aborts the run in flight
 * and starts its own, so it is never dropped and a superseded run can never
 * render. Requests time out (FETCH_TIMEOUT_MS), so a run always ends.
 */
let currentRun = null;

function refreshActive(force = false) {
  if (currentRun) {
    if (!force) return currentRun.promise;
    currentRun.controller.abort();
  }
  const controller = new AbortController();
  const run = { tab: state.tab, controller, signal: controller.signal, promise: null };
  currentRun = run;
  run.promise = runRefresh(run, force).finally(() => {
    if (currentRun === run) currentRun = null;
  });
  return run.promise;
}

/** An expanded <details> in the tab would be lost by rebuilding its list. */
function tabHasOpenDetails(tab) {
  return Boolean(document.querySelector(`#tab-${tab} details[open]`));
}

function setRefreshPaused(paused) {
  $("refresh-paused").hidden = !paused;
}

async function runRefresh(run, force) {
  const tab = run.tab;
  // Keep expanded details open across the auto-refresh: the tab body is left
  // alone, but the status header still updates and the footer says so.
  const paused = !force && tabHasOpenDetails(tab);
  try {
    if (!paused && ((tab === "stats" && state.statsFamily === "mt") || tab === "channels")) {
      const data = await fetchJson(run, "/api/stats");
      renderStatus(data.status);
      if (tab === "stats") {
        renderIfChanged("stats", data.stats, "", () => renderStats(data.stats));
      } else {
        const channels = data.stats.channels;
        renderIfChanged("channels", channels, "", () => renderChannels(channels));
      }
    } else {
      const status = await fetchJson(run, "/api/status");
      renderStatus(status);
      if (paused) {
        // Body intentionally not refreshed.
      } else if (tab === "stats") {
        await loadJrawStats(run);
      } else if (tab === "chat") {
        await loadChat(run);
      } else if (tab === "nodes") {
        await loadNodes(run);
      } else if (tab === "map") {
        await loadMap(run);
      } else if (tab === "packets") {
        await loadPackets(run);
      } else if (tab === "raw") {
        await loadRaw(run);
      } else if (tab === "receptions") {
        await loadReceptions(run);
      } else if (tab === "traces") {
        await loadTraces(run);
      } else if (tab === "sources") {
        const sources = status.sources || [];
        renderIfChanged("sources", sources, "", () => renderSources(sources));
      }
    }
    if (run.signal.aborted) return;
    setRefreshPaused(paused);
    refreshAgoLabels();
    $("last-refresh").textContent = `updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    // A superseded run is not an error; its successor reports the outcome.
    if (run.signal.aborted) return;
    console.error(error);
    $("last-refresh").textContent = `error: ${error.message}`;
  }
}

function selectTab(tab) {
  state.tab = tab;
  for (const button of document.querySelectorAll("#tabs button")) {
    button.classList.toggle("active", button.dataset.tab === tab);
    button.setAttribute("aria-selected", button.dataset.tab === tab ? "true" : "false");
  }
  for (const panel of document.querySelectorAll(".panel")) {
    panel.classList.toggle("active", panel.id === `tab-${tab}`);
  }
  refreshActive(true);
}

function bind() {
  for (const button of document.querySelectorAll("#tabs button")) {
    button.addEventListener("click", () => selectTab(button.dataset.tab));
  }
  // Each toolbar belongs to the active tab, so every control forces a refresh
  // of that tab; the forced run supersedes whatever was in flight.
  $("chat-channel").addEventListener("change", (event) => {
    state.channel = event.target.value;
    refreshActive(true);
  });
  $("raw-kind").addEventListener("change", (event) => {
    state.rawKind = event.target.value;
    refreshActive(true);
  });
  for (const id of [
    "chat-refresh",
    "raw-refresh",
    "receptions-refresh",
    "traces-refresh",
    "channels-refresh",
    "sources-refresh",
    "packet-refresh",
  ]) {
    $(id).addEventListener("click", () => refreshActive(true));
  }
  for (const [id, key] of [
    ["jraw-payload", "jrawPayload"],
    ["jraw-route", "jrawRoute"],
    ["jraw-channel", "jrawChannel"],
    ["jraw-decrypted", "jrawDecrypted"],
    ["jraw-region", "jrawRegion"],
  ]) {
    $(id).addEventListener("change", (event) => {
      state[key] = event.target.value;
      refreshActive(true);
    });
  }
  let jrawSearchTimer = 0;
  $("jraw-search").addEventListener("input", (event) => {
    state.jrawSearch = event.target.value;
    clearTimeout(jrawSearchTimer);
    jrawSearchTimer = setTimeout(() => refreshActive(true), 2 * SEARCH_DEBOUNCE_MS);
  });
  // Payload and route numbers mean different things per network.
  $("packet-family").addEventListener("change", () => {
    for (const key of ["jrawPayload", "jrawRoute", "jrawChannel", "jrawDecrypted", "jrawRegion", "jrawSearch"]) state[key] = "";
    $("jraw-search").value = "";
    $("jraw-decrypted").value = "";
  });
  for (const [id, key] of [
    ["packet-family", "packetFamily"],
    ["packet-protocol", "packetProtocol"],
    ["packet-channel", "packetChannel"],
    ["packet-gateway", "packetGateway"],
    ["packet-source", "packetSource"],
    ["packet-decrypted", "packetDecrypted"],
  ]) {
    $(id).addEventListener("change", (event) => {
      state[key] = event.target.value;
      refreshActive(true);
    });
  }
  for (const [id, key] of [
    ["map-meshtastic", "mapMeshtastic"],
    ["map-meshcore", "mapMeshCore"],
  ]) {
    $(id).addEventListener("change", (event) => {
      state[key] = event.target.checked;
      refreshActive(true);
    });
  }
  $("map-max-age").addEventListener("change", (event) => {
    state.mapMaxAge = event.target.value;
    refreshActive(true);
  });
  $("map-fit").addEventListener("click", fitMap);
  for (const button of document.querySelectorAll("#stats-family button")) {
    button.addEventListener("click", () => {
      state.statsFamily = button.dataset.family;
      showStatsFamily();
      refreshActive(true);
    });
  }
  for (const header of document.querySelectorAll("th[data-jsort]")) {
    const sortBy = () => {
      const key = header.dataset.jsort;
      if (state.jrawSort === key) {
        state.jrawSortDir = state.jrawSortDir === "asc" ? "desc" : "asc";
      } else {
        state.jrawSort = key;
        state.jrawSortDir = ["last_heard", "first_heard", "frames"].includes(key) ? "desc" : "asc";
      }
      renderJrawNodes();
    };
    header.tabIndex = 0;
    header.addEventListener("click", sortBy);
    header.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      sortBy();
    });
  }
  updateJrawSortHeaders();
  $("node-family").addEventListener("change", (event) => {
    state.nodeFamily = event.target.value;
    refreshActive(true);
  });
  let searchTimer = 0;
  $("node-search").addEventListener("input", (event) => {
    state.nodeSearch = event.target.value;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(renderNodes, SEARCH_DEBOUNCE_MS);
  });
  $("node-role-filter").addEventListener("change", (event) => {
    state.nodeRole = event.target.value;
    renderNodes();
  });
  $("node-via-filter").addEventListener("change", (event) => {
    state.nodeVia = event.target.value;
    renderNodes();
  });
  $("node-hardware-filter").addEventListener("change", (event) => {
    state.nodeHardware = event.target.value;
    renderNodes();
  });
  $("node-channel-filter").addEventListener("change", (event) => {
    state.nodeChannel = event.target.value;
    renderNodes();
  });
  for (const header of document.querySelectorAll("th[data-sort]")) {
    const sortBy = () => {
      const key = header.dataset.sort;
      if (state.nodeSort === key) {
        state.nodeSortDir = state.nodeSortDir === "asc" ? "desc" : "asc";
      } else {
        state.nodeSort = key;
        state.nodeSortDir = ["last_heard", "snr", "hops", "battery"].includes(key) ? "desc" : "asc";
      }
      renderNodes();
    };
    header.tabIndex = 0;
    header.addEventListener("click", sortBy);
    header.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      sortBy();
    });
  }
  updateNodeSortHeaders();
  $("node-dialog-close").addEventListener("click", () => $("node-dialog").close());
  // No polling while the page is hidden; catch up as soon as it is shown again.
  setInterval(() => {
    if (!document.hidden && $("auto-refresh").checked) refreshActive();
  }, POLL_INTERVAL_MS);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && $("auto-refresh").checked) refreshActive();
  });
}

const nodePageMatch = location.pathname.match(/^\/node\/(\d+)\/?$/);
if (nodePageMatch) {
  initNodePage(Number(nodePageMatch[1]));
} else {
  bind();
  refreshActive();
}
