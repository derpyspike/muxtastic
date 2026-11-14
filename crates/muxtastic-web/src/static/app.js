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
  nodeNames: new Map(),
  packetProtocol: "",
  packetChannel: "",
  packetGateway: "",
  packetSource: "",
  packetDecrypted: "",
  refreshing: false,
};

const $ = (id) => document.getElementById(id);

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
  if (text !== undefined) node.textContent = text;
  return node;
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

function fmtAgo(seconds) {
  if (!seconds) return "—";
  const diff = Math.max(0, Date.now() / 1000 - Number(seconds));
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function fmtSnr(value) {
  return value == null ? "—" : `${Number(value).toFixed(1)} dB`;
}

function fmtRssi(value) {
  return value == null ? "—" : `${value} dBm`;
}

function fmtCoord(value) {
  return value == null ? null : (Number(value) * 1e-7).toFixed(5);
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

async function getJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
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
  renderNodeStrips(status.nodes || []);
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

function renderHourly(buckets) {
  const container = $("hourly");
  container.innerHTML = "";
  const max = Math.max(1, ...buckets.map((bucket) => bucket.count));
  const total = buckets.reduce((sum, bucket) => sum + bucket.count, 0);
  $("hourly-total").textContent = `${fmtNum(total)} packets`;

  const row = element("div", "bars-row");
  for (const bucket of buckets) {
    const bar = element("div", "bar");
    const fill = element("span");
    fill.style.height = `${Math.max(2, (bucket.count / max) * 100)}%`;
    const label = `${fmtNum(bucket.count)} packets · ${new Date(bucket.hour_start * 1000).toLocaleString()}`;
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

const PIE_COLORS = ["#b4befe", "#89b4fa", "#f9e2af", "#cba6f7", "#f38ba8", "#74c7ec", "#fab387", "#89dceb"];

function renderPie(pieId, legendId, totalId, buckets, labelFor, total, emptyText, showCount = true) {
  const pie = $(pieId);
  const legend = $(legendId);
  legend.innerHTML = "";
  if (totalId) $(totalId).textContent = `${fmtNum(total)} packets`;

  const data = buckets.filter((bucket) => bucket.count > 0);
  if (!data.length) {
    pie.style.background = "var(--panel-2)";
    legend.appendChild(empty(emptyText));
    return;
  }

  const stops = [];
  let angle = 0;
  data.forEach((bucket, index) => {
    const start = angle;
    angle += bucket.percent * 3.6;
    stops.push(`${PIE_COLORS[index % PIE_COLORS.length]} ${start.toFixed(2)}deg ${angle.toFixed(2)}deg`);
  });
  pie.style.background = `conic-gradient(${stops.join(",")})`;

  data.forEach((bucket, index) => {
    const entry = element("div", "entry");
    const swatch = element("span", "swatch");
    swatch.style.background = PIE_COLORS[index % PIE_COLORS.length];
    entry.appendChild(swatch);
    entry.appendChild(element("span", "", labelFor(bucket)));
    entry.appendChild(element("b", "", fmtPercent(bucket.percent)));
    if (showCount) entry.appendChild(element("span", "", `${fmtNum(bucket.count)} pkts`));
    legend.appendChild(entry);
  });
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

function renderPortnumPie(portnums) {
  const total = portnums.reduce((sum, bucket) => sum + bucket.count, 0);
  renderPie(
    "portnum-pie",
    "portnum-pie-legend",
    "portnum-pie-total",
    portnums,
    (bucket) => bucket.label,
    total,
    "No decoded packets yet.",
    false,
  );
}

function renderStats(data) {
  renderStatus(data.status);
  const totals = data.stats.totals;
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
  renderPortnumPie(data.stats.portnums);
  renderCounts("portnums", data.stats.portnums);
  renderCounts("transports", data.stats.transports);
  renderStatChannels(data.stats.channels);
  renderTopNodes(data.stats.top_nodes);
}

function renderChannels(channels) {
  const list = $("channels-list");
  list.innerHTML = "";
  const total = channels.reduce((sum, channel) => sum + channel.count, 0);
  $("channels-summary").textContent = `${channels.length} channels · ${fmtNum(total)} packets · last hour`;

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

function traceNodeLabel(num) {
  return state.nodeNames.get(Number(num)) || shortId(num);
}

function renderTraceGraph(container, title, start, route, end, snrs) {
  const block = element("div");
  block.appendChild(element("div", "trace-graph-title", title));
  const graph = element("div", "trace-graph");
  const nodes = [start, ...route, end].filter((node, index, all) => index === 0 || node !== all[index - 1]);
  if (!nodes.length) {
    block.appendChild(element("div", "trace-empty", "No route recorded."));
    container.appendChild(block);
    return;
  }
  nodes.forEach((node, index) => {
    if (index > 0) {
      const link = element("div", "trace-link");
      link.appendChild(element("span", "arrow", "→"));
      if (snrs && snrs[index - 1] != null) link.appendChild(element("span", "", traceSnr(snrs[index - 1])));
      graph.appendChild(link);
    }
    const classes = ["trace-node"];
    if (index === 0) classes.push("start");
    if (index === nodes.length - 1) classes.push("end");
    const box = element("div", classes.join(" "), traceNodeLabel(node));
    box.title = shortId(node);
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
    summary.appendChild(element("b", "", `${traceNodeLabel(trace.from_num)} → ${traceNodeLabel(trace.to_num)}`));
    summary.appendChild(element("span", "", `${fmtAgo(trace.received_at)}`));
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
    renderTraceGraph(graphs, "Direct route", trace.from_num, trace.route, trace.to_num, trace.snr_towards);
    if (trace.route_back.length) {
      renderTraceGraph(graphs, "Back route", trace.to_num, trace.route_back, trace.from_num, trace.snr_back);
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

async function loadNodeNames() {
  const nodes = await getJson("/api/nodes");
  state.nodeNames = new Map(nodes.map((node) => [Number(node.num), nodeLabel(node)]));
  return nodes;
}

async function loadTraces() {
  await loadNodeNames();
  const traces = await getJson("/api/traceroutes?limit=200");
  renderTraces(traces);
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
      item.appendChild(document.createTextNode(String(value)));
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
    const time = element("td", "", fmtAgo(node.last_heard));
    time.title = fmtTime(node.last_heard);
    row.appendChild(time);
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
    head.appendChild(element("span", "sender", message.sender || shortId(message.from_num)));
    head.appendChild(element("span", "chan", channelLabel(message.channel, message.channel_name)));
    const time = element("span", "time", fmtAgo(message.rx_time || message.received_at));
    time.title = fmtTime(message.rx_time || message.received_at);
    head.appendChild(time);
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
    if (message.hop_start != null && message.hop_limit != null) {
      meta.appendChild(element("span", "", `hops ${message.hop_start - message.hop_limit}/${message.hop_start}`));
    }
    if (message.relay_node) meta.appendChild(element("span", "", `relay ${relayId(message.relay_node)}`));
    if (message.source === "mqtt") meta.appendChild(element("span", "", "source MQTT"));
    if (message.source === "client") meta.appendChild(element("span", "", "source client"));
    if (message.via_mqtt) meta.appendChild(element("span", "", "via MQTT"));
    if (message.decrypted) meta.appendChild(decryptedTag());
    if (message.reception_count > 0) {
      const best = message.best_snr == null ? "" : ` · best ${fmtSnr(message.best_snr)}`;
      meta.appendChild(element("span", "", `${message.gateway_count} gateway${message.gateway_count === 1 ? "" : "s"}${best}`));
    }
    card.appendChild(meta);

    if (message.reception_count > 0) {
      const details = document.createElement("details");
      details.className = "receptions";
      details.appendChild(element("summary", "", `heard by ${message.gateway_count} gateway${message.gateway_count === 1 ? "" : "s"}`));
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
    const time = element("span", "time", fmtAgo(reception.received_at));
    time.title = fmtTime(reception.received_at);
    head.appendChild(time);
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
    if (reception.hop_start != null && reception.hop_limit != null) {
      meta.appendChild(element("span", "", `hops ${reception.hop_start - reception.hop_limit}/${reception.hop_start}`));
    }
    if (reception.relay_node) meta.appendChild(element("span", "", `relay ${relayId(reception.relay_node)}`));
    row.appendChild(meta);
    container.appendChild(row);
  }
}

function fillChannelSelect(select, current, channels) {
  select.innerHTML = "";
  const all = element("option", "", "All channels");
  all.value = "";
  select.appendChild(all);
  for (const channel of channels) {
    const option = element("option", "", channelLabel(channel.channel, channel.name));
    option.value = channel.key || channelKey(channel.channel, channel.name);
    select.appendChild(option);
  }
  select.value = current;
}

async function loadChannels() {
  const channels = await getJson("/api/channels");
  fillChannelSelect($("chat-channel"), state.channel, channels);
  fillChannelSelect($("packet-channel"), state.packetChannel, channels);
}

function fillFilterSelect(select, current, allLabel, options) {
  select.innerHTML = "";
  const all = element("option", "", allLabel);
  all.value = "";
  select.appendChild(all);
  for (const option of options) {
    const item = element("option", "", `${option.label} (${fmtNum(option.count)})`);
    item.value = option.value;
    select.appendChild(item);
  }
  select.value = current;
}

async function loadPackets() {
  await loadNodeNames();
  await loadChannels();
  const filters = await getJson("/api/packet-filters");
  fillFilterSelect($("packet-protocol"), state.packetProtocol, "All protocols", filters.portnums);
  fillFilterSelect($("packet-gateway"), state.packetGateway, "All gateways", filters.gateways);

  const params = new URLSearchParams({ limit: "500" });
  if (state.packetProtocol) params.set("portnum", state.packetProtocol);
  if (state.packetChannel) params.set("channel", state.packetChannel);
  if (state.packetGateway) params.set("gateway", state.packetGateway);
  if (state.packetSource) params.set("source", state.packetSource);
  if (state.packetDecrypted) params.set("decrypted", state.packetDecrypted);
  const packets = await getJson(`/api/packets?${params}`);
  renderPackets(packets);
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
    const time = element("td", "", fmtAgo(packet.received_at));
    time.title = `${fmtTime(packet.received_at)} · #${packet.packet_id}`;
    row.appendChild(time);

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

async function loadChat() {
  await loadNodeNames();
  const query = state.channel === "" ? "" : `?channel=${encodeURIComponent(state.channel)}`;
  const messages = await getJson(`/api/messages${query}`);
  renderMessages(messages);
}

function nodeRoleLabel(role) {
  return ROLE_NAMES[role] || (role == null ? "—" : `Role ${role}`);
}

function usedHops(node) {
  if (node.hop_start == null || node.hop_limit == null) return null;
  return Math.max(0, Number(node.hop_start) - Number(node.hop_limit));
}

function nodeSortValue(node, key) {
  switch (key) {
    case "name": return nodeLabel(node).toLowerCase();
    case "id": return (node.node_id || shortId(node.num)).toLowerCase();
    case "last_heard": return Number(node.last_heard ?? 0);
    case "snr": return node.snr == null ? Number.NEGATIVE_INFINITY : Number(node.snr);
    case "hops": return usedHops(node) ?? Number.NEGATIVE_INFINITY;
    case "battery": return node.battery_level == null ? Number.NEGATIVE_INFINITY : Number(node.battery_level);
    case "role": return nodeRoleLabel(node.role).toLowerCase();
    case "hardware": return (node.hardware || "").toLowerCase();
    case "channel": return node.channel == null ? Number.NEGATIVE_INFINITY : Number(node.channel);
    case "position": return node.latitude_i != null && node.longitude_i != null ? 1 : 0;
    case "via": return (node.gateways || "").toLowerCase();
    default: return 0;
  }
}

function updateNodeSortHeaders() {
  for (const th of document.querySelectorAll("th[data-sort]")) {
    th.classList.toggle("sorted", th.dataset.sort === state.nodeSort);
    th.classList.toggle("asc", th.dataset.sort === state.nodeSort && state.nodeSortDir === "asc");
  }
}

function populateNodeFilters() {
  const roleSelect = $("node-role-filter");
  const currentRole = state.nodeRole;
  const roles = [...new Set(state.nodes.map((node) => node.role).filter((role) => role != null))].sort((a, b) => a - b);
  roleSelect.innerHTML = '<option value="">All roles</option>';
  for (const role of roles) {
    const option = element("option", "", nodeRoleLabel(role));
    option.value = String(role);
    roleSelect.appendChild(option);
  }
  roleSelect.value = currentRole;

  const hardwareSelect = $("node-hardware-filter");
  const currentHardware = state.nodeHardware;
  const hardware = [...new Set(state.nodes.map((node) => node.hardware).filter((value) => value && value !== "UNKNOWN"))].sort();
  hardwareSelect.innerHTML = '<option value="">All hardware</option>';
  for (const value of hardware) {
    const option = element("option", "", value);
    option.value = value;
    hardwareSelect.appendChild(option);
  }
  hardwareSelect.value = currentHardware;

  const channelSelect = $("node-channel-filter");
  const currentChannel = state.nodeChannel;
  const channels = new Map();
  for (const node of state.nodes) {
    if (node.channel == null) continue;
    const key = channelKey(node.channel, node.channel_name);
    if (!channels.has(key)) channels.set(key, channelLabel(node.channel, node.channel_name));
  }
  channelSelect.innerHTML = '<option value="">All channels</option>';
  for (const [value, label] of [...channels.entries()].sort((left, right) => Number(left[0]) - Number(right[0]))) {
    const option = element("option", "", label);
    option.value = value;
    channelSelect.appendChild(option);
  }
  channelSelect.value = currentChannel;
}

function renderNodes() {
  const body = $("nodes-body");
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
    const a = nodeSortValue(left, state.nodeSort);
    const b = nodeSortValue(right, state.nodeSort);
    let result;
    if (typeof a === "string" || typeof b === "string") result = String(a).localeCompare(String(b));
    else result = Number(a) - Number(b);
    if (result === 0) result = Number(left.num) - Number(right.num);
    return state.nodeSortDir === "asc" ? result : -result;
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
    row.addEventListener("click", (event) => {
      if (event.target.closest("a")) return;
      openNodeDialog(node.num);
    });
    row.appendChild(element("td", "", nodeLabel(node)));
    row.appendChild(element("td", "mono", node.node_id || shortId(node.num)));
    const heard = element("td", "", fmtAgo(node.last_heard));
    heard.title = fmtTime(node.last_heard);
    row.appendChild(heard);
    row.appendChild(element("td", "num", fmtSnr(node.snr)));
    const hops = usedHops(node);
    row.appendChild(element("td", "num", hops == null ? "—" : `${hops}/${node.hop_start}`));
    row.appendChild(element("td", "num", node.battery_level == null ? "—" : `${node.battery_level}%`));
    row.appendChild(element("td", "", nodeRoleLabel(node.role)));
    row.appendChild(element("td", "muted", node.hardware || "—"));
    row.appendChild(element("td", "", node.channel == null ? "—" : channelLabel(node.channel, node.channel_name)));

    const position = element("td", "");
    const latitude = fmtCoord(node.latitude_i);
    const longitude = fmtCoord(node.longitude_i);
    if (latitude && longitude) {
      const link = element("a", "", `${latitude}, ${longitude}`);
      link.href = `https://www.openstreetmap.org/?mlat=${latitude}&mlon=${longitude}#map=15/${latitude}/${longitude}`;
      link.target = "_blank";
      link.rel = "noreferrer";
      position.appendChild(link);
    } else {
      position.textContent = "—";
    }
    row.appendChild(position);
    row.appendChild(
      element("td", "", gatewayLabels(node.gateways) || (node.via_mqtt ? "MQTT" : "LoRa")),
    );
    body.appendChild(row);
  }
}

async function loadNodes() {
  state.nodes = await loadNodeNames();
  populateNodeFilters();
  renderNodes();
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
  facts.appendChild(fact("Last heard", `${fmtAgo(node.last_heard)} · ${fmtTime(node.last_heard)}`));
  facts.appendChild(fact("SNR", fmtSnr(node.snr)));
  const detailHops = usedHops(node);
  facts.appendChild(fact("Hops", detailHops == null ? "—" : `${detailHops}/${node.hop_start}`));
  facts.appendChild(fact("Channel", node.channel == null ? "—" : channelLabel(node.channel, node.channel_name)));
  facts.appendChild(fact("Gateways", gatewayLabels(node.gateways) || "—"));
  facts.appendChild(fact("Battery", node.battery_level == null ? "—" : `${node.battery_level}%`));
  facts.appendChild(fact("Voltage", node.voltage == null ? "—" : `${Number(node.voltage).toFixed(2)} V`));
  facts.appendChild(fact("Channel util", node.channel_utilization == null ? "—" : `${Number(node.channel_utilization).toFixed(1)}%`));
  facts.appendChild(fact("Air util TX", node.air_util_tx == null ? "—" : `${Number(node.air_util_tx).toFixed(1)}%`));
  facts.appendChild(fact("Via", node.via_mqtt ? "MQTT" : "LoRa"));
  facts.appendChild(fact("Source", node.source || "—"));
  facts.appendChild(fact("Public key", node.public_key ? `${node.public_key.slice(0, 16)}…` : "—"));
  const latitude = fmtCoord(node.latitude_i);
  const longitude = fmtCoord(node.longitude_i);
  const positionFact = element("div", "fact");
  positionFact.appendChild(document.createTextNode("Position"));
  const positionValue = element("b");
  if (latitude && longitude) {
    const link = element("a", "", `${latitude}, ${longitude}`);
    link.href = `https://www.openstreetmap.org/?mlat=${latitude}&mlon=${longitude}#map=15/${latitude}/${longitude}`;
    link.target = "_blank";
    link.rel = "noreferrer";
    positionValue.appendChild(link);
  } else {
    positionValue.textContent = "—";
  }
  positionFact.appendChild(positionValue);
  facts.appendChild(positionFact);
  body.appendChild(facts);

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
    ["Packet", ""], ["Port", ""], ["Transport", ""], ["Channel", ""],
    ["Bytes", "num"], ["SNR", "num"], ["RSSI", "num"], ["Relay", ""], ["Via", ""], ["Time", ""],
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
    row.appendChild(element("td", "", packet.transport_name));
    row.appendChild(element("td", "", channelLabel(packet.channel, packet.channel_name)));
    row.appendChild(element("td", "num", fmtBytes(packet.bytes)));
    row.appendChild(element("td", "num", fmtSnr(packet.rx_snr)));
    row.appendChild(element("td", "num", fmtRssi(packet.rx_rssi)));
    row.appendChild(element("td", "mono", relayId(packet.relay_node) || "—"));
    row.appendChild(element("td", "", packet.via_mqtt ? "MQTT" : "LoRa"));
    const time = element("td", "", fmtAgo(packet.received_at));
    time.title = fmtTime(packet.received_at);
    row.appendChild(time);
    tbody.appendChild(row);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
  body.appendChild(wrap);
}

function renderNodeDialog(data) {
  $("node-dialog-title").textContent = nodeLabel(data.node);
  const body = $("node-dialog-body");
  body.innerHTML = "";
  renderNodeDetail(body, data);
}

async function openNodeDialog(num) {
  try {
    const data = await getJson(`/api/nodes/${encodeURIComponent(num)}`);
    $("node-dialog-open").href = `/node/${encodeURIComponent(num)}`;
    renderNodeDialog(data);
    $("node-dialog").showModal();
  } catch (error) {
    console.error(error);
  }
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
    const time = element("span", "time", fmtAgo(frame.received_at));
    time.title = fmtTime(frame.received_at);
    head.appendChild(time);
    card.appendChild(head);

    const grid = element("div", "grid");
    const add = (label, value) => {
      if (value === null || value === undefined || value === "") return;
      const item = element("div");
      item.appendChild(element("b", "", `${label}: `));
      item.appendChild(document.createTextNode(String(value)));
      grid.appendChild(item);
    };
    add("length", `${frame.frame_len} B`);
    add("route", frame.route_name);
    add("payload", frame.payload_name);
    add("node", frame.node_name);
    add("path", frame.path_hex);
    add("sender", frame.sender_hash);
    add("destination", frame.destination_hash);
    add("channel hash", frame.channel_hash == null ? null : `0x${Number(frame.channel_hash).toString(16).padStart(2, "0")}`);
    add("RSSI", fmtRssi(frame.rx_rssi));
    add("SNR", fmtSnr(frame.rx_snr));
    add("Δf", frame.frequency_error == null ? null : `${Math.round(Number(frame.frequency_error))} Hz`);
    add("CR", frame.coding_rate == null ? null : Number(frame.coding_rate) + 4);
    add("rx time", fmtTime(frame.rx_time));
    if (frame.public_key) add("public key", `${frame.public_key.slice(0, 16)}…`);
    card.appendChild(grid);

    const details = document.createElement("details");
    details.appendChild(element("summary", "", "raw hex"));
    details.appendChild(element("code", "hex", frame.frame_hex));
    card.appendChild(details);
    list.appendChild(card);
  }
}

async function loadRaw() {
  await loadNodeNames();
  const query = state.rawKind === "" ? "" : `?kind=${encodeURIComponent(state.rawKind)}`;
  const frames = await getJson(`/api/raw${query}`);
  renderRaw(frames);
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
    const time = element("span", "time", fmtAgo(reception.received_at));
    time.title = fmtTime(reception.received_at);
    head.appendChild(time);
    card.appendChild(head);

    const grid = element("div", "grid");
    const add = (label, value) => {
      if (value === null || value === undefined || value === "") return;
      const item = element("div");
      item.appendChild(element("b", "", `${label}: `));
      item.appendChild(document.createTextNode(String(value)));
      grid.appendChild(item);
    };
    add("channel", channelLabel(reception.channel, reception.channel_name));
    add("relay", reception.relay_node ? relayId(reception.relay_node) : null);
    add("SNR", fmtSnr(reception.rx_snr));
    add("RSSI", fmtRssi(reception.rx_rssi));
    add("Δf", reception.rx_frequency_error == null ? null : `${Math.round(Number(reception.rx_frequency_error))} Hz`);
    add("CR", reception.rx_coding_rate == null ? null : Number(reception.rx_coding_rate) + 4);
    if (reception.hop_start != null && reception.hop_limit != null) {
      add("hops", `${reception.hop_start - reception.hop_limit}/${reception.hop_start}`);
    }
    add("rx time", fmtTime(reception.rx_time));
    card.appendChild(grid);
    list.appendChild(card);
  }
}

async function loadReceptions() {
  await loadNodeNames();
  const receptions = await getJson("/api/receptions?limit=200");
  renderRecentReceptions(receptions);
}

async function refreshActive(force = false) {
  if (state.refreshing) return;
  // Keep expanded details open across the 3 s auto-refresh.
  if (!force && state.tab === "chat" && document.querySelector("#chat-list details[open]")) return;
  if (!force && state.tab === "channels" && document.querySelector("#channels-list details[open]")) return;
  if (!force && state.tab === "sources" && document.querySelector("#sources-list details[open]")) return;
  if (!force && state.tab === "traces" && document.querySelector("#traces-list details[open]")) return;
  state.refreshing = true;
  try {
    const data = await getJson("/api/stats");
    renderStatus(data.status);
    if (state.tab === "stats") {
      renderStats(data);
    } else if (state.tab === "chat") {
      await loadChannels();
      await loadChat();
    } else if (state.tab === "nodes") {
      await loadNodes();
    } else if (state.tab === "packets") {
      await loadPackets();
    } else if (state.tab === "channels") {
      renderChannels(data.stats.channels);
    } else if (state.tab === "raw") {
      await loadRaw();
    } else if (state.tab === "receptions") {
      await loadReceptions();
    } else if (state.tab === "traces") {
      await loadTraces();
    } else if (state.tab === "sources") {
      renderSources(data.status.sources || []);
    }
    $("last-refresh").textContent = `updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    console.error(error);
    $("last-refresh").textContent = `error: ${error.message}`;
  } finally {
    state.refreshing = false;
  }
}

function selectTab(tab) {
  state.tab = tab;
  for (const button of document.querySelectorAll("#tabs button")) {
    button.classList.toggle("active", button.dataset.tab === tab);
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
  $("chat-channel").addEventListener("change", (event) => {
    state.channel = event.target.value;
    loadChat();
  });
  $("chat-refresh").addEventListener("click", loadChat);
  $("raw-kind").addEventListener("change", (event) => {
    state.rawKind = event.target.value;
    loadRaw();
  });
  $("raw-refresh").addEventListener("click", loadRaw);
  $("receptions-refresh").addEventListener("click", loadReceptions);
  $("traces-refresh").addEventListener("click", loadTraces);
  $("channels-refresh").addEventListener("click", () => refreshActive(true));
  $("sources-refresh").addEventListener("click", () => refreshActive(true));
  for (const [id, key] of [
    ["packet-protocol", "packetProtocol"],
    ["packet-channel", "packetChannel"],
    ["packet-gateway", "packetGateway"],
    ["packet-source", "packetSource"],
    ["packet-decrypted", "packetDecrypted"],
  ]) {
    $(id).addEventListener("change", (event) => {
      state[key] = event.target.value;
      loadPackets();
    });
  }
  $("packet-refresh").addEventListener("click", loadPackets);
  $("node-search").addEventListener("input", (event) => {
    state.nodeSearch = event.target.value;
    renderNodes();
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
    header.addEventListener("click", () => {
      const key = header.dataset.sort;
      if (state.nodeSort === key) {
        state.nodeSortDir = state.nodeSortDir === "asc" ? "desc" : "asc";
      } else {
        state.nodeSort = key;
        state.nodeSortDir = ["last_heard", "snr", "hops", "battery"].includes(key) ? "desc" : "asc";
      }
      renderNodes();
    });
  }
  $("node-dialog-close").addEventListener("click", () => $("node-dialog").close());
  setInterval(() => {
    if ($("auto-refresh").checked) refreshActive();
  }, 3000);
}

const nodePageMatch = location.pathname.match(/^\/node\/(\d+)\/?$/);
if (nodePageMatch) {
  initNodePage(Number(nodePageMatch[1]));
} else {
  bind();
  refreshActive();
}
