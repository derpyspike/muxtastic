# Web UI and SQLite history

`muxtastic-web` is a separate crate that serves a small tabbed dashboard and
records mesh history in a normal SQLite file. It is wired into the daemon but
does not affect the protocol, routing or MQTT paths if disabled.

## Configuration

```toml
[web]
enabled = true
host = "127.0.0.1"          # loopback by default
port = 8080
database = "data/muxtastic.db"
retention_days = 7          # 0 = keep packet history forever
```

Legacy YAML uses the same `web:` section. The database directory is created on
startup. `database = ":memory:"` is accepted but history is then lost when the
daemon stops. Set `enabled = false` for a headless daemon.

The UI has no authentication. It binds to loopback by default; if you expose it
to a network, put it behind a reverse proxy with authentication or a firewall.

## MQTT source mode

By default the dashboard is fed by the mux's physical-node connection. An
optional read-only MQTT source can feed the same database too, either as a
standalone viewer (`--web-only`) or alongside the normal physical nodes:

```toml
[web.mqtt]
enabled = true
broker = "mqtt.meshtastic.org"
port = 8883
tls = true
username = ""
password = ""
client_id = "muxtastic-webd"
topics = ["msh/#", "raw/#", "jencore/#", "jenrnode/#"]
keepalive = 60
```

```bash
muxtastic --web-only --config configs/config.yaml
```

With `--web-only`, Muxtastic does **not** open a physical node, start the mux
TCP server, run the MQTT bridge, provision a node or announce mDNS. It only runs
SQLite, the web server and the MQTT source. The status pills show the node as
offline and MQTT as connected.

Without `--web-only`, the same source runs next to the physical nodes when
`[web.mqtt].enabled = true`. It is read-only, adds MQTT-only nodes to the UI,
and skips packets whose gateway id belongs to one of the local physical nodes,
so the local MQTT bridges do not duplicate history already captured over LoRa.

Ingestion rules:

- `msh/#` and `raw/#`: decoded as `ServiceEnvelope` protobufs; the contained
  `MeshPacket` is recorded as packets/messages/nodes.
- `msh/{region}/2/e/{channel}/...`: the channel name is recorded so the Chat
  filter uses readable names. Packet channel indexes are bucketed from a stable
  hash of the channel name because the local index is not meaningful across
  brokers.
- `jencore/#` and `jenrnode/#`: the payload is stored as a reassembled raw frame
  (`raw_frames`), using the `!nodeid` topic suffix as the gateway.
- Retained messages are skipped to avoid replaying stale history.
- The source never publishes, so it cannot create MQTT loops.

Limitations:

- Only packets that are decoded on the broker can populate Chat/Nodes;
  encrypted traffic will not produce text.
- Nexus `Δf`/`CR` are not carried by the standard MQTT mirror (the mux loses the
  unknown fields when decoding), so MQTT-sourced receptions show them as
  unavailable. Physical receptions keep the firmware values when present.
- Raw-frame RSSI/SNR and sequence metadata are not present on the raw feed
  topics, so MQTT-sourced raw rows show `source MQTT` and omit those fields.
- The packet's own `via_mqtt` flag is preserved as received. The separate
  `source` column records how the row entered this database (`physical`, `mqtt`
  or `client`).

## Extra channel decryption

Opaque packets can be decoded with extra channel keys stored in the web config:

```toml
[[web.extra_channels]]
name = "Madrid"
key = "AQ=="

[[web.extra_channels]]
name = "*"
key = "AQ=="
```

Keys are base64 PSKs. One-byte keys use the Meshtastic default-key shorthand
(`AQ==` is the default key); 16-byte and 32-byte keys are used directly. Named
channels are tried only when the packet's channel hash matches that name + key.
A `*` name is a wildcard: its key is tried against any packet, and a successful
decode is labelled `*-0xNN` from the one-byte PSK (for example `*-0x01`). Extra
channels are tried in config order.

Set `try_all_one_byte_keys = true` under `[web]` to append wildcard entries for
all 255 non-zero one-byte PSKs (`0x01..=0xff`) after the configured channels.
They are tried sequentially and labelled `*-0x01` through `*-0xff`. Classic AES-CTR channel encryption is
attempted; AEAD-only channel packets are left opaque.

Successful decodes are stored as normal decoded packets, so they appear in
Chat, Nodes, Channels, Receptions and the raw Meshtastic feed with the extra
channel name and a `decrypted` marker. The Mesh Stats page has a separate
`Decrypted` count.

## Connected node header

The header shows one card per physical node, to the right of the Muxtastic
brand and left of the status pills, with:

- the short-name badge, coloured with the last 24 bits of the node number as
  RGB (the same scheme Meshtastic uses), with black/white contrast chosen from
  the colour luminance;
- the node long name;
- a `connected`, `waiting for node info` or `offline` state pill.

The node cards stay on one horizontally scrollable row; long names truncate with
the full name in a tooltip. Full details (instance/port, firmware, PlatformIO
environment, hardware model, LoRa settings and region) are available in the
Sources tab. With a multi-node
`[[nodes]]` config there is one card per node in that row; the SQLite history
and aggregate statistics are shared across them. In `--web-only` mode there is
no local node, so the row is hidden.

## Tabs

- **Mesh Stats** — total packets, messages, nodes, payload bytes, raw frames,
  receptions and multi-heard packets; per-hour packet/byte counts for the last
  hour; a 24-hour packet chart; channel-mix and portnum pie charts; portnum,
  transport, channel and top-sender breakdowns with percentages; separate cards for the
  `via_mqtt` flag, broker-sourced packets and reception totals. Decoded, opaque,
  decrypted and PKI packet counts are separate; opaque channel hashes use synthetic
  channel ids above the configured channels. Except for the transport
  breakdown, packets whose transport is `TRANSPORT_INTERNAL` are excluded from
  the aggregate stats.
- **Chat** — text-message log with sender, channel, timestamps, SNR/RSSI, hops,
  MQTT markers, the relay node and the Nexus-only `Δf` (Hz) and `CR`
  diagnostics when the firmware reports them. The relay node is displayed as
  its low byte (`0xNN`), matching the firmware's usual 1-byte relay field. When
  a packet was heard by a gateway, an expandable “heard by N gateways” section
  lists every receiver with its own SNR, RSSI, `Δf`, `CR`, relay node and hop
  data. The channel dropdown filters the log. Packets decoded with an extra
  channel key show a `decrypted` marker.
- **Nodes** — known nodes with name, id, hardware, last-heard channel,
  `used_hops/hop_start`, battery, role, position and hearing gateways. Filter
  by role/source/hardware/channel, sort by any column (default last heard; hops
  sorts by used hops), and click a row for a detail dialog with all node facts
  and its packet table. The dialog has an **Open in new tab** link to the
  standalone `/node/{num}` view.
- **Packets** — protocol-oriented packet table with time, sender/recipient,
  portnum, text contents, channel, hearing gateways, bytes, RF metrics, source
  and decryption state. Filter by protocol, canonical channel, gateway, source
  and decrypted/not decrypted.
- **Channels** — per-channel packet count, payload bytes, packets/h, bytes/h and
  percentage of all packets, with an expandable node breakdown ordered by
  packet count.
- **Raw feeds** — reassembled Nexus `JRAW` frames plus a Meshtastic packet feed.
  Type 1 (JenCore/MeshCore) shows route, payload type, path hashes,
  sender/destination hashes and ADVERT name/public key when present; type 2
  (JenRNode/Reticulum) shows the raw payload; type 3 (Meshtastic) shows the
  encoded `MeshPacket` and portnum. Each row has expandable hex, shows
  `Δf`/`CR` when present, and marks frames decoded with an extra key.
- **Receptions** — recent per-gateway packet observations with receiver,
  packet/from ids, relay node, source, SNR, RSSI, `Δf`, `CR`, hops, receive
  time and a `decrypted` marker.
- **Traces** — recent traceroutes as dropdowns. Each opens horizontal direct
  and back-route graphs with hop node IDs and per-hop SNR when present; a
  `decrypted` marker identifies traces recovered with an extra key.
- **Sources** — all configured physical links and MQTT sources (including the
  read-only MQTT source) rendered like the node header: colour badge, long
  name, firmware/LoRa/hardware details, endpoint, connected/offline state,
  topics and the virtual mux `host:port`. Physical sources keep their node
  identity. Local MQTT bridges sharing a broker endpoint are merged into one
  `MQTT` source card instead of repeating each physical node; its expandable
  gateways list shows every local node uplinking through it plus every gateway
  seen in MQTT-sourced packets, with name, packet count and last-heard time.
  Each physical source has expandable direct-node and connected-client lists;
  clients show peer IP:port, connected/idle time and RX/TX bytes/frame counts.

Gateway ids are resolved to a node name whenever the node is known; the raw
`!hex` id is only shown when the node has never been heard. This applies to the
Nodes table, node details, receptions, traceroutes, raw frames and the MQTT
gateway list.

Channel names are scoped to the receiving node. Each physical/MQTT gateway has
its own `receiver + channel index` map, because nodes may have the same index
assigned to different channel names or a different order. The resolved name is
stored on each packet/message/reception: different names at the same index stay
separate, while the same name at different indexes is one logical channel.
Channels without a known name fall back to `#index`, `Opaque 0xNN` or `PKI`.

The page polls `/api/stats` every 3 seconds and refreshes the active tab. The
status pills show physical link, MQTT state, connected clients and uptime.

## HTTP API

| Endpoint | Description |
|---|---|
| `GET /` | Dashboard |
| `GET /static/app.js` | Dashboard script |
| `GET /static/style.css` | Dashboard styles |
| `GET /api/stats` | Live status, node cards, physical/MQTT sources, rates, percentages, channel/node breakdowns and channel list |
| `GET /api/messages?channel=<name\|#index>&limit=200` | Text messages, newest first |
| `GET /api/nodes` | Known nodes with hardware |
| `GET /api/nodes/{num}` | One node plus its recent packet rows |
| `GET /node/{num}` | Standalone full-page node detail view |
| `GET /api/raw?kind=1\|2\|3&limit=200` | Reassembled JRAW or Meshtastic raw frames |
| `GET /api/channels` | Channels seen in packet history |
| `GET /api/receptions?limit=200` | Recent per-gateway receptions |
| `GET /api/traceroutes?limit=200` | Recent direct/back traceroutes |
| `GET /api/direct-nodes?receiver=!hex&limit=200` | Zero-hop nodes heard directly by one physical source |
| `GET /api/packets?portnum=N&channel=<name\|#index>&gateway=!hex&source=physical&decrypted=true&limit=500` | Filtered packet list |
| `GET /api/packet-filters` | Protocol and gateway options/counts for the Packets tab |
| `GET /api/mqtt-gateways?limit=500` | Gateways seen in MQTT-sourced packets/raw frames |
| `GET /api/receptions?from_num=N&packet_id=N` | Per-gateway receptions for one packet |

All responses are JSON except `/` and the static assets.

## Database

The file is ordinary SQLite (WAL mode). While the daemon runs:

```bash
sqlite3 data/muxtastic.db
```

Tables:

| Table | Contents |
|---|---|
| `packets` | One summary row per Meshtastic packet, deduplicated on `(from_num, packet_id)` when the id is non-zero (id, from/to, relay node, local channel index, resolved `channel_name`, `decrypted` flag, portnum, payload `bytes`, transport, via_mqtt, ingestion `source`, reception/gateway counts, best SNR/RSSI, RF/hops, Nexus `rx_frequency_error`/`rx_coding_rate`, received_at) |
| `packet_receptions` | One row per receiver/gateway that heard a packet: local channel index, resolved `channel_name`, `decrypted` flag, receiver id, relay node, source, RSSI, SNR, hop data, Nexus `Δf`/`CR` when available, rx_time and received_at |
| `messages` | Text messages, deduplicated on `(from_num, packet_id)` when the id is non-zero; local channel index, resolved `channel_name`, ingestion source and Nexus diagnostics |
| `nodes` | Latest known node identity, RF metrics, battery, position, public key and latest ingestion source |
| `channels` | Global channel index/name fallback |
| `node_channels` | Per-receiver channel index/name map (since schema v9) |
| `raw_frames` | Reassembled JRAW frames plus Meshtastic packet protobufs, kind/source, gateway, sequence, frame blob, MeshCore header fields, Nexus diagnostics and RF metrics |
| `traceroutes` | Traceroute responses with direct `route`/`snr_towards` and back `route_back`/`snr_back` JSON arrays |

The `bytes` column is the decoded payload length (or encrypted payload length
for encrypted packets). `relay_node` is stored raw; the UI shows its low byte
(`0xNN`) because Meshtastic normally uses a 1-byte relay value. Hourly packet/byte
counts use the last 3600 seconds, while the table and pie percentages are
all-time totals.

Configured channels keep ids `0..=255`. Opaque channel hashes are stored at
`256 + hash` and PKI packets use channel `512`, so they never merge with
configured channels in stats or filters. Crystal-clear (decoded) packets have a
portnum; opaque packets have `portnum = NULL`.

`web.retention_days` (default `7`, `0` disables) prunes `packets`, `messages`,
`packet_receptions`, `raw_frames` and `traceroutes` older than the window.
Nodes and channels are kept.

Example:

```sql
SELECT channel, COUNT(*) FROM packets GROUP BY channel ORDER BY 2 DESC;
SELECT from_num, text, datetime(rx_time, 'unixepoch') FROM messages ORDER BY id DESC LIMIT 20;
SELECT num, long_name, last_heard, battery_level FROM nodes ORDER BY last_heard DESC;
SELECT kind, route_name, payload_name, length(frame) FROM raw_frames ORDER BY id DESC LIMIT 20;
```

Packet-derived history is pruned automatically after `web.retention_days`
(default `7`; set `0` to keep everything). The cleanup removes old packets,
messages, receptions, raw frames and traceroutes while leaving nodes and
channels.

## Ingestion

The physical read loop feeds every parsed `FromRadio` frame into the database
through a bounded queue and a single writer task. Nexus JRAW chunks are skipped
in the packet table; the shared assembler in `AppState` reassembles them once
and the completed frame is stored in `raw_frames`. Client messages echoed for
web/UI visibility are recorded too, with `source='client'`; duplicate packets
are ignored by the unique `(from_num, packet_id)` index when the id is non-zero,
and duplicate text messages are suppressed the same way.

Each real reception is also written to `packet_receptions`, keyed by
`(from_num, packet_id, receiver)`. The local node is the receiver for the
physical path; MQTT receptions use the envelope's `gateway_id` (falling back to
the topic suffix). With multiple physical nodes the shared tables aggregate
their traffic; the receiver id distinguishes which physical node heard a
packet. The packet summary is updated with reception/gateway counts
and best SNR/RSSI. A client echo has no reception row, so it cannot inflate the
gateway count; if the physical reception arrives afterwards, the summary and
message row are updated with the real RF values.

## Code map

- `crates/muxtastic-web/src/db.rs` — schema, queue writer, queries and types.
- `crates/muxtastic-web/src/mqtt_source.rs` — read-only broker ingestion for
  `--web-only` or alongside the physical nodes.
- `crates/muxtastic-web/src/server.rs` — Axum router, JSON API and assets.
- `crates/muxtastic-web/src/static/` — embedded HTML, CSS and JavaScript.
- `crates/muxtastic/src/app.rs` — database handle, raw-tunnel assembler, uptime.
- `crates/muxtastic/src/main.rs` — opens the database, starts the writer and web
  server, and builds the live status callback.
- `crates/muxtastic/src/physical.rs` — records frames and completed raw frames.
