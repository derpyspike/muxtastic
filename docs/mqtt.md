# MQTT bridge

Muxtastic can publish mesh traffic to a primary MQTT broker and, optionally, a
second broker. Both legs share one client id and are driven by the same mux
process; the radio node is untouched (except for the opt-in provisioning step).
In a multi-node `[[nodes]]` config each node has its own `[nodes.mqtt_bridge]`
and its own bridge instance, so client ids and gateway ids use that node's
number.

```
LoRa mesh ◄──► physical node
                    │ PhoneAPI over serial/TCP
                    ▼
             ┌───────────────┐
             │ muxtastic     │
             │  primary leg ─┼──► <primary-broker>
             │  secondary leg┼──► <secondary-broker> (optional)
             └───────────────┘
```

## Fan-out rules

| Path | Trigger | Primary | Secondary |
|---|---|---|---|
| Proxy relay | `mqttClientProxyMessage` from the node or a client | topic + payload verbatim | same |
| Standard mirror | known channel + `standard_mirror_active()` + LoRa transport | `msh/{region}/2/e/{channel}/!{gateway}` with `channel_id` set | same |
| Raw gateway | per-leg `raw_uplink` + per-leg scope (`uncovered` or `all`) + LoRa transport | `raw/{region}/!{sender}` | same rule, evaluated independently |
| JenCore raw feed | reassembled JRAW type 1 + `jencore_raw_uplink` | `jencore/{region}/!{gateway}` raw frame bytes | same |
| JenRNode raw feed | reassembled JRAW type 2 + `jenrnode_raw_uplink` | `jenrnode/{region}/!{gateway}` raw frame bytes | same |
| Downlink | broker message when `downlink_enabled=true` | never sent to a broker | never |

Shared gates: packets with `via_mqtt=true` and non-LoRa transports
(`transport_mechanism` outside `1..=4`) are skipped on the raw and mirror paths.
Proxy relay is independent of the raw/mirror flags. Proxy publishes also require
`uplink_enabled=true` and, unless `ignore_ok_to_mqtt=true`, the `uplink_enabled`
flag of the channel the message belongs to. The channel is taken from the
envelope's `channel_id`, or from the topic (`msh/{region}/2/e/{channel}/...`);
a channel the node does not list by that name is allowed.

Proxy messages sent by a connected client are never published as retained, and
a proxy topic outside `{root_topic}/` is placed under it.

The bridge connects once the physical node has reported its node number, and
never publishes with a placeholder id. Until then the bridge is idle.

Region resolution: explicit `region` > region learned from a proxy topic >
`EU_868`.

## Configuration

```toml
[mqtt_bridge]
enabled = true
broker = "mqtt.meshtastic.org"
port = 8883
tls = true
username = ""
password = ""
uplink_enabled = true
downlink_enabled = false
ignore_ok_to_mqtt = false
mqtt_username = ""          # client-id: mux-v{ver}-{mqtt_username}-{nodehex}
root_topic = "msh"
raw_root_topic = "raw"
region = ""                 # empty = auto
raw_uplink = false
raw_scope = "uncovered"     # uncovered | all
standard_mirror = "auto"    # auto | on | off

# Nexus RAW_TUNNEL feeds (independent of raw_uplink/standard_mirror):
jencore_raw_uplink = false
jenrnode_raw_uplink = false
jencore_root_topic = "jencore"
jenrnode_root_topic = "jenrnode"

keepalive = 60

# Optional second broker:
# [mqtt_bridge.broker2]
# enabled = true
# broker = ""
# port = 8883
# tls = true
# username = ""
# password = ""
# keepalive = 60
# raw_uplink = false
# raw_scope = "uncovered"
```

The legacy YAML keys are identical (`mqtt_bridge`, `broker2`, ...). Credentials
belong only in a gitignored local config file and are never logged.

## Identity

Both legs share one derived id per bridge instance:

```
with mqtt_username:    mux-v{ver}-{mqtt_username}-{nodehex}   (stable)
without (per boot):    mux-v{ver}-{nodehex}-{uuid12}
```

The id is sanitized to printable ASCII and capped at 32 characters. The
username is budgeted so the node id is never truncated. Sharing one id is safe
because the legs never point at the same `host:port`; if a config repeats the
primary broker, the secondary leg is disabled with a warning.

Some community brokers have rejected computer sessions with
`Not authorized`. If the secondary leg flaps with that error, set
`broker2.enabled=false` and restart; do not retry blindly.

## Provisioning

When the bridge is enabled, Muxtastic attempts once per boot to make the local
node ready:

1. Query `moduleConfig.mqtt`.
2. If `enabled` and (when needed) `proxy_to_client_enabled` are already true,
   stop.
3. Otherwise send `begin_edit_settings`, `set_module_config` (only flipping the
   missing flags), and `commit_edit_settings`.
4. Re-query up to three times to verify.

Network-capable nodes (`hasWifi` or `hasEthernet`) use the `mqtt-only` profile:
only `enabled` is managed and the proxy flag is never touched. Other nodes use
the `full` profile and may get both flags. Address, username, password, root
topic and channels are copied verbatim and never modified.

## Downlink safety

A broker message is injected into the node as an `mqttClientProxyMessage` only
when `downlink_enabled=true`. Before injecting, Muxtastic:

- validates the topic is under `msh/` or `raw/`;
- suppresses messages it just published (topic + payload hash, 30 s window);
- skips retained messages;
- drops envelopes whose `gateway_id` is our own node id.

The primary leg subscribes to `msh/#` and `raw/#` even when downlink is
disabled; inbound messages are then dropped.

## Nexus raw feeds (JRAW)

The Nexus firmware can forward raw MeshCore and RNode/Reticulum frames to the
phone API when `FEATURE_RAW_TUNNEL_TO_PHONE` is enabled. Each frame arrives as a
`MeshPacket` with the **encrypted** payload variant and a 9-byte header:

```
"JRAW" | version(1) | type(1=MeshCore, 2=RNode) | seq | chunk index | chunk count | data
```

Frames up to 247 bytes use one chunk; 248–494 bytes use two. Muxtastic detects
these packets, reassembles the chunks (5 s window, keyed by type + sequence) and
publishes the **reassembled raw frame bytes** on the feed topics:

```
jencore/{region}/!{gatewayhex}    # type 1: full MeshCore/JenCore frame
jenrnode/{region}/!{gatewayhex}   # type 2: RNode/Reticulum payload
```

- The gateway id is the enclosing `MeshPacket.from`: the local node that heard
  the frame. The original sender is inside the raw frame.
- The payload is the raw frame only (no JRAW header). The feed is lossless for
  the frame itself; RSSI/SNR metadata is not included.
- The feeds are independent of `raw_uplink`, `raw_scope` and
  `standard_mirror`. Enable each one with `jencore_raw_uplink` /
  `jenrnode_raw_uplink`; change the topic roots with `jencore_root_topic` /
  `jenrnode_root_topic`.
- The feeds fan out to the secondary broker like other uplinks.
- The Nexus-only `rx_frequency_error` and `rx_coding_rate` fields are not in
  the upstream protobuf used by Muxtastic, so they are not exposed here.
- Inbound raw injection (publishing a raw frame that the mux hands back to the
  node) is not implemented; downlink still uses `mqttClientProxyMessage`.

## Per-packet dedupe

- Gateway packet ids are remembered for 60 s; a duplicate within that window is
  skipped.
- Proxy packet ids are remembered for 60 s and drive `raw_scope=uncovered`.
- The standard mirror skips ids already published by the proxy path.
- The caches are bounded (500 ids / 200 recent publishes) and pruned by age.

## Verification

Watch the periodic stats line:

```
MQTT bridge stats: connected=true published=… gateway=… standard=…
jencore_raw=… jenrnode_raw=… dropped_uplink=… dropped_downlink=…
loop_guard=… echo=… published2=… dropped2=…
```

`published` and `published2` climbing together means both brokers are receiving
traffic. `dropped2` climbing alone means the secondary is unreachable while the
primary is fine.

## Failure modes

| Symptom | Meaning | Action |
|---|---|---|
| `secondary connection lost (Not authorized)` | broker rejected the session | set `broker2.enabled=false`, restart |
| `secondary not connected; dropping mirror` at boot | transient connect race | normal, resolves after the connect |
| `dropped2` climbing, primary fine | secondary unreachable | investigate the LAN→WAN path |
| No standard mirror | channel unknown, `standard_mirror=off`, or brokers match in `auto` | use `on` or check the channel config |
| Provisioning `verify read-back mismatch` | node did not persist the flags | inspect the node-side MQTT config |

## Code map

- `crates/muxtastic-core/src/mqtt.rs` — topics, region, identity, coverage,
  broker overlap, dedupe windows, envelope helpers.
- `crates/muxtastic-core/src/provision.rs` — admin message builders and flag
  matching.
- `crates/muxtastic-core/src/raw_tunnel.rs` — JRAW detection, reassembly and
  feed topics.
- `crates/muxtastic/src/mqtt.rs` — two `rumqttc` legs, fan-out, downlink,
  stats.
- `crates/muxtastic/src/provision.rs` — query/set/commit/verify flow.
