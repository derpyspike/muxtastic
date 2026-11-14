//! Human-readable details for the connected physical node.
//!
//! The frequency calculation mirrors the Meshtastic firmware's
//! `RadioInterface::applyModemConfig`: region band, channel hash, preset or
//! manual modem parameters, `override_frequency`, then `frequency_offset`.

use meshtastic::protobufs as pb;
use serde::Serialize;

use crate::state::StateCache;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NodeDetails {
    pub node_num: u32,
    pub long_name: String,
    pub short_name: String,
    pub firmware_version: String,
    pub pio_env: String,
    pub hw_model: String,
    pub lora: Option<LoraDetails>,
    pub color: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LoraDetails {
    pub summary: String,
    pub spread_factor: u32,
    pub bandwidth_khz: f32,
    pub coding_rate: u32,
    pub frequency_mhz: Option<f32>,
    pub channel_num: Option<u32>,
    pub region: String,
    pub preset: Option<String>,
}

/// Build the header snapshot from the state cache, if a node identity exists.
pub fn node_details(cache: &StateCache) -> Option<NodeDetails> {
    let node_info = cache.node_info.as_ref()?;
    let user = node_info.user.as_ref()?;
    let node_num = if cache.my_node_num != 0 {
        cache.my_node_num
    } else {
        node_info.num
    };

    let long_name = non_empty(&user.long_name)
        .or_else(|| non_empty(&user.short_name))
        .unwrap_or_else(|| format!("!{node_num:08x}"));
    let short_name =
        non_empty(&user.short_name).unwrap_or_else(|| format!("{:04X}", node_num & 0xFFFF));

    let metadata = cache.metadata.as_ref();
    let firmware_version = metadata
        .and_then(|metadata| non_empty(&metadata.firmware_version))
        .unwrap_or_else(|| "unknown".to_owned());
    let pio_env = cache
        .my_info
        .as_ref()
        .and_then(|my_info| non_empty(&my_info.pio_env))
        .unwrap_or_else(|| "unknown".to_owned());

    let hw_model = metadata
        .map(|metadata| metadata.hw_model)
        .filter(|value| *value != 0)
        .unwrap_or(user.hw_model);
    let hw_model = pb::HardwareModel::try_from(hw_model)
        .map(|model| model.as_str_name().to_owned())
        .unwrap_or_else(|_| format!("HW_{hw_model}"));

    let lora = cache
        .lora_config
        .as_ref()
        .map(|lora| lora_details(lora, primary_channel_name(cache)));

    Some(NodeDetails {
        node_num,
        long_name,
        short_name,
        firmware_version,
        pio_env,
        hw_model,
        lora,
        color: node_color(node_num),
    })
}

/// Meshtastic node colour: the last 24 bits of the node number as RGB.
pub fn node_color(node_num: u32) -> String {
    format!("#{:06x}", node_num & 0x00FF_FFFF)
}

pub fn lora_details(lora: &pb::config::LoRaConfig, channel_name: &str) -> LoraDetails {
    let (bandwidth_khz, spread_factor, mut coding_rate, preset) = if lora.use_preset {
        preset_params(lora.modem_preset)
    } else {
        (
            bandwidth_code_to_khz(lora.bandwidth),
            if lora.spread_factor == 0 {
                9
            } else {
                lora.spread_factor
            },
            if lora.coding_rate == 0 {
                5
            } else {
                lora.coding_rate
            },
            None,
        )
    };

    if lora.use_preset && (5..=8).contains(&lora.coding_rate) && lora.coding_rate != coding_rate {
        coding_rate = lora.coding_rate;
    }

    let (region, frequency_mhz, channel_num) = match region_band(lora.region) {
        Some((start, end, name)) => {
            let bandwidth_mhz = bandwidth_khz / 1000.0;
            let channels = ((end - start) / bandwidth_mhz).floor().max(1.0) as u64;
            let index = if lora.channel_num != 0 {
                u64::from(lora.channel_num - 1)
            } else {
                djb2(channel_name)
            };
            let index = index % channels;

            let mut frequency = start + bandwidth_khz / 2000.0 + index as f32 * bandwidth_mhz;
            let overridden = lora.override_frequency != 0.0;
            if overridden {
                frequency = lora.override_frequency;
            }
            frequency += lora.frequency_offset;

            (
                name.to_owned(),
                Some(frequency),
                (!overridden).then_some(index as u32),
            )
        }
        None => (format!("REGION_{}", lora.region), None, None),
    };

    let bandwidth = if (bandwidth_khz.fract()).abs() < 0.01 {
        format!("{bandwidth_khz:.0}")
    } else {
        format!("{bandwidth_khz:.1}")
    };
    let summary = match frequency_mhz {
        Some(frequency) => {
            format!("SF{spread_factor}/{bandwidth}/CR{coding_rate}/{frequency:.3}")
        }
        None => format!("SF{spread_factor}/{bandwidth}/CR{coding_rate}"),
    };

    LoraDetails {
        summary,
        spread_factor,
        bandwidth_khz,
        coding_rate,
        frequency_mhz,
        channel_num,
        region,
        preset: preset.map(str::to_owned),
    }
}

fn primary_channel_name(cache: &StateCache) -> &str {
    cache
        .channels
        .iter()
        .find(|channel| channel.role == pb::channel::Role::Primary as i32)
        .or_else(|| cache.channels.iter().find(|channel| channel.index == 0))
        .or_else(|| cache.channels.first())
        .and_then(|channel| channel.settings.as_ref())
        .map(|settings| settings.name.as_str())
        .unwrap_or_default()
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn bandwidth_code_to_khz(code: u32) -> f32 {
    match code {
        0 => 125.0,
        31 => 31.25,
        62 => 62.5,
        other => other as f32,
    }
}

fn preset_params(preset: i32) -> (f32, u32, u32, Option<&'static str>) {
    let (bandwidth, spread, coding, name) = match preset {
        0 => (250.0, 11, 5, "LONG_FAST"),
        1 => (125.0, 12, 8, "LONG_SLOW"),
        2 => (62.5, 12, 8, "VERY_LONG_SLOW"),
        3 => (125.0, 10, 5, "MEDIUM_SLOW"),
        4 => (250.0, 9, 5, "MEDIUM_FAST"),
        5 => (250.0, 8, 5, "SHORT_SLOW"),
        6 => (250.0, 7, 5, "SHORT_FAST"),
        7 => (125.0, 11, 5, "LONG_MODERATE"),
        8 => (500.0, 7, 5, "SHORT_TURBO"),
        9 => (500.0, 11, 5, "LONG_TURBO"),
        _ => (250.0, 11, 5, "UNKNOWN"),
    };
    (bandwidth, spread, coding, Some(name))
}

fn region_band(region: i32) -> Option<(f32, f32, &'static str)> {
    Some(match region {
        0 => (902.0, 928.0, "UNSET"),
        1 => (902.0, 928.0, "US"),
        2 => (433.0, 434.0, "EU_433"),
        3 => (869.4, 869.65, "EU_868"),
        4 => (470.0, 510.0, "CN"),
        5 => (920.5, 923.5, "JP"),
        6 => (915.0, 928.0, "ANZ"),
        7 => (920.0, 923.0, "KR"),
        8 => (920.0, 925.0, "TW"),
        9 => (868.7, 869.2, "RU"),
        10 => (865.0, 867.0, "IN"),
        11 => (864.0, 868.0, "NZ_865"),
        12 => (920.0, 925.0, "TH"),
        13 => (2400.0, 2483.5, "LORA_24"),
        14 => (433.0, 434.7, "UA_433"),
        15 => (868.0, 868.6, "UA_868"),
        16 => (433.0, 435.0, "MY_433"),
        17 => (919.0, 924.0, "MY_919"),
        18 => (917.0, 925.0, "SG_923"),
        19 => (433.0, 434.7, "PH_433"),
        20 => (868.0, 869.4, "PH_868"),
        21 => (915.0, 918.0, "PH_915"),
        22 => (433.05, 434.79, "ANZ_433"),
        23 => (433.075, 434.775, "KZ_433"),
        24 => (863.0, 868.0, "KZ_863"),
        25 => (865.0, 868.0, "NP_865"),
        26 => (902.0, 907.5, "BR_902"),
        _ => return None,
    })
}

fn djb2(value: &str) -> u64 {
    let mut hash = 5381u64;
    for byte in value.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u64::from(byte));
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lora(
        use_preset: bool,
        preset: i32,
        bandwidth: u32,
        sf: u32,
        cr: u32,
    ) -> pb::config::LoRaConfig {
        pb::config::LoRaConfig {
            use_preset,
            modem_preset: preset,
            bandwidth,
            spread_factor: sf,
            coding_rate: cr,
            region: 3, // EU_868
            ..Default::default()
        }
    }

    #[test]
    fn matches_the_firmware_frequency_formula() {
        let details = lora_details(&lora(false, 0, 62, 7, 5), "LongFast");
        assert_eq!(details.spread_factor, 7);
        assert_eq!(details.bandwidth_khz, 62.5);
        assert_eq!(details.coding_rate, 5);
        let frequency = details.frequency_mhz.expect("frequency");
        assert!((frequency - 869.618_8).abs() < 0.001, "{frequency}");
        assert_eq!(details.summary, "SF7/62.5/CR5/869.619");
        assert_eq!(details.channel_num, Some(3));
        assert_eq!(details.region, "EU_868");
    }

    #[test]
    fn expands_a_preset() {
        let details = lora_details(&lora(true, 0, 0, 0, 0), "LongFast");
        assert_eq!(details.summary, "SF11/250/CR5/869.525");
        assert_eq!(details.preset.as_deref(), Some("LONG_FAST"));
    }

    #[test]
    fn uses_override_frequency() {
        let mut config = lora(false, 0, 125, 9, 5);
        config.override_frequency = 868.1;
        config.frequency_offset = 0.05;
        let details = lora_details(&config, "LongFast");
        let frequency = details.frequency_mhz.expect("frequency");
        assert!((frequency - 868.15).abs() < 0.001, "{frequency}");
        assert_eq!(details.channel_num, None);
    }

    #[test]
    fn colours_use_the_last_24_bits() {
        assert_eq!(node_color(0x1122_3344), "#223344");
        assert_eq!(node_color(0xAABB_CCDD), "#bbccdd");
    }
}
