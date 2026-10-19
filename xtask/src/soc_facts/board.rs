//! A board's SoC facts from its IPSW DeviceTree: the SoC name, the CPU
//! clusters and PEs with their implementation blocks, the AIC and the PMGR
//! as `machine::soc` reads them, and the NVRAM hand-off slot the loader
//! fills.
use super::sptm::BLOCKS;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use stela_runtime::machine::adt::Node;

/// The AIC properties that are not stated register facts.
const AIC_SKIPPED: [&str; 4] = ["name", "compatible", "reg", "AAPL,phandle"];
const NVRAM_PROXY: &str = "nvram-proxy-data";

fn hex(value: u64) -> String {
    format!("{value:#x}")
}

fn text(value: &[u8]) -> String {
    let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
    String::from_utf8_lossy(&value[..end]).into_owned()
}

fn strings(value: &[u8]) -> Vec<String> {
    value
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// `/arm-io` `ranges` applied to an `/arm-io` child's offset.
fn translate(io: &Node<'_>, offset: u64) -> Option<u64> {
    io.ranges()?
        .into_iter()
        .find(|(child, _, size)| (*child..child + size).contains(&offset))
        .map(|(child, parent, _)| parent + offset - child)
}

fn range(pair: (u64, u64)) -> Value {
    json!([hex(pair.0), hex(pair.1)])
}

/// One cluster: its type, core compatible, the PEs' `reg`, the shared
/// blocks and each PE's `cpu-impl-reg`.
fn clusters(cpus: &Node<'_>) -> Result<Vec<Value>> {
    let mut clusters: Vec<(u32, Value)> = Vec::new();
    for node in cpus.children().context("/cpus has no children")? {
        let Some(cluster_type) = node.property("cluster-type") else {
            continue;
        };
        let id = node.first_u32("cluster-id").unwrap_or(u32::MAX);
        let die = node.first_u32("die-id");
        let reg = node.first_u32("reg").context("a /cpus node has no reg")?;
        let block = |name| node.pairs(name).and_then(|p| p.first().copied());
        let key = (die.unwrap_or(0) << 16) | id;
        let position = clusters.iter().position(|(other, _)| *other == key);
        let index = match position {
            Some(index) => index,
            None => {
                clusters.push((
                    key,
                    json!({
                        "cluster_type": text(cluster_type),
                        "cluster_id": id,
                        "die_id": die,
                        "compatible": node.property("compatible").map(text),
                        "l2_cache_size": node.first_u32("l2-cache-size"),
                        "reg": [],
                        BLOCKS[0]: [],
                        BLOCKS[1]: block(BLOCKS[1]).map(range),
                        BLOCKS[2]: block(BLOCKS[2]).map(range),
                    }),
                ));
                clusters.len() - 1
            }
        };
        let cluster = &mut clusters[index].1;
        cluster["reg"]
            .as_array_mut()
            .expect("array")
            .push(json!(hex(u64::from(reg))));
        cluster[BLOCKS[0]]
            .as_array_mut()
            .expect("array")
            .push(block(BLOCKS[0]).map_or(Value::Null, range));
    }
    Ok(clusters.into_iter().map(|(_, value)| value).collect())
}

fn aic(io: &Node<'_>) -> Option<Value> {
    let aic = io.child("aic")?;
    let reg: Vec<Value> = aic
        .pairs("reg")
        .unwrap_or_default()
        .into_iter()
        .map(|(offset, bytes)| range((translate(io, offset).unwrap_or(offset), bytes)))
        .collect();
    let mut stated = serde_json::Map::new();
    for (name, value) in aic.properties().unwrap_or_default() {
        let name = String::from_utf8_lossy(name).into_owned();
        if AIC_SKIPPED.contains(&name.as_str()) || value.len() != 4 {
            continue;
        }
        let cell = u32::from_le_bytes(value.try_into().expect("4 bytes"));
        stated.insert(name, json!(hex(u64::from(cell))));
    }
    Some(json!({
        "compatible": aic.property("compatible").map(strings),
        "reg": reg,
        "stated": stated,
    }))
}

/// The PMGR's compatible, its `reg` count and `reg[0]`, the base of the
/// CPU start registers (m1n1 `src/smp.c`).
fn pmgr(io: &Node<'_>) -> Option<Value> {
    let pmgr = io.child("pmgr")?;
    let reg = pmgr.pairs("reg").unwrap_or_default();
    Some(json!({
        "compatible": pmgr.property("compatible").map(strings),
        "reg_count": reg.len(),
        "reg0": reg.first().map(|&(offset, bytes)| {
            range((translate(io, offset).unwrap_or(offset), bytes))
        }),
    }))
}

/// The facts of one board's DeviceTree.
pub fn facts(tree: &[u8]) -> Result<Value> {
    let root = Node::root(tree).context("DeviceTree has no root")?;
    let io = root.child("arm-io").context("DeviceTree has no /arm-io")?;
    let cpus = root.child("cpus").context("DeviceTree has no /cpus")?;
    Ok(json!({
        "product_soc_name": root
            .child("product")
            .and_then(|product| product.property("product-soc-name"))
            .map(text),
        "clusters": clusters(&cpus)?,
        "aic": aic(&io),
        "pmgr": pmgr(&io),
        "nvram_proxy_bytes": root
            .child("chosen")
            .and_then(|chosen| chosen.property(NVRAM_PROXY))
            .map(<[u8]>::len),
    }))
}
