//! Independently bounded selected-event tables and complete class marginals.
use super::{Family, FAMILY_COUNT, classes::{self, Kind, Lanes, Signature}, operands::{Activity, Capture}};
use alloc::{collections::BTreeMap, vec::Vec};
use serde::{Serialize, Serializer};

const WORD_LIMIT: usize = 4096;
// Leave room for all 4096 legacy control rows in the existing 2 MiB envelope.
const JOINT_LIMIT: usize = 448;
const SITE_LIMIT: usize = 512;
const WITNESS_LIMIT: usize = 64;
const LENGTH_BUCKETS: usize = 65;

fn add(value: &mut u64, amount: u64, saturated: &mut bool) {
    if let Some(next)=value.checked_add(amount) { *value=next; }
    else { *value=u64::MAX; *saturated=true; }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::{GuestState,aarch64::FloatingPointOperation};

    fn capture() -> (Capture,[Option<Lanes>;2]) {
        let state=GuestState::default();
        let operation=FloatingPointOperation::decode(0x1e20_2820).unwrap().unwrap();
        let mut capture=Capture::before(&state,&operation);
        let outputs=capture.finish(&state,true);
        (capture,outputs)
    }

    #[test]
    fn independent_caps_keep_existing_counts_complete_marginals_and_late_witnesses() {
        let (capture,outputs)=capture();
        let mut observations=Observations::new(9);
        for word in 0..WORD_LIMIT as u32+17 {
            observations.record(Event { family:Family::Binary,word,pc:u64::from(word),retired:u64::from(word),fpcr:0,fpsr_before:0,fpsr_after:0 },&capture,outputs);
        }
        observations.record(Event { family:Family::Binary,word:0,pc:0,retired:0,fpcr:0,fpsr_before:0,fpsr_after:0 },&capture,outputs);
        assert_eq!(observations.words.len(),WORD_LIMIT);
        assert_eq!(observations.joint.len(),JOINT_LIMIT);
        assert_eq!(observations.sites.len(),SITE_LIMIT);
        assert_eq!(observations.dropped,[17,(WORD_LIMIT+17-JOINT_LIMIT) as u64,(WORD_LIMIT+17-SITE_LIMIT) as u64]);
        assert_eq!(observations.words[&0],2);
        let total=(WORD_LIMIT+18) as u64;
        assert_eq!(observations.families[Family::Binary as usize].activity[Activity::Evaluated as usize],total);
        assert_eq!(observations.families[Family::Binary as usize].roles[0].ieee[0],total);
        assert_eq!(observations.population,total);
        assert!(observations.uniform);
        assert_eq!(observations.witnesses.len(),WITNESS_LIMIT);
        assert!(observations.witnesses.iter().any(|witness| witness.ordinal>WITNESS_LIMIT as u64));
        let mut ordinals:Vec<_>=observations.witnesses.iter().map(|witness| witness.ordinal).collect();
        ordinals.sort_unstable();
        ordinals.dedup();
        assert_eq!(ordinals.len(),WITNESS_LIMIT);
        observations.population=u64::MAX;
        observations.record(Event { family:Family::Binary,word:0,pc:0,retired:0,fpcr:0,fpsr_before:0,fpsr_after:0 },&capture,outputs);
        assert!(!observations.uniform);
        assert!(observations.saturated);
        observations.families[Family::Binary as usize].roles[0].ieee[0]=u64::MAX;
        observations.record(Event { family:Family::Binary,word:0,pc:0,retired:0,fpcr:0,fpsr_before:0,fpsr_after:0 },&capture,outputs);
        assert_eq!(observations.families[Family::Binary as usize].roles[0].ieee[0],u64::MAX);
    }

    #[test]
    fn facts_separate_raw_specials_integer_sources_and_half_span_domains() {
        let half=|value| Some(Lanes::gather(Kind::Ieee { bits:16 },1, |_| value));
        let facts=Facts::of(Family::Fused,&[half(0x3c00),half(0x3c00),half(0x3c00)]);
        assert_eq!(facts.all_raw_normal,Some(true));
        assert_eq!(facts.half_fma_exact_double_span_v1_applicable,1);
        assert_eq!(facts.half_fma_exact_double_span_v1_passed,1);
        let facts=Facts::of(Family::Fused,&[half(0),half(1),half(0x7c00)]);
        assert_eq!((facts.zero_roles,facts.subnormal_roles,facts.special_roles),(1,2,4));
        assert_eq!(facts.half_fma_exact_double_span_v1_applicable,0);
        assert_eq!(facts.all_raw_normal_or_zero,Some(false));
        let facts=Facts::of(Family::Conversion,&[Some(Lanes::gather(Kind::Integer { bits:16,signed:false },1, |_| 0x7c00)),None,None]);
        assert_eq!(facts.all_raw_normal,None);
        assert_eq!(facts.special_roles,0);
    }
}

fn lengths<S: Serializer>(values: &[u64; LENGTH_BUCKETS], serializer: S) -> Result<S::Ok,S::Error> {
    values.as_slice().serialize(serializer)
}

#[derive(Debug, Clone, Serialize)]
struct Role {
    captured_lanes: u64,
    ieee: [u64; 12],
    integer_zero: u64,
    integer_negative: u64,
    #[serde(serialize_with="lengths")]
    integer_magnitude_bits: [u64; LENGTH_BUCKETS],
    #[serde(serialize_with="lengths")]
    integer_trailing_zeros: [u64; LENGTH_BUCKETS],
    predicate_zero_all_ones_other: [u64; 3],
    nzcv: [u64; 16],
}

impl Default for Role {
    fn default() -> Self {
        Self { captured_lanes: 0,ieee:[0;12],integer_zero:0,integer_negative:0,
            integer_magnitude_bits:[0;LENGTH_BUCKETS],integer_trailing_zeros:[0;LENGTH_BUCKETS],
            predicate_zero_all_ones_other:[0;3],nzcv:[0;16] }
    }
}

impl Role {
    fn record(&mut self, value: Lanes, saturated: &mut bool) {
        add(&mut self.captured_lanes,u64::from(value.count),saturated);
        for lane in 0..u32::from(value.count) {
            let raw=value.lane(lane);
            match value.kind {
                Kind::Ieee { bits } => add(&mut self.ieee[usize::from(classes::ieee_class(u32::from(bits),raw))],1,saturated),
                Kind::Integer { bits,signed } => {
                    let (negative,magnitude,trailing)=classes::integer_class(u32::from(bits),signed,raw);
                    if raw==0 { add(&mut self.integer_zero,1,saturated); }
                    if negative { add(&mut self.integer_negative,1,saturated); }
                    add(&mut self.integer_magnitude_bits[usize::from(magnitude)],1,saturated);
                    add(&mut self.integer_trailing_zeros[usize::from(trailing)],1,saturated);
                }
                Kind::Predicate { bits } => add(&mut self.predicate_zero_all_ones_other[
                    if raw==0 { 0 } else if raw==classes::mask(u32::from(bits)) { 1 } else { 2 }],1,saturated),
                Kind::Nzcv => add(&mut self.nzcv[raw as usize],1,saturated),
            }
        }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
struct FamilyTotals {
    activity: [u64; 4],
    evaluated_lane_steps: u64,
    evaluated_logical_input_uses: u64,
    discarded_result_samples: u64,
    // Inputs are selected raw fields even on refusal; activity separates those
    // from evaluated lanes. Results exist only after successful completion.
    roles: [Role; 5],
    all_normal: [u64; 3],
    all_normal_or_zero: [u64; 3],
    half_span_applicable_lanes: u64,
    half_span_passed_lanes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Facts {
    all_raw_normal: Option<bool>,
    all_raw_normal_or_zero: Option<bool>,
    zero_roles: u8,
    subnormal_roles: u8,
    special_roles: u8,
    half_fma_exact_double_span_v1_applicable: u8,
    half_fma_exact_double_span_v1_passed: u8,
}

impl Facts {
    fn of(family: Family, inputs: &[Option<Lanes>;3]) -> Self {
        let mut facts=Self { all_raw_normal:Some(true),all_raw_normal_or_zero:Some(true),
            zero_roles:0,subnormal_roles:0,special_roles:0,
            half_fma_exact_double_span_v1_applicable:0,half_fma_exact_double_span_v1_passed:0 };
        let mut ieee_lanes=0;
        for (role,input) in inputs.iter().enumerate() {
            let Some(input)=input else { continue };
            let Kind::Ieee { bits }=input.kind else { continue };
            for lane in 0..u32::from(input.count) {
                ieee_lanes+=1;
                let class=classes::ieee_class(u32::from(bits),input.lane(lane));
                if class<2 { facts.zero_roles|=1<<role; }
                if (2..4).contains(&class) { facts.subnormal_roles|=1<<role; }
                if class>=8 { facts.special_roles|=1<<role; }
                if !(4..8).contains(&class) { facts.all_raw_normal=Some(false); }
                if !(class<2 || (4..8).contains(&class)) { facts.all_raw_normal_or_zero=Some(false); }
            }
        }
        if ieee_lanes==0 { facts.all_raw_normal=None; facts.all_raw_normal_or_zero=None; }
        if family==Family::Fused && let [Some(left),Some(right),Some(addend)]=*inputs
            && [left,right,addend].iter().all(|value| matches!(value.kind,Kind::Ieee { bits:16 }) && value.count==left.count)
        {
            for lane in 0..u32::from(left.count) {
                if let (Some(l),Some(r),Some(a))=(classes::normal_exponent(16,left.lane(lane)),
                    classes::normal_exponent(16,right.lane(lane)),classes::normal_exponent(16,addend.lane(lane))) {
                    facts.half_fma_exact_double_span_v1_applicable|=1<<lane;
                    if (-31..=40).contains(&(l+r-a)) { facts.half_fma_exact_double_span_v1_passed|=1<<lane; }
                }
            }
        }
        facts
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct JointKey {
    word: u32,
    family: Family,
    fpcr: u32,
    activity: Activity,
    frac_bits: Option<u8>,
    discarded_result: bool,
    inputs: [Option<Signature>;3],
    outputs: [Option<Signature>;2],
    facts: Facts,
}

#[derive(Debug, Clone, Serialize)]
struct Witness {
    ordinal: u64,
    guest_pc: u64,
    retired_before: u64,
    word: u32,
    fpcr: u32,
    fpsr_before: u32,
    fpsr_after: u32,
    activity: Activity,
    inputs: [Option<Lanes>;3],
    outputs: [Option<Lanes>;2],
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Snapshot {
    schema: u32,
    value_scope: &'static str,
    role_order: [&'static str;5],
    activity_order: [Activity;4],
    ieee_class_order: [&'static str;12],
    fresh_exceptions: Option<u32>,
    observed_guard_branch: Option<&'static str>,
    word_limit: usize,
    joint_limit: usize,
    site_limit: usize,
    word_dropped_samples: u64,
    joint_dropped_samples: u64,
    site_dropped_samples: u64,
    counter_saturated: bool,
    family_marginals: [FamilyTotals;FAMILY_COUNT],
    words: Vec<(u32,u64)>,
    joint: Vec<(JointKey,u64)>,
    sites: Vec<((u64,u32),u64)>,
    witness_algorithm: &'static str,
    witness_population: u64,
    witness_uniform: bool,
    witnesses: Vec<Witness>,
}

#[derive(Clone, Copy)]
pub(super) struct Event {
    pub family: Family,
    pub word: u32,
    pub pc: u64,
    pub retired: u64,
    pub fpcr: u32,
    pub fpsr_before: u32,
    pub fpsr_after: u32,
}

pub(super) struct Observations {
    families: [FamilyTotals;FAMILY_COUNT],
    words: BTreeMap<u32,u64>,
    joint: BTreeMap<JointKey,u64>,
    sites: BTreeMap<(u64,u32),u64>,
    dropped: [u64;3],
    saturated: bool,
    random: u64,
    population: u64,
    uniform: bool,
    witnesses: Vec<Witness>,
}

fn count<K:Ord>(map: &mut BTreeMap<K,u64>,key: K,limit: usize,dropped: &mut u64,saturated: &mut bool) {
    if let Some(value)=map.get_mut(&key) { add(value,1,saturated); }
    else if map.len()<limit { map.insert(key,1); }
    else { add(dropped,1,saturated); }
}

impl Observations {
    #[cfg(test)]
    pub(super) fn maximum_test_fixture() -> Self {
        let mut observations=Self::new(u64::MAX);
        for totals in &mut observations.families {
            totals.activity.fill(u64::MAX);
            totals.evaluated_lane_steps=u64::MAX;
            totals.evaluated_logical_input_uses=u64::MAX;
            totals.discarded_result_samples=u64::MAX;
            totals.all_normal.fill(u64::MAX);
            totals.all_normal_or_zero.fill(u64::MAX);
            totals.half_span_applicable_lanes=u64::MAX;
            totals.half_span_passed_lanes=u64::MAX;
            for role in &mut totals.roles {
                role.captured_lanes=u64::MAX;
                role.ieee.fill(u64::MAX);
                role.integer_zero=u64::MAX;
                role.integer_negative=u64::MAX;
                role.integer_magnitude_bits.fill(u64::MAX);
                role.integer_trailing_zeros.fill(u64::MAX);
                role.predicate_zero_all_ones_other.fill(u64::MAX);
                role.nzcv.fill(u64::MAX);
            }
        }
        observations.words=(0..WORD_LIMIT).map(|i| (u32::MAX-i as u32,u64::MAX)).collect();
        observations.sites=(0..SITE_LIMIT).map(|i| ((u64::MAX-i as u64,u32::MAX),u64::MAX)).collect();
        let signature=Signature { kind:Kind::Integer { bits:64,signed:false },count:u8::MAX,
            codes:u32::MAX,signs:u8::MAX,normal_exponent_min:Some(i16::MIN),normal_exponent_max:Some(i16::MIN),
            magnitude_bits:u64::MAX,trailing_zeros:u64::MAX };
        observations.joint=(0..JOINT_LIMIT).map(|i| (JointKey { word:u32::MAX-i as u32,
            family:Family::ExtremaScale,fpcr:u32::MAX,activity:Activity::RefusedBeforeEvaluation,
            frac_bits:Some(u8::MAX),discarded_result:false,inputs:[Some(signature);3],outputs:[Some(signature);2],
            facts:Facts { all_raw_normal:Some(false),all_raw_normal_or_zero:Some(false),zero_roles:u8::MAX,
                subnormal_roles:u8::MAX,special_roles:u8::MAX,half_fma_exact_double_span_v1_applicable:u8::MAX,
                half_fma_exact_double_span_v1_passed:u8::MAX } },u64::MAX)).collect();
        observations.witnesses=(0..WITNESS_LIMIT).map(|_| Witness { ordinal:u64::MAX,guest_pc:u64::MAX,
            retired_before:u64::MAX,word:u32::MAX,fpcr:u32::MAX,fpsr_before:u32::MAX,fpsr_after:u32::MAX,
            activity:Activity::RefusedBeforeEvaluation,inputs:[Some(Lanes { kind:signature.kind,count:u8::MAX,raw:[u64::MAX;2] });3],
            outputs:[Some(Lanes { kind:signature.kind,count:u8::MAX,raw:[u64::MAX;2] });2] }).collect();
        observations.dropped.fill(u64::MAX);
        observations.population=u64::MAX;
        observations.saturated=true;
        observations.uniform=false;
        observations
    }

    pub(super) fn new(seed: u64) -> Self {
        Self { families:core::array::from_fn(|_| FamilyTotals::default()),words:BTreeMap::new(),
            joint:BTreeMap::new(),sites:BTreeMap::new(),dropped:[0;3],saturated:false,
            random:seed^0xd74b_6a9c_286e_f153,population:0,uniform:true,witnesses:Vec::new() }
    }

    // Separate SplitMix stream, rejection sampling avoids modulo bias. Never
    // consumes the event sampler's random stream or guest/security entropy.
    fn uniform_below(&mut self, bound: u64) -> u64 {
        let threshold=bound.wrapping_neg()%bound;
        loop {
            self.random=self.random.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value=self.random;
            value=(value^(value>>30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value=(value^(value>>27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value^=value>>31;
            if value>=threshold { return value%bound; }
        }
    }

    pub(super) fn record(&mut self, event: Event,capture:&Capture,outputs:[Option<Lanes>;2]) {
        let Event { family,word,pc,retired,fpcr,fpsr_before,fpsr_after }=event;
        let facts=Facts::of(family,&capture.inputs);
        let totals=&mut self.families[family as usize];
        add(&mut totals.activity[capture.activity as usize],1,&mut self.saturated);
        if capture.activity==Activity::Evaluated {
            add(&mut totals.evaluated_lane_steps,u64::from(capture.lane_steps),&mut self.saturated);
            add(&mut totals.evaluated_logical_input_uses,capture.inputs.iter().flatten().map(|value| u64::from(value.count)).sum(),&mut self.saturated);
        }
        if capture.discarded_result { add(&mut totals.discarded_result_samples,1,&mut self.saturated); }
        for (role,value) in capture.inputs.iter().chain(outputs.iter()).enumerate() {
            if let Some(value)=value { totals.roles[role].record(*value,&mut self.saturated); }
        }
        for (buckets,value) in [(&mut totals.all_normal,facts.all_raw_normal),(&mut totals.all_normal_or_zero,facts.all_raw_normal_or_zero)] {
            add(&mut buckets[value.map_or(2,usize::from)],1,&mut self.saturated);
        }
        add(&mut totals.half_span_applicable_lanes,u64::from(facts.half_fma_exact_double_span_v1_applicable.count_ones()),&mut self.saturated);
        add(&mut totals.half_span_passed_lanes,u64::from(facts.half_fma_exact_double_span_v1_passed.count_ones()),&mut self.saturated);
        count(&mut self.words,word,WORD_LIMIT,&mut self.dropped[0],&mut self.saturated);
        count(&mut self.sites,(pc,word),SITE_LIMIT,&mut self.dropped[2],&mut self.saturated);
        let key=JointKey { word,family,fpcr,activity:capture.activity,frac_bits:capture.frac_bits,
            discarded_result:capture.discarded_result,inputs:capture.inputs.map(|value| value.map(Lanes::signature)),
            outputs:outputs.map(|value| value.map(Lanes::signature)),facts };
        count(&mut self.joint,key,JOINT_LIMIT,&mut self.dropped[1],&mut self.saturated);
        let Some(population)=self.population.checked_add(1) else { self.uniform=false; self.saturated=true; return };
        self.population=population;
        let slot=if self.witnesses.len()<WITNESS_LIMIT { self.witnesses.len() as u64 } else { self.uniform_below(population) };
        if slot<WITNESS_LIMIT as u64 {
            let witness=Witness { ordinal:population,guest_pc:pc,retired_before:retired,word,fpcr,
                fpsr_before,fpsr_after,activity:capture.activity,inputs:capture.inputs,outputs };
            if slot==self.witnesses.len() as u64 { self.witnesses.push(witness); }
            else { self.witnesses[slot as usize]=witness; }
        }
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        Snapshot { schema:1,value_scope:"Selected raw layout fields, not effective flushed values, native-success counts, guard causes, fresh exceptions, physical RAM traffic or time weights; IEEE layout includes alternative-Half precision encodings. Sites are engine-local virtual PCs. Word/joint/site tables retain first-seen keys up to caps, count existing keys thereafter and report dropped new-key samples; complete marginals include all selected events. Reservoir uniformity is over selected events only. Integer lengths use seven bits per lane, IEEE codes four and predicate codes two; fact booleans use false/true/not-applicable buckets.",
            role_order:["left_or_source","right","original_addend","result","flags_or_second_result"],
            activity_order:[Activity::Evaluated,Activity::SkippedConditional,Activity::RefusedBeforeEvaluation,Activity::NotCapturedFamily],
            ieee_class_order:classes::FP_CLASSES,fresh_exceptions:None,observed_guard_branch:None,
            word_limit:WORD_LIMIT,joint_limit:JOINT_LIMIT,site_limit:SITE_LIMIT,
            word_dropped_samples:self.dropped[0],joint_dropped_samples:self.dropped[1],site_dropped_samples:self.dropped[2],
            counter_saturated:self.saturated,family_marginals:self.families.clone(),
            words:self.words.iter().map(|(&key,&count)| (key,count)).collect(),
            joint:self.joint.iter().map(|(&key,&count)| (key,count)).collect(),
            sites:self.sites.iter().map(|(&key,&count)| (key,count)).collect(),
            witness_algorithm:"algorithm_r_64_splitmix64_independent_seed_xor_d74b6a9c286ef153_unbiased_rejection_v1",
            witness_population:self.population,witness_uniform:self.uniform,witnesses:self.witnesses.clone() }
    }
}
