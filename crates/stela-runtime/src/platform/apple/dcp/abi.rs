//! The method and callback ABI of the DCP IOMFB link (the 26A434 interface
//! version, [`crate::builds`]): which four-character tag names which method,
//! the wire sizes of its input and output, and how a method's arguments are
//! packed into those bytes.
//!
//! ## Tags and sizes
//!
//! Tags are per firmware interface: the public tables move them between
//! releases (Asahi Linux `drivers/gpu/drm/apple/iomfb_v12_3.c` and
//! `iomfb_v13_3.c`; m1n1 `proxyclient/m1n1/fw/dcp/ipc.py`, whose `>= 14.7`
//! branch has `A406 swap_start_dcp` and `A407 swap_submit_dcp`). The rows
//! below are the 26A434 J473AP interface's, transcribed from the exact-build
//! record in docs/research/display-gpu.md ("Verified method/callback
//! matrix"); method names follow the public tables where both name one.
//! Every call the AP makes is checked against its row, so a call whose
//! sizes differ from the interface refuses by name instead of being parsed
//! with the wrong layout.
//!
//! ## Argument packing (m1n1 `ipc.py`, `Method.__init__`)
//!
//! A method's input is its by-value and in/in-out pointer arguments in
//! declaration order with no alignment padding between them, then one
//! `_null` byte per pointer argument (one per element for an array of
//! pointers), padded to a multiple of 4. Its output is its out and in-out
//! pointer arguments in order, then its return value, padded the same way.
//! A `bool` is one byte. [`Fields`] and [`Packed`] read and write that form.

/// One AP-to-coprocessor method of the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Method {
    pub tag: [u8; 4],
    /// The AP class whose stub calls it.
    pub class: &'static str,
    pub name: &'static str,
    pub input: u32,
    pub output: u32,
}

/// One coprocessor-to-AP callback of the interface. A size the record
/// leaves open is `None`; the model only makes callbacks whose sizes are
/// recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Callback {
    pub tag: [u8; 4],
    pub class: &'static str,
    /// The AP handler's method, empty where the record names none.
    pub name: &'static str,
    pub input: Option<u32>,
    pub output: Option<u32>,
}

const fn m(
    tag: &[u8; 4],
    class: &'static str,
    name: &'static str,
    input: u32,
    output: u32,
) -> Method {
    Method {
        tag: *tag,
        class,
        name,
        input,
        output,
    }
}

const fn c(
    tag: &[u8; 4],
    class: &'static str,
    name: &'static str,
    input: Option<u32>,
    output: Option<u32>,
) -> Callback {
    Callback {
        tag: *tag,
        class,
        name,
        input,
        output,
    }
}

/// The interface's row for method `tag`.
pub fn method(tag: &[u8; 4]) -> Option<&'static Method> {
    METHODS.iter().find(|method| &method.tag == tag)
}

/// The interface's row for callback `tag`.
pub fn callback(tag: &[u8; 4]) -> Option<&'static Callback> {
    CALLBACKS.iter().find(|callback| &callback.tag == tag)
}

/// A printable tag.
pub fn tag_str(tag: &[u8; 4]) -> &str {
    core::str::from_utf8(tag).unwrap_or("????")
}

/// A reader over a method's packed input.
pub struct Fields<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        let end = self
            .at
            .checked_add(n)
            .filter(|&end| end <= self.bytes.len())
            .ok_or("DCP method input is shorter than its arguments")?;
        let field = &self.bytes[self.at..end];
        self.at = end;
        Ok(field)
    }

    pub fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }

    pub fn bool(&mut self) -> Result<bool, &'static str> {
        Ok(self.u8()? != 0)
    }

    pub fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    pub fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        self.take(n)
    }
}

/// A writer of a method's packed output, padded to its recorded length.
#[derive(Default)]
pub struct Packed(alloc::vec::Vec<u8>);

impl Packed {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(mut self, value: u8) -> Self {
        self.0.push(value);
        self
    }

    pub fn bool(self, value: bool) -> Self {
        self.u8(u8::from(value))
    }

    pub fn u32(mut self, value: u32) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn u64(mut self, value: u64) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn bytes(mut self, value: &[u8]) -> Self {
        self.0.extend_from_slice(value);
        self
    }

    /// The bytes, padded with zeros to `length`, or a refusal when the
    /// arguments do not fit it.
    pub fn finish(mut self, length: u32) -> Result<alloc::vec::Vec<u8>, &'static str> {
        let length = length as usize;
        if self.0.len() > length {
            return Err("DCP method output exceeds its recorded size");
        }
        self.0.resize(length, 0);
        Ok(self.0)
    }
}

/// The link status a successful `uint32_t` result carries. The AP converts
/// it with `iomfb_status_from_link` (0x3d9cf30): 0 is `kIOReturnSuccess`,
/// 1..=18 index its error table (0xaf72f0: 1 0xe00002bc, 2 0xe00002c7, ...,
/// 18 0xe0000001) and larger values also read as success. Asahi's
/// `iomfb_template.c` (`dcp_swapped`) treats any nonzero swap result as a
/// failed swap.
pub const IO_RETURN_SUCCESS: u32 = 0;

/// The interface's methods.
#[rustfmt::skip]
pub const METHODS: &[Method] = &[
    m(b"A000", "UPPipeAP_H13P", "late_init_signal", 0x4, 0x4),
    m(b"A001", "UPPipeAP_H13P", "alss_supported", 0x0, 0x4),
    m(b"A002", "UPPipeAP_H13P", "reset_dsc", 0x0, 0x0),
    m(b"A003", "UPPipeAP_H13P", "display_edr_factor_changed", 0x4, 0x0),
    m(b"A004", "UPPipeAP_H13P", "set_contrast", 0x4, 0x0),
    m(b"A005", "UPPipeAP_H13P", "set_csc_mode", 0x4, 0x0),
    m(b"A006", "UPPipeAP_H13P", "set_op_mode", 0x4, 0x0),
    m(b"A007", "UPPipeAP_H13P", "set_op_gamma_mode", 0x4, 0x0),
    m(b"A008", "UPPipeAP_H13P", "set_video_out_mode", 0x4, 0x0),
    m(b"A009", "UPPipeAP_H13P", "set_meta_allowed", 0x4, 0x0),
    m(b"A010", "UPPipeAP_H13P", "set_tunneled_color_mode", 0x4, 0x0),
    m(b"A011", "UPPipeAP_H13P", "set_bwr_line_time_us", 0x8, 0x0),
    m(b"A012", "UPPipeAP_H13P", "performance_feedback", 0x8, 0x0),
    m(b"A013", "UPPipeAP_H13P", "notify_swap_complete", 0x4, 0x0),
    m(b"A014", "UPPipeAP_H13P", "is_run_mode_change_pending", 0x0, 0x4),
    m(b"A015", "UPPipeAP_H13P", "ready_for_run_mode_change", 0x0, 0x4),
    m(b"A016", "UPPipeAP_H13P", "set_thermal_throttle_cap", 0x4, 0x0),
    m(b"A017", "UPPipeAP_H13P", "emergency_shutdown_normal_mode", 0x0, 0x0),
    m(b"A018", "UPPipeAP_H13P", "set_target_run_mode", 0x0, 0x4),
    m(b"A019", "UPPipeAP_H13P", "rt_bandwidth_setup", 0x0, 0x4),
    m(b"A020", "UPPipeAP_H13P", "rt_bandwidth_update", 0xc, 0x4),
    m(b"A021", "UPPipeAP_H13P", "rt_bandwidth_write_update", 0x8, 0x4),
    m(b"A022", "UPPipeAP_H13P", "cif_blending_eco_present", 0x0, 0x4),
    m(b"A023", "UPPipeAP_H13P", "request_bic_update", 0x0, 0x4),
    m(b"A024", "UPPipeAP_H13P", "early_power_off_warning", 0x0, 0x0),
    m(b"A025", "UPPipeAP_H13P", "get_max_frame_size", 0xc, 0x8),
    m(b"A026", "UPPipeAP_H13P", "shadow_FIFO_empty", 0x0, 0x4),
    m(b"A027", "UPPipeAP_H13P", "setup_video_limits", 0x0, 0x0),
    m(b"A028", "UPPipeAP_H13P", "can_program_swap", 0x0, 0x4),
    m(b"A029", "UPPipeAP_H13P", "in_auto_mode", 0x0, 0x4),
    m(b"A030", "UPPipeAP_H13P", "is_piodma_used", 0x0, 0x4),
    m(b"A031", "UPPipeAP_H13P", "push_black_frame", 0x0, 0x0),
    m(b"A032", "UPPipeAP_H13P", "read_crc", 0x8, 0x4),
    m(b"A033", "UPPipeAP_H13P", "update_notify_clients_dcp", 0x6c, 0x0),
    m(b"A034", "UPPipeAP_H13P", "is_hilo", 0x0, 0x4),
    m(b"A035", "UPPipeAP_H13P", "apt_supported", 0x0, 0x4),
    m(b"A036", "UPPipeAP_H13P", "get_dfb_info", 0x2c, 0x2c),
    m(b"A037", "UPPipeAP_H13P", "get_dfb_compression_info", 0x8, 0x8),
    m(b"A038", "UPPipeAP_H13P", "get_frame_done_time", 0x0, 0x8),
    m(b"A039", "UPPipeAP_H13P", "get_performance_headroom", 0x0, 0x4),
    m(b"A040", "UPPipeAP_H13P", "are_stats_active", 0x0, 0x4),
    m(b"A041", "UPPipeAP_H13P", "supports_odd_h_blanking", 0x0, 0x4),
    m(b"A042", "UPPipeAP_H13P", "is_first_hw_version", 0x0, 0x4),
    m(b"A043", "UPPipeAP_H13P", "set_blendout_CSC_mode", 0x0, 0x0),
    m(b"A044", "UPPipeAP_H13P", "update_ext_disp_clock_info", 0x8, 0x4),
    m(b"A100", "UPPipe2", "get_gamma_table_gated", 0x4, 0xc10),
    m(b"A101", "UPPipe2", "set_gamma_table_gated", 0xc10, 0x4),
    m(b"A102", "UPPipe2", "test_control", 0x8, 0x4),
    m(b"A103", "UPPipe2", "get_config_frame_size", 0xc, 0x8),
    m(b"A104", "UPPipe2", "set_config_frame_size", 0x8, 0x0),
    m(b"A105", "UPPipe2", "program_config_frame_size", 0x0, 0x0),
    m(b"A106", "UPPipe2", "read_blend_crc", 0x0, 0x4),
    m(b"A107", "UPPipe2", "read_config_crc", 0x0, 0x4),
    m(b"A108", "UPPipe2", "disable_wpc_calibration", 0x4, 0x4),
    m(b"A109", "UPPipe2", "vftg_is_running", 0x0, 0x4),
    m(b"A110", "UPPipe2", "vftg_debug", 0x4, 0x0),
    m(b"A111", "UPPipe2", "vftg_set_color_channels", 0xc, 0x0),
    m(b"A112", "UPPipe2", "set_color_filter_scale", 0x4, 0x4),
    m(b"A113", "UPPipe2", "set_corner_temps", 0x10, 0x4),
    m(b"A114", "UPPipe2", "reset_aot_enabled", 0x0, 0x0),
    m(b"A115", "UPPipe2", "aot_enabled", 0x0, 0x4),
    m(b"A116", "UPPipe2", "aot_active", 0x0, 0x4),
    m(b"A117", "UPPipe2", "set_timings_enabled", 0x4, 0x4),
    m(b"A118", "UPPipe2", "get_frame_size", 0xc, 0xc),
    m(b"A119", "UPPipe2", "set_block_dcp", 0x106c, 0x4),
    m(b"A120", "UPPipe2", "get_block", 0x5c, 0x1004),
    m(b"A121", "UPPipe2", "abort_block_dcp", 0xc, 0x4),
    m(b"A122", "UPPipe2", "get_buf_block_dcp", 0x106c, 0x4),
    m(b"A123", "UPPipe2", "start_task_dcp", 0x18, 0x4),
    m(b"A124", "UPPipe2", "abort_task_dcp", 0xc, 0x4),
    m(b"A125", "UPPipe2", "check_task_status_dcp", 0xc, 0x4),
    m(b"A126", "UPPipe2", "get_block_size_dcp", 0x14, 0x8),
    m(b"A127", "UPPipe2", "get_matrix", 0x80, 0x7c),
    m(b"A128", "UPPipe2", "set_matrix", 0x80, 0x4),
    m(b"A129", "UPPipe2", "get_internal_timing_attributes_gated", 0x34, 0x34),
    m(b"A130", "UPPipe2", "display_edr_factor_changed", 0x4, 0x0),
    m(b"A131", "UPPipe2", "set_contrast", 0x4, 0x0),
    m(b"A132", "UPPipe2", "p3_to_disp_cs", 0x20, 0x4),
    m(b"A133", "UPPipe2", "max_panel_brightness", 0x0, 0x4),
    m(b"A134", "UPPipe2", "swap_flush_stream_replay", 0x0, 0x0),
    m(b"A135", "UPPipe2", "init_ca_pmu", 0x0, 0x4),
    m(b"A136", "UPPipe2", "pmu_service_matched", 0x0, 0x4),
    m(b"A137", "UPPipe2", "backlight_service_matched", 0x0, 0x4),
    m(b"A200", "PropRelay", "setBool", 0x8, 0x4),
    m(b"A201", "PropRelay", "setInt", 0x8, 0x4),
    m(b"A202", "PropRelay", "setFx", 0x8, 0x4),
    m(b"A203", "PropRelay", "setPropDynamic", 0x8, 0x4),
    m(b"A204", "PropRelay", "getBool", 0x4, 0x4),
    m(b"A205", "PropRelay", "getInt", 0x4, 0x4),
    m(b"A206", "PropRelay", "getFx", 0x4, 0x4),
    m(b"A350", "UnifiedPipeline2", "displayHeight", 0x0, 0x4),
    m(b"A351", "UnifiedPipeline2", "displayWidth", 0x0, 0x4),
    m(b"A352", "UnifiedPipeline2", "applyProperty", 0x8, 0x4),
    m(b"A353", "UnifiedPipeline2", "getMinFramePeriodNs", 0x0, 0x8),
    m(b"A354", "UnifiedPipeline2", "set_fast_preset_in_progress", 0x10, 0xc),
    m(b"A355", "UnifiedPipeline2", "getTiledModes", 0x5dc, 0x5d4),
    m(b"A356", "UnifiedPipeline2", "removeTiledModes", 0x0, 0x4),
    m(b"A357", "UnifiedPipeline2", "insertTiledModes", 0x70, 0x68),
    m(b"A358", "UnifiedPipeline2", "removeDisplayWallModeList", 0x0, 0x4),
    m(b"A359", "UnifiedPipeline2", "buildDisplayWallModeList", 0x14, 0x8),
    m(b"A360", "UnifiedPipeline2", "getMasterSwapID", 0x0, 0x4),
    m(b"A361", "UnifiedPipeline2", "setMasterSwapID", 0x4, 0x0),
    m(b"A362", "UnifiedPipeline2", "manage_elements", 0x4, 0x0),
    m(b"A363", "UnifiedPipeline2", "manage_properties", 0x4, 0x0),
    m(b"A364", "UnifiedPipeline2", "getVideoDataForIDs", 0x7c, 0x74),
    m(b"A365", "UnifiedPipeline2", "insertMergeModes", 0x7c, 0x74),
    m(b"A366", "UnifiedPipeline2", "setup_peer_dcp", 0x4, 0x0),
    m(b"A367", "UnifiedPipeline2", "getDSCCapabilities", 0x24, 0x20),
    m(b"A368", "UnifiedPipeline2", "setDSCCapabilities", 0x24, 0x20),
    m(b"A369", "UnifiedPipeline2", "getRequiresDSC", 0x0, 0x4),
    m(b"A370", "UnifiedPipeline2", "getDSCBitsPerPixel", 0x4, 0x8),
    m(b"A371", "UnifiedPipeline2", "setDSCBitsPerPixel", 0x4, 0x8),
    m(b"A372", "UnifiedPipeline2", "getDSCslicesize", 0xc, 0xc),
    m(b"A373", "UnifiedPipeline2", "setDSCslicesize", 0xc, 0xc),
    m(b"A374", "UnifiedPipeline2", "getMatchingMode", 0x5dc, 0x5d4),
    m(b"A375", "UnifiedPipeline2", "getDisplayProductId", 0x18, 0x14),
    m(b"A376", "UnifiedPipeline2", "get_dw_mode_size", 0x8, 0xc),
    m(b"A377", "UnifiedPipeline2", "getDisplayIDs", 0x14, 0x14),
    m(b"A378", "UnifiedPipeline2", "getPlatformExtDisplayLimits", 0x28, 0x20),
    m(b"A379", "UnifiedPipeline2", "is_external", 0x0, 0x4),
    m(b"A380", "UnifiedPipeline2", "get_system_type", 0x0, 0x4),
    m(b"A381", "UnifiedPipeline2", "get_dw_params", 0x0, 0x14),
    m(b"A382", "UnifiedPipeline2", "dw_reset_dual_pipe", 0x0, 0x0),
    m(b"A383", "UnifiedPipeline2", "is_dw_supported", 0x0, 0x4),
    m(b"A384", "UnifiedPipeline2", "headless", 0x0, 0x4),
    m(b"A385", "UnifiedPipeline2", "are_timings_enabled_rpc", 0x0, 0x4),
    m(b"A386", "UnifiedPipeline2", "get_apt_nframes_completed_rpc", 0x0, 0x4),
    m(b"A387", "UnifiedPipeline2", "export_idle_method", 0x4, 0x0),
    m(b"A388", "UnifiedPipeline2", "get_timing_attributes_gated", 0x34, 0x34),
    m(b"A389", "UnifiedPipeline2", "set_create_DFB", 0x0, 0x0),
    m(b"A390", "UnifiedPipeline2", "vi_set_temperature_hint", 0x0, 0x4),
    m(b"A391", "UnifiedPipeline2", "allocate_bandwidth_callback_gated", 0x4, 0x4),
    m(b"A392", "UnifiedPipeline2", "getSupportsPanelReplay", 0x0, 0x4),
    m(b"A393", "UnifiedPipeline2", "setSupportsPanelReplay", 0x0, 0x0),
    m(b"A394", "UnifiedPipeline2", "get_is_displayX1", 0x0, 0x4),
    m(b"A395", "UnifiedPipeline2", "set_is_displayX1", 0x4, 0x0),
    m(b"A396", "UnifiedPipeline2", "update_max_edr_headroom", 0x0, 0x0),
    m(b"A397", "UnifiedPipeline2", "get_fast_preset_switch_ext_disp_supported", 0x0, 0x4),
    m(b"A398", "UnifiedPipeline2", "setFastPresetSwitchSupported", 0x0, 0x0),
    m(b"A399", "UnifiedPipeline2", "is_j575d", 0x0, 0x4),
    m(b"A400", "IOMobileFramebufferAP", "free_signal", 0x0, 0x0),
    m(b"A401", "IOMobileFramebufferAP", "start_signal", 0x0, 0x4),
    m(b"A402", "IOMobileFramebufferAP", "stop_signal", 0x0, 0x0),
    m(b"A403", "IOMobileFramebufferAP", "swap_begin", 0x0, 0x0),
    m(b"A404", "IOMobileFramebufferAP", "rotate_surface", 0xc, 0x4),
    m(b"A405", "IOMobileFramebufferAP", "get_framebuffer_id", 0x0, 0x4),
    m(b"A406", "IOMobileFramebufferAP", "swap_start_dcp", 0x10, 0x8),
    m(b"A407", "IOMobileFramebufferAP", "swap_submit_dcp", 0x1d30, 0xc),
    m(b"A408", "IOMobileFramebufferAP", "swap_submit_dcp_main", 0xff4, 0xc),
    m(b"A409", "IOMobileFramebufferAP", "swap_submit_dcp_blitter", 0xd48, 0x4),
    m(b"A410", "IOMobileFramebufferAP", "swap_signal", 0x8, 0x4),
    m(b"A411", "IOMobileFramebufferAP", "set_display_device", 0x4, 0x4),
    m(b"A412", "IOMobileFramebufferAP", "is_main_display", 0x0, 0x4),
    m(b"A413", "IOMobileFramebufferAP", "set_digital_out_mode", 0x8, 0x4),
    m(b"A414", "IOMobileFramebufferAP", "get_digital_out_state", 0x8, 0x8),
    m(b"A415", "IOMobileFramebufferAP", "get_display_area", 0xc, 0xc),
    m(b"A416", "IOMobileFramebufferAP", "set_tvout_mode", 0x4, 0x4),
    m(b"A417", "IOMobileFramebufferAP", "set_tvout_signaltype", 0x4, 0x4),
    m(b"A418", "IOMobileFramebufferAP", "set_wss_info", 0x8, 0x4),
    m(b"A419", "IOMobileFramebufferAP", "set_content_flags", 0x4, 0x0),
    m(b"A420", "IOMobileFramebufferAP", "get_gamma_table", 0xc10, 0xc10),
    m(b"A421", "IOMobileFramebufferAP", "set_gamma_table", 0xc10, 0xc10),
    m(b"A422", "IOMobileFramebufferAP", "get_matrix", 0x50, 0x4c),
    m(b"A423", "IOMobileFramebufferAP", "set_matrix", 0x50, 0x4),
    m(b"A424", "IOMobileFramebufferAP", "set_contrast", 0x8, 0x8),
    m(b"A425", "IOMobileFramebufferAP", "set_white_on_black_mode", 0x4, 0x4),
    m(b"A426", "IOMobileFramebufferAP", "set_color_remap_mode", 0x4, 0x4),
    m(b"A427", "IOMobileFramebufferAP", "get_color_remap_mode", 0x8, 0x8),
    m(b"A428", "IOMobileFramebufferAP", "setBrightnessCorrection", 0x4, 0x4),
    m(b"A429", "IOMobileFramebufferAP", "create_gain_map_dcp", 0x70, 0x10),
    m(b"A430", "IOMobileFramebufferAP", "set_gain_map_cap_buffer_dcp", 0x34, 0xc),
    m(b"A431", "IOMobileFramebufferAP", "delete_gain_map", 0x4, 0x4),
    m(b"A432", "IOMobileFramebufferAP", "create_lpr_metadata_dcp", 0x38, 0x10),
    m(b"A433", "IOMobileFramebufferAP", "delete_lpr_metadata", 0x4, 0x4),
    m(b"A434", "IOMobileFramebufferAP", "temp_queue_swap_cancel", 0x4, 0x4),
    m(b"A435", "IOMobileFramebufferAP", "swap_cancel", 0x4, 0x4),
    m(b"A436", "IOMobileFramebufferAP", "swap_cancel_all_dcp", 0x8, 0x4),
    m(b"A437", "IOMobileFramebufferAP", "surface_is_replaceable", 0x8, 0x8),
    m(b"A438", "IOMobileFramebufferAP", "kernel_tests", 0xa0, 0xa0),
    m(b"A439", "IOMobileFramebufferAP", "splc_set_brightness", 0x4, 0x4),
    m(b"A440", "IOMobileFramebufferAP", "splc_get_brightness", 0x8, 0x8),
    m(b"A441", "IOMobileFramebufferAP", "set_block_dcp", 0x106c, 0x4),
    m(b"A442", "IOMobileFramebufferAP", "get_block_dcp", 0x5c, 0x1004),
    m(b"A443", "IOMobileFramebufferAP", "abort_block_dcp", 0xc, 0x4),
    m(b"A444", "IOMobileFramebufferAP", "get_buf_block_dcp", 0x106c, 0x4),
    m(b"A445", "IOMobileFramebufferAP", "start_task_dcp", 0x18, 0x4),
    m(b"A446", "IOMobileFramebufferAP", "abort_task_dcp", 0xc, 0x4),
    m(b"A447", "IOMobileFramebufferAP", "check_task_status_dcp", 0xc, 0x4),
    m(b"A448", "IOMobileFramebufferAP", "get_block_size_dcp", 0x10, 0x8),
    m(b"A449", "IOMobileFramebufferAP", "swap_set_color_matrix", 0x84, 0x7c),
    m(b"A450", "IOMobileFramebufferAP", "set_parameter_dcp", 0x28, 0x4),
    m(b"A451", "IOMobileFramebufferAP", "display_width", 0x0, 0x4),
    m(b"A452", "IOMobileFramebufferAP", "display_height", 0x0, 0x4),
    m(b"A453", "IOMobileFramebufferAP", "get_display_size", 0x4, 0x8),
    m(b"A454", "IOMobileFramebufferAP", "do_create_default_frame_buffer", 0x0, 0x4),
    m(b"A455", "IOMobileFramebufferAP", "printRegs", 0x0, 0x0),
    m(b"A456", "IOMobileFramebufferAP", "enable_disable_dithering", 0x4, 0x4),
    m(b"A457", "IOMobileFramebufferAP", "set_underrun_color", 0x4, 0x4),
    m(b"A458", "IOMobileFramebufferAP", "enable_disable_video_power_savings", 0x4, 0x4),
    m(b"A459", "IOMobileFramebufferAP", "set_video_dac_gain", 0x4, 0x4),
    m(b"A460", "IOMobileFramebufferAP", "set_line21_data", 0x4, 0x4),
    m(b"A461", "IOMobileFramebufferAP", "enableInternalToExternalMirroring", 0x4, 0x4),
    m(b"A462", "IOMobileFramebufferAP", "getExternalMirroringCapability", 0x18, 0x18),
    m(b"A463", "IOMobileFramebufferAP", "setRenderingAngle", 0x8, 0x8),
    m(b"A464", "IOMobileFramebufferAP", "setOverscanSafeRegion", 0x14, 0x14),
    m(b"A465", "IOMobileFramebufferAP", "setSharedEventMemBlockSize", 0x8, 0x0),
    m(b"A466", "IOMobileFramebufferAP", "first_client_open", 0x0, 0x0),
    m(b"A467", "IOMobileFramebufferAP", "last_client_close_dcp", 0x4, 0x4),
    m(b"A468", "IOMobileFramebufferAP", "getDebugInfoBuffer", 0x4, 0xc),
    m(b"A469", "IOMobileFramebufferAP", "flush_debug_flags", 0x4, 0x0),
    m(b"A470", "IOMobileFramebufferAP", "io_fence_notify", 0x14, 0x4),
    m(b"A471", "IOMobileFramebufferAP", "swap_wait_dcp", 0x10, 0x4),
    m(b"A472", "IOMobileFramebufferAP", "get_link_quality_dcp", 0x0, 0x4),
    m(b"A473", "IOMobileFramebufferAP", "announce_next_swap_pts", 0x8, 0x4),
    m(b"A474", "IOMobileFramebufferAP", "set_ttr_buffer_dva", 0x10, 0x0),
    m(b"A475", "IOMobileFramebufferAP", "setDisplayRefreshProperties", 0x0, 0x4),
    m(b"A476", "IOMobileFramebufferAP", "exportProperty", 0x8, 0x0),
    m(b"A477", "IOMobileFramebufferAP", "applyProperty", 0x8, 0x4),
    m(b"A478", "IOMobileFramebufferAP", "flush_supportsPower", 0x4, 0x0),
    m(b"A479", "IOMobileFramebufferAP", "abort_swaps_dcp", 0x8, 0x4),
    m(b"A480", "IOMobileFramebufferAP", "remove_gain_maps", 0xc, 0xc),
    m(b"A481", "IOMobileFramebufferAP", "remove_lpr_metadata", 0xc, 0xc),
    m(b"A482", "IOMobileFramebufferAP", "update_dfb", 0x240, 0x4),
    m(b"A483", "IOMobileFramebufferAP", "update_dfb", 0x230, 0x4),
    m(b"A484", "IOMobileFramebufferAP", "setPowerState", 0x10, 0x8),
    m(b"A485", "IOMobileFramebufferAP", "isKeepOnScreen", 0x0, 0x4),
    m(b"A486", "IOMobileFramebufferAP", "resetStats", 0x0, 0x0),
    m(b"A487", "IOMobileFramebufferAP", "set_dcp_clamshellstate", 0x4, 0x0),
    m(b"A488", "IOMobileFramebufferAP", "send_clamshell_state_to_controller", 0x0, 0x4),
    m(b"A489", "IOMobileFramebufferAP", "get_shared_disp_state", 0x0, 0x4),
    m(b"A490", "IOMobileFramebufferAP", "set_has_frame_swap_function", 0x4, 0x0),
    m(b"A491", "IOMobileFramebufferAP", "getPerformanceStats", 0x4, 0x8),
    m(b"A492", "IOMobileFramebufferAP", "set_lpr_buffers", 0x34, 0x4),
    m(b"A500", "DCPPowerManager", "link_shutdown_signal", 0x4, 0x0),
    m(b"A501", "DCPPowerManager", "power_state_will_change_to", 0x10, 0x4),
];

/// The interface's callbacks.
#[rustfmt::skip]
pub const CALLBACKS: &[Callback] = &[
    c(b"D000", "UPPipeAP_H13P", "did_boot_signal", None, Some(0x4)),
    c(b"D001", "UPPipeAP_H13P", "did_power_on_signal", None, Some(0x4)),
    c(b"D002", "UPPipeAP_H13P", "will_power_off_signal", None, None),
    c(b"D003", "UPPipeAP_H13P", "rt_bandwidth_setup_ap", Some(0x4), Some(0x2c)),
    c(b"D004", "UPPipeAP_H13P", "", Some(0x8), None),
    c(b"D005", "UPPipeAP_H13P", "", Some(0x8), None),
    c(b"D006", "UPPipeAP_H13P", "set_frame_sync_props", Some(0x54), Some(0x50)),
    c(b"D007", "UPPipeAP_H13P", "", Some(0x8), Some(0x4)),
    c(b"D008", "UPPipeAP_H13P", "", Some(0xc), Some(0x4)),
    c(b"D100", "UnifiedPipeline", "match_pmu_service", None, None),
    c(b"D101", "UnifiedPipeline", "", None, Some(0x4)),
    c(b"D102", "UnifiedPipeline", "set_number_property", Some(0x44), None),
    c(b"D103", "UnifiedPipeline", "trigger_user_cal_loader", None, None),
    c(b"D104", "UnifiedPipeline", "set_boolean_property", Some(0x44), None),
    c(b"D105", "UnifiedPipeline", "set_string_property", Some(0x80), None),
    c(b"D106", "UnifiedPipeline", "", Some(0x40), None),
    c(b"D107", "UnifiedPipeline", "create_provider_service", None, Some(0x4)),
    c(b"D108", "UnifiedPipeline", "create_product_service", None, Some(0x4)),
    c(b"D109", "UnifiedPipeline", "create_PMU_service", None, Some(0x4)),
    c(b"D110", "UnifiedPipeline", "create_iomfb_service", None, Some(0x4)),
    c(b"D111", "UnifiedPipeline", "create_backlight_service", None, Some(0x4)),
    c(b"D112", "UnifiedPipeline", "create_nvram_service", None, Some(0x4)),
    c(b"D113", "UnifiedPipeline", "CoreAnalyticsSendEven", None, None),
    c(b"D114", "UnifiedPipeline", "get_tiling_state", Some(0x10), Some(0x8)),
    c(b"D115", "UnifiedPipeline", "set_tiling_state", Some(0x10), Some(0x4)),
    c(b"D116", "UnifiedPipeline", "set_idle_caching_state_ap", Some(0xc), None),
    c(b"D117", "UnifiedPipeline", "upload_trace_start", Some(0x14), Some(0x4)),
    c(b"D118", "UnifiedPipeline", "upload_trace_chunk", None, None),
    c(b"D119", "UnifiedPipeline", "upload_trace_end", Some(0x4), Some(0x4)),
    c(b"D120", "UnifiedPipeline", "start_hardware_boot", None, Some(0x4)),
    c(b"D121", "UnifiedPipeline", "is_dark_boot", None, Some(0x4)),
    c(b"D122", "UnifiedPipeline", "is_waking_from_hibernate", None, Some(0x4)),
    c(b"D123", "UnifiedPipeline", "detect_fastsim", None, Some(0x4)),
    c(b"D124", "UnifiedPipeline", "read_edt_data", Some(0x64), Some(0x24)),
    c(b"D125", "UnifiedPipeline", "read_edt_string", Some(0x48), Some(0x48)),
    c(b"D126", "UnifiedPipeline", "setDCPAVPropStart", Some(0x4), Some(0x4)),
    c(b"D127", "UnifiedPipeline", "setDCPAVPropChunk", Some(0x1008), Some(0x4)),
    c(b"D128", "UnifiedPipeline", "setDCPAVPropEnd", Some(0x40), Some(0x4)),
    c(b"D129", "UnifiedPipeline", "allocate_bandwidth", Some(0x1c), Some(0x14)),
    c(b"D130", "UnifiedPipeline", "update_ext_pipe_count", Some(0x8), None),
    c(b"D131", "UnifiedPipeline", "get_ext_pipe_count", Some(0x10), Some(0xc)),
    c(b"D132", "UnifiedPipeline", "apply_suppress", Some(0x4), None),
    c(b"D133", "UnifiedPipeline", "vi_is_displayX1", None, Some(0x4)),
    c(b"D200", "UPPipe", "", None, Some(0x4)),
    c(b"D201", "UPPipe", "get_buffer_by_id", Some(0xc), Some(0x10)),
    c(b"D202", "UPPipe", "get_buffer_by_id", Some(0x18), None),
    c(b"D203", "UPPipe", "aot_supported_peek", None, Some(0x4)),
    c(b"D204", "UPPipe", "get_ideal_screen_space", None, Some(0x4)),
    c(b"D205", "UPPipe", "read_carveout", Some(0xc), None),
    c(b"D206", "UPPipe", "match_pmu_service", None, Some(0x4)),
    c(b"D207", "UPPipe", "match_backlight_service", None, Some(0x4)),
    c(b"D208", "UPPipe", "update_backlight_factor_prop", Some(0x4), None),
    c(b"D209", "UPPipe", "get_calendar_time_ms", None, Some(0x8)),
    c(b"D210", "UPPipe", "setup_fcam_stats_config_ap", Some(0x4), Some(0x51c)),
    c(b"D211", "UPPipe", "allocate_ttr_buffer", Some(0x4), Some(0x14)),
    c(b"D300", "PropRelay", "", Some(0x10), None),
    c(b"D400", "ServiceRelay", "get_property", Some(0x4c), Some(0xc04)),
    c(b"D401", "ServiceRelay", "get_uint_prop", Some(0x50), Some(0xc)),
    c(b"D402", "ServiceRelay", "set_uint_prop", Some(0x4c), None),
    c(b"D403", "ServiceRelay", "get_uint_prop", Some(0x4c), Some(0x8)),
    c(b"D404", "ServiceRelay", "set_uint_prop", Some(0x48), None),
    c(b"D405", "ServiceRelay", "get_fx_prop", Some(0x4c), Some(0x8)),
    c(b"D406", "ServiceRelay", "set_fx_prop", Some(0x48), None),
    c(b"D407", "ServiceRelay", "set_bool_prop", Some(0x48), None),
    c(b"D408", "ServiceRelay", "getClockFrequency", Some(0x8), Some(0x8)),
    c(b"D409", "ServiceRelay", "enableDeviceClock", Some(0xc), Some(0x4)),
    c(b"D410", "ServiceRelay", "enableDevicePower", Some(0x14), Some(0x8)),
    c(b"D411", "ServiceRelay", "mapDeviceMemoryWithIndex", Some(0x10), Some(0x1c)),
    c(b"D412", "ServiceRelay", "", Some(0x448), None),
    c(b"D413", "ServiceRelay", "", None, None),
    c(b"D414", "ServiceRelay", "", Some(0x50), Some(0x4)),
    c(b"D415", "ServiceRelay", "setProperty", Some(0x4c), Some(0x4)),
    c(b"D416", "ServiceRelay", "setProperty", Some(0x84), Some(0x4)),
    c(b"D417", "ServiceRelay", "setProperty", Some(0x448), None),
    c(b"D418", "ServiceRelay", "setProperty", None, None),
    c(b"D419", "ServiceRelay", "setProperty", Some(0x50), Some(0x4)),
    c(b"D420", "ServiceRelay", "setProperty", Some(0x4c), Some(0x4)),
    c(b"D421", "ServiceRelay", "setProperty", Some(0x84), Some(0x4)),
    c(b"D422", "ServiceRelay", "setProperty", Some(0x48), Some(0x4)),
    c(b"D423", "ServiceRelay", "removeProperty", Some(0x44), None),
    c(b"D424", "ServiceRelay", "removeProperty", Some(0x44), None),
    c(b"D450", "MemDescRelay", "from_id", Some(0x8), Some(0x14)),
    c(b"D451", "MemDescRelay", "allocate_buffer", Some(0x14), Some(0x14)),
    c(b"D452", "MemDescRelay", "prepare", Some(0x8), Some(0x4)),
    c(b"D453", "MemDescRelay", "complete", Some(0x8), Some(0x4)),
    c(b"D454", "MemDescRelay", "release_descriptor", Some(0x4), Some(0x4)),
    c(b"D550", "IOMobileFramebuffer", "", Some(0x444), None),
    c(b"D551", "IOMobileFramebuffer", "", None, None),
    c(b"D552", "IOMobileFramebuffer", "", None, None),
    c(b"D553", "IOMobileFramebuffer", "", None, None),
    c(b"D554", "IOMobileFramebuffer", "", Some(0x4c), Some(0x4)),
    c(b"D555", "IOMobileFramebuffer", "", Some(0x4c), Some(0x4)),
    c(b"D556", "IOMobileFramebuffer", "", Some(0x48), Some(0x4)),
    c(b"D557", "IOMobileFramebuffer", "", Some(0x80), Some(0x4)),
    c(b"D558", "IOMobileFramebuffer", "", Some(0x80), Some(0x4)),
    c(b"D559", "IOMobileFramebuffer", "", Some(0x444), None),
    c(b"D560", "IOMobileFramebuffer", "", None, None),
    c(b"D561", "IOMobileFramebuffer", "", None, None),
    c(b"D562", "IOMobileFramebuffer", "", None, None),
    c(b"D563", "IOMobileFramebuffer", "", Some(0x4c), Some(0x4)),
    c(b"D564", "IOMobileFramebuffer", "", Some(0x4c), Some(0x4)),
    c(b"D565", "IOMobileFramebuffer", "", Some(0x48), Some(0x4)),
    c(b"D566", "IOMobileFramebuffer", "", Some(0x80), Some(0x4)),
    c(b"D567", "IOMobileFramebuffer", "", Some(0x80), Some(0x4)),
    c(b"D568", "IOMobileFramebuffer", "", Some(0x80), Some(0x4)),
    c(b"D569", "IOMobileFramebuffer", "", Some(0x44), Some(0x4)),
    c(b"D570", "IOMobileFramebuffer", "", None, None),
    c(b"D571", "IOMobileFramebuffer", "", Some(0x8), Some(0x4)),
    c(b"D572", "IOMobileFramebuffer", "powerUpDART", Some(0x4), Some(0x4)),
    c(b"D573", "IOMobileFramebuffer", "", Some(0x4), Some(0x8)),
    c(b"D574", "IOMobileFramebuffer", "", Some(0x4), Some(0x8)),
    c(b"D575", "IOMobileFramebuffer", "hotPlug_notify_gated", Some(0x58), Some(0x4c)),
    c(b"D576", "IOMobileFramebuffer", "", Some(0x4), None),
    c(b"D577", "IOMobileFramebuffer", "", Some(0x8), None),
    c(b"D578", "IOMobileFramebuffer", "", None, None),
    c(b"D579", "IOMobileFramebuffer", "", Some(0x4), Some(0x4)),
    c(b"D580", "IOMobileFramebuffer", "", None, None),
    c(b"D581", "IOMobileFramebuffer", "", None, None),
    c(b"D582", "IOMobileFramebuffer", "swap_complete_head_of_line", Some(0xc), None),
    c(b"D583", "IOMobileFramebuffer", "set_prox_sensing_needed", Some(0x4), None),
    c(b"D584", "IOMobileFramebuffer", "", None, None),
    c(b"D585", "IOMobileFramebuffer", "apt_quanta_switch_notify_dispatch", Some(0xc), None),
    c(b"D586", "IOMobileFramebuffer", "create_default_fb_surface", Some(0x8), Some(0x4)),
    c(b"D587", "IOMobileFramebuffer", "clear_default_surface", None, None),
    c(b"D588", "IOMobileFramebuffer", "swap_notify_gated", Some(0x18), None),
    c(b"D589", "IOMobileFramebuffer", "swap_info_notify_dispatch", Some(0xe4), Some(0xe0)),
    c(b"D590", "IOMobileFramebuffer", "relbufinfo_notify_dispatch", Some(0x14), None),
    c(b"D591", "IOMobileFramebuffer", "updateBufferMappingCount_gated", Some(0x4), Some(0x4)),
    c(b"D592", "IOMobileFramebuffer", "", None, None),
    c(b"D593", "IOMobileFramebuffer", "update_ap_hdcp_encryption_status", Some(0x8), None),
    c(b"D594", "IOMobileFramebuffer", "swap_complete_ap_gated", Some(0x730), None),
    c(b"D595", "IOMobileFramebuffer", "batched_swap_complete_ap_gated", None, None),
    c(b"D596", "IOMobileFramebuffer", "swap_complete_intent_gated", Some(0x14), None),
    c(b"D597", "IOMobileFramebuffer", "abort_swap_ap_gated", Some(0x4), None),
    c(b"D598", "IOMobileFramebuffer", "enable_backlight_message_ap_gated", Some(0x4), None),
    c(b"D599", "IOMobileFramebuffer", "setSystemConsoleMode", Some(0x4), None),
    c(b"D600", "IOMobileFramebuffer", "setSystemConsoleMode_gated", Some(0x4), None),
    c(b"D601", "IOMobileFramebuffer", "isDFBAllocated", None, Some(0x4)),
    c(b"D602", "IOMobileFramebuffer", "", None, Some(0x4)),
    c(b"D603", "IOMobileFramebuffer", "find_swap_function_gated", None, None),
    c(b"D700", "DCPPowerManager", "set_kernel_power_assert", Some(0x4), Some(0x4)),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tag_is_unique_and_well_formed() {
        for (i, method) in METHODS.iter().enumerate() {
            assert_eq!(method.tag[0], b'A');
            assert!(method.tag[1..].iter().all(u8::is_ascii_digit));
            assert!(METHODS[i + 1..].iter().all(|other| other.tag != method.tag));
            assert_eq!(method.input % 4, 0, "{}", tag_str(&method.tag));
            assert_eq!(method.output % 4, 0, "{}", tag_str(&method.tag));
        }
        for (i, callback) in CALLBACKS.iter().enumerate() {
            assert_eq!(callback.tag[0], b'D');
            assert!(
                CALLBACKS[i + 1..]
                    .iter()
                    .all(|other| other.tag != callback.tag)
            );
        }
    }

    #[test]
    fn the_public_interface_anchors_hold() {
        // m1n1 ipc.py (>= 14.7): A406 swap_start_dcp(unsigned int*, unsigned
        // long) packs to {u32, u64, null} = 13 -> 0x10, returning {u32, ret}.
        let start = method(b"A406").unwrap();
        assert_eq!(
            (start.name, start.input, start.output),
            ("swap_start_dcp", 0x10, 8)
        );
        // update_dfb(IOSurface*) is one 0x22c-byte IOSurface and its null
        // byte, padded: the >= 13.5 IOSurface size holds for this interface.
        assert_eq!(
            method(b"A483").unwrap().input,
            (0x22c_u32 + 1).next_multiple_of(4)
        );
        assert_eq!(method(b"A401").unwrap().name, "start_signal");
        assert_eq!(callback(b"D120").unwrap().name, "start_hardware_boot");
        assert_eq!(callback(b"D594").unwrap().input, Some(0x730));
        assert!(method(b"A999").is_none());
        // The 26A434 dispatch stubs: D127 takes data[0x1000], offset and
        // length and answers a bool; D575 packs u64 state, the 0x4b-byte
        // IOMFB_TiledDisplayInfo, a bool and the info's null flag, and
        // answers the info back.
        assert_eq!(
            (
                callback(b"D127").unwrap().input,
                callback(b"D127").unwrap().output
            ),
            (Some(0x1000 + 8), Some(4))
        );
        let hotplug = callback(b"D575").unwrap();
        assert_eq!(
            (hotplug.input, hotplug.output),
            (Some((8u32 + 0x4b + 1 + 1).next_multiple_of(4)), Some(0x4c))
        );
        // getVideoDataForIDs: timing 0x50, color 0x20, two u32, a bool and
        // three null flags in; the two records, the bool and the result out.
        assert_eq!(method(b"A364").unwrap().input, 0x50 + 0x20 + 8 + 1 + 3);
        assert_eq!(
            method(b"A364").unwrap().output,
            (0x50u32 + 0x20 + 2).next_multiple_of(4)
        );
    }

    #[test]
    fn packing_has_no_interior_alignment() {
        // {u32 swap_id, u64 client, bool swap_id_null}
        let input = Packed::new()
            .u32(7)
            .u64(0x1122)
            .bool(false)
            .finish(0x10)
            .unwrap();
        assert_eq!(input.len(), 0x10);
        let mut fields = Fields::new(&input);
        assert_eq!(fields.u32(), Ok(7));
        assert_eq!(fields.u64(), Ok(0x1122));
        assert_eq!(fields.bool(), Ok(false));
        assert!(Packed::new().u64(0).u64(0).finish(8).is_err());
        assert!(Fields::new(&[0; 3]).u32().is_err());
    }
}
