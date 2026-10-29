/* SPDX-License-Identifier: MIT */
/* Compile the actual vendor declarations under both the full-core target and
 * Cargo's OS-hook target. Every active record/scalar measurement must match;
 * ordinary long is reported separately and never relaxes a record comparison.
 * Core builds use their genuine NvPort atomic/module defines; OS-hook builds
 * also define NV_KERNEL_INTERFACE_LAYER, as the real adapter headers do.
 * This fixture supplies constants only, no fake records or platform provider.
 */
#include <stddef.h>
#include "nv.h"
#include "stela_pci.h"
#include "libelf.h"

#define STELA_NVIDIA_RECORD_LAYOUT(M) \
    M("sizeof(nv_state_t)", sizeof(nv_state_t)) \
    M("alignof(nv_state_t)", _Alignof(nv_state_t)) \
    M("sizeof(nv_pci_info_t)", sizeof(nv_pci_info_t)) \
    M("alignof(nv_pci_info_t)", _Alignof(nv_pci_info_t)) \
    M("sizeof(nv_aperture_t)", sizeof(nv_aperture_t)) \
    M("alignof(nv_aperture_t)", _Alignof(nv_aperture_t)) \
    M("sizeof(nv_cached_gpu_info_t)", sizeof(nv_cached_gpu_info_t)) \
    M("alignof(nv_cached_gpu_info_t)", _Alignof(nv_cached_gpu_info_t)) \
    M("sizeof(nv_phys_addr_range_t)", sizeof(nv_phys_addr_range_t)) \
    M("alignof(nv_phys_addr_range_t)", _Alignof(nv_phys_addr_range_t)) \
    M("sizeof(nv_soc_irq_info_t)", sizeof(nv_soc_irq_info_t)) \
    M("alignof(nv_soc_irq_info_t)", _Alignof(nv_soc_irq_info_t)) \
    M("sizeof(nv_event_t)", sizeof(nv_event_t)) \
    M("alignof(nv_event_t)", _Alignof(nv_event_t)) \
    M("sizeof(nv_kern_mapping_t)", sizeof(nv_kern_mapping_t)) \
    M("alignof(nv_kern_mapping_t)", _Alignof(nv_kern_mapping_t)) \
    M("sizeof(nv_usermap_access_params_t)", sizeof(nv_usermap_access_params_t)) \
    M("alignof(nv_usermap_access_params_t)", _Alignof(nv_usermap_access_params_t)) \
    M("sizeof(nv_alloc_mapping_context_t)", sizeof(nv_alloc_mapping_context_t)) \
    M("alignof(nv_alloc_mapping_context_t)", _Alignof(nv_alloc_mapping_context_t)) \
    M("sizeof(nv_alloc_mapping_list_node_t)", sizeof(nv_alloc_mapping_list_node_t)) \
    M("alignof(nv_alloc_mapping_list_node_t)", _Alignof(nv_alloc_mapping_list_node_t)) \
    M("sizeof(nvidia_stack_t)", sizeof(nvidia_stack_t)) \
    M("alignof(nvidia_stack_t)", _Alignof(nvidia_stack_t)) \
    M("sizeof(LibosElf64Header)", sizeof(LibosElf64Header)) \
    M("alignof(LibosElf64Header)", _Alignof(LibosElf64Header)) \
    M("sizeof(LibosElf64SectionHeader)", sizeof(LibosElf64SectionHeader)) \
    M("alignof(LibosElf64SectionHeader)", _Alignof(LibosElf64SectionHeader)) \
    M("sizeof(struct stela_nvidia_pci)", sizeof(struct stela_nvidia_pci)) \
    M("alignof(struct stela_nvidia_pci)", _Alignof(struct stela_nvidia_pci)) \
    M("sizeof(nv_firmware_type_t)", sizeof(nv_firmware_type_t)) \
    M("alignof(nv_firmware_type_t)", _Alignof(nv_firmware_type_t)) \
    M("sizeof(nv_firmware_chip_family_t)", sizeof(nv_firmware_chip_family_t)) \
    M("alignof(nv_firmware_chip_family_t)", _Alignof(nv_firmware_chip_family_t)) \
    M("sizeof(NvBool)", sizeof(NvBool)) \
    M("alignof(NvBool)", _Alignof(NvBool)) \
    M("sizeof(NvLength)", sizeof(NvLength)) \
    M("alignof(NvLength)", _Alignof(NvLength)) \
    M("sizeof(NvUPtr)", sizeof(NvUPtr)) \
    M("alignof(NvUPtr)", _Alignof(NvUPtr)) \
    M("sizeof(NV_STATUS)", sizeof(NV_STATUS)) \
    M("alignof(NV_STATUS)", _Alignof(NV_STATUS)) \
    M("sizeof(void *)", sizeof(void *)) \
    M("alignof(void *)", _Alignof(void *)) \
    M("offsetof(nv_state_t,priv)", offsetof(nv_state_t,priv)) \
    M("offsetof(nv_state_t,os_state)", offsetof(nv_state_t,os_state)) \
    M("offsetof(nv_state_t,flags)", offsetof(nv_state_t,flags)) \
    M("offsetof(nv_state_t,pci_info)", offsetof(nv_state_t,pci_info)) \
    M("offsetof(nv_state_t,subsystem_id)", offsetof(nv_state_t,subsystem_id)) \
    M("offsetof(nv_state_t,subsystem_vendor)", offsetof(nv_state_t,subsystem_vendor)) \
    M("offsetof(nv_state_t,gpu_id)", offsetof(nv_state_t,gpu_id)) \
    M("offsetof(nv_state_t,iovaspace_id)", offsetof(nv_state_t,iovaspace_id)) \
    M("offsetof(nv_state_t,nv_uuid_cache)", offsetof(nv_state_t,nv_uuid_cache)) \
    M("offsetof(nv_state_t,handle)", offsetof(nv_state_t,handle)) \
    M("offsetof(nv_state_t,pci_cfg_space)", offsetof(nv_state_t,pci_cfg_space)) \
    M("offsetof(nv_state_t,bars)", offsetof(nv_state_t,bars)) \
    M("offsetof(nv_state_t,regs)", offsetof(nv_state_t,regs)) \
    M("offsetof(nv_state_t,dpaux)", offsetof(nv_state_t,dpaux)) \
    M("offsetof(nv_state_t,hdacodec_regs)", offsetof(nv_state_t,hdacodec_regs)) \
    M("offsetof(nv_state_t,mipical_regs)", offsetof(nv_state_t,mipical_regs)) \
    M("offsetof(nv_state_t,fb)", offsetof(nv_state_t,fb)) \
    M("offsetof(nv_state_t,ud)", offsetof(nv_state_t,ud)) \
    M("offsetof(nv_state_t,simregs)", offsetof(nv_state_t,simregs)) \
    M("offsetof(nv_state_t,num_dpaux_instance)", offsetof(nv_state_t,num_dpaux_instance)) \
    M("offsetof(nv_state_t,interrupt_line)", offsetof(nv_state_t,interrupt_line)) \
    M("offsetof(nv_state_t,dpaux_irqs)", offsetof(nv_state_t,dpaux_irqs)) \
    M("offsetof(nv_state_t,dpaux_devname)", offsetof(nv_state_t,dpaux_devname)) \
    M("offsetof(nv_state_t,soc_irq_info)", offsetof(nv_state_t,soc_irq_info)) \
    M("offsetof(nv_state_t,current_soc_irq)", offsetof(nv_state_t,current_soc_irq)) \
    M("offsetof(nv_state_t,num_soc_irqs)", offsetof(nv_state_t,num_soc_irqs)) \
    M("offsetof(nv_state_t,hdacodec_irq)", offsetof(nv_state_t,hdacodec_irq)) \
    M("offsetof(nv_state_t,tcpc2disp_irq)", offsetof(nv_state_t,tcpc2disp_irq)) \
    M("offsetof(nv_state_t,soc_dcb_blob)", offsetof(nv_state_t,soc_dcb_blob)) \
    M("offsetof(nv_state_t,soc_dcb_size)", offsetof(nv_state_t,soc_dcb_size)) \
    M("offsetof(nv_state_t,disp_sw_soc_chip_id)", offsetof(nv_state_t,disp_sw_soc_chip_id)) \
    M("offsetof(nv_state_t,soc_is_dpalt_mode_supported)", offsetof(nv_state_t,soc_is_dpalt_mode_supported)) \
    M("offsetof(nv_state_t,soc_is_hfrp_supported)", offsetof(nv_state_t,soc_is_hfrp_supported)) \
    M("offsetof(nv_state_t,soc_is_external_phy_supported)", offsetof(nv_state_t,soc_is_external_phy_supported)) \
    M("offsetof(nv_state_t,dma_mask)", offsetof(nv_state_t,dma_mask)) \
    M("offsetof(nv_state_t,is_tegra_pci_igpu)", offsetof(nv_state_t,is_tegra_pci_igpu)) \
    M("offsetof(nv_state_t,supports_tegra_igpu_rg)", offsetof(nv_state_t,supports_tegra_igpu_rg)) \
    M("offsetof(nv_state_t,is_tegra_pci_igpu_rg_enabled)", offsetof(nv_state_t,is_tegra_pci_igpu_rg_enabled)) \
    M("offsetof(nv_state_t,tegra_pci_igpu_pg_mask)", offsetof(nv_state_t,tegra_pci_igpu_pg_mask)) \
    M("offsetof(nv_state_t,gpc_fuse_status_offset)", offsetof(nv_state_t,gpc_fuse_status_offset)) \
    M("offsetof(nv_state_t,primary_vga)", offsetof(nv_state_t,primary_vga)) \
    M("offsetof(nv_state_t,sim_env)", offsetof(nv_state_t,sim_env)) \
    M("offsetof(nv_state_t,rc_timer_enabled)", offsetof(nv_state_t,rc_timer_enabled)) \
    M("offsetof(nv_state_t,event_list)", offsetof(nv_state_t,event_list)) \
    M("offsetof(nv_state_t,event_spinlock)", offsetof(nv_state_t,event_spinlock)) \
    M("offsetof(nv_state_t,kern_mappings)", offsetof(nv_state_t,kern_mappings)) \
    M("offsetof(nv_state_t,dma_dev)", offsetof(nv_state_t,dma_dev)) \
    M("offsetof(nv_state_t,niso_dma_dev)", offsetof(nv_state_t,niso_dma_dev)) \
    M("offsetof(nv_state_t,queue)", offsetof(nv_state_t,queue)) \
    M("offsetof(nv_state_t,request_firmware)", offsetof(nv_state_t,request_firmware)) \
    M("offsetof(nv_state_t,request_fw_client_rm)", offsetof(nv_state_t,request_fw_client_rm)) \
    M("offsetof(nv_state_t,allow_fallback_to_monolithic_rm)", offsetof(nv_state_t,allow_fallback_to_monolithic_rm)) \
    M("offsetof(nv_state_t,enable_firmware_logs)", offsetof(nv_state_t,enable_firmware_logs)) \
    M("offsetof(nv_state_t,removed)", offsetof(nv_state_t,removed)) \
    M("offsetof(nv_state_t,console_device)", offsetof(nv_state_t,console_device)) \
    M("offsetof(nv_state_t,is_external_gpu)", offsetof(nv_state_t,is_external_gpu)) \
    M("offsetof(nv_state_t,preserve_vidmem_allocations)", offsetof(nv_state_t,preserve_vidmem_allocations)) \
    M("offsetof(nv_state_t,force_dma32_alloc)", offsetof(nv_state_t,force_dma32_alloc)) \
    M("offsetof(nv_state_t,d0_state_in_suspend)", offsetof(nv_state_t,d0_state_in_suspend)) \
    M("offsetof(nv_state_t,profiler_owner)", offsetof(nv_state_t,profiler_owner)) \
    M("offsetof(nv_state_t,profiler_context)", offsetof(nv_state_t,profiler_context)) \
    M("offsetof(nv_state_t,rmapi)", offsetof(nv_state_t,rmapi)) \
    M("offsetof(nv_state_t,dma_buf_supported)", offsetof(nv_state_t,dma_buf_supported)) \
    M("offsetof(nv_state_t,is_shutdown)", offsetof(nv_state_t,is_shutdown)) \
    M("offsetof(nv_state_t,coherent)", offsetof(nv_state_t,coherent)) \
    M("offsetof(nv_state_t,mem_has_struct_page)", offsetof(nv_state_t,mem_has_struct_page)) \
    M("offsetof(nv_state_t,coherent_gpu_mem_mode)", offsetof(nv_state_t,coherent_gpu_mem_mode)) \
    M("offsetof(nv_state_t,ats_support)", offsetof(nv_state_t,ats_support)) \
    M("offsetof(nv_state_t,cpu_numa_node_id)", offsetof(nv_state_t,cpu_numa_node_id)) \
    M("offsetof(nv_state_t,iommus)", offsetof(nv_state_t,iommus)) \
    M("offsetof(nv_state_t,clocks)", offsetof(nv_state_t,clocks)) \
    M("offsetof(nv_state_t,client_managed_console)", offsetof(nv_state_t,client_managed_console)) \
    M("offsetof(nv_state_t,sysmem_mapped_console)", offsetof(nv_state_t,sysmem_mapped_console)) \
    M("offsetof(nv_state_t,cached_gpu_info)", offsetof(nv_state_t,cached_gpu_info)) \
    M("offsetof(nv_state_t,is_pm_unsupported)", offsetof(nv_state_t,is_pm_unsupported)) \
    M("offsetof(nv_state_t,is_cxl_dev)", offsetof(nv_state_t,is_cxl_dev)) \
    M("offsetof(nv_state_t,cached_persistence_mode)", offsetof(nv_state_t,cached_persistence_mode)) \
    M("offsetof(nv_state_t,nv_uuid_cache.valid)", offsetof(nv_state_t,nv_uuid_cache.valid)) \
    M("offsetof(nv_state_t,nv_uuid_cache.uuid)", offsetof(nv_state_t,nv_uuid_cache.uuid)) \
    M("offsetof(nv_state_t,nv_uuid_cache.pci_uuid_read_attempted)", offsetof(nv_state_t,nv_uuid_cache.pci_uuid_read_attempted)) \
    M("offsetof(nv_state_t,nv_uuid_cache.pci_uuid_from_dvsec_pdi)", offsetof(nv_state_t,nv_uuid_cache.pci_uuid_from_dvsec_pdi)) \
    M("offsetof(nv_state_t,nv_uuid_cache.pci_uuid_status)", offsetof(nv_state_t,nv_uuid_cache.pci_uuid_status)) \
    M("offsetof(nv_state_t,pci_info.domain)", offsetof(nv_state_t,pci_info.domain)) \
    M("offsetof(nv_state_t,pci_info.bus)", offsetof(nv_state_t,pci_info.bus)) \
    M("offsetof(nv_state_t,pci_info.slot)", offsetof(nv_state_t,pci_info.slot)) \
    M("offsetof(nv_state_t,pci_info.function)", offsetof(nv_state_t,pci_info.function)) \
    M("offsetof(nv_state_t,rmapi.hClient)", offsetof(nv_state_t,rmapi.hClient)) \
    M("offsetof(nv_state_t,iommus.iso_iommu_present)", offsetof(nv_state_t,iommus.iso_iommu_present)) \
    M("offsetof(nv_state_t,iommus.dispIsoStreamId)", offsetof(nv_state_t,iommus.dispIsoStreamId)) \
    M("offsetof(nv_state_t,clocks.max_dispclk_rate_using_disppllkhz)", offsetof(nv_state_t,clocks.max_dispclk_rate_using_disppllkhz)) \
    M("offsetof(nv_pci_info_t,domain)", offsetof(nv_pci_info_t,domain)) \
    M("offsetof(nv_pci_info_t,bus)", offsetof(nv_pci_info_t,bus)) \
    M("offsetof(nv_pci_info_t,slot)", offsetof(nv_pci_info_t,slot)) \
    M("offsetof(nv_pci_info_t,function)", offsetof(nv_pci_info_t,function)) \
    M("offsetof(nv_pci_info_t,vendor_id)", offsetof(nv_pci_info_t,vendor_id)) \
    M("offsetof(nv_pci_info_t,device_id)", offsetof(nv_pci_info_t,device_id)) \
    M("offsetof(nv_aperture_t,cpu_address)", offsetof(nv_aperture_t,cpu_address)) \
    M("offsetof(nv_aperture_t,size)", offsetof(nv_aperture_t,size)) \
    M("offsetof(nv_aperture_t,offset)", offsetof(nv_aperture_t,offset)) \
    M("offsetof(nv_aperture_t,map)", offsetof(nv_aperture_t,map)) \
    M("offsetof(nv_aperture_t,map_u)", offsetof(nv_aperture_t,map_u)) \
    M("offsetof(struct stela_nvidia_pci,context)", offsetof(struct stela_nvidia_pci,context)) \
    M("offsetof(struct stela_nvidia_pci,read)", offsetof(struct stela_nvidia_pci,read)) \
    M("offsetof(struct stela_nvidia_pci,write)", offsetof(struct stela_nvidia_pci,write))

#define STELA_LAYOUT_VALUE(label, expression) (expression),
const unsigned long long stela_nvidia_record_layout_values[] = {
    STELA_NVIDIA_RECORD_LAYOUT(STELA_LAYOUT_VALUE)
};
#undef STELA_LAYOUT_VALUE

#define STELA_LAYOUT_LABEL(label, expression) (label),
const char *const stela_nvidia_record_layout_labels[] = {
    STELA_NVIDIA_RECORD_LAYOUT(STELA_LAYOUT_LABEL)
};
#undef STELA_LAYOUT_LABEL

const unsigned long long stela_nvidia_record_layout_count =
    sizeof(stela_nvidia_record_layout_values) / sizeof(stela_nvidia_record_layout_values[0]);

/* LP64 hosted tests do not exchange pointers/callers with the Win64 core.
 * These two platform facts are deliberately outside the active-record vector.
 */
const unsigned long long stela_nvidia_platform_long[] = {sizeof(long), _Alignof(long)};
