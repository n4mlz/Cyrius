#[derive(Clone, Copy)]
pub struct BootSectorConfig {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fats: u8,
    pub fat_size: u32,
    pub media: u8,
    pub total_sectors: u32,
    pub root_cluster: u32,
}
