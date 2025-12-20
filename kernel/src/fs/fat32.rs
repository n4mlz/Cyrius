//! Minimal read-only FAT32 implementation backed by a `BlockDevice`.
//!
//! # Implicit dependency
//! Assumes the underlying block device uses a 512-byte logical sector, matching the test images
//! generated in `xtask`. Larger sector sizes are rejected during mount to avoid partial-sector
//! reads until buffering support is added. Only FAT32 BPBs are accepted; FAT12/16 layouts are
//! rejected early because the kernel does not implement their directory layout.

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

use crate::device::block::BlockDevice;
use crate::util::spinlock::SpinLock;

use super::{DirEntry, Directory, File, FileType, Metadata, NodeRef, PathComponent, VfsError};

const FAT32_SIGNATURE: [u8; 2] = [0x55, 0xAA];
const ATTR_LONG_NAME: u8 = 0x0F;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_VOLUME_ID: u8 = 0x08;
#[allow(dead_code)]
const ATTR_ARCHIVE: u8 = 0x20;
const END_OF_CHAIN: u32 = 0x0FFFFFF8;
const BAD_CLUSTER: u32 = 0x0FFFFFF7;
const LFN_CHARS_PER_ENTRY: usize = 13;

#[derive(Debug)]
pub enum FatError {
    UnsupportedSectorSize(u16),
    InvalidBootSector,
    InvalidCluster(u32),
    DeviceError,
    UnexpectedEof,
    Corrupted,
    NotFound,
}

impl From<FatError> for VfsError {
    fn from(value: FatError) -> Self {
        match value {
            FatError::UnsupportedSectorSize(_) => VfsError::UnderlyingDevice,
            FatError::InvalidBootSector => VfsError::Corrupted,
            FatError::InvalidCluster(_) => VfsError::Corrupted,
            FatError::DeviceError => VfsError::UnderlyingDevice,
            FatError::UnexpectedEof => VfsError::UnexpectedEof,
            FatError::Corrupted => VfsError::Corrupted,
            FatError::NotFound => VfsError::NotFound,
        }
    }
}

pub struct FatFileSystem<D: BlockDevice + Send> {
    root: Arc<FatDirectory<D>>,
}

impl<D: BlockDevice + Send> FatFileSystem<D> {
    pub fn new(mut device: D) -> Result<Self, FatError> {
        let block_size = device.block_size();
        if block_size != 512 {
            return Err(FatError::UnsupportedSectorSize(block_size as u16));
        }

        let mut sector0 = [0u8; 512];
        device
            .read_blocks(0, &mut sector0)
            .map_err(|_| FatError::DeviceError)?;

        let bpb = BiosParameterBlock::parse(&sector0)?;
        if bpb.bytes_per_sector != block_size as u16 {
            return Err(FatError::UnsupportedSectorSize(bpb.bytes_per_sector));
        }
        let volume = Arc::new(FatVolume::new(device, bpb)?);
        let chain = volume.cluster_chain(volume.bpb.root_cluster)?;
        let root = Arc::new(FatDirectory {
            volume: volume.clone(),
            chain,
        });
        Ok(Self { root })
    }

    pub fn root_dir(&self) -> Arc<FatDirectory<D>> {
        self.root.clone()
    }
}

impl<D: BlockDevice + Send + 'static> From<FatFileSystem<D>> for Arc<dyn Directory> {
    fn from(fs: FatFileSystem<D>) -> Self {
        fs.root_dir()
    }
}

struct FatVolume<D: BlockDevice + Send> {
    device: SpinLock<D>,
    bpb: BiosParameterBlock,
    fat_start: u64,
    data_start: u64,
    cluster_size: u32,
    max_cluster: u32,
    fat_cache: SpinLock<FatCache>,
}

impl<D: BlockDevice + Send> FatVolume<D> {
    fn new(device: D, bpb: BiosParameterBlock) -> Result<Self, FatError> {
        let fat_start = u64::from(bpb.reserved_sector_count) * bpb.bytes_per_sector as u64;
        let fat_len = bpb
            .fat_size_sectors()
            .checked_mul(bpb.bytes_per_sector as u64)
            .ok_or(FatError::Corrupted)?;
        let fat_bytes = u64::from(bpb.num_fats)
            .checked_mul(fat_len)
            .ok_or(FatError::Corrupted)?;
        let data_start = fat_start
            .checked_add(fat_bytes)
            .ok_or(FatError::Corrupted)?;
        let cluster_size = u32::from(bpb.bytes_per_sector) * u32::from(bpb.sectors_per_cluster);
        let total_sectors = bpb.total_sectors();
        let fat_sectors = u64::from(bpb.num_fats) * bpb.fat_size_sectors();
        let data_sectors = total_sectors
            .checked_sub(u64::from(bpb.reserved_sector_count) + fat_sectors)
            .ok_or(FatError::Corrupted)?;
        let data_clusters: u32 = (data_sectors / u64::from(bpb.sectors_per_cluster))
            .try_into()
            .map_err(|_| FatError::Corrupted)?;
        let max_cluster = data_clusters.saturating_add(1); // clusters start at 2

        if cluster_size == 0 {
            return Err(FatError::Corrupted);
        }

        Ok(Self {
            device: SpinLock::new(device),
            bpb,
            fat_start,
            data_start,
            cluster_size,
            max_cluster,
            fat_cache: SpinLock::new(FatCache::new(bpb.bytes_per_sector as usize)),
        })
    }

    fn cluster_offset(&self, cluster: u32) -> Result<u64, FatError> {
        if cluster < 2 {
            return Err(FatError::InvalidCluster(cluster));
        }
        let index = u64::from(cluster - 2);
        let offset = index
            .checked_mul(self.cluster_size as u64)
            .and_then(|v| v.checked_add(self.data_start))
            .ok_or(FatError::Corrupted)?;
        Ok(offset)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FatError> {
        const MAX_BLOCKS_PER_READ: usize = 32; // limit DMA buffer size (~16KiB)
        let block_size = self.bpb.bytes_per_sector as usize;
        if buf.is_empty() {
            return Ok(());
        }

        let mut remaining = buf.len();
        let mut written = 0usize;
        let mut cursor = offset;

        while remaining > 0 {
            let cursor_usize: usize = cursor.try_into().map_err(|_| FatError::Corrupted)?;
            let start_block = cursor_usize / block_size;
            let within_block = cursor_usize % block_size;

            let max_bytes = remaining.min(MAX_BLOCKS_PER_READ * block_size - within_block);
            let block_span = ((within_block + max_bytes).div_ceil(block_size)).max(1);

            let num_blocks = self.device.lock().num_blocks();
            let end_block = start_block
                .checked_add(block_span)
                .ok_or(FatError::Corrupted)?;
            if u64::try_from(end_block).map_err(|_| FatError::Corrupted)? > num_blocks {
                return Err(FatError::UnexpectedEof);
            }

            let mut scratch = vec![0u8; block_span * block_size];
            {
                let mut dev = self.device.lock();
                if let Err(err) = dev.read_blocks(start_block as u64, &mut scratch) {
                    crate::println!(
                        "[fat32] read error {:?} blocks={} start={} cursor={} remaining={}",
                        err,
                        block_span,
                        start_block,
                        cursor,
                        remaining
                    );
                    return Err(FatError::DeviceError);
                }
            }

            let start = within_block;
            let end = start + max_bytes;
            buf[written..written + max_bytes].copy_from_slice(&scratch[start..end]);

            written += max_bytes;
            remaining -= max_bytes;
            cursor = cursor
                .checked_add(max_bytes as u64)
                .ok_or(FatError::Corrupted)?;
        }

        Ok(())
    }

    fn read_cluster(&self, cluster: u32) -> Result<Vec<u8>, FatError> {
        let offset = self.cluster_offset(cluster)?;
        let mut buf = vec![0u8; self.cluster_size as usize];
        self.read_at(offset, &mut buf)?;
        Ok(buf)
    }

    fn read_fat_entry(&self, cluster: u32) -> Result<u32, FatError> {
        let fat_offset = u64::from(cluster) * 4;
        let sector_index = (fat_offset / u64::from(self.bpb.bytes_per_sector)) as u32;
        let within_sector = (fat_offset % u64::from(self.bpb.bytes_per_sector)) as usize;

        let mut cache = self.fat_cache.lock();
        let sector = cache.read_sector(sector_index, self)?;
        let slice = sector
            .get(within_sector..within_sector + 4)
            .ok_or(FatError::UnexpectedEof)?;
        Ok(u32::from_le_bytes(
            slice.try_into().expect("slice length verified"),
        ))
    }

    fn cluster_chain(&self, start: u32) -> Result<Vec<u32>, FatError> {
        if start < 2 {
            return Err(FatError::InvalidCluster(start));
        }
        let mut chain = Vec::new();
        let mut current = start;
        loop {
            if current >= END_OF_CHAIN {
                break;
            }
            if current >= self.max_cluster {
                return Err(FatError::Corrupted);
            }
            chain.push(current);
            let next = self.read_fat_entry(current)?;
            if next == BAD_CLUSTER {
                return Err(FatError::Corrupted);
            }
            if next >= END_OF_CHAIN {
                break;
            }
            if chain.contains(&next) {
                return Err(FatError::Corrupted);
            }
            current = next;
        }
        Ok(chain)
    }
}

struct FatCache {
    cached_sector: Option<u32>,
    data: Box<[u8]>,
}

impl FatCache {
    fn new(sector_size: usize) -> Self {
        Self {
            cached_sector: None,
            data: vec![0u8; sector_size].into_boxed_slice(),
        }
    }

    fn read_sector<D: BlockDevice + Send>(
        &mut self,
        sector: u32,
        volume: &FatVolume<D>,
    ) -> Result<&[u8], FatError> {
        if self.cached_sector == Some(sector) {
            return Ok(&self.data);
        }

        let offset = volume
            .fat_start
            .checked_add(u64::from(sector) * volume.bpb.bytes_per_sector as u64)
            .ok_or(FatError::Corrupted)?;
        self.fill_from(offset, volume)?;
        self.cached_sector = Some(sector);
        Ok(&self.data)
    }

    fn fill_from<D: BlockDevice + Send>(
        &mut self,
        offset: u64,
        volume: &FatVolume<D>,
    ) -> Result<(), FatError> {
        volume
            .read_at(offset, &mut self.data)
            .map_err(|_| FatError::DeviceError)
    }
}

#[derive(Clone, Copy)]
struct BiosParameterBlock {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sector_count: u16,
    num_fats: u8,
    fat_size_32: u32,
    root_cluster: u32,
    total_sectors_32: u32,
}

impl BiosParameterBlock {
    fn parse(sector0: &[u8]) -> Result<Self, FatError> {
        if sector0.len() < 512 {
            return Err(FatError::InvalidBootSector);
        }

        if sector0[510..512] != FAT32_SIGNATURE {
            return Err(FatError::InvalidBootSector);
        }

        let bytes_per_sector = u16::from_le_bytes([sector0[11], sector0[12]]);
        let sectors_per_cluster = sector0[13];
        let reserved_sector_count = u16::from_le_bytes([sector0[14], sector0[15]]);
        let num_fats = sector0[16];
        let total_sectors_16 = u16::from_le_bytes([sector0[19], sector0[20]]);
        let total_sectors_32 =
            u32::from_le_bytes([sector0[32], sector0[33], sector0[34], sector0[35]]);
        let fat_size_16 = u16::from_le_bytes([sector0[22], sector0[23]]);
        let fat_size_32 = u32::from_le_bytes([sector0[36], sector0[37], sector0[38], sector0[39]]);
        let root_cluster = u32::from_le_bytes([sector0[44], sector0[45], sector0[46], sector0[47]]);

        if bytes_per_sector == 0 || sectors_per_cluster == 0 || num_fats == 0 {
            return Err(FatError::InvalidBootSector);
        }

        if fat_size_16 != 0 || total_sectors_16 != 0 {
            return Err(FatError::InvalidBootSector);
        }

        if fat_size_32 == 0 || root_cluster < 2 {
            return Err(FatError::InvalidBootSector);
        }

        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sector_count,
            num_fats,
            fat_size_32,
            root_cluster,
            total_sectors_32,
        })
    }

    fn fat_size_sectors(&self) -> u64 {
        u64::from(self.fat_size_32)
    }

    fn total_sectors(&self) -> u64 {
        u64::from(self.total_sectors_32)
    }
}

pub struct FatDirectory<D: BlockDevice + Send> {
    volume: Arc<FatVolume<D>>,
    chain: Vec<u32>,
}

impl<D: BlockDevice + Send + 'static> Directory for FatDirectory<D> {
    fn metadata(&self) -> Result<Metadata, VfsError> {
        Ok(Metadata {
            file_type: FileType::Directory,
            size: u64::from(self.chain.len() as u32) * u64::from(self.volume.cluster_size),
        })
    }

    fn read_dir(&self) -> Result<Vec<DirEntry>, VfsError> {
        let mut entries = Vec::new();
        for cluster in &self.chain {
            let data = self
                .volume
                .read_cluster(*cluster)
                .map_err(|_| VfsError::UnderlyingDevice)?;
            for entry in DirectoryEntries::new(&data) {
                let entry = entry?;
                if entry.is_volume() {
                    continue;
                }
                if entry.first_cluster < 2 {
                    continue;
                }
                entries.push(DirEntry {
                    name: entry.name.clone(),
                    metadata: entry.metadata(),
                });
            }
        }
        Ok(entries)
    }

    fn lookup(&self, name: &PathComponent) -> Result<NodeRef, VfsError> {
        let target = normalise_name(name.as_str());
        for cluster in &self.chain {
            let data = self
                .volume
                .read_cluster(*cluster)
                .map_err(|_| VfsError::UnderlyingDevice)?;
            for entry in DirectoryEntries::new(&data) {
                let entry = entry?;
                if entry.is_volume() {
                    continue;
                }
                if entry.first_cluster < 2 {
                    continue;
                }
                if entry.cmp_name == target {
                    return match entry.kind {
                        FileType::Directory => Ok(NodeRef::Directory(Arc::new(FatDirectory {
                            volume: self.volume.clone(),
                            chain: self
                                .volume
                                .cluster_chain(entry.first_cluster)
                                .map_err(|_| VfsError::Corrupted)?,
                        }))),
                        FileType::File => Ok(NodeRef::File(Arc::new(FatFile {
                            volume: self.volume.clone(),
                            clusters: self
                                .volume
                                .cluster_chain(entry.first_cluster)
                                .map_err(|_| VfsError::Corrupted)?,
                            size: entry.file_size,
                        }))),
                        FileType::Symlink => Err(VfsError::NotFound),
                    };
                }
            }
        }
        Err(VfsError::NotFound)
    }
}

pub struct FatFile<D: BlockDevice + Send> {
    volume: Arc<FatVolume<D>>,
    clusters: Vec<u32>,
    size: u32,
}

impl<D: BlockDevice + Send + 'static> File for FatFile<D> {
    fn metadata(&self) -> Result<Metadata, VfsError> {
        Ok(Metadata {
            file_type: FileType::File,
            size: u64::from(self.size),
        })
    }

    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, VfsError> {
        if offset as u64 >= u64::from(self.size) {
            return Ok(0);
        }
        let remaining = (self.size as usize)
            .checked_sub(offset)
            .ok_or(VfsError::Corrupted)?;
        let to_read = remaining.min(buf.len());
        let cluster_size = self.volume.cluster_size as usize;
        let mut copied = 0usize;
        let mut cursor = offset;

        while copied < to_read {
            let cluster_index = cursor / cluster_size;
            let within = cursor % cluster_size;
            let cluster = *self
                .clusters
                .get(cluster_index)
                .ok_or(VfsError::UnexpectedEof)?;
            let data = self
                .volume
                .read_cluster(cluster)
                .map_err(|_| VfsError::UnderlyingDevice)?;
            let available = (cluster_size - within).min(to_read - copied);
            buf[copied..copied + available].copy_from_slice(&data[within..within + available]);
            copied += available;
            cursor += available;
        }

        Ok(copied)
    }
}

#[derive(Debug, Clone)]
struct ParsedDirEntry {
    name: String,
    cmp_name: String,
    kind: FileType,
    first_cluster: u32,
    file_size: u32,
    attr: u8,
}

impl ParsedDirEntry {
    fn metadata(&self) -> Metadata {
        Metadata {
            file_type: self.kind,
            size: u64::from(self.file_size),
        }
    }

    fn is_volume(&self) -> bool {
        self.attr & ATTR_VOLUME_ID != 0
    }
}

struct DirectoryEntries<'a> {
    data: &'a [u8],
    index: usize,
    long_name: LongNameAccumulator,
}

impl<'a> DirectoryEntries<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            index: 0,
            long_name: LongNameAccumulator::new(),
        }
    }
}

impl<'a> Iterator for DirectoryEntries<'a> {
    type Item = Result<ParsedDirEntry, VfsError>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index + 32 <= self.data.len() {
            let entry = &self.data[self.index..self.index + 32];
            self.index += 32;

            if entry[0] == 0x00 {
                return None;
            }
            if entry[0] == 0xE5 {
                self.long_name.clear();
                continue;
            }
            let attr = entry[11];
            if attr & ATTR_LONG_NAME == ATTR_LONG_NAME {
                match parse_long_name(entry) {
                    Some((seq, chunk)) => self.long_name.push(seq, chunk),
                    None => self.long_name.clear(),
                }
                continue;
            }

            let display_name = self
                .long_name
                .take_string()
                .unwrap_or_else(|| parse_short_name(&entry[0..11]));
            let cmp_name = normalise_name(&display_name);
            let cluster_high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
            let cluster_low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
            let first_cluster = (cluster_high << 16) | cluster_low;
            let file_size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
            let kind = if attr & ATTR_DIRECTORY != 0 {
                FileType::Directory
            } else {
                FileType::File
            };

            self.long_name.clear();
            return Some(Ok(ParsedDirEntry {
                name: display_name,
                cmp_name,
                kind,
                first_cluster,
                file_size,
                attr,
            }));
        }
        None
    }
}

fn parse_short_name(raw: &[u8]) -> String {
    let (name, ext) = raw.split_at(8);
    let name = trim_spaces(name);
    let ext = trim_spaces(ext);
    if ext.is_empty() {
        normalise_name(&name)
    } else {
        normalise_name(&format!("{name}.{}", ext))
    }
}

fn parse_long_name(entry: &[u8]) -> Option<(u8, [u16; LFN_CHARS_PER_ENTRY])> {
    if entry.len() < 32 {
        return None;
    }
    let seq = entry[0];
    let order = seq & 0x1F;
    if order == 0 {
        return None;
    }

    let mut chunk = [0u16; LFN_CHARS_PER_ENTRY];
    let fill = |start: usize, count: usize, buf: &mut [u16], idx: usize| {
        let mut current_idx = idx;
        for pair in entry[start..start + count].chunks_exact(2) {
            if current_idx >= buf.len() {
                break;
            }
            buf[current_idx] = u16::from_le_bytes([pair[0], pair[1]]);
            current_idx += 1;
        }
        current_idx
    };
    let mut written = 0;
    written = fill(1, 10, &mut chunk, written);
    written = fill(14, 12, &mut chunk, written);
    let _ = fill(28, 4, &mut chunk, written);

    Some((seq, chunk))
}

fn trim_spaces(raw: &[u8]) -> String {
    let end = raw
        .iter()
        .rposition(|b| *b != b' ')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    core::str::from_utf8(&raw[..end])
        .unwrap_or_default()
        .to_string()
}

fn normalise_name(raw: &str) -> String {
    raw.chars()
        .map(|c| c.to_ascii_uppercase())
        .collect::<String>()
}

struct LongNameAccumulator {
    parts: alloc::vec::Vec<(u8, [u16; LFN_CHARS_PER_ENTRY])>,
}

impl LongNameAccumulator {
    fn new() -> Self {
        Self {
            parts: alloc::vec::Vec::new(),
        }
    }

    fn clear(&mut self) {
        self.parts.clear();
    }

    fn push(&mut self, seq: u8, chunk: [u16; LFN_CHARS_PER_ENTRY]) {
        self.parts.push((seq & 0x1F, chunk));
    }

    fn take_string(&self) -> Option<String> {
        let max_index = self.parts.iter().map(|(idx, _)| *idx).max()?;
        if max_index == 0 {
            return None;
        }

        let mut buf = alloc::vec::Vec::new();
        buf.resize(max_index as usize * LFN_CHARS_PER_ENTRY, 0xFFFF);

        for (index, chunk) in &self.parts {
            let pos = index.checked_sub(1)? as usize * LFN_CHARS_PER_ENTRY;
            if pos >= buf.len() {
                return None;
            }
            for (offset, code) in chunk.iter().enumerate() {
                let slot = pos + offset;
                if slot < buf.len() {
                    buf[slot] = *code;
                }
            }
        }

        let mut out = String::new();
        for code in buf {
            if code == 0x0000 || code == 0xFFFF {
                break;
            }
            if let Some(ch) = char::from_u32(code as u32) {
                out.push(ch);
            }
        }

        if out.is_empty() { None } else { Some(out) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::println;
    use crate::test::kernel_test_case;

    fn base_fat32_boot_sector() -> [u8; 512] {
        let mut sector = [0u8; 512];
        sector[510..512].copy_from_slice(&FAT32_SIGNATURE);
        sector[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes_per_sector
        sector[13] = 1; // sectors_per_cluster
        sector[14..16].copy_from_slice(&32u16.to_le_bytes()); // reserved sectors
        sector[16] = 1; // number of FATs
        sector[32..36].copy_from_slice(&4096u32.to_le_bytes()); // total sectors
        sector[36..40].copy_from_slice(&64u32.to_le_bytes()); // fat_size_32
        sector[44..48].copy_from_slice(&2u32.to_le_bytes()); // root_cluster
        sector
    }

    #[kernel_test_case]
    fn bpb_rejects_fat16_layout() {
        println!("[test] bpb_rejects_fat16_layout");

        let mut sector = base_fat32_boot_sector();
        sector[22..24].copy_from_slice(&1u16.to_le_bytes()); // fat_size_16 set -> should be rejected
        assert!(matches!(
            BiosParameterBlock::parse(&sector),
            Err(FatError::InvalidBootSector)
        ));
    }

    #[kernel_test_case]
    fn bpb_rejects_invalid_root_cluster() {
        println!("[test] bpb_rejects_invalid_root_cluster");

        let mut sector = base_fat32_boot_sector();
        sector[44..48].copy_from_slice(&1u32.to_le_bytes()); // root cluster must start from 2
        assert!(matches!(
            BiosParameterBlock::parse(&sector),
            Err(FatError::InvalidBootSector)
        ));
    }

    #[kernel_test_case]
    fn bpb_accepts_minimal_fat32() {
        println!("[test] bpb_accepts_minimal_fat32");

        let sector = base_fat32_boot_sector();
        let parsed = BiosParameterBlock::parse(&sector).expect("parse valid fat32 bpb");
        assert_eq!(parsed.bytes_per_sector, 512);
        assert_eq!(parsed.sectors_per_cluster, 1);
        assert_eq!(parsed.root_cluster, 2);
    }

    #[kernel_test_case]
    fn long_filename_is_preserved() {
        println!("[test] long_filename_is_preserved");

        let mut cluster = [0u8; 64];
        // LFN entry for "sample.txt"
        cluster[0] = 0x41; // sequence (last, order 1)
        cluster[11] = ATTR_LONG_NAME;
        cluster[26] = 0;
        cluster[27] = 0;
        let name_utf16: [u16; 10] = [
            b's' as u16,
            b'a' as u16,
            b'm' as u16,
            b'p' as u16,
            b'l' as u16,
            b'e' as u16,
            b'.' as u16,
            b't' as u16,
            b'x' as u16,
            b't' as u16,
        ];
        // first 5 chars go to bytes 1..11
        for (i, ch) in name_utf16.iter().take(5).enumerate() {
            let bytes = ch.to_le_bytes();
            cluster[1 + i * 2] = bytes[0];
            cluster[1 + i * 2 + 1] = bytes[1];
        }
        // next 6 chars go to bytes 14..26
        for (i, ch) in name_utf16.iter().skip(5).take(6).enumerate() {
            let bytes = ch.to_le_bytes();
            let base = 14 + i * 2;
            cluster[base] = bytes[0];
            cluster[base + 1] = bytes[1];
        }
        // no remaining chars for bytes 28..32; leave as 0xFFFF (padding)
        for pair in cluster[28..32].chunks_exact_mut(2) {
            pair.copy_from_slice(&0xFFFFu16.to_le_bytes());
        }

        // Short name entry
        cluster[32..32 + 11].copy_from_slice(b"SAMPLE  TXT");
        cluster[32 + 11] = ATTR_ARCHIVE;
        cluster[32 + 26] = 3; // cluster low
        cluster[32 + 28] = 10; // size (arbitrary)

        let mut entries = DirectoryEntries::new(&cluster);
        let parsed = entries.next().expect("first entry").expect("ok");
        assert_eq!(parsed.name, "sample.txt");
        assert_eq!(parsed.cmp_name, "SAMPLE.TXT");

        let target = normalise_name("sample.txt");
        assert_eq!(parsed.cmp_name, target);
    }
}
