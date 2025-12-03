//! Minimal read-only FAT32 implementation backed by a `BlockDevice`.
//!
//! # Implicit dependency
//! Assumes the underlying block device uses a 512-byte logical sector, matching the test images
//! generated in `xtask`. Larger sector sizes are rejected during mount to avoid partial-sector
//! reads until buffering support is added.

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
const END_OF_CHAIN: u32 = 0x0FFFFFF8;
const BAD_CLUSTER: u32 = 0x0FFFFFF7;

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

        if cluster_size == 0 {
            return Err(FatError::Corrupted);
        }

        Ok(Self {
            device: SpinLock::new(device),
            bpb,
            fat_start,
            data_start,
            cluster_size,
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
        let block_size = self.bpb.bytes_per_sector as usize;
        if buf.is_empty() {
            return Ok(());
        }

        let offset_usize: usize = offset.try_into().map_err(|_| FatError::Corrupted)?;
        let start_block = offset_usize / block_size;
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(FatError::Corrupted)?;
        let end_usize: usize = end.try_into().map_err(|_| FatError::Corrupted)?;
        let end_block = end_usize.div_ceil(block_size);
        let block_count = end_block
            .checked_sub(start_block)
            .ok_or(FatError::Corrupted)?;

        let mut scratch = vec![0u8; block_count * block_size];
        {
            let mut dev = self.device.lock();
            dev.read_blocks(start_block as u64, &mut scratch)
                .map_err(|_| FatError::DeviceError)?;
        }

        let start_offset = offset_usize % block_size;
        let range_start = start_offset;
        let range_end = start_offset + buf.len();
        if range_end > scratch.len() {
            return Err(FatError::UnexpectedEof);
        }
        buf.copy_from_slice(&scratch[range_start..range_end]);
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

        let _total_sectors = if total_sectors_16 != 0 {
            u32::from(total_sectors_16)
        } else {
            total_sectors_32
        };

        let fat_size = if fat_size_16 != 0 {
            u32::from(fat_size_16)
        } else {
            fat_size_32
        };

        if fat_size == 0 {
            return Err(FatError::InvalidBootSector);
        }

        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sector_count,
            num_fats,
            fat_size_32: fat_size,
            root_cluster,
        })
    }

    fn fat_size_sectors(&self) -> u64 {
        u64::from(self.fat_size_32)
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
                if entry.name == target {
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
}

impl<'a> DirectoryEntries<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, index: 0 }
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
                continue;
            }
            let attr = entry[11];
            if attr & ATTR_LONG_NAME == ATTR_LONG_NAME {
                continue;
            }

            let name = parse_short_name(&entry[0..11]);
            let cluster_high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
            let cluster_low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
            let first_cluster = (cluster_high << 16) | cluster_low;
            let file_size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
            let kind = if attr & ATTR_DIRECTORY != 0 {
                FileType::Directory
            } else {
                FileType::File
            };

            return Some(Ok(ParsedDirEntry {
                name,
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
