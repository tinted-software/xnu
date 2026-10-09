//! A writable `hadris-storage` block device over the output image file.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

use hadris_io::{Error, ErrorKind, ErrorType};
use hadris_storage::sync::BlockDevice;
use hadris_storage::{BlockIndex, BlockSize};

const BLOCK: u32 = 4096;
const BLOCK_SIZE: BlockSize = match BlockSize::new(BLOCK) {
    Some(size) => size,
    None => panic!("4096 is a valid block size"),
};

/// A host image file addressed in 4096-byte blocks.
///
/// The file is created (or truncated) and extended to the container's size, so
/// blocks the writer never touches stay holes.
#[derive(Debug)]
pub struct ImageDevice {
    file: File,
    blocks: u64,
}

impl ImageDevice {
    /// Creates `path` holding a sparse `size`-byte container.
    ///
    /// `size` must be a multiple of 4096.
    pub fn create(path: &Path, size: u64) -> std::io::Result<Self> {
        if size % u64::from(BLOCK) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("container size {size} is not a multiple of {BLOCK}"),
            ));
        }
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(size)?;
        Ok(Self {
            file,
            blocks: size / u64::from(BLOCK),
        })
    }

    fn range(&self, first: BlockIndex, len: usize) -> Result<u64, Error<std::io::Error>> {
        let count = (len / BLOCK as usize) as u64;
        let end = first.get().checked_add(count);
        let offset = first
            .get()
            .checked_mul(u64::from(BLOCK))
            .filter(|_| len % BLOCK as usize == 0 && end.is_some_and(|end| end <= self.blocks));
        offset.ok_or_else(|| Error::new(ErrorKind::InvalidInput, "block request outside the image"))
    }
}

impl ErrorType for ImageDevice {
    type Error = std::io::Error;
}

impl BlockDevice for ImageDevice {
    fn block_size(&self) -> BlockSize {
        BLOCK_SIZE
    }

    fn block_count(&self) -> u64 {
        self.blocks
    }

    fn writable(&self) -> bool {
        true
    }

    fn read_blocks(&mut self, first: BlockIndex, buf: &mut [u8]) -> Result<(), Error<Self::Error>> {
        let offset = self.range(first, buf.len())?;
        self.file
            .read_exact_at(buf, offset)
            .map_err(|err| Error::device(err, "reading the image failed"))
    }

    fn write_blocks(&mut self, first: BlockIndex, buf: &[u8]) -> Result<(), Error<Self::Error>> {
        let offset = self.range(first, buf.len())?;
        self.file
            .write_all_at(buf, offset)
            .map_err(|err| Error::device(err, "writing the image failed"))
    }

    fn flush(&mut self) -> Result<(), Error<Self::Error>> {
        self.file
            .sync_data()
            .map_err(|err| Error::device(err, "flushing the image failed"))
    }
}
