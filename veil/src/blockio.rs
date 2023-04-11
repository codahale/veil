use std::io;
use std::io::Read;

/// Extension trait for reading fixed-sized blocks of data.
pub trait ReadBlock: Read {
    /// Reads a `buf`-sized block of data, returning the number of bytes read into `buf`.
    /// If the returned count is less than the length of `buf`, an `EOF` was encountered.
    fn read_block(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let max = buf.len();
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => break,
                Ok(n) => buf = &mut buf[n..],
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(max - buf.len())
    }
}

impl<R> ReadBlock for R where R: Read {}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn blockwise_reads() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let data = rng.gen::<[u8; 20]>();

        let mut reader = Cursor::new(&data);
        let mut block = [0u8; 16];

        let n = reader.read_block(&mut block).expect("error reading");
        assert_eq!(n, 16);
        assert_eq!(&block, &data[..16]);

        let n = reader.read_block(&mut block).expect("error reading");
        assert_eq!(n, 4);
        assert_eq!(&block[..4], &data[16..]);
    }
}
