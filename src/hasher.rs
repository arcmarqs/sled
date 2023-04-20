use crc32fast;
use blake3;

#[cfg(feature = "crypto-checksum")]
pub const OUT_LEN: usize = 32;

#[cfg(not(feature="crypto-checksum"))]
pub const OUT_LEN: usize = 4;

pub type Digest = [u8;OUT_LEN];

pub struct CHasher {
    #[cfg(feature = "crypto-checksum")]
        inner: blake3::Hasher,

    #[cfg(not(feature="crypto-checksum"))]
        inner: crc32fast::Hasher
}

impl CHasher {
    pub fn new() -> Self {
        let inner = {
            #[cfg(feature = "crypto-checksum")]
                 {blake3::Hasher::new()}
    
            #[cfg(not(feature="crypto-checksum"))]
                crc32fast::Hasher::new()
        };

        CHasher { inner }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> Digest {

        let res ={  
            #[cfg(feature = "crypto-checksum")]
                {self.inner.finalize()}

            #[cfg(not(feature="crypto-checksum"))]
                self.inner.finalize().to_be_bytes()
        };

        res
    }
}