use std::{
    cell::RefCell,
    io::{self, Write},
};

use legix_error::{ExnResult, ResultExt};
use legix_zlib::stream::deflate;

use crate::Sink;

impl Sink {
    /// Compress with the given level, or disable compression with `None`. Compression is disabled by default.
    pub fn compress(mut self, compression: Option<legix_zlib::Compression>) -> Self {
        self.compressor = compression.map(|level| RefCell::new(deflate::Write::new(io::sink(), level)));
        self
    }
}

impl legix_object::Write for Sink {
    fn write_buf_with_known_id(
        &self,
        kind: legix_object::Kind,
        mut from: &[u8],
        id: legix_hash::ObjectId,
    ) -> ExnResult<legix_hash::ObjectId> {
        self.write_stream_with_known_id(kind, from.len() as u64, &mut from, id)
    }

    fn write_stream(
        &self,
        kind: legix_object::Kind,
        mut size: u64,
        from: &mut dyn io::Read,
    ) -> ExnResult<legix_hash::ObjectId> {
        let mut buf = [0u8; u16::MAX as usize];
        let header = legix_object::encode::loose_header(kind, size);

        let possibly_compress = |buf: &[u8]| -> io::Result<()> {
            if let Some(compressor) = self.compressor.as_ref() {
                compressor.try_borrow_mut().expect("no recursion").write_all(buf)?;
            }
            Ok(())
        };

        let mut hasher = legix_hash::hasher(self.object_hash);
        hasher.update(&header);
        possibly_compress(&header).or_erased()?;

        while size != 0 {
            let bytes = (size as usize).min(buf.len());
            from.read_exact(&mut buf[..bytes]).or_erased()?;
            hasher.update(&buf[..bytes]);
            possibly_compress(&buf[..bytes]).or_erased()?;
            size -= bytes as u64;
        }
        if let Some(compressor) = self.compressor.as_ref() {
            let mut c = compressor.borrow_mut();
            c.flush().or_erased()?;
            c.reset();
        }

        hasher.try_finalize().or_erased()
    }

    fn write_stream_with_known_id(
        &self,
        kind: legix_object::Kind,
        mut size: u64,
        from: &mut dyn io::Read,
        id: legix_hash::ObjectId,
    ) -> ExnResult<legix_hash::ObjectId> {
        let mut buf = [0u8; u16::MAX as usize];
        let header = legix_object::encode::loose_header(kind, size);

        let possibly_compress = |buf: &[u8]| -> io::Result<()> {
            if let Some(compressor) = self.compressor.as_ref() {
                compressor.try_borrow_mut().expect("no recursion").write_all(buf)?;
            }
            Ok(())
        };

        possibly_compress(&header).or_erased()?;

        while size != 0 {
            let bytes = (size as usize).min(buf.len());
            from.read_exact(&mut buf[..bytes]).or_erased()?;
            possibly_compress(&buf[..bytes]).or_erased()?;
            size -= bytes as u64;
        }
        if let Some(compressor) = self.compressor.as_ref() {
            let mut c = compressor.borrow_mut();
            c.flush().or_erased()?;
            c.reset();
        }

        Ok(id)
    }
}
