use std::sync::atomic::AtomicBool;

use legix_error::ExnMessageResult;

use crate::File;

impl File {
    /// Verify the integrity of the index to assure its consistency.
    pub fn verify_integrity(&self) -> ExnMessageResult {
        use legix_error::{ResultExt, message};

        let _span = legix_features::trace::coarse!("legix_index::File::verify_integrity()");
        if let Some(checksum) = self.checksum {
            let num_bytes_to_hash = self
                .path
                .metadata()
                .or_raise(|| message("Could not read index file to generate hash"))?
                .len()
                - checksum.as_bytes().len() as u64;
            let should_interrupt = AtomicBool::new(false);
            legix_hash::bytes_of_file(
                &self.path,
                num_bytes_to_hash,
                checksum.kind(),
                &mut legix_features::progress::Discard,
                &should_interrupt,
            )
            .or_raise(|| message("Could not read index file to generate hash"))?
            .verify(&checksum)
            .or_raise(|| message("Index checksum mismatch"))?;
        }
        Ok(())
    }
}
