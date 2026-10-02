use crate::find::Entry;
use legix_error::ExnResult;

/// An in-memory object database without pack locations.
#[derive(Clone)]
pub struct Memory {
    objects: std::sync::Arc<legix_hashtable::HashMap<legix_hash::ObjectId, (legix_object::Kind, Vec<u8>)>>,
}

impl Memory {
    /// Create a database containing all `objects`.
    ///
    /// Each item is `(id, (kind, data))`, where `data` is the uncompressed object body without a
    /// loose-object header. IDs are trusted rather than recomputed. If an ID occurs more than once,
    /// the last item wins.
    pub fn new(objects: impl IntoIterator<Item = (legix_hash::ObjectId, (legix_object::Kind, Vec<u8>))>) -> Self {
        Self {
            objects: std::sync::Arc::new(objects.into_iter().collect()),
        }
    }
}

impl crate::Find for Memory {
    fn contains(&self, id: &legix_hash::oid) -> bool {
        self.objects.contains_key(id)
    }

    fn try_find_cached<'a>(
        &self,
        id: &legix_hash::oid,
        buffer: &'a mut Vec<u8>,
        _pack_cache: &mut dyn crate::cache::DecodeEntry,
    ) -> ExnResult<Option<(legix_object::Data<'a>, Option<crate::data::entry::Location>)>> {
        Ok(self.objects.get(id).map(|(kind, data)| {
            buffer.clear();
            buffer.extend_from_slice(data);
            (legix_object::Data::new(buffer, *kind, id.kind()), None)
        }))
    }

    fn location_by_oid(&self, _id: &legix_hash::oid, _buf: &mut Vec<u8>) -> Option<crate::data::entry::Location> {
        None
    }

    fn pack_offsets_and_oid(&self, _pack_id: u32) -> Option<Vec<(crate::data::Offset, legix_hash::ObjectId)>> {
        None
    }

    fn entry_by_location(&self, _location: &crate::data::entry::Location) -> Option<Entry> {
        None
    }
}
