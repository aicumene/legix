use std::{
    fs::File,
    io::{Read, Write},
};

use zeroize::Zeroizing;

use crate::{DocumentKey, Error, KeyState, KeyStore, ObjectStore, Oid, Pointer, object};

/// Whether a document can be read here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    /// Its key and its object are here.
    Readable,
    /// Its key was destroyed here: the document is erased.
    Erased,
    /// Its key is not here, not yet or not for this key store.
    KeyMissing,
    /// Its key is here, its object is not.
    ObjectMissing,
}

/// Documents stored encrypted, each under a key of its own: the pointer goes into the repository, the object into an
/// [`ObjectStore`] and the key into a [`KeyStore`].
#[derive(Debug)]
pub struct Documents<K> {
    objects: ObjectStore,
    keys: K,
}

impl<K: KeyStore> Documents<K> {
    /// Documents with their objects in `objects` and their keys in `keys`.
    pub fn new(objects: ObjectStore, keys: K) -> Self {
        Documents { objects, keys }
    }

    /// Where the objects are.
    pub fn objects(&self) -> &ObjectStore {
        &self.objects
    }

    /// Where the keys are.
    pub fn keys(&self) -> &K {
        &self.keys
    }

    /// Encrypt `document` under a new key, keep the object and the key, and return the pointer to store in the
    /// document's place.
    pub fn add(&self, document: impl Read) -> Result<Pointer, Error> {
        let key = DocumentKey::generate()?;
        let pointer = self.objects.seal(&key, document)?;
        self.keys.put(&pointer.oid, &key)?;
        Ok(pointer)
    }

    /// Write the document `pointer` names to `out` and return its length.
    ///
    /// The object is checked against its id before anything is decrypted, so what is written is exactly the document
    /// the pointer — and a signed commit that holds it — refers to.
    pub fn read(&self, pointer: &Pointer, out: impl Write) -> Result<u64, Error> {
        let (key, object) = self.checked(pointer)?;
        object::open(&key, object, out)
    }

    /// The document `pointer` names, in memory. See [`Documents::read`].
    pub fn read_to_vec(&self, pointer: &Pointer) -> Result<Vec<u8>, Error> {
        let (key, object) = self.checked(pointer)?;
        let size = usize::try_from(pointer.size).map_err(|_| Error::Pointer("the size does not fit in memory"))?;
        // If opening fails part-way, the part already decrypted is zeroed when it is dropped.
        let mut document = Zeroizing::new(Vec::with_capacity(size));
        object::open(&key, object, &mut *document)?;
        Ok(std::mem::take(&mut *document))
    }

    /// Whether the document of the object `oid` can be read here. The object is not checked against its id.
    pub fn status(&self, oid: &Oid) -> Result<Status, Error> {
        Ok(match self.keys.get(oid)? {
            KeyState::Erased => Status::Erased,
            KeyState::Missing => Status::KeyMissing,
            KeyState::Present(_) if self.objects.contains(oid)? => Status::Readable,
            KeyState::Present(_) => Status::ObjectMissing,
        })
    }

    /// Erase the document of the object `oid`: destroy its key in this key store and remove its object from this
    /// object store.
    ///
    /// The pointer stays in the history, and the history's ids and signatures stay valid. Reading the pointer answers
    /// [`Error::Erased`] from then on. Key stores elsewhere that hold the key — on other devices, in backups — must
    /// erase it too; until they do, they can read the document.
    pub fn erase(&self, oid: &Oid) -> Result<(), Error> {
        self.keys.erase(oid)?;
        self.objects.remove(oid)?;
        Ok(())
    }

    /// The key of the document and its object, checked against the pointer.
    fn checked(&self, pointer: &Pointer) -> Result<(DocumentKey, File), Error> {
        let oid = pointer.oid;
        let key = match self.keys.get(&oid)? {
            KeyState::Present(key) => key,
            KeyState::Erased => return Err(Error::Erased(oid)),
            KeyState::Missing => return Err(Error::KeyMissing(oid)),
        };
        self.objects.verify(&oid)?;
        let object = self.objects.open(&oid)?;
        if Some(object.metadata()?.len()) != pointer.object_len() {
            return Err(Error::Pointer("its size does not match the object"));
        }
        Ok((key, object))
    }
}
