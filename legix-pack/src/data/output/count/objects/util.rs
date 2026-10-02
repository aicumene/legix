pub trait InsertImmutable {
    fn insert(&self, id: legix_hash::ObjectId) -> bool;
}

mod trait_impls {
    use std::cell::RefCell;

    use legix_hash::ObjectId;
    use legix_hashtable::HashSet;

    use super::InsertImmutable;

    impl InsertImmutable for legix_hashtable::sync::ObjectIdMap<()> {
        fn insert(&self, id: ObjectId) -> bool {
            self.insert(id, ()).is_none()
        }
    }

    impl InsertImmutable for RefCell<HashSet<ObjectId>> {
        fn insert(&self, item: ObjectId) -> bool {
            self.borrow_mut().insert(item)
        }
    }
}
