use std::hint::black_box;

use bstr::BString;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use legix_index::State;
use legix_object::{Tree, Write, tree::EntryKind};

fn from_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("from_tree");

    let (flat_id, flat_objects, flat_entries) = flat_tree();
    group.throughput(Throughput::Elements(flat_entries));
    group.bench_function("flat 10k files", |b| {
        b.iter(|| {
            let state = State::from_tree(&flat_id, &flat_objects, Default::default()).expect("tree can be read");
            black_box(state);
        });
    });

    let (wide_deep_id, wide_deep_objects, wide_deep_entries) = wide_deep_tree();
    group.throughput(Throughput::Elements(wide_deep_entries));
    group.bench_function("wide 100 x 100 files", |b| {
        b.iter(|| {
            let state =
                State::from_tree(&wide_deep_id, &wide_deep_objects, Default::default()).expect("tree can be read");
            black_box(state);
        });
    });

    let (sparse_id, sparse_objects, sparse_entries) = sparse_tree();
    group.throughput(Throughput::Elements(sparse_entries));
    group.bench_function("sparse 10k directories", |b| {
        b.iter(|| {
            let state = State::from_tree(&sparse_id, &sparse_objects, Default::default()).expect("tree can be read");
            black_box(state);
        });
    });
}

criterion_group!(benches, from_tree);
criterion_main!(benches);

fn flat_tree() -> (legix_hash::ObjectId, MemoryDb, u64) {
    let objects = memory_db();
    let mut editor = legix_object::tree::Editor::new(Tree::default(), &legix_object::find::Never, legix_hash::Kind::Sha1);
    let id = repeated_id(b'a');
    const FILE_COUNT: u64 = 10_000;
    for idx in 0..FILE_COUNT {
        editor
            .upsert([BString::from(format!("file-{idx:05}"))], EntryKind::Blob, id)
            .expect("valid path");
    }
    let id = editor.write(|tree| objects.write(tree)).expect("tree can be written");
    (id, objects, FILE_COUNT)
}

fn wide_deep_tree() -> (legix_hash::ObjectId, MemoryDb, u64) {
    let objects = memory_db();
    let mut editor = legix_object::tree::Editor::new(Tree::default(), &legix_object::find::Never, legix_hash::Kind::Sha1);
    let id = repeated_id(b'a');
    const DIR_COUNT: u64 = 100;
    const FILE_COUNT: u64 = 100;
    for dir_idx in 0..DIR_COUNT {
        for file_idx in 0..FILE_COUNT {
            editor
                .upsert(
                    [
                        BString::from(format!("dir-{dir_idx:03}")),
                        BString::from(format!("file-{file_idx:03}")),
                    ],
                    EntryKind::Blob,
                    id,
                )
                .expect("valid path");
        }
    }
    let id = editor.write(|tree| objects.write(tree)).expect("tree can be written");
    (id, objects, DIR_COUNT * FILE_COUNT)
}

fn sparse_tree() -> (legix_hash::ObjectId, MemoryDb, u64) {
    let objects = memory_db();
    let empty_tree_id = objects.write(&Tree::default()).expect("empty tree can be written");
    let mut editor = legix_object::tree::Editor::new(Tree::default(), &legix_object::find::Never, legix_hash::Kind::Sha1);
    const SPARSE_DIR_COUNT: u64 = 10_000;
    for idx in 0..SPARSE_DIR_COUNT {
        editor
            .upsert(
                [BString::from(format!("sparse-{idx:05}"))],
                EntryKind::Tree,
                empty_tree_id,
            )
            .expect("valid path");
    }
    let id = editor.write(|tree| objects.write(tree)).expect("tree can be written");
    (id, objects, SPARSE_DIR_COUNT)
}

type MemoryDb = legix_odb::memory::Proxy<legix_object::find::Never>;

fn memory_db() -> MemoryDb {
    legix_odb::memory::Proxy::new(legix_object::find::Never, legix_hash::Kind::Sha1)
}

fn repeated_id(byte: u8) -> legix_hash::ObjectId {
    legix_hash::ObjectId::from_hex(&vec![byte; legix_hash::Kind::Sha1.len_in_hex()]).expect("valid hex")
}
