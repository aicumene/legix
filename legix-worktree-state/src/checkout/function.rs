use std::sync::atomic::AtomicBool;

use legix_error::{ExnResult, ResultExt, message};
use legix_features::{interrupt, parallel::in_parallel_with_finalize};
use legix_worktree::{Stack, stack};

use crate::checkout::chunk;

/// Checkout the entire `index` into `dir`, and resolve objects found in index entries with `objects` to write their content to their
/// respective path in `dir`.
/// Use `files` to count each fully checked out file, and count the amount written `bytes`. If `should_interrupt` is `true`, the
/// operation will abort.
/// `options` provide a lot of context on how to perform the operation.
///
/// ### Handling the return value
///
/// Note that interruption still produce an `Ok(…)` value, so the caller should look at `should_interrupt` to communicate the outcome.
///
pub fn checkout<Find>(
    index: &mut legix_index::State,
    dir: impl Into<std::path::PathBuf>,
    objects: Find,
    files: &dyn legix_features::progress::Count,
    bytes: &dyn legix_features::progress::Count,
    should_interrupt: &AtomicBool,
    options: crate::checkout::Options,
) -> ExnResult<crate::checkout::Outcome>
where
    Find: legix_object::Find + Send + Clone,
{
    let paths = index.take_path_backing();
    let res = checkout_inner(index, &paths, dir, objects, files, bytes, should_interrupt, options);
    index.return_path_backing(paths);
    res
}

#[expect(clippy::too_many_arguments)]
fn checkout_inner<Find>(
    index: &mut legix_index::State,
    paths: &legix_index::PathStorage,
    dir: impl Into<std::path::PathBuf>,
    objects: Find,
    files: &dyn legix_features::progress::Count,
    bytes: &dyn legix_features::progress::Count,
    should_interrupt: &AtomicBool,
    mut options: crate::checkout::Options,
) -> ExnResult<crate::checkout::Outcome>
where
    Find: legix_object::Find + Send + Clone,
{
    let num_files = files.counter();
    let num_bytes = bytes.counter();
    let dir = dir.into();
    let (chunk_size, thread_limit, num_threads) = legix_features::parallel::optimize_chunk_size_and_thread_limit(
        100,
        index.entries().len().into(),
        options.thread_limit,
        None,
    );

    let mut path_cache = Stack::from_state_and_ignore_case(
        dir,
        options.fs.ignore_case,
        stack::State::for_checkout(
            options.overwrite_existing,
            options.validate,
            std::mem::take(&mut options.attributes),
        ),
        index,
        paths,
    );
    if !options.destination_is_initially_empty {
        path_cache.enable_terminal_symlink_check();
    }
    let mut ctx = chunk::Context {
        buf: Vec::new(),
        options: (&options).into(),
        path_cache,
        filters: options.filters,
        objects,
    };

    let chunk::Outcome {
        mut collisions,
        mut errors,
        mut bytes_written,
        files: files_updated,
        delayed_symlinks,
        delayed_paths_unknown,
        delayed_paths_unprocessed,
    } = if num_threads == 1 {
        let entries_with_paths = interrupt::Iter::new(index.entries_mut_with_paths_in(paths), should_interrupt);
        let mut delayed_filter_results = Vec::new();
        let mut out = chunk::process(
            entries_with_paths,
            &num_files,
            &num_bytes,
            &mut delayed_filter_results,
            &mut ctx,
        )?;
        chunk::process_delayed_filter_results(delayed_filter_results, &num_files, &num_bytes, &mut out, &mut ctx)?;
        out
    } else {
        let entries_with_paths = interrupt::Iter::new(index.entries_mut_with_paths_in(paths), should_interrupt);
        in_parallel_with_finalize(
            legix_features::iter::Chunks {
                inner: entries_with_paths,
                size: chunk_size,
            },
            thread_limit,
            {
                let ctx = ctx.clone();
                move |_| (Vec::new(), ctx)
            },
            |chunk, (delayed_filter_results, ctx)| {
                chunk::process(chunk.into_iter(), &num_files, &num_bytes, delayed_filter_results, ctx)
            },
            |(delayed_filter_results, mut ctx)| {
                let mut out = chunk::Outcome::default();
                chunk::process_delayed_filter_results(
                    delayed_filter_results,
                    &num_files,
                    &num_bytes,
                    &mut out,
                    &mut ctx,
                )?;
                ctx.filters
                    .driver_state_mut()
                    .shutdown(legix_filter::driver::shutdown::Mode::WaitForProcesses)
                    .or_raise(|| message("Could not shut down filter processes"))
                    .or_erased()?;
                Ok(out)
            },
            chunk::Reduce {
                aggregate: Default::default(),
            },
        )?
    };

    for (entry, entry_path) in delayed_symlinks {
        bytes_written += chunk::checkout_entry_handle_result(
            entry,
            entry_path,
            &mut errors,
            &mut collisions,
            &num_files,
            &num_bytes,
            &mut ctx,
        )?
        .as_bytes()
        .expect("only symlinks are delayed here, they are never filtered (or delayed again)")
            as u64;
    }

    ctx.filters
        .driver_state_mut()
        .shutdown(legix_filter::driver::shutdown::Mode::WaitForProcesses)
        .or_raise(|| message("Could not shut down filter processes"))
        .or_erased()?;

    Ok(crate::checkout::Outcome {
        files_updated,
        collisions,
        errors,
        bytes_written,
        delayed_paths_unknown,
        delayed_paths_unprocessed,
    })
}
