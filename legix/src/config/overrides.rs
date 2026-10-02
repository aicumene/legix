use legix_error::ResultExt;

use crate::{
    Error, Result,
    bstr::{BStr, BString, ByteSlice},
};

pub(crate) fn append(
    config: &mut legix_config::File,
    values: impl IntoIterator<Item = impl legix_utils::AsBStr>,
    source: legix_config::Source,
    mut make_comment: impl FnMut(&BStr) -> Option<BString>,
) -> Result<()> {
    let mut file = legix_config::File::new(legix_config::file::Metadata::from(source));
    for key_value in values {
        let key_value = key_value.as_bstr();
        let mut tokens = key_value.splitn(2, |b| *b == b'=').map(ByteSlice::trim);
        let key = tokens.next().expect("always one value").as_bstr();
        let value = tokens.next();
        let key = legix_config::KeyRef::parse_unvalidated(key).ok_or_else(|| {
            let input: BString = key.into();
            Error::from_error(legix_error::message!(
                "{input:?} is not a valid configuration key. Examples are 'core.abbrev' or 'remote.origin.url'"
            ))
        })?;
        let mut section = file
            .section_mut_or_create_new(key.section_name, key.subsection_name)
            .or_erased()?;
        let comment = make_comment(key_value);
        let value = value.map(ByteSlice::as_bstr);
        match comment {
            Some(comment) => section.push_with_comment(key.value_name, value, &**comment),
            None => section.push(key.value_name, value),
        }
        .or_erased()?;
    }
    config.append(file).or_erased()?;
    Ok(())
}
