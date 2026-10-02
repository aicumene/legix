//! Validation for various kinds of git related items.
//!
//! Errors expose a classification-only [`legix_error::ClassificationMarker`] source.
//! Use [`legix_error::classify()`] or `is_validation()` on [`legix_error::Exn`] and [`legix_error::Error`] to check the
//! classification, without depending on the concrete diagnostic type. The concrete validation
//! error remains available for downcasting and probable-cause selection.
//!
//! ## Examples
//!
//! ```
//! use bstr::ByteSlice;
//!
//! assert!(legix_validate::reference::name(b"refs/heads/main".as_bstr()).is_ok());
//! assert!(legix_validate::tag::name(b"v1.2.3".as_bstr()).is_ok());
//! assert!(legix_validate::submodule::name(b"vendor/package".as_bstr()).is_ok());
//!
//! assert!(legix_validate::path::component(b"src".as_bstr(), None, Default::default()).is_ok());
//! assert!(legix_validate::path::component(b".git".as_bstr(), None, Default::default()).is_err());
//! ```
#![deny(missing_docs)]
#![forbid(unsafe_code)]

///
pub mod reference;

///
pub mod tag;

///
pub mod submodule;

///
pub mod path;
