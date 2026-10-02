use legix_features::trace::{coarse, detail, span};
#[test]
fn span() {
    let _x = span!(legix_features::trace::Level::Coarse, "hello");
    span!(legix_features::trace::Level::Coarse, "hello", x = "value", y = 42);
    span!(target: "other", legix_features::trace::Level::Coarse, "hello", x = "value", y = 42);

    let _x = coarse!("hello");
    coarse!("hello", x = "value", y = 42);
    coarse!(target: "other", "hello", x = "value", y = 42);

    let _y = detail!("hello");
    detail!("hello", x = "value", y = 42);
    detail!(target: "other", "hello", x = "value", y = 42);
}
