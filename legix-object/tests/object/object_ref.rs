mod from_loose {
    use legix_object::ObjectRef;

    #[test]
    fn shorter_than_advertised() {
        insta::assert_debug_snapshot!(ObjectRef::from_loose(b"tree 1000\x00", legix_testtools::object_hash(),)
                .expect_err("shorter than advertised"), "shorter than advertised", @"object data was shorter than its size declared in the header");
    }
}
