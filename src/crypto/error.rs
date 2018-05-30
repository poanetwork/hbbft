error_chain! {
    errors {
        NotEnoughShares {
            description("not enough signature shares")
        }
        DuplicateEntry {
            description("signature shares contain a duplicated index")
        }
    }
}
