error_chain! {
    errors {
        NotEnoughShares {
            description("not enough signature shares")
        }
        DuplicateEntry {
            description("signature shares contain a duplicated index")
        }
        MlockFailed(desc: String) {
            description("failed mlock a region of memory")
            display("{}", desc)
        }
        MunlockFailed(desc: String) {
            description("failed munlock a region of memory")
            display("{}", desc)
        }
    }
}
