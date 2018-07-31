use bincode;

use crypto;
use honey_badger;

error_chain!{
    links {
        Crypto(crypto::Error, crypto::ErrorKind);
        HoneyBadger(honey_badger::Error, honey_badger::ErrorKind);
    }

    foreign_links {
        Bincode(Box<bincode::ErrorKind>);
    }

    errors {
        UnknownSender
    }
}
