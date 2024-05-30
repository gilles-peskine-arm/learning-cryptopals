use std::env;
use std::ops::BitXor;

#[derive(Debug, PartialEq)]
struct Bytes(Vec<u8>);

impl BitXor for Bytes {
    type Output = Self;
    fn bitxor(self, Self(rhs): Self) -> Self::Output {
        let Self(lhs) = self;
        assert_eq!(lhs.len(), rhs.len());
        Self(lhs.iter().zip(rhs.iter())
             .map(|(l,r)| l ^ r).collect())
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    // Panic if there are no arguments
    let hex1 = &args[1];
    let hex2 = &args[2];
    // Panic if a hex string is invalid
    let data1 = Bytes(hex::decode(hex1).expect("Invalid hex string 1"));
    let data2 = Bytes(hex::decode(hex2).expect("Invalid hex string 1"));
    let Bytes(result) = data1 ^ data2;
    println!("{}", hex::encode(result));
}
