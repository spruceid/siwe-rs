use hex;
use sha3::{Digest, Keccak256};

fn keccak256(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes.as_ref());
    hasher.finalize().into()
}

pub fn to_checksum(addr: &[u8; 20], chain_id: Option<u8>) -> String {
    let addr_hex = hex::encode(addr);
    let prefixed_addr = match chain_id {
        Some(chain_id) => format!("{}0x{}", chain_id, addr_hex),
        None => format!("{}", addr_hex),
    };
    let hash = hex::encode(keccak256(&prefixed_addr));
    let hash = hash.as_bytes();

    let addr_hex = addr_hex.as_bytes();

    addr_hex.iter().zip(hash).fold("0x".to_owned(), |mut encoded, (addr, hash)| {
        encoded.push(if *hash >= 56 {
            addr.to_ascii_uppercase() as char
        } else {
            addr.to_ascii_lowercase() as char
        });
        encoded
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn addr_checksum() {
        let addr_list = vec![
            // mainnet
            (
                None,
                "27b1fdb04752bbc536007a920d24acb045561c26",
                "0x27b1fdb04752bbc536007a920d24acb045561c26",
            ),
            (
                None,
                "3599689e6292b81b2d85451025146515070129bb",
                "0x3599689E6292b81B2d85451025146515070129Bb",
            ),
            (
                None,
                "42712d45473476b98452f434e72461577d686318",
                "0x42712D45473476b98452f434e72461577D686318",
            ),
            (
                None,
                "52908400098527886e0f7030069857d2e4169ee7",
                "0x52908400098527886E0F7030069857D2E4169EE7",
            ),
            (
                None,
                "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                None,
                "6549f4939460de12611948b3f82b88c3c8975323",
                "0x6549f4939460DE12611948b3f82b88C3C8975323",
            ),
            (
                None,
                "66f9664f97f2b50f62d13ea064982f936de76657",
                "0x66f9664f97F2b50F62D13eA064982f936dE76657",
            ),
            (
                None,
                "88021160c5c792225e4e5452585947470010289d",
                "0x88021160C5C792225E4E5452585947470010289D",
            ),
            // rsk mainnet
            (
                Some(30),
                "27b1fdb04752bbc536007a920d24acb045561c26",
                "0x27b1FdB04752BBc536007A920D24ACB045561c26",
            ),
            (
                Some(30),
                "3599689e6292b81b2d85451025146515070129bb",
                "0x3599689E6292B81B2D85451025146515070129Bb",
            ),
            (
                Some(30),
                "42712d45473476b98452f434e72461577d686318",
                "0x42712D45473476B98452f434E72461577d686318",
            ),
            (
                Some(30),
                "52908400098527886e0f7030069857d2e4169ee7",
                "0x52908400098527886E0F7030069857D2E4169ee7",
            ),
            (
                Some(30),
                "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "0x5aaEB6053f3e94c9b9a09f33669435E7ef1bEAeD",
            ),
            (
                Some(30),
                "6549f4939460de12611948b3f82b88c3c8975323",
                "0x6549F4939460DE12611948B3F82B88C3C8975323",
            ),
            (
                Some(30),
                "66f9664f97f2b50f62d13ea064982f936de76657",
                "0x66F9664f97f2B50F62d13EA064982F936de76657",
            ),
        ];

        for (chain_id, addr, checksummed_addr) in addr_list {
            let addr = <[u8; 20]>::from_hex(addr).unwrap();
            assert_eq!(to_checksum(&addr, chain_id), String::from(checksummed_addr));
        }
    }
}
