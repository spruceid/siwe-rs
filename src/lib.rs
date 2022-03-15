use chrono::{DateTime, Utc};
use core::{
    convert::Infallible,
    fmt::{self, Display, Formatter},
    str::FromStr,
};
use ethers_core::{types::H160, utils::to_checksum};
use hex::FromHex;
use http::uri::{Authority, InvalidUri};
use iri_string::types::UriString;
use thiserror::Error;

pub mod nonce;
pub mod rfc3339;

pub use rfc3339::TimeStamp;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Version {
    V1 = 1,
}

impl FromStr for Version {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "1" {
            Ok(Self::V1)
        } else {
            Err(ParseError::Format("Bad Version"))
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub domain: Authority,
    pub address: [u8; 20],
    pub statement: Option<String>,
    pub uri: UriString,
    pub version: Version,
    pub chain_id: u64,
    pub nonce: String,
    pub issued_at: TimeStamp,
    pub expiration_time: Option<TimeStamp>,
    pub not_before: Option<TimeStamp>,
    pub request_id: Option<String>,
    pub resources: Vec<UriString>,
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "{}{}", &self.domain, PREAMBLE)?;
        writeln!(f, "{}", to_checksum(&H160(self.address), None))?;
        writeln!(f)?;
        if let Some(statement) = &self.statement {
            writeln!(f, "{}", statement)?;
        }
        writeln!(f)?;
        writeln!(f, "{}{}", URI_TAG, &self.uri)?;
        writeln!(f, "{}{}", VERSION_TAG, self.version as u64)?;
        writeln!(f, "{}{}", CHAIN_TAG, &self.chain_id)?;
        writeln!(f, "{}{}", NONCE_TAG, &self.nonce)?;
        write!(f, "{}{}", IAT_TAG, &self.issued_at)?;
        if let Some(exp) = &self.expiration_time {
            write!(f, "\n{}{}", EXP_TAG, &exp)?
        };
        if let Some(nbf) = &self.not_before {
            write!(f, "\n{}{}", NBF_TAG, &nbf)?
        };
        if let Some(rid) = &self.request_id {
            write!(f, "\n{}{}", RID_TAG, rid)?
        };
        if !self.resources.is_empty() {
            write!(f, "\n{}", RES_TAG)?;
            for res in &self.resources {
                write!(f, "\n- {}", res)?;
            }
        };
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid Domain: {0}")]
    Domain(#[from] InvalidUri),
    #[error("Formatting Error: {0}")]
    Format(&'static str),
    #[error("Invalid Address: {0}")]
    Address(#[from] hex::FromHexError),
    #[error("Invalid Statement: {0}")]
    Statement(&'static str),
    #[error("Invalid URI: {0}")]
    Uri(#[from] iri_string::validate::Error),
    #[error("Invalid Timestamp: {0}")]
    TimeStamp(#[from] chrono::format::ParseError),
    #[error("Invalid Nonce: {0}")]
    Nonce(&'static str),
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error(transparent)]
    Never(#[from] Infallible),
}

fn tagged<'a>(tag: &'static str, line: Option<&'a str>) -> Result<&'a str, ParseError> {
    line.and_then(|l| l.strip_prefix(tag))
        .ok_or(ParseError::Format(tag))
}

fn parse_line<S: FromStr<Err = E>, E: Into<ParseError>>(
    tag: &'static str,
    line: Option<&str>,
) -> Result<S, ParseError> {
    tagged(tag, line).and_then(|s| S::from_str(s).map_err(|e| e.into()))
}

fn tag_optional<'a>(
    tag: &'static str,
    line: Option<&'a str>,
) -> Result<Option<&'a str>, ParseError> {
    match tagged(tag, line).map(Some) {
        Err(ParseError::Format(t)) if t == tag => Ok(None),
        r => r,
    }
}

impl FromStr for Message {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.split('\n');
        let domain = lines
            .next()
            .and_then(|preamble| preamble.strip_suffix(PREAMBLE))
            .map(Authority::from_str)
            .ok_or(ParseError::Format("Missing Preamble Line"))??;
        let address = tagged(ADDR_TAG, lines.next())
            .and_then(|a| {
                if is_checksum(a) {
                    Ok(a)
                } else {
                    Err(ParseError::Format("Address is not in EIP 55 format"))
                }
            })
            .and_then(|a| <[u8; 20]>::from_hex(a).map_err(|e| e.into()))?;

        // Skip the new line:
        lines.next();
        let statement = match lines.next() {
            None => return Err(ParseError::Format("No lines found after address")),
            Some("") => None,
            Some(s) => {
                lines.next();
                Some(s.to_string())
            }
        };

        let uri = parse_line(URI_TAG, lines.next())?;
        let version = parse_line(VERSION_TAG, lines.next())?;
        let chain_id = parse_line(CHAIN_TAG, lines.next())?;
        let nonce = parse_line(NONCE_TAG, lines.next())?;
        let issued_at = tagged(IAT_TAG, lines.next())?.parse()?;

        let mut line = lines.next();
        let expiration_time = match tag_optional(EXP_TAG, line)? {
            Some(exp) => {
                line = lines.next();
                Some(exp.parse()?)
            }
            None => None,
        };
        let not_before = match tag_optional(NBF_TAG, line)? {
            Some(nbf) => {
                line = lines.next();
                Some(nbf.parse()?)
            }
            None => None,
        };

        let request_id = match tag_optional(RID_TAG, line)? {
            Some(rid) => {
                line = lines.next();
                Some(rid.into())
            }
            None => None,
        };

        let resources = match line {
            Some(RES_TAG) => lines.map(|s| parse_line("- ", Some(s))).collect(),
            Some(_) => Err(ParseError::Format("Unexpected Content")),
            None => Ok(vec![]),
        }?;

        Ok(Message {
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        })
    }
}

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error(transparent)]
    Crypto(#[from] k256::ecdsa::Error),
    #[error(transparent)]
    Serialization(#[from] fmt::Error),
    #[error("Recovered key does not match address")]
    Signer,
    #[error("Message is not currently valid")]
    Time,
}

// is_checksum takes an UNPREFIXED eth address and returns whether it is in checksum format or not.
pub fn is_checksum(address: &str) -> bool {
    match <[u8; 20]>::from_hex(address) {
        Ok(s) => {
            let sum = to_checksum(&H160(s), None);
            let sum = sum.trim_start_matches("0x");
            sum == address
        }
        Err(_) => false
    }
}

impl Message {
    pub fn verify_eip191(&self, sig: &[u8; 65]) -> Result<Vec<u8>, VerificationError> {
        use k256::{
            ecdsa::{
                recoverable::{Id, Signature},
                signature::Signature as S,
                Signature as Sig,
            },
            elliptic_curve::sec1::ToEncodedPoint,
        };
        use sha3::{Digest, Keccak256};
        let pk = Signature::new(&Sig::from_bytes(&sig[..64])?, Id::new(&sig[64] % 27)?)?
            .recover_verify_key(&self.eip191_string()?)?;

        if Keccak256::default()
            .chain(&pk.to_encoded_point(false).as_bytes()[1..])
            .finalize()[12..]
            != self.address
        {
            Err(VerificationError::Signer)
        } else {
            Ok(pk.to_bytes().into_iter().collect())
        }
    }

    pub fn verify(&self, sig: [u8; 65]) -> Result<Vec<u8>, VerificationError> {
        if !self.valid_now() {
            Err(VerificationError::Time)
        } else {
            self.verify_eip191(&sig)
        }
    }

    pub fn valid_now(&self) -> bool {
        self.valid_at(&Utc::now())
    }

    pub fn valid_at(&self, t: &DateTime<Utc>) -> bool {
        self.not_before.as_ref().map(|nbf| nbf < t).unwrap_or(true)
            && self
                .expiration_time
                .as_ref()
                .map(|exp| exp >= t)
                .unwrap_or(true)
    }

    pub fn eip191_string(&self) -> Result<Vec<u8>, fmt::Error> {
        let s = self.to_string();
        Ok(format!("\x19Ethereum Signed Message:\n{}{}", s.as_bytes().len(), s).into())
    }

    pub fn eip191_hash(&self) -> Result<[u8; 32], fmt::Error> {
        use sha3::{Digest, Keccak256};
        Ok(Keccak256::default()
            .chain(&self.eip191_string()?)
            .finalize()
            .into())
    }
}

const PREAMBLE: &str = " wants you to sign in with your Ethereum account:";
const ADDR_TAG: &str = "0x";
const URI_TAG: &str = "URI: ";
const VERSION_TAG: &str = "Version: ";
const CHAIN_TAG: &str = "Chain ID: ";
const NONCE_TAG: &str = "Nonce: ";
const IAT_TAG: &str = "Issued At: ";
const EXP_TAG: &str = "Expiration Time: ";
const NBF_TAG: &str = "Not Before: ";
const RID_TAG: &str = "Request ID: ";
const RES_TAG: &str = "Resources:";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        // correct order
        let message = r#"service.org wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json"#;

        assert!(Message::from_str(message).is_ok());

        assert_eq!(message, &Message::from_str(message).unwrap().to_string());

        // incorrect order
        assert!(Message::from_str(
            r#"service.org wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Nonce: 32891756
Chain ID: 1
Issued At: 2021-09-30T16:25:24Z
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json"#,
        )
        .is_err());

        //  no statement
        let message = r#"service.org wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

URI: https://service.org/login
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json"#;

        assert!(Message::from_str(message).is_ok());

        assert_eq!(message, &Message::from_str(message).unwrap().to_string());
    }

    #[test]
    fn validation() {
        let message = Message::from_str(
            r#"localhost:4361 wants you to sign in with your Ethereum account:
0x6Da01670d8fc844e736095918bbE11fE8D564163

SIWE Notepad Example

URI: http://localhost:4361
Version: 1
Chain ID: 1
Nonce: kEWepMt9knR6lWJ6A
Issued At: 2021-12-07T18:28:18.807Z"#,
        )
        .unwrap();
        let correct = <[u8; 65]>::from_hex(r#"6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap();
        assert!(message.verify_eip191(&correct).is_ok());
        let incorrect = <[u8; 65]>::from_hex(r#"7228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap();
        assert!(message.verify_eip191(&incorrect).is_err());
    }

    #[test]
    fn validation1() {
        let message = Message::from_str(r#"localhost wants you to sign in with your Ethereum account:
0x4b60ffAf6fD681AbcC270Faf4472011A4A14724C

Allow localhost to access your orbit using their temporary session key: did:key:z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg#z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg

URI: did:key:z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg#z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg
Version: 1
Chain ID: 1
Nonce: PPrtjztx2lYqWbqNs
Issued At: 2021-12-20T12:29:25.907Z
Expiration Time: 2021-12-20T12:44:25.906Z
Resources:
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#put
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#del
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#get
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#list"#).unwrap();
        let correct = <[u8; 65]>::from_hex(r#"20c0da863b3dbfbb2acc0fb3b9ec6daefa38f3f20c997c283c4818ebeca96878787f84fccc25c4087ccb31ebd782ae1d2f74be076a49c0a8604419e41507e9381c"#).unwrap();
        assert!(message.verify_eip191(&correct).is_ok());
        let incorrect = <[u8; 65]>::from_hex(r#"30c0da863b3dbfbb2acc0fb3b9ec6daefa38f3f20c997c283c4818ebeca96878787f84fccc25c4087ccb31ebd782ae1d2f74be076a49c0a8604419e41507e9381c"#).unwrap();
        assert!(message.verify_eip191(&incorrect).is_err());
    }

    const PARSING_POSITIVE: &str = include_str!("../tests/siwe/test/parsing_positive.json");
    const PARSING_NEGATIVE: &str = include_str!("../tests/siwe/test/parsing_negative.json");
    const VALIDATION_POSITIVE: &str = include_str!("../tests/siwe/test/validation_positive.json");
    const VALIDATION_NEGATIVE: &str = include_str!("../tests/siwe/test/validation_negative.json");

    fn fields_to_message(fields: &serde_json::Value) -> anyhow::Result<Message> {
        let fields = fields.as_object().unwrap();
        Ok(Message {
            domain: fields["domain"].as_str().unwrap().try_into().unwrap(),
            address: <[u8; 20]>::from_hex(
                fields["address"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("0x")
                    .unwrap(),
            )
            .unwrap(),
            statement: fields
                .get("statement")
                .map(|s| s.as_str().unwrap().try_into().unwrap()),
            uri: fields["uri"].as_str().unwrap().try_into().unwrap(),
            version: <Version as std::str::FromStr>::from_str(fields["version"].as_str().unwrap())
                .unwrap(),
            chain_id: fields["chainId"].as_u64().unwrap(),
            nonce: fields["nonce"].as_str().unwrap().try_into().unwrap(),
            issued_at: <TimeStamp as std::str::FromStr>::from_str(
                fields["issuedAt"].as_str().unwrap(),
            )
            .unwrap(),
            expiration_time: match fields.get("expirationTime") {
                Some(e) => Some(<TimeStamp as std::str::FromStr>::from_str(
                    e.as_str().unwrap(),
                )?),
                None => None,
            },
            not_before: fields
                .get("notBefore")
                .map(|e| <TimeStamp as std::str::FromStr>::from_str(e.as_str().unwrap()).unwrap()),
            request_id: fields
                .get("requestId")
                .map(|e| e.as_str().unwrap().to_string()),
            resources: fields
                .get("resources")
                .map(|e| {
                    e.as_array()
                        .unwrap()
                        .iter()
                        .map(|r| {
                            <UriString as std::str::FromStr>::from_str(r.as_str().unwrap()).unwrap()
                        })
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    #[test]
    fn parsing_positive() {
        let tests: serde_json::Value = serde_json::from_str(PARSING_POSITIVE).unwrap();
        for (test_name, test) in tests.as_object().unwrap() {
            print!("{} -> ", test_name);
            let parsed_message = Message::from_str(test["message"].as_str().unwrap()).unwrap();
            let fields = &test["fields"];
            let expected_message = fields_to_message(fields).unwrap();
            assert!(parsed_message == expected_message);
            println!("✅")
        }
    }

    #[test]
    fn parsing_negative() {
        let tests: serde_json::Value = serde_json::from_str(PARSING_NEGATIVE).unwrap();
        for (test_name, test) in tests.as_object().unwrap() {
            print!("{} -> ", test_name);
            assert!(Message::from_str(test.as_str().unwrap()).is_err());
            println!("✅")
        }
    }

    #[test]
    fn validation_positive() {
        let tests: serde_json::Value = serde_json::from_str(VALIDATION_POSITIVE).unwrap();
        for (test_name, test) in tests.as_object().unwrap() {
            print!("{} -> ", test_name);
            let fields = &test;
            let message = fields_to_message(fields).unwrap();
            let signature = <[u8; 65]>::from_hex(
                fields.as_object().unwrap()["signature"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("0x")
                    .unwrap(),
            )
            .unwrap();
            assert!(message.verify(signature).is_ok());
            println!("✅")
        }
    }

    #[test]
    fn validation_negative() {
        let tests: serde_json::Value = serde_json::from_str(VALIDATION_NEGATIVE).unwrap();
        for (test_name, test) in tests.as_object().unwrap() {
            print!("{} -> ", test_name);
            let fields = &test;
            let message = fields_to_message(fields);
            let signature = <[u8; 65]>::from_hex(
                fields.as_object().unwrap()["signature"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("0x")
                    .unwrap(),
            );
            assert!(
                message.is_err()
                    || signature.is_err()
                    || message.unwrap().verify(signature.unwrap()).is_err()
            );
            println!("✅")
        }
    }

    const VALID_CASES: &'static [&'static str] = &[
        // From the spec:
        // All caps
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        // All Lower
        "0xde709f2102306220921060314715629080e2fb77",
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];

    const INVALID_CASES: &'static [&'static str] = &[
        // From eip55 Crate:
        "0xD1220a0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        "0xdbF03B407c01e7cD3CBea99509d93f8DDDC8C6FB",
        "0xfb6916095ca1df60bB79Ce92cE3Ea74c37c5D359",
        "0x5aAeb6053f3E94C9b9A09f33669435E7Ef1BeAed",
        // FROM SO QUESTION:
        "0xCF5609B003B2776699EEA1233F7C82D5695CC9AA",
        // From eip55 Crate Issue
        "0x000000000000000000000000000000000000dEAD",
    ];

    #[test]
    fn test_is_checksum() {
        for case in VALID_CASES {
            let c = case.trim_start_matches("0x");
            assert_eq!(is_checksum(&c), true)
        }

        for case in INVALID_CASES {
            let c = case.trim_start_matches("0x");
            assert_eq!(is_checksum(&c), false)
        }
    }
}
