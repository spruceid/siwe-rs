use chrono::{DateTime, SecondsFormat, Utc};
use core::{
    convert::Infallible,
    fmt::{self, Display, Formatter},
    str::FromStr,
};
use iri_string::types::{UriAbsoluteString, UriString};
use thiserror::Error;
use url::Host as GHost;

type Host = GHost<String>;

type TimeStamp = DateTime<Utc>;

#[derive(Copy, Clone)]
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

pub struct Message {
    pub domain: Host,
    pub address: [u8; 20],
    pub statement: String,
    pub uri: UriAbsoluteString,
    pub version: Version,
    pub chain_id: String,
    pub nonce: String,
    pub issued_at: String,
    pub expiration_time: Option<String>,
    pub not_before: Option<String>,
    pub request_id: Option<String>,
    pub resources: Vec<UriString>,
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "{}{}", &self.domain, PREAMBLE)?;
        writeln!(f, "0x{}", hex::encode(&self.address))?;
        writeln!(f, "\n{}\n", &self.statement)?;
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
    Domain(#[from] url::ParseError),
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

fn parse_line<'a, S: FromStr<Err = E>, E: Into<ParseError>>(
    tag: &'static str,
    line: Option<&'a str>,
) -> Result<S, ParseError> {
    tagged(tag, line).and_then(|s| S::from_str(s).map_err(|e| e.into()))
}

fn tag_optional<'a>(
    tag: &'static str,
    line: Option<&'a str>,
) -> Result<Option<&'a str>, ParseError> {
    match tagged(tag, line).map(|s| Some(s)) {
        Err(ParseError::Format(t)) if t == tag => Ok(None),
        r => r,
    }
}

impl FromStr for Message {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use hex::FromHex;
        let mut lines = s.split("\n");
        let domain = lines
            .next()
            .and_then(|preamble| preamble.strip_suffix(PREAMBLE))
            .map(Host::parse)
            .ok_or(ParseError::Format("Missing Preamble Line"))??;
        let address = tagged(ADDR_TAG, lines.next())
            .and_then(|a| <[u8; 20]>::from_hex(a).map_err(|e| e.into()))?;
        let statement = match (lines.next(), lines.next(), lines.next()) {
            (Some(""), Some(s), Some("")) => s.to_string(),
            _ => return Err(ParseError::Statement("Missing Statement")),
        };
        let uri = parse_line(URI_TAG, lines.next())?;
        let version = parse_line(VERSION_TAG, lines.next())?;
        let chain_id = parse_line(CHAIN_TAG, lines.next())?;
        let nonce = parse_line(NONCE_TAG, lines.next())?;
        let issued_at = tagged(IAT_TAG, lines.next()).and_then(|iat| {
            TimeStamp::from_str(iat)?;
            Ok(iat.into())
        })?;

        let mut line = lines.next();
        let expiration_time = match tag_optional(EXP_TAG, line)? {
            Some(exp) => {
                TimeStamp::from_str(&exp)?;
                line = lines.next();
                Some(exp.into())
            }
            None => None,
        };
        let not_before = match tag_optional(NBF_TAG, line)? {
            Some(nbf) => {
                TimeStamp::from_str(nbf)?;
                line = lines.next();
                Some(nbf.into())
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
}

impl Message {
    pub fn verify_eip191(&self, sig: [u8; 65]) -> Result<Vec<u8>, VerificationError> {
        use k256::{
            ecdsa::{
                recoverable::{Id, Signature},
                signature::Signature as S,
                Error, Signature as Sig, VerifyingKey,
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

    pub fn valid_now(&self) -> bool {
        let now = Utc::now();
        self.not_before
            .as_ref()
            .and_then(|s| TimeStamp::from_str(s).ok())
            .map(|nbf| now >= nbf)
            .unwrap_or(true)
            && self
                .expiration_time
                .as_ref()
                .and_then(|s| TimeStamp::from_str(s).ok())
                .map(|exp| now < exp)
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

const PREAMBLE: &'static str = " wants you to sign in with your Ethereum account:";
const ADDR_TAG: &'static str = "0x";
const URI_TAG: &'static str = "URI: ";
const VERSION_TAG: &'static str = "Version: ";
const CHAIN_TAG: &'static str = "Chain ID: ";
const NONCE_TAG: &'static str = "Nonce: ";
const IAT_TAG: &'static str = "Issued At: ";
const EXP_TAG: &'static str = "Expiration Time: ";
const NBF_TAG: &'static str = "Not Before: ";
const RID_TAG: &'static str = "Request ID: ";
const RES_TAG: &'static str = "Resources:";

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn parsing() {
        // correct order
        let message = r#"service.org wants you to sign in with your Ethereum account:
0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2

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
0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2

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
        .is_err())
    }

    #[test]
    fn validation() {
        let message = Message::from_str(
            r#"login.xyz wants you to sign in with your Ethereum account:
0xe2f03cb7a54ddd886da9b0d227bfcb2d61429699

Sign-In With Ethereum Example Statement

URI: https://login.xyz
Version: 1
Chain ID: 1
Nonce: k13wuejc
Issued At: 2021-11-12T17:37:48.462Z"#,
        )
        .unwrap();
        let correct = <[u8; 65]>::from_hex(r#"795110331a07a4d475419fbdb346feb4c0579dcc8228989964474e07d98dbf425f38776cd6ca037f58288acc7b15e720c9cecac988479177fb70592f2391aaff1b"#).unwrap();
        assert!(message.verify_eip191(correct).is_ok());
        let incorrect = <[u8; 65]>::from_hex(r#"895110331a07a4d475419fbdb346feb4c0579dcc8228989964474e07d98dbf425f38776cd6ca037f58288acc7b15e720c9cecac988479177fb70592f2391aaff1b"#).unwrap();
        assert!(message.verify_eip191(incorrect).is_err());
    }

    #[test]
    fn validation1() {
        let message = Message::from_str(
            r#"login.xyz wants you to sign in with your Ethereum account:
0x4b60ffaf6fd681abcc270faf4472011a4a14724c

sign-In With Ethereum Example Statement

URI: https://login.xyz
Version: 1
Chain ID: 1
Nonce: k13wuejc
Issued At: 2021-11-12T17:37:48.462Z"#,
        )
        .unwrap();
        let correct = <[u8; 65]>::from_hex(r#"40208c53a8939040a9b98edc7a523af4f2eff7ecac17796a9828be055d1e52de53ff813544652ecd7cdeddae01326d778728cb741835b3f135d6fb89865012cf1c"#).unwrap();
        assert!(message.verify_eip191(correct).is_ok());
        let incorrect = <[u8; 65]>::from_hex(r#"50208c53a8939040a9b98edc7a523af4f2eff7ecac17796a9828be055d1e52de53ff813544652ecd7cdeddae01326d778728cb741835b3f135d6fb89865012cf1c"#).unwrap();
        assert!(message.verify_eip191(incorrect).is_err());
    }
}
