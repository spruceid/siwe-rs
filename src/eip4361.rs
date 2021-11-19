use chrono::{DateTime, Utc};
use core::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};
use iri_string::types::{UriAbsoluteString, UriString};
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{line_ending, not_line_ending},
    combinator::{all_consuming, eof, flat_map},
    sequence::{preceded, terminated, tuple},
    IResult, ParseTo,
};
use thiserror::Error;
use url::Host as GHost;

type Host = GHost<String>;

type TimeStamp = DateTime<Utc>;

#[derive(Copy, Clone)]
pub enum Version {
    V1 = 1,
}

impl FromStr for Version {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "1" {
            Ok(Self::V1)
        } else {
            Err(())
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
    pub issued_at: TimeStamp,
    pub expiration_time: Option<TimeStamp>,
    pub not_before: Option<TimeStamp>,
    pub request_id: Option<String>,
    pub resources: Vec<UriString>,
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "{}{}", &self.domain, PREAMBLE)?;
        writeln!(f, "{}", hex::encode(&self.address))?;
        writeln!(f, "\n{}\n", &self.statement)?;
        writeln!(f, "{}{}", URI_TAG, &self.uri)?;
        writeln!(f, "{}{}", VERSION_TAG, self.version as u64)?;
        writeln!(f, "{}{}", CHAIN_TAG, &self.chain_id)?;
        writeln!(f, "{}{}", NONCE_TAG, &self.nonce)?;
        writeln!(f, "{}{}", IAT_TAG, &self.issued_at)?;
        if let Some(exp) = &self.expiration_time {
            writeln!(f, "{}{}", EXP_TAG, exp)?
        };
        if let Some(nbf) = &self.not_before {
            writeln!(f, "{}{}", NBF_TAG, nbf)?
        };
        if let Some(rid) = &self.request_id {
            writeln!(f, "{}{}", RID_TAG, rid)?
        };
        if !self.resources.is_empty() {
            writeln!(f, "{}", RES_TAG)?;
            for res in &self.resources {
                writeln!(f, "- {}", res)?;
            }
        };
        Ok(())
    }
}

type NomErr<O> = (O, nom::error::ErrorKind);

fn line<'a>(s: &'a str) -> IResult<&'a str, &'a str, NomErr<&'a str>> {
    terminated(not_line_ending, alt((line_ending, eof)))(s)
}

fn tagged_line<'a, S: FromStr>(
    t: &str,
) -> impl FnMut(&'a str) -> nom::IResult<&'a str, S, NomErr<&'a str>> {
    flat_map(
        line,
        preceded(tag(t), |s: &str| {
            Ok((
                "",
                ParseTo::parse_to(&s).ok_or(nom::Err::Error((s, nom::error::ErrorKind::Fail)))?,
            ))
        }),
    )
}

fn parse_message<'a>(s: &'a str) -> IResult<&'a str, Message, NomErr<&'a str>> {
    // tuple((
    //     // terminated("") domain,

    // ))
    todo!()
}

impl FromStr for Message {
    type Err = nom::Err<(String, nom::error::ErrorKind)>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        all_consuming(parse_message)(s)
            .map(|(_, m)| m)
            .map_err(|e| e.to_owned())
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
            ecdsa::{recoverable::Signature, signature::Signature as s},
            elliptic_curve::sec1::ToEncodedPoint,
        };
        use sha3::{Digest, Keccak256};
        let pk = Signature::from_bytes(&sig)?.recover_verify_key(&self.eip191_string()?)?;

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
        let t = Utc::now();
        self.not_before.map_or(true, |n| t >= n) && self.expiration_time.map_or(true, |e| t < e)
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

#[test]
fn parse() {
    Message::from_str(
        r#"service.org wants you to sign in with your Ethereum account:
0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json"#,
    )
    .unwrap();
}
