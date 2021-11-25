use super::cacao::*;
use iri_string::types::UriAbsoluteString;
use std::{
    convert::Infallible,
    fmt::{Error, Write},
    str::FromStr,
};
use thiserror::Error;

pub struct EIP4361;

impl Representation for EIP4361 {
    const ID: &'static str = "eip4361";
    type Err = Error;
    type Output = String;
    fn serialize(payload: &Payload) -> Result<Self::Output, Self::Err> {
        let mut w = String::new();
        writeln!(&mut w, "{}{}", &payload.aud, PREAMBLE)?;
        writeln!(&mut w, "{}", &payload.address().ok_or(Error)?)?;
        writeln!(&mut w, "\n{}\n", &payload.statement)?;
        writeln!(&mut w, "{}{}", URI_TAG, &payload.uri)?;
        writeln!(&mut w, "{}{}", VERSION_TAG, payload.version as u64)?;
        writeln!(
            &mut w,
            "{}{}",
            CHAIN_TAG,
            &payload
                .chain_id()
                .and_then(|c| c.split(':').nth(1))
                .ok_or(Error)?
        )?;
        writeln!(&mut w, "{}{}", NONCE_TAG, &payload.nonce)?;
        write!(&mut w, "{}{}", IAT_TAG, &payload.iat)?;
        if let Some(exp) = &payload.exp {
            write!(&mut w, "\n{}{}", EXP_TAG, &exp)?
        };
        if let Some(nbf) = &payload.nbf {
            write!(&mut w, "\n{}{}", NBF_TAG, &nbf)?
        };
        if let Some(rid) = &payload.requestId {
            write!(&mut w, "\n{}{}", RID_TAG, rid)?
        };
        if !payload.resources.is_empty() {
            write!(&mut w, "\n{}", RES_TAG)?;
            for res in &payload.resources {
                write!(&mut w, "\n- {}", res)?;
            }
        };
        Ok(w)
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

pub fn from_str(s: &str) -> Result<Payload, ParseError> {
    use hex::FromHex;
    let mut lines = s.split("\n");
    let aud = lines
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
    let version = if 1u32 == parse_line(VERSION_TAG, lines.next())? {
        Version::V1
    } else {
        return Err(ParseError::Format("Bad Version"));
    };
    let chain_id = tagged(CHAIN_TAG, lines.next())?;
    let nonce = parse_line(NONCE_TAG, lines.next())?;
    let iat = tagged(IAT_TAG, lines.next()).and_then(|iat| {
        TimeStamp::from_str(iat)?;
        Ok(iat.into())
    })?;

    let mut line = lines.next();
    let exp = match tag_optional(EXP_TAG, line)? {
        Some(exp) => {
            TimeStamp::from_str(&exp)?;
            line = lines.next();
            Some(exp.into())
        }
        None => None,
    };
    let nbf = match tag_optional(NBF_TAG, line)? {
        Some(nbf) => {
            TimeStamp::from_str(nbf)?;
            line = lines.next();
            Some(nbf.into())
        }
        None => None,
    };

    let requestId = match tag_optional(RID_TAG, line)? {
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

    let iss = UriAbsoluteString::from_str(&format!(
        "did:pkh:eip155:{}:0x{}",
        chain_id,
        hex::encode(address)
    ))?;

    Ok(Payload {
        aud,
        iss,
        statement,
        uri,
        version,
        nonce,
        iat,
        exp,
        nbf,
        requestId,
        resources,
    })
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

        let m = from_str(message).unwrap();

        assert_eq!(message, &EIP4361::serialize(&m).unwrap());

        // incorrect order
        assert!(from_str(
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
}
