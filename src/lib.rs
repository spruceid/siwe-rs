#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

use core::{
    convert::Infallible,
    fmt::{self, Display, Formatter},
    str::FromStr,
};
#[cfg(feature = "ethers")]
use ethers::prelude::*;
use hex::FromHex;
use http::uri::{Authority, InvalidUri};
use iri_string::types::UriString;
#[cfg(feature = "serde")]
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::convert::TryInto;
use thiserror::Error;
use time::OffsetDateTime;

#[cfg(feature = "ethers")]
mod eip1271;
mod nonce;
mod rfc3339;
pub use nonce::generate_nonce;
pub use rfc3339::TimeStamp;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// EIP-4361 version.
pub enum Version {
    /// V1
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

/// EIP-4361 message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The RFC 3986 authority that is requesting the signing.
    pub domain: Authority,
    /// The Ethereum address performing the signing conformant to capitalization encoded checksum specified in EIP-55 where applicable.
    pub address: [u8; 20],
    /// A human-readable ASCII assertion that the user will sign, and it must not contain '\n' (the byte 0x0a).
    pub statement: Option<String>,
    /// An RFC 3986 URI referring to the resource that is the subject of the signing (as in the subject of a claim).
    pub uri: UriString,
    /// The current version of the message, which MUST be 1 for this specification.
    pub version: Version,
    /// The EIP-155 Chain ID to which the session is bound, and the network where Contract Accounts MUST be resolved.
    pub chain_id: u64,
    /// A randomized token typically chosen by the relying party and used to prevent replay attacks, at least 8 alphanumeric characters.
    pub nonce: String,
    /// The ISO 8601 datetime string of the current time.
    pub issued_at: TimeStamp,
    /// The ISO 8601 datetime string that, if present, indicates when the signed authentication message is no longer valid.
    pub expiration_time: Option<TimeStamp>,
    /// The ISO 8601 datetime string that, if present, indicates when the signed authentication message will become valid.
    pub not_before: Option<TimeStamp>,
    /// An system-specific identifier that may be used to uniquely refer to the sign-in request.
    pub request_id: Option<String>,
    /// A list of information or references to information the user wishes to have resolved as part of authentication by the relying party. They are expressed as RFC 3986 URIs separated by "\n- " where \n is the byte 0x0a.
    pub resources: Vec<UriString>,
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "{}{}", &self.domain, PREAMBLE)?;
        writeln!(f, "{}", eip55(&self.address))?;
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
/// Errors raised during parsing/deserialization.
pub enum ParseError {
    #[error("Invalid Domain: {0}")]
    /// Domain field is non-conformant.
    Domain(#[from] InvalidUri),
    #[error("Formatting Error: {0}")]
    /// Catch-all for all other parsing errors.
    Format(&'static str),
    #[error("Invalid Address: {0}")]
    /// Address field is non-conformant.
    Address(#[from] hex::FromHexError),
    #[error("Invalid URI: {0}")]
    /// URI field is non-conformant.
    Uri(#[from] iri_string::validate::Error),
    #[error("Invalid Timestamp: {0}")]
    /// Timestamp is non-conformant.
    TimeStamp(#[from] time::Error),
    #[error(transparent)]
    /// Chain ID is non-conformant.
    ParseIntError(#[from] std::num::ParseIntError),
    #[error(transparent)]
    /// Infallible variant.
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
                    Err(ParseError::Format("Address is not in EIP-55 format"))
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
        let nonce = parse_line(NONCE_TAG, lines.next()).and_then(|nonce: String| {
            if nonce.len() < 8 {
                Err(ParseError::Format("Nonce must be longer than 8 characters"))
            } else {
                Ok(nonce)
            }
        })?;
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

#[cfg(feature = "serde")]
impl Serialize for Message {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

#[cfg(feature = "serde")]
struct MessageVisitor;

#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for MessageVisitor {
    type Value = Message;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an EIP-4361 formatted message")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match Message::from_str(value) {
            Ok(message) => Ok(message),
            Err(error) => Err(E::custom(format!("error parsing message: {}", error))),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Message {
    fn deserialize<D>(deserializer: D) -> Result<Message, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(MessageVisitor)
    }
}

#[cfg_attr(
    feature = "typed-builder",
    derive(typed_builder::TypedBuilder),
    builder(doc)
)]
#[derive(Default)]
/// Verification options and configuration
pub struct VerificationOpts {
    /// RFC 4501 dns authority that is requesting the signing (Optional)
    pub domain: Option<Authority>,
    /// Randomized token used to prevent replay attacks, at least 8 alphanumeric characters (Optional)
    pub nonce: Option<String>,
    /// ISO 8601 datetime string of the current time (Optional)
    pub timestamp: Option<OffsetDateTime>,
    #[cfg(feature = "ethers")]
    /// RPC Provider use for on-chain checks. Necessary for contract wallets signatures.
    pub rpc_provider: Option<Provider<Http>>,
}

#[derive(Error, Debug)]
/// Reasons for the verification of a signed message to fail.
pub enum VerificationError {
    #[error(transparent)]
    /// Signature is not a valid k256 signature (it can be returned if the contract wallet verification failed or is not enabled).
    Crypto(#[from] k256::ecdsa::Error),
    #[error(transparent)]
    /// Message failed to be serialized.
    Serialization(#[from] fmt::Error),
    #[error("Recovered key does not match address or contract wallet support is not enabled.")]
    /// Catch-all for invalid signature (it can be returned if contract wallet support is not enabled).
    Signer,
    #[error("Message is not currently valid")]
    /// Message is not currently valid.
    Time,
    #[error("Message domain does not match")]
    /// Expected message domain does not match.
    DomainMismatch,
    #[error("Message nonce does not match")]
    /// Expected message nonce does not match.
    NonceMismatch,
    #[cfg(feature = "ethers")]
    // Using a String because the original type requires a lifetime.
    #[error("Contract wallet query failed: {0}")]
    /// Contract wallet verification failed unexpectedly.
    ContractCall(String),
    #[error("The signature is not 65 bytes long. It might mean that it is a EIP1271 signature and you have the `ethers` feature disabled or configured a provider.")]
    /// The signature is not 65 bytes long. It might mean that it is a EIP1271 signature and you have the `ethers` feature disabled or configured a provider.
    SignatureLength,
}

/// Takes an UNPREFIXED eth address and returns whether it is in checksum format or not.
pub fn is_checksum(address: &str) -> bool {
    match <[u8; 20]>::from_hex(address) {
        Ok(s) => {
            let sum = eip55(&s);
            let sum = sum.trim_start_matches("0x");
            sum == address
        }
        Err(_) => false,
    }
}

impl Message {
    /// Verify the integrity of the message by matching its signature.
    ///
    /// # Arguments
    /// - `sig` - Signature of the message signed by the wallet
    ///
    /// # Example
    /// ```ignore
    /// let signer: Vec<u8> = message.verify_eip191(&signature)?;
    /// ```
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
            .recover_verifying_key(&self.eip191_bytes()?)?;

        if Keccak256::default()
            .chain_update(&pk.to_encoded_point(false).as_bytes()[1..])
            .finalize()[12..]
            != self.address
        {
            Err(VerificationError::Signer)
        } else {
            Ok(pk.to_bytes().into_iter().collect())
        }
    }

    #[cfg(feature = "ethers")]
    /// Verify the integrity of a, potentially, EIP-1271 signed message.
    ///
    /// # Arguments
    /// - `sig` - Signature of the message signed by the wallet.
    /// - `provider` - Provider used to query the chain.
    ///
    /// # Example
    /// ```ignore
    /// let is_valid: bool = message.verify_eip1271(&signature, "https://cloudflare-eth.com".try_into().unwrap())?;
    /// ```
    pub async fn verify_eip1271(
        &self,
        sig: &[u8],
        provider: &Provider<Http>,
    ) -> Result<bool, VerificationError> {
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::new_with_prefix(self.eip191_bytes().unwrap()).finalize();
        eip1271::verify_eip1271(self.address, hash.as_ref(), sig, provider).await
    }

    /// Validates time constraints and integrity of the object by matching it's signature.
    ///
    /// # Arguments
    /// - `sig` - Signature of the message signed by the wallet
    /// - `opts` - Verification options and configuration
    ///
    /// # Example
    /// ```ignore
    /// let message: Message = str.parse()?;
    /// let signature: [u8; 65];
    ///
    /// if let Err(e) = message.verify(&signature).await {
    ///     // message cannot be correctly authenticated at this time
    /// }
    ///
    /// // do application-specific things
    /// ```
    pub async fn verify(
        &self,
        sig: &[u8],
        opts: &VerificationOpts,
    ) -> Result<(), VerificationError> {
        match (
            opts.timestamp
                .as_ref()
                .map(|t| self.valid_at(t))
                .unwrap_or_else(|| self.valid_now()),
            opts.domain.as_ref(),
            opts.nonce.as_ref(),
        ) {
            (false, _, _) => return Err(VerificationError::Time),
            (_, Some(d), _) if *d != self.domain => return Err(VerificationError::DomainMismatch),
            (_, _, Some(n)) if *n != self.nonce => return Err(VerificationError::NonceMismatch),
            _ => (),
        };

        let res = if sig.len() == 65 {
            self.verify_eip191(sig.try_into().unwrap())
        } else {
            Err(VerificationError::SignatureLength)
        };

        #[cfg(feature = "ethers")]
        if let Err(e) = res {
            if let Some(provider) = &opts.rpc_provider {
                if self.verify_eip1271(sig, provider).await? {
                    return Ok(());
                }
            }
            return Err(e);
        }
        res.map(|_| ())
    }

    /// Validates the time constraints of the message at current time.
    ///
    /// # Example
    /// ```ignore
    /// if message.valid_now() { ... };
    ///
    /// // equivalent to
    /// if message.valid_at(&OffsetDateTime::now_utc()) { ... };
    /// ```
    pub fn valid_now(&self) -> bool {
        self.valid_at(&OffsetDateTime::now_utc())
    }

    /// Validates the time constraints of the message at a specific point in time.
    ///
    /// # Arguments
    /// - `t` - timestamp to use when validating time constraints
    ///
    /// # Example
    /// ```ignore
    /// if message.valid_now() { ... };
    ///
    /// // equivalent to
    /// if message.valid_at(&OffsetDateTime::now_utc()) { ... };
    /// ```
    pub fn valid_at(&self, t: &OffsetDateTime) -> bool {
        self.not_before.as_ref().map(|nbf| nbf < t).unwrap_or(true)
            && self
                .expiration_time
                .as_ref()
                .map(|exp| exp >= t)
                .unwrap_or(true)
    }

    /// Produces EIP-191 Personal-Signature pre-hash signing input
    ///
    /// # Example
    /// ```ignore
    /// let eip191_bytes: Vec<u8> = message.eip191_bytes()?;
    /// ```
    pub fn eip191_bytes(&self) -> Result<Vec<u8>, fmt::Error> {
        let s = self.to_string();
        Ok(format!("\x19Ethereum Signed Message:\n{}{}", s.as_bytes().len(), s).into())
    }

    /// Produces EIP-191 Personal-Signature Hashed signing-input
    ///
    /// # Example
    /// ```ignore
    /// let eip191_hash: [u8; 32] = message.eip191_hash()?;
    /// ```
    pub fn eip191_hash(&self) -> Result<[u8; 32], fmt::Error> {
        use sha3::{Digest, Keccak256};
        Ok(Keccak256::default()
            .chain_update(&self.eip191_bytes()?)
            .finalize()
            .into())
    }
}

/// Takes an eth address and returns it as a checksum formatted string.
pub fn eip55(addr: &[u8; 20]) -> String {
    use sha3::{Digest, Keccak256};
    let addr_str = hex::encode(addr);
    let hash = Keccak256::digest(addr_str.as_bytes());
    "0x".chars()
        .chain(addr_str.chars().enumerate().map(|(i, c)| {
            match (c, hash[i >> 1] & if i % 2 == 0 { 128 } else { 8 } != 0) {
                ('a'..='f' | 'A'..='F', true) => c.to_ascii_uppercase(),
                _ => c.to_ascii_lowercase(),
            }
        }))
        .collect()
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
    use time::format_description::well_known::Rfc3339;

    use super::*;
    use std::convert::TryInto;

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

    #[tokio::test]
    async fn verification() {
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

    #[tokio::test]
    async fn verification1() {
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
    const VERIFICATION_POSITIVE: &str =
        include_str!("../tests/siwe/test/verification_positive.json");
    const VERIFICATION_NEGATIVE: &str =
        include_str!("../tests/siwe/test/verification_negative.json");
    #[cfg(feature = "ethers")]
    const VERIFICATION_EIP1271: &str = include_str!("../tests/siwe/test/eip1271.json");

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

    #[tokio::test]
    async fn verification_positive() {
        let tests: serde_json::Value = serde_json::from_str(VERIFICATION_POSITIVE).unwrap();
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
            let timestamp = fields
                .as_object()
                .unwrap()
                .get("time")
                .and_then(|timestamp| {
                    OffsetDateTime::parse(timestamp.as_str().unwrap(), &Rfc3339).ok()
                });
            let opts = VerificationOpts {
                timestamp,
                ..Default::default()
            };
            assert!(message.verify(&signature, &opts).await.is_ok());
            println!("✅")
        }
    }

    #[cfg(feature = "ethers")]
    #[tokio::test]
    async fn verification_eip1271() {
        let tests: serde_json::Value = serde_json::from_str(VERIFICATION_EIP1271).unwrap();
        for (test_name, test) in tests.as_object().unwrap() {
            print!("{} -> ", test_name);
            let message = Message::from_str(test["message"].as_str().unwrap()).unwrap();
            let signature = <Vec<u8>>::from_hex(
                test["signature"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("0x")
                    .unwrap(),
            )
            .unwrap();
            let opts = VerificationOpts {
                rpc_provider: Some("https://cloudflare-eth.com".try_into().unwrap()),
                ..Default::default()
            };
            assert!(message.verify(&signature, &opts).await.is_ok());
            println!("✅")
        }
    }

    #[tokio::test]
    async fn verification_negative() {
        let tests: serde_json::Value = serde_json::from_str(VERIFICATION_NEGATIVE).unwrap();
        for (test_name, test) in tests.as_object().unwrap() {
            print!("{} -> ", test_name);
            let fields = &test;
            let message = fields_to_message(fields);
            let signature = <Vec<u8>>::from_hex(
                fields.as_object().unwrap()["signature"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("0x")
                    .unwrap(),
            );
            let domain_binding =
                fields
                    .as_object()
                    .unwrap()
                    .get("domainBinding")
                    .and_then(|domain_binding| {
                        Authority::from_str(domain_binding.as_str().unwrap()).ok()
                    });
            let match_nonce = fields
                .as_object()
                .unwrap()
                .get("matchNonce")
                .and_then(|match_nonce| match_nonce.as_str())
                .map(|n| n.to_string());
            let timestamp = fields
                .as_object()
                .unwrap()
                .get("time")
                .and_then(|timestamp| {
                    OffsetDateTime::parse(timestamp.as_str().unwrap(), &Rfc3339).ok()
                });
            #[allow(clippy::needless_update)]
            let opts = VerificationOpts {
                domain: domain_binding,
                nonce: match_nonce,
                timestamp,
                ..Default::default()
            };
            assert!(
                message.is_err()
                    || signature.is_err()
                    || message
                        .unwrap()
                        .verify(&signature.unwrap(), &opts,)
                        .await
                        .is_err()
            );
            println!("✅")
        }
    }

    const VALID_CASES: &[&str] = &[
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

    const INVALID_CASES: &[&str] = &[
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
            assert!(is_checksum(c))
        }

        for case in INVALID_CASES {
            let c = case.trim_start_matches("0x");
            assert!(!is_checksum(c))
        }
    }

    #[test]
    fn eip55_test() {
        // vectors from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md

        assert!(test_eip55(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        ));
        assert!(test_eip55(
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        ));
        assert!(test_eip55(
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
        ));
        assert!(test_eip55(
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
        ));

        assert!(test_eip55(
            "0x52908400098527886E0F7030069857D2E4169EE7",
            "0x52908400098527886E0F7030069857D2E4169EE7",
        ));
        assert!(test_eip55(
            "0x8617e340b3d01fa5f11f306f4090fd50e238070d",
            "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        ));
        assert!(test_eip55(
            "0xde709f2102306220921060314715629080e2fb77",
            "0xde709f2102306220921060314715629080e2fb77",
        ));
        assert!(test_eip55(
            "0x27b1fdb04752bbc536007a920d24acb045561c26",
            "0x27b1fdb04752bbc536007a920d24acb045561c26"
        ));
        assert!(test_eip55(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        ));
        assert!(test_eip55(
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        ));
        assert!(test_eip55(
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        ));
        assert!(test_eip55(
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
        ));
    }

    fn test_eip55(addr: &str, checksum: &str) -> bool {
        let unprefixed = addr.strip_prefix("0x").unwrap();
        eip55(&<[u8; 20]>::from_hex(unprefixed).unwrap()) == checksum
            && eip55(&<[u8; 20]>::from_hex(unprefixed.to_lowercase()).unwrap()) == checksum
            && eip55(&<[u8; 20]>::from_hex(unprefixed.to_uppercase()).unwrap()) == checksum
    }
}
