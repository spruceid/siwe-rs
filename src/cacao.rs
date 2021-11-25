use async_trait::async_trait;
use chrono::{DateTime, Utc};
use iri_string::types::{UriAbsoluteString, UriString};
use std::{marker::PhantomData, str::FromStr};
use thiserror::Error;
use url::Host as GHost;

pub type Host = GHost<String>;
pub type TimeStamp = DateTime<Utc>;

pub struct CACAO<S: SignatureScheme> {
    pub h: Header,
    pub p: Payload,
    pub s: <<S as SignatureScheme>::SigType as SignatureType>::Signature,
}

pub struct Header {
    t: String,
}

#[async_trait]
pub trait SignatureScheme {
    type SigType: SignatureType;
    type RepOutput: Into<<<Self as SignatureScheme>::SigType as SignatureType>::Payload>;
    type Rep: Representation<Output = Self::RepOutput>;
    type Err;
    fn id() -> String {
        [Self::Rep::ID, "-", Self::SigType::ID].concat()
    }
    fn header() -> Header {
        Header { t: Self::id() }
    }
    async fn verify(
        payload: &CACAO<Self>,
    ) -> Result<<<Self as SignatureScheme>::SigType as SignatureType>::Output, Self::Err>
    where
        Self: Sized;
}

#[derive(Default)]
pub struct GenericScheme<R, S>(PhantomData<R>, PhantomData<S>);

#[derive(Error, Debug)]
pub enum VerificationError<S, E> {
    // pub enum VerificationError<S: StdErr, E: StdErr> {
    #[error("Verification Failed")]
    Crypto,
    #[error(transparent)]
    Serialization(#[from] S),
    #[error("Missing Payload Verification Material")]
    MissingVerificationMaterial,
    #[error(transparent)]
    Custom(E),
}

#[async_trait]
impl<R, S, P> SignatureScheme for GenericScheme<R, S>
where
    R: Representation<Output = P>,
    S: SignatureType,
    P: Into<S::Payload> + Send,
    S::Signature: Sync + Send,
    S::VerificationMaterial: Send + Sync,
    S::Payload: Send + Sync,
    R::Err: Send + Sync

{
    type Rep = R;
    type SigType = S;
    type RepOutput = P;
    type Err = VerificationError<R::Err, ()>;
    async fn verify(
        payload: &CACAO<Self>,
    ) -> Result<<<Self as SignatureScheme>::SigType as SignatureType>::Output, Self::Err>
    where
        Self: Sized,
    {
        Ok(Self::SigType::verify(
            &Self::Rep::serialize(&payload.p)?.into(),
            &Self::SigType::get_vmat(payload).ok_or(Self::Err::MissingVerificationMaterial)?,
            &payload.s,
        ).await
        .map_err(|_| Self::Err::Crypto)?)
    }
}

pub struct BasicSignature<S> {
    pub s: S,
}

pub trait Representation {
    const ID: &'static str;
    type Err;
    type Output;
    fn serialize(payload: &Payload) -> Result<Self::Output, Self::Err>;
}

#[async_trait]
pub trait SignatureType {
    const ID: &'static str;
    type Signature;
    type Payload;
    type VerificationMaterial;
    type Output;
    type Err;
    async fn verify(
        payload: &Self::Payload,
        key: &Self::VerificationMaterial,
        signature: &Self::Signature,
    ) -> Result<Self::Output, Self::Err>;
    fn get_vmat<S: SignatureScheme<SigType = Self>>(
        payload: &CACAO<S>,
    ) -> Option<Self::VerificationMaterial>;
}

#[derive(Copy, Clone)]
pub enum Version {
    V1 = 1,
}

#[derive(Clone)]
pub struct Payload {
    pub aud: Host,
    pub exp: Option<String>,
    pub iat: String,
    pub iss: UriAbsoluteString,
    pub nbf: Option<String>,
    pub uri: UriAbsoluteString,
    pub nonce: String,
    pub version: Version,
    pub requestId: Option<String>,
    pub resources: Vec<UriString>,
    pub statement: String,
}

impl Payload {
    pub fn sign<S: SignatureScheme>(
        self,
        s: <<S as SignatureScheme>::SigType as SignatureType>::Signature,
    ) -> CACAO<S> {
        CACAO {
            h: S::header(),
            p: self,
            s,
        }
    }

    pub fn address<'a>(&'a self) -> Option<&'a str> {
        self.iss.as_str().split(':').nth(4)
    }

    pub fn chain_id<'a>(&'a self) -> Option<&'a str> {
        let rest = self.iss.as_str().strip_prefix("did:pkh:")?;
        Some(rest.split_at(rest.rfind(':').unwrap_or(rest.len())).0)
    }

    pub fn iss<'a>(&'a self) -> &'a str {
        &self.iss.as_str()
    }

    pub fn valid_now(&self) -> bool {
        let now = Utc::now();
        self.nbf
            .as_ref()
            .and_then(|s| TimeStamp::from_str(s).ok())
            .map(|nbf| now >= nbf)
            .unwrap_or(true)
            && self
                .exp
                .as_ref()
                .and_then(|s| TimeStamp::from_str(s).ok())
                .map(|exp| now < exp)
                .unwrap_or(true)
    }
}
