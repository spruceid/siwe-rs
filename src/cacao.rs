use async_trait::async_trait;
use chrono::{DateTime, Utc};
use iri_string::types::{UriAbsoluteString, UriString};
use std::{marker::PhantomData, str::FromStr};
use thiserror::Error;
use url::Host as GHost;

pub type Host = GHost<String>;
pub type TimeStamp = DateTime<Utc>;

pub struct CACAO<S: SignatureScheme> {
    h: Header,
    p: Payload,
    s: <S::SigType as SignatureType>::Signature,
}

impl<S> CACAO<S>
where
    S: SignatureScheme,
{
    pub fn new(p: Payload, s: <S::SigType as SignatureType>::Signature) -> Self {
        Self {
            h: S::header(),
            p,
            s,
        }
    }

    pub fn header(&self) -> &Header {
        &self.h
    }

    pub fn payload(&self) -> &Payload {
        &self.p
    }

    pub fn signature(&self) -> &<S::SigType as SignatureType>::Signature {
        &self.s
    }

    pub async fn verify(
        &self,
    ) -> Result<
        <S::SigType as SignatureType>::Output,
        VerificationError<<S::Rep as Representation>::Err>,
    >
    where
        S: Send + Sync,
        S::RepOutput: Send + Sync,
        <S::SigType as SignatureType>::Signature: Send + Sync,
        <S::SigType as SignatureType>::Payload: Send + Sync,
        <S::SigType as SignatureType>::VerificationMaterial: Send + Sync,
        <S::Rep as Representation>::Err: Send + Sync,
    {
        S::verify_cacao(&self).await
    }
}

pub struct Header {
    t: String,
}

#[async_trait]
pub trait SignatureScheme {
    type SigType: SignatureType;
    type RepOutput: Into<<<Self as SignatureScheme>::SigType as SignatureType>::Payload>;
    type Rep: Representation<Output = Self::RepOutput>;
    fn id() -> String {
        [Self::Rep::ID, "-", Self::SigType::ID].concat()
    }
    fn header() -> Header {
        Header { t: Self::id() }
    }
    async fn verify(
        payload: &Payload,
        sig: &<Self::SigType as SignatureType>::Signature,
    ) -> Result<
        <Self::SigType as SignatureType>::Output,
        VerificationError<<Self::Rep as Representation>::Err>,
    >
    where
        Self::RepOutput: Send + Sync,
        <Self::SigType as SignatureType>::Signature: Send + Sync,
        <Self::SigType as SignatureType>::Payload: Send + Sync,
        <Self::SigType as SignatureType>::VerificationMaterial: Send + Sync,
        <Self::Rep as Representation>::Err: Send + Sync,
    {
        if !payload.valid_now() {
            return Err(VerificationError::NotCurrentlyValid);
        };
        Ok(Self::SigType::verify(
            &Self::Rep::serialize(&payload)?.into(),
            &Self::SigType::get_vmat(&payload)
                .ok_or(VerificationError::MissingVerificationMaterial)?,
            &sig,
        )
        .await
        .map_err(|_| VerificationError::Crypto)?)
    }

    async fn verify_cacao(
        cacao: &CACAO<Self>,
    ) -> Result<
        <<Self as SignatureScheme>::SigType as SignatureType>::Output,
        VerificationError<<Self::Rep as Representation>::Err>,
    >
    where
        Self: Sized,
        Self::RepOutput: Send + Sync,
        <Self::SigType as SignatureType>::Signature: Send + Sync,
        <Self::SigType as SignatureType>::Payload: Send + Sync,
        <Self::SigType as SignatureType>::VerificationMaterial: Send + Sync,
        <Self::Rep as Representation>::Err: Send + Sync,
    {
        Self::verify(cacao.payload(), cacao.signature()).await
    }
}

#[derive(Default)]
pub struct GenericScheme<R, S>(PhantomData<R>, PhantomData<S>);

#[async_trait]
impl<R, S, P> SignatureScheme for GenericScheme<R, S>
where
    R: Representation<Output = P>,
    S: SignatureType,
    P: Into<S::Payload> + Send,
{
    type Rep = R;
    type SigType = S;
    type RepOutput = P;
}

#[derive(Error, Debug)]
pub enum VerificationError<S> {
    // pub enum VerificationError<S: StdErr, E: StdErr> {
    #[error("Verification Failed")]
    Crypto,
    #[error(transparent)]
    Serialization(#[from] S),
    #[error("Missing Payload Verification Material")]
    MissingVerificationMaterial,
    #[error("Not Currently Valid")]
    NotCurrentlyValid,
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

pub trait Parse: Representation {
    type ParseErr;
    fn deserialize(rep: &Self::Output) -> Result<Payload, Self::ParseErr>;
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
    fn get_vmat(payload: &Payload) -> Option<Self::VerificationMaterial>;
}

#[derive(Copy, Clone)]
pub enum Version {
    V1 = 1,
}

#[derive(Clone)]
pub struct Payload {
    pub domain: Host,
    pub iss: UriAbsoluteString,
    pub statement: String,
    pub aud: UriAbsoluteString,
    pub version: Version,
    pub nonce: String,
    pub iat: String,
    pub exp: Option<String>,
    pub nbf: Option<String>,
    pub requestId: Option<String>,
    pub resources: Vec<UriString>,
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

    pub async fn verify<S: SignatureScheme>(
        &self,
        s: &<<S as SignatureScheme>::SigType as SignatureType>::Signature,
    ) -> Result<
        <S::SigType as SignatureType>::Output,
        VerificationError<<S::Rep as Representation>::Err>,
    >
    where
        S: Send + Sync,
        S::RepOutput: Send + Sync,
        <S::SigType as SignatureType>::Signature: Send + Sync,
        <S::SigType as SignatureType>::Payload: Send + Sync,
        <S::SigType as SignatureType>::VerificationMaterial: Send + Sync,
        <S::Rep as Representation>::Err: Send + Sync,
    {
        S::verify(&self, s).await
    }

    pub fn represent<S: SignatureScheme>(
        &self,
    ) -> Result<S::RepOutput, <S::Rep as Representation>::Err> {
        S::Rep::serialize(&self)
    }

    pub fn parse<S: SignatureScheme, R>(
        rep: &S::RepOutput,
    ) -> Result<Self, <S::Rep as Parse>::ParseErr>
    where
        S::Rep: Parse,
    {
        S::Rep::deserialize(rep)
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
