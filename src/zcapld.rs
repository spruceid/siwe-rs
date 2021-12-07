use crate::cacao::*;
use didkit::DID_METHODS;

use async_trait::async_trait;
use iri_string::types::{UriAbsoluteString, UriString};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none, DisplayFromStr};
use ssi::{
    vc::{Proof, URI},
    zcap::{Delegation as ZcapDelegation, Invocation as ZcapInvocation},
};

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DelProps {
    // domain
    #[serde_as(as = "DisplayFromStr")]
    pub domain: Authority,
    // resources
    pub capability_action: Vec<UriString>,
    // nbf
    pub valid_from: Option<String>,
    // exp
    pub valid_until: Option<String>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InvProps {
    // domain
    #[serde_as(as = "DisplayFromStr")]
    pub domain: Authority,
    // uri
    pub invocation_target: UriAbsoluteString,
    // resources
    pub capability_action: Vec<UriString>,
    // statement
    pub challenge: String,
    // nbf
    pub valid_from: Option<String>,
    // exp
    pub valid_until: Option<String>,
    // requestId
    pub nonce: Option<String>,
}

pub type KeplerInvocation = ZcapInvocation<InvProps>;
pub type KeplerDelegation = ZcapDelegation<(), DelProps>;

pub struct ZcapInv;

impl Representation for ZcapInv {
    const ID: &'static str = "zcapldinvocation";
    type Err = ();
    type Output = ZcapInvocation<InvProps>;
    fn serialize(p: &Payload) -> Result<Self::Output, ()> {
        Ok(ZcapInvocation {
            context: Default::default(),
            id: URI::String(p.nonce.clone()),
            property_set: InvProps {
                domain: p.domain.clone(),
                invocation_target: p.aud.clone(),
                capability_action: p.resources.clone(),
                challenge: p.statement.clone(),
                valid_from: p.nbf.clone(),
                valid_until: p.exp.clone(),
                nonce: p.requestId.clone(),
            },
            proof: None,
        })
    }
}

pub struct ZcapLDP;

#[async_trait]
impl SignatureType for ZcapLDP {
    const ID: &'static str = "ldp";
    type Signature = Proof;
    type Payload = ZcapInvocation<InvProps>;
    type VerificationMaterial = ();
    type Output = ();
    type Err = Vec<String>;

    async fn verify(
        payload: &Self::Payload,
        _key: &Self::VerificationMaterial,
        signature: &Self::Signature,
    ) -> Result<Self::Output, Self::Err> {
        let clone = payload.clone();
        let res = ZcapInvocation {
            proof: Some(signature.clone()),
            ..clone
        }
        .verify_signature(None, DID_METHODS.to_resolver())
        .await;
        if res.errors.is_empty() {
            Ok(())
        } else {
            Err(res.errors)
        }
    }

    fn get_vmat(_: &Payload) -> Option<Self::VerificationMaterial> {
        Some(())
    }
}
