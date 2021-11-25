use super::cacao::*;
use async_trait::async_trait;
use hex::FromHex;
use k256::{
    ecdsa::{
        recoverable::{Id, Signature},
        signature::Signature as S,
        Error, Signature as Sig, VerifyingKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
};
use sha3::{Digest, Keccak256};

pub struct EIP191;

#[async_trait]
impl SignatureType for EIP191 {
    const ID: &'static str = "eip191";
    type Payload = Vec<u8>;
    type VerificationMaterial = [u8; 20];
    type Signature = BasicSignature<[u8; 65]>;
    type Err = Error;
    type Output = VerifyingKey;
    async fn verify(
        payload: &Self::Payload,
        address: &Self::VerificationMaterial,
        signature: &Self::Signature,
    ) -> Result<Self::Output, Self::Err> {
        let vk = Signature::new(
            &Sig::from_bytes(&signature.s[..64])?,
            Id::new(&signature.s[64] % 27)?,
        )?
        .recover_verify_key(&get_eip191_bytes(payload))?;

        if &Keccak256::default()
            .chain(&vk.to_encoded_point(false).as_bytes()[1..])
            .finalize()[12..] == address {
            Ok(vk)
        } else {
            Err(Self::Err::new())
        }
    }

    fn get_vmat<S: SignatureScheme<SigType = Self>>(
        payload: &CACAO<S>,
    ) -> Option<Self::VerificationMaterial> {
        match (payload.p.chain_id()?.get(..7), payload.p.address()) {
            (Some("eip155:"), Some(a)) => <Self::VerificationMaterial>::from_hex(&a[2..]).ok(),
            _ => None,
        }
    }
}

pub fn get_eip191_bytes<P: AsRef<[u8]>>(payload: P) -> Vec<u8> {
    [
        format!("\x19Ethereum Signed Message:\n{}", &payload.as_ref().len()).as_bytes(),
        &payload.as_ref(),
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn validation() {
        use hex::FromHex;
        let message = r#"example EIP191 message"#.as_bytes().to_owned();
        let addr = <[u8; 20]>::from_hex("a391f7add776806c4dff3886bbe6370be8f73683").unwrap();

        let correct = BasicSignature { s: <[u8; 65]>::from_hex("7232514f3165922303f83abed772f193ab3e3767be5428e5df94821bbd250edd08e2970c873b9a43751ef001e6d8f09bafe057162162affcb4f6c1434bd948391c").unwrap() };
        EIP191::verify(&message, &addr, &correct).await.unwrap();

        let incorrect = BasicSignature { s: <[u8; 65]>::from_hex("8232514f3165922303f83abed772f193ab3e3767be5428e5df94821bbd250edd08e2970c873b9a43751ef001e6d8f09bafe057162162affcb4f6c1434bd948391c").unwrap() };
        assert!(EIP191::verify(&message, &addr, &incorrect).await.is_err());
    }
}
