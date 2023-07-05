use std::collections::BTreeMap;
use std::borrow::Borrow;

use ethers::{
    abi::{Abi, Function, Param, ParamType, StateMutability},
    contract::{AbiError, ContractInstance},
    providers::Middleware,
    prelude::*,
};

use crate::VerificationError;

const METHOD_NAME: &str = "isValidSignature";

pub trait SiweMiddlewareExt: Middleware + Sized {
    fn get_contract(&self, address: [u8; 20]) -> ContractInstance<&Self, Self> {
         #[allow(deprecated)]
        let abi = Abi {
            constructor: None,
            functions: BTreeMap::from([(
                METHOD_NAME.to_string(),
                vec![Function {
                    name: METHOD_NAME.to_string(),
                    inputs: vec![
                        Param {
                            name: " _message".to_string(),
                            kind: ParamType::FixedBytes(32),
                            internal_type: Some("bytes32".to_string()),
                        },
                        Param {
                            name: " _signature".to_string(),
                            kind: ParamType::Bytes,
                            internal_type: Some("bytes".to_string()),
                        },
                    ],
                    outputs: vec![Param {
                        name: "".to_string(),
                        kind: ParamType::FixedBytes(4),
                        internal_type: Some("bytes4".to_string()),
                    }],
                    constant: None,
                    state_mutability: StateMutability::View,
                }],
            )]),
            events: BTreeMap::new(),
            errors: BTreeMap::new(),
            receive: false,
            fallback: false,
        };
     
        ContractInstance::<&Self, Self>::new(address, abi, self.borrow())
    }
}

impl <M: Middleware> SiweMiddlewareExt for M {}

pub async fn verify_eip1271<P: SiweMiddlewareExt>(
    address: [u8; 20],
    message_hash: &[u8; 32],
    signature: &[u8],
    provider: P,
) -> Result<bool, VerificationError> {
    match provider.get_contract(address)
        .method::<_, [u8; 4]>(
            METHOD_NAME,
            (*message_hash, Bytes::from(signature.to_owned())),
        )
        .unwrap()
        .call()
        .await
    {
        Ok([22, 38, 186, 126]) => Ok(true),
        Err(ContractError::AbiError(AbiError::DecodingError(_))) | Ok(_) => Ok(false),
        Err(e) => Err(VerificationError::ContractCall(e.to_string())),
    }
}
