use std::collections::BTreeMap;

use ethers::{
    abi::{Abi, Function, Param, ParamType, StateMutability},
    contract::{AbiError, Contract},
    prelude::*,
};

use crate::VerificationError;

const METHOD_NAME: &str = "isValidSignature";

pub async fn verify_eip1271(
    address: [u8; 20],
    message_hash: &[u8; 32],
    signature: &[u8],
    provider: &Provider<Http>,
) -> Result<bool, VerificationError> {
    #[allow(deprecated)]
    let abi = Abi {
        constructor: None,
        functions: BTreeMap::from([(
            "isValidSignature".to_string(),
            vec![Function {
                name: "isValidSignature".to_string(),
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

    let contract = Contract::new(address.into(), abi, provider);

    match contract
        .method::<_, [u8; 4]>(
            METHOD_NAME,
            (*message_hash, Bytes::from(signature.to_owned())),
        )
        .unwrap()
        .call()
        .await
    {
        Ok(r) => Ok(r == [22, 38, 186, 126]),
        Err(ContractError::AbiError(AbiError::DecodingError(_))) => Ok(false),
        Err(e) => Err(VerificationError::ContractCall(e.to_string())),
    }
}
