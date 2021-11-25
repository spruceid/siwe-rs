use super::{cacao::GenericScheme, eip191::EIP191, eip4361::EIP4361};

pub type WalletSIWE = GenericScheme<EIP4361, EIP191>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cacao::*;
    use crate::eip4361::from_str;
    use hex::FromHex;

    #[async_std::test]
    async fn validation() {
        // from https://github.com/blockdemy/eth_personal_sign
        let message = from_str(
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
        WalletSIWE::verify(&message.clone().sign(BasicSignature { s: correct }))
            .await
            .unwrap();

        let incorrect = <[u8; 65]>::from_hex(r#"50208c53a8939040a9b98edc7a523af4f2eff7ecac17796a9828be055d1e52de53ff813544652ecd7cdeddae01326d778728cb741835b3f135d6fb89865012cf1c"#).unwrap();
        assert!(
            WalletSIWE::verify(&message.sign(BasicSignature { s: incorrect }))
                .await
                .is_err()
        );
    }


    #[async_std::test]
    async fn validation1() {
        // from siwe tests, they're wrong w.r.t order of chain-id, nonce and iat??
        let message = from_str(
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
        WalletSIWE::verify(&message.clone().sign(BasicSignature { s: correct }))
            .await
            .unwrap();
        let incorrect = <[u8; 65]>::from_hex(r#"895110331a07a4d475419fbdb346feb4c0579dcc8228989964474e07d98dbf425f38776cd6ca037f58288acc7b15e720c9cecac988479177fb70592f2391aaff1b"#).unwrap();
        assert!(
            WalletSIWE::verify(&message.sign(BasicSignature { s: incorrect }))
                .await
                .is_err()
        );
    }
}
