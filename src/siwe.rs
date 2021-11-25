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
        // from siwe tests
        let message = from_str(
            r#"login.xyz wants you to sign in with your Ethereum account:
0xb8a316ea8a9e48ebd25b73c71bc0f22f5c337d1f

Sign-In With Ethereum Example Statement

URI: https://login.xyz
Version: 1
Chain ID: 1
Nonce: uolthxpe
Issued At: 2021-11-25T02:36:37.013Z"#,
        )
        .unwrap();
        let correct = <[u8; 65]>::from_hex(r#"6eabbdf0861ca83b6cf98381dcbc3db16dffce9a0449dc8b359718d13b0093c3285b6dea7e84ad1aa4871b63899319a988ddf39df3080bcdc60f68dd0942e8221c"#).unwrap();
        WalletSIWE::verify(&message.clone().sign(BasicSignature { s: correct }))
            .await
            .unwrap();
        let incorrect = <[u8; 65]>::from_hex(r#"7eabbdf0861ca83b6cf98381dcbc3db16dffce9a0449dc8b359718d13b0093c3285b6dea7e84ad1aa4871b63899319a988ddf39df3080bcdc60f68dd0942e8221c"#).unwrap();
        assert!(
            WalletSIWE::verify(&message.sign(BasicSignature { s: incorrect }))
                .await
                .is_err()
        );
    }
}
