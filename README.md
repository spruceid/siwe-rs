# Sign-In with Ethereum

This crate provides a pure Rust implementation of EIP-4361: Sign In With Ethereum.

## Installation

SIWE can be easily installed in any Rust project by including it in said project's `cargo.toml` file:

``` toml
siwe = "0.4"
```

## Usage

SIWE exposes a `Message` struct which implements EIP-4361.

### Parsing a SIWE Message

Parsing is done via the `Message` implementation of `FromStr`:

``` rust,ignore
let message: Message = string_message.parse()?;
```

### Verifying and Authenticating a SIWE Message

Verification and Authentication is performed via EIP-191, using the `address` field of the `Message` as the expected signer. This returns the Ethereum public key of the signer:

``` rust,ignore
let signer: Vec<u8> = message.verify_eip191(&signature)?;
```

The time constraints (expiry and not-before) can also be validated, at current or particular times:

``` rust,ignore
if message.valid_now() { ... };

// equivalent to
if message.valid_at(&OffsetDateTime::now_utc()) { ... };
```

Combined verification of time constraints and authentication can be done in a single call with `verify`:

``` rust,ignore
message.verify(&signature).await?;
```

### Serialization of a SIWE Message

`Message` instances can also be serialized as their EIP-4361 string representations via the `Display` implementation of `Message`:

``` rust,ignore
println!("{}", &message);
```

As well as in EIP-191 Personal-Signature pre-hash signing input form (if your Ethereum wallet does not support EIP-191 directly):

``` rust,ignore
let eip191_bytes: Vec<u8> = message.eip191_bytes()?;
```

And directly as the EIP-191 Personal-Signature Hashed signing-input (made over the `.eip191_string` output):

``` rust,ignore
let eip191_hash: [u8; 32] = message.eip191_hash()?;
```

## Example

Parsing and verifying a `Message` is easy:

``` rust,ignore
let message: Message = str.parse()?;
let signature: [u8; 65];

if let Err(e) = message.verify(&signature).await {
    // message cannot be correctly authenticated at this time
}

// do application-specific things
```

## Disclaimer

Our Rust library for Sign-In with Ethereum has not yet undergone a formal security
audit. We welcome continued feedback on the usability, architecture, and security
of this implementation.

## See Also

- [Sign-In with Ethereum: TypeScript](https://github.com/spruceid/siwe)
- [Example SIWE application: login.xyz](https://login.xyz)
- [EIP-4361 Specification Draft](https://eips.ethereum.org/EIPS/eip-4361)
- [EIP-191 Specification](https://eips.ethereum.org/EIPS/eip-191)
