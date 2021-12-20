# Sign In With Ethereum

This crate provides a pure Rust implementation of EIP-4631: Sign In With Ethereum.

## Installation

SIWE can be easily installed in any Rust project by including it in said project's `cargo.toml` file:

``` toml
siwe = "0.1"
```

## Usage

SIWE exposes a `Message` struct which implements EIP-4361.

### Parsing a SIWE Message

Parsing is done via the `Message` implementation of `FromStr`:

``` rust
let message: Message = string_message.parse()?;
```

### Verifying and Authenticating a SIWE Message

Verification and Authentication is performed via EIP-191, using the `.address` field of the `Message` as the expected signer:

``` rust
message.verify_eip191(&signature)?;
```

The time constraints (expiry and not-before) can also be validated:

``` rust
if message.valid_now() { ... };
```

### Serialization of a SIWE Message

`Message` instances can also be serialized as their EIP-4361 string representations via the `Display` implementation of `Message`:

``` rust
println!("{}", &message);
```

As well as in EIP-191 Personal-Signature pre-hash signing input form (if your Ethereum wallet does not support EIP-191 directly):

``` rust
let eip191_string: String = message.eip191_string()?;
```

And directly as the EIP-191 Personal-Signature Hashed signing-input (made over the `.eip191_string` output):

``` rust
let eip191_hash: [u8; 32] = message.eip191_hash()?;
```

## Example

Parsing and verifying a `Message` is easy:

``` rust
let message: Message = str.parse()?;
let signature: [u8; 65];

if !message.valid_now() {
    // the message is expired or not yet valid, handle this case
};

if let Err(e) = message.verify_eip191(signature) {
    // message cannot be correctly authenticated, handle this case
}

// do application-specific things
```

## See Also

- [Sign In With Ethereum: Typescript](https://github.com/spruceid/siwe)
- [Example SIWE application: login.xyz](https://github.com/spruceid/loginxyz)
- [EIP-4361 Specification Draft](https://github.com/spruceid/EIPs/blob/eip-4361/EIPS/eip-4361.md)
- [EIP-191 Specification](https://eips.ethereum.org/EIPS/eip-191)
