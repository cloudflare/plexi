# Plexi

![plexi banner image](./docs/assets/plexi_banner.png)

Plexi is a flexible auditor for [Transparency systems](https://blog.cloudflare.com/key-transparency).

This software has not been audited. Please use at your sole discretion.

## Feature highlights
* Verify [akd](https://github.com/facebook/akd) based signatures

## Installation

| Environment        | CLI Command                                                                     |
|:-------------------|:--------------------------------------------------------------------------------|
| Cargo (Rust 1.74+) | `cargo install plexi_cli --git https://github.com/cloudflare/plexi --bin plexi` |

## Usage

### Verify akd signature

Once the namespace and the epoch is set, the following command should return `Signature valid`.

```shell
NAMESPACE="test.whatsapp.key-transparency.v1"
EPOCH="434592"
AUDITOR_PUBLIC_KEY="$(curl -sS 'https://akd-auditor.cloudflare.com/info' | jq -r '.keys[0].public_key')"

curl -sS "https://akd-auditor.cloudflare.com/namespaces/${NAMESPACE}/audits/${EPOCH}" | \
  plexi verify --namespace "${NAMESPACE}" --publickey "${AUDITOR_PUBLIC_KEY}"
```

## Contributing
Please see our [contribution guidelines](./.github/CONTRIBUTING.md).

## License
This project is Licensed under [Apache License, Version 2.0](./LICENSE).