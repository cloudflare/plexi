# Plexi

![Plexi banner](./docs/assets/plexi_banner.png)

Plexi is a flexible auditor for [Transparency systems](https://blog.cloudflare.com/key-transparency).

## Tables of Content

* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
  * [Configure your auditor remote](#configure-your-auditor-remote)
  * [Listing monitored Logs](#listing-monitored-logs)
  * [Auditting a signature](#auditting-a-signature)
* [Conduct](#conduct)
* [License](#license)

## Features

* Verify authenticity of a signature, to confirm it has been signed by a given public key
* Verify the validity of [facebook/akd](https://github.com/facebook/akd) proofs
* List Logs an Auditor monitors

## Installation

| Environment                                                   | CLI Command           |
|:--------------------------------------------------------------|:----------------------|
| [Cargo](https://www.rust-lang.org/tools/install) (Rust 1.76+) | `cargo install plexi` |

## Usage

You can use the `--help` option to get more details about the commands and their options.

```bash
plexi [OPTIONS] <COMMAND>
```

### Configure your auditor remote

`plexi` does not come with a default remote auditor. You should decide whichever suit your needs.

You can do so either by passing `--remote-url=<REMOTE>`, or setting `PLEXI_REMOTE_URL` environment variable.

A list of common remote is provided bellow

| Name       | Remote                                          |
|:-----------|:------------------------------------------------|
| Cloudflare | `https://plexi.key-transparency.cloudflare.com` |

If you have deployed your own auditor, you can add a remote by filing a [GitHub issue](https://github.com/cloudflare/plexi/issues).

### Listing monitored Logs

An auditor monitors multiple Logs at once. To discover which Logs an auditor is monitoring, you run the following

```shell
plexi ls --remote-url 'https://plexi.key-transparency.cloudflare.com'
whatsapp.key-transparency.v1
```

### Auditting a signature

Key Transparency Auditor vouch for Log validity. They do so by ensuring epoch uniqueness, and verifying the associated proof

`plexi audit` provides information about a given epoch, and its validity. It can perform a local audit to confirm the auditor behaviour.

For instance, to verify WhatsApp Log auditted by Cloudflare Auditor, you run the following
```shell
> plexi audit --remote-url 'https://plexi.key-transparency.cloudflare.com' --namespace 'whatsapp.key-transparency.v1' --long
Namespace: whatsapp.key-transparency.v1
Ciphersuite: ed25519(protobuf)
Timestamp: 2024-09-19T09:59:44Z
Epoch height: 476847
Epoch digest: 9d217c91dc629d16a3b1379e8fd7c949c27b1b6038259e3918bd0da3cd6c34d1
Signature: e4c83e3091ba8764752120bd7a726a28759d25a01f39d07131d6ba66a913d58d8f0f48f63bc7e037cc5ddd81dc76acc847dbf8d02b2f55251e6f2b1f00191902
Verification: success
```

## Conduct

Plexi and Cloudflare OpenSource generally follows the [Contributor Covenant Code of Conduct](https://github.com/cloudflare/.github/blob/26b37ca2ba7ab3d91050ead9f2c0e30674d3b91e/CODE_OF_CONDUCT.md). Violating the CoC could result in a warning or a ban to Plexi or any and all repositories in the Cloudflare organization.

## License
This project is Licensed under [Apache License, Version 2.0](../LICENSE).
