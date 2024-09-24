# Plexi

![Plexi banner](./docs/assets/plexi_banner.png)

Plexi is a flexible auditor for [Key Transparency systems](https://blog.cloudflare.com/key-transparency).

## Tables of Content

* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
  * [Configure your auditor remote](#configure-your-auditor-remote)
  * [List monitored Logs](#list-monitored-logs)
  * [Audit a signature](#audit-a-signature)
* [Conduct](#conduct)
* [License](#license)

## Features

* Verify authenticity of a signature, to confirm it has been signed by a given public key
* Verify the validity of [facebook/akd](https://github.com/facebook/akd) proofs
* List Logs an Auditor monitors

## Installation

| Environment                                                   | CLI Command           |
|:--------------------------------------------------------------|:----------------------|
| [Cargo](https://www.rust-lang.org/tools/install) (Rust 1.81+) | `cargo install plexi` |

## Usage

Use the `--help` option for more details about the commands and their options.

```bash
plexi [OPTIONS] <COMMAND>
```

### Configure your auditor remote

`plexi` does not come with a default remote auditor, and you will need to choose your own. 

You can do so either by passing `--remote-url=<REMOTE>` or setting the `PLEXI_REMOTE_URL` environment variable.

A common remote is provided below:

| Name       | Remote                                          |
|:-----------|:------------------------------------------------|
| Cloudflare | `https://plexi.key-transparency.cloudflare.com` |

If you have deployed your own auditor, you can add a remote by filing a [GitHub issue](https://github.com/cloudflare/plexi/issues).

### List monitored Logs

An auditor monitors multiple Logs at once. To discover which Logs an auditor is monitoring, run the following:

```shell
plexi ls --remote-url 'https://plexi.key-transparency.cloudflare.com'
whatsapp.key-transparency.v1
```

### Audit a signature

The Key Transparency Auditor vouches for Log validity by ensuring epoch uniqueness. and verifying the associated proof

`plexi audit` provides information about a given epoch and its validity. It can perform a local audit to confirm the auditor behaviour.

For instance, to verify WhatsApp Log auditted by Cloudflare Auditor, run the following:
```shell
> plexi audit --remote-url 'https://plexi.key-transparency.cloudflare.com' --namespace 'whatsapp.key-transparency.v1' --long
Namespace
  Name                	: whatsapp.key-transparency.v1
  Ciphersuite         	: ed25519(protobuf)

Signature (2024-09-23T16:53:45Z)
  Epoch height      	: 489193
  Epoch digest      	: cbe5097ae832a3ae51ad866104ffd4aa1f7479e873fd18df9cb96a02fc91ebfe
  Signature         	: fe94973e19da826487b637c019d3ce52f0c08093ada00b4fe6563e2f8117b4345121342bc33aae249be47979dfe704478e2c18aed86e674df9f934b718949c08
  Signature verification: success
  Proof verification	: success
```

## Conduct

Plexi and Cloudflare OpenSource generally follows the [Contributor Covenant Code of Conduct](https://github.com/cloudflare/.github/blob/26b37ca2ba7ab3d91050ead9f2c0e30674d3b91e/CODE_OF_CONDUCT.md). Violating the CoC could result in a warning or a ban to Plexi or any and all repositories in the Cloudflare organization.

## License
This project is Licensed under [Apache License, Version 2.0](./LICENSE).
