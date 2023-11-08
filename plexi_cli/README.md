# plexi

plexi allows you to validate result from a Key Transparency Auditor.

## Tables of Content

* [Features](#features)
* [What's next](#whats-next)
* [Installation](#installation)
* [Usage](#usage)
  * [Verify a signature](#verify-a-signature)
  * [Signing a report](#signing-a-report)

## Features

* Verify authenticity of a signature, to confirm it has been signed by a given public key
* Sign reports, allowing log to issue emergency epoch signatures

## What's next

* Report API interaction

## Installation

| Environment        | CLI Command                                                  |
|:-------------------|:-------------------------------------------------------------|
| Cargo (Rust 1.76+) | `cargo install plexi --git https://github.com/thibmeu/plexi` |

## Usage

You can use the `--help` option to get more details about the commands and their options.

```bash
plexi [OPTIONS] <COMMAND>
```

### Verify a signature

Public key is a 32 bytes ed25519 hex encoded public key. If valid, Signature valid is output.

```shell
plexi verify --publickey '508607faff7cb16be841e901eca41a6239461f239e7e610c9ea2576f334bc144' input.json
```

Input can either be a file or provided on the standard input. In the above, input.json is
```json
{
    "timestamp":1712579917252,
    "epoch":2,
    "digest":"2111111111111111111111111111111111111111111111111111111111111111",
    "signature":"1388df1d6a9557de6965e567665e38f4820da9866df67d6e1ca301273cd4a061ea658fb7ad372f144fe098bd3d72ef11a0de98e060a6cfa9b9436ca595d2fa0d"
}
```

### Signing a report

Log can provide emergency signature, in case the auditor is offline.
Signing key is a 32 byte ed25519 hex encoded signing key.
By default, output is on stdout

```shell
plexi sign --signingkey '508607faff7cb16be841e901eca41a6239461f239e7e610c9ea2576f334bc144' input.json
```
