[![CC BY 4.0][cc-by-shield]][cc-by]

# Electronic Health Certificates

This repository contains a proposal for encoding and signing Electronic Health Certificates (EHC), as a candidate to be adapted and adopted by eHealth authorities and other stakeholders as they seem fit.


# Requirements and Design Principles

The following requirements and principles has been used when designing the Electronic Health Certificates (EHC):

  1. Electronic Health Certificates shall be carried by the holder and must have the ability to be securely validated off-line (using strong and proven cryptographic primitives).

     *Example: Signed data with machine readable content.*

  2. Use an as compact encoding as practically possible, taking other requirements into consideration, to ensure reliable decoding using optical means.

     *Example: CBOR in combination with deflate compression and Aztec encoding.*

  3. Use existing, proven and modern open standards, with running code available (when possible) for all common platforms and operating environments to limit implementation efforts and minimise risk of interoperability issues.

     *Example: CBOR Web Tokens (CWT).*

  4. When existing standards does not exist, define and test new mechanisms based on existing mechanisms and ensure running code exists.

     *Example: Base45 encoding per new Internet Draft.*

  5. Ensure compatibility with existing systems for optical decoding.

     *Example: Base45 encoding for optical transport.*


## Installation

The test code is written in [Python](https://www.python.org/) and can be executed on most Unix/Linux system. [Python Poetry](https://python-poetry.org/) is required and can be installed using `pip3 install poetry`. Once Poetry is installed, the following commands may be used to set up a test environment:

    poetry shell
    poetry install


## Test

To run a simple test suite, use the following command:

    poetry run make test

Sample output is saved to `test.bin` (raw binary EHC), `test_aztec.png` (Aztec) and `test_qrcode.png` (QR). The `test` target will also verify the EHC and write its output to `test.txt`.

### Testing with Docker

For testing with Docker on a standard Linux host, the following command sequence may be used:

    docker build -t hcert .
    docker run -it --rm hcert

### Testing with Fedora Linux

For native testing on a Fedora Linux host, the following command sequence may be used:

    dnf install -y git make jq python3 python3-pip python3-cryptography
    pip3 install poetry
    git clone https://github.com/kirei/hcert.git /tmp/hcert
    cd /tmp/hcert
    poetry install && poetry run make test


## Data Format

The EHC is represented using CBOR Web Token (CWT) as defined [RFC 8392](https://tools.ietf.org/html/rfc8392). The EHC payload is transported in a **hcert** claim (claim key TBD) containing a CBOR map (object) of various schemata.

Before transport as Aztec, the EHC is compressed using ZLIB ([RFC1950](https://tools.ietf.org/html/rfc1950)) and optionally encoded using Base45 (to handle legacy equipment designed to operate on ASCII payloads).


## Overview

![overview](hcert_overview.png)

# Presentation

[A short presentation on the background of this initative is available](hcert-preso.pdf).


# Specification

[A draft specification is available](hcert_spec.md).


# Contributions

Contributions are very welcome - please file a pull request.

_________________

This work is licensed under a
[Creative Commons Attribution 4.0 International License][cc-by].

[![CC BY 4.0][cc-by-image]][cc-by]

[cc-by]: http://creativecommons.org/licenses/by/4.0/
[cc-by-image]: https://i.creativecommons.org/l/by/4.0/88x31.png
[cc-by-shield]: https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg
