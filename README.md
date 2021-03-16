[![CC BY 4.0][cc-by-shield]][cc-by]

# Electronic Health Certificates

This repository contains a proposal for encoding and signing Electronic Health Certificates (EHC), as a candidate to be adapted and adopted by eHealth authorities and other stakeholders as they seem fit.


## Installation

The test code is written in [Python](https://www.python.org/) and can be executed on most Unix/Linux system. [Python Poetry](https://python-poetry.org/) is required and can be installed using `pip3 install poetry`. Once Poetry is installed, the following commands may be used to set up a test environment:

    poetry shell
    poetry install


## Test

To run a simple test suite, use the following command:

    poetry run make test

Sample output is saved to `test.bin` (raw binary EHC), `test_aztec.png` (Aztec) and `test_qrcode.png` (QR). The `test` target will also verify the EHC and write its output to `test.txt`.


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
