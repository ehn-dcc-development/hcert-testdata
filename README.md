[![CC BY 4.0][cc-by-shield]][cc-by]

# Electronic Health Certificates Test

This repository contains a test implementation for Electronic Health Certificates. The [specification](https://github.com/DIGGSweden/hcert) has been moved to [DIGGSweden](https://github.com/DIGGSweden).


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
