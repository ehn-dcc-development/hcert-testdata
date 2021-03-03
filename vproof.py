#!/usr/bin/env python3

import argparse
import binascii
import json
import time
import zlib
from typing import Dict, Optional

import cbor2
from cose import EC2, CoseAlgorithms, CoseEllipticCurves, CoseMessage
from cose.attributes.headers import CoseHeaderKeys
from cose.keys.cosekey import CoseKey, KeyOps
from cose.messages.sign1message import Sign1Message
from cryptojwt.utils import b64d

SIGN_ALG = CoseAlgorithms.ES256
CONTENT_TYPE_CBOR = 60


def read_jwk(filename: str, private: bool = True) -> CoseKey:

    with open(filename, "rt") as jwk_file:
        jwk_dict = json.load(jwk_file)

    if jwk_dict["kty"] != "EC":
        raise ValueError("Only EC keys supported")

    if jwk_dict["crv"] != "P-256":
        raise ValueError("Only P-256 supported")

    return EC2(
        kid=jwk_dict["kid"].encode(),
        key_ops=KeyOps.SIGN if private else KeyOps.VERIFY,
        alg=SIGN_ALG,
        crv=CoseEllipticCurves.P_256,
        x=b64d(jwk_dict["x"].encode()),
        y=b64d(jwk_dict["y"].encode()),
        d=b64d(jwk_dict["d"].encode()) if "d" in jwk_dict else None,
    )


def vproof_sign(
    private_key: CoseKey,
    alg: CoseAlgorithms,
    payload: Dict,
) -> bytes:
    protected_header = {
        CoseHeaderKeys.ALG: alg.id,
        CoseHeaderKeys.KID: private_key.kid.decode(),
        CoseHeaderKeys.CONTENT_TYPE: CONTENT_TYPE_CBOR,
    }
    unprotected_header = {}
    print("Protected header:", protected_header)
    print("Unprotected header:", unprotected_header)
    sign1 = Sign1Message(
        phdr=protected_header, uhdr=unprotected_header, payload=cbor2.dumps(payload)
    )
    return sign1.encode(private_key=private_key)


def vproof_verify(public_key: CoseKey, signed_data: bytes):
    cose_msg: Sign1Message = CoseMessage.decode(signed_data)
    print("Protected header:", cose_msg.phdr)
    print("Unprotected header:", cose_msg.uhdr)

    if not cose_msg.verify_signature(public_key=public_key):
        raise RuntimeError("Bad signature")

    decoded_payload = cbor2.loads(cose_msg.payload)
    return decoded_payload


def main():
    """ Main function"""

    parser = argparse.ArgumentParser(description="Vaccin Proof Signer")

    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_sign = subparsers.add_parser("sign", help="Sign proof")
    parser_sign.add_argument(
        "--key", metavar="filename", help="Private JWK filename", required=True
    )
    parser_sign.add_argument(
        "--input",
        metavar="filename",
        help="JSON-encoded proof payload",
        required=True,
    )
    parser_sign.add_argument(
        "--output",
        metavar="filename",
        help="Compressed CBOR output",
        required=False,
    )

    parser_verify = subparsers.add_parser("verify", help="Verify signed proof")
    parser_verify.add_argument(
        "--key", metavar="filename", help="Public JWK filename", required=True
    )
    parser_verify.add_argument(
        "--input",
        metavar="filename",
        help="Compressed CBOR input",
        required=True,
    )
    parser_verify.add_argument(
        "--output",
        metavar="filename",
        help="JSON-encoded proof payload",
        required=False,
    )

    args = parser.parse_args()

    if args.command == "sign":
        key = read_jwk(args.key, private=True)
        with open(args.input, "rt") as input_file:
            input_data = json.load(input_file)
        signed_data = vproof_sign(
            private_key=key,
            alg=SIGN_ALG,
            payload=input_data,
        )
        compressed_data = zlib.compress(signed_data)

        print(f"Raw COSE: {len(signed_data)} bytes")
        print(f"Compressed COSE: {len(compressed_data)} bytes")

        if args.output:
            with open(args.output, "wb") as output_file:
                output_file.write(compressed_data)
        else:
            print("Output:", binascii.hexlify(compressed_data).decode())

    elif args.command == "verify":
        key = read_jwk(args.key, private=False)
        with open(args.input, "rb") as input_file:
            compressed_data = input_file.read()
        signed_data = zlib.decompress(compressed_data)
        payload = vproof_verify(public_key=key, signed_data=signed_data)
        if args.output:
            with open(args.output, "wt") as output_file:
                json.dump(payload, output_file, indent=4)
        else:
            print("Verified payload:", json.dumps(payload, indent=4))


if __name__ == "__main__":
    main()
