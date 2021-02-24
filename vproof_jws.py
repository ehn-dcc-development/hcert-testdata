#!/usr/bin/env python3

import argparse
import binascii
import json
import zlib
from typing import Dict

import cbor2
from cose import EC2, CoseAlgorithms, CoseEllipticCurves, CoseMessage
from cose.keys.cosekey import CoseKey
from cose.messages.sign1message import Sign1Message
from cryptojwt.utils import b64d


def read_jwk(filename: str) -> CoseKey:

    with open(filename, "rt") as jwk_file:
        jwk_dict = json.load(jwk_file)

    if jwk_dict["kty"] != "EC":
        raise ValueError("Only EC keys supported")

    if jwk_dict["crv"] != "P-256":
        raise ValueError("Only P-256 supported")

    return EC2(
        kid=jwk_dict["kid"].encode(),
        alg=CoseAlgorithms.ES256,
        crv=CoseEllipticCurves.P_256,
        x=b64d(jwk_dict["x"].encode()),
        y=b64d(jwk_dict["y"].encode()),
        d=b64d(jwk_dict["d"].encode()) if "d" in jwk_dict else None,
    )


def vproof_sign(private_key: CoseKey, payload: Dict) -> bytes:
    protected_header = {"alg": "ES256"}
    unprotected_header = {"kid": private_key.kid.decode()}
    sign1 = Sign1Message(
        phdr=protected_header, uhdr=unprotected_header, payload=cbor2.dumps(payload)
    )
    signed_data = sign1.encode(private_key=private_key)
    compressed_signed_data = zlib.compress(signed_data)

    print(f"Raw COSE: {len(signed_data)} bytes")
    print(f"Compressed COSE: {len(compressed_signed_data)} bytes")

    return compressed_signed_data


def vproof_sign_jws(jwk_filename: str, payload: Dict) -> bytes:

    from cryptojwt.jws.jws import JWS
    from cryptojwt.jwx import key_from_jwk_dict

    with open(jwk_filename) as f:
        key = key_from_jwk_dict(json.load(f))
        signed_data = JWS(payload, alg="ES256").sign_compact(keys=[key])

    print(signed_data)
    compressed_signed_data = zlib.compress(signed_data.encode())

    print(f"Raw JWS: {len(signed_data)} bytes")
    print(f"Compressed JWS: {len(compressed_signed_data)} bytes")

    return compressed_signed_data


def vproof_verify(public_key: CoseKey, compressed_signed_data: bytes):
    signed_data = zlib.decompress(compressed_signed_data)
    cose_msg: Sign1Message = CoseMessage.decode(signed_data)
    print("Protected header:", cose_msg.phdr)
    print("Unprotected header:", cose_msg.uhdr)

    decoded_payload = cbor2.loads(cose_msg.payload)

    if not cose_msg.verify_signature(public_key=public_key):
        raise RuntimeError("Bad signature")

    print("Payload:", json.dumps(decoded_payload))
    return decoded_payload


def main():
    """ Main function"""

    parser = argparse.ArgumentParser(description="Vaccin Proof Signer")
    parser.add_argument("--key", metavar="filename", required=True)
    parser.add_argument("--input", metavar="filename", required=True)
    parser.add_argument("--output", metavar="filename", required=False)

    subparsers = parser.add_subparsers(dest="command", required=True)
    parser_sign = subparsers.add_parser("sign", help="Sign input data")
    parser_verify = subparsers.add_parser("verify", help="Verify signed data")

    args = parser.parse_args()

    key = read_jwk(args.key)

    if args.command == "sign":
        with open(args.input, "rt") as input_file:
            input_data = json.load(input_file)
        compressed_signed_data = vproof_sign(key, input_data)
        vproof_sign_jws(args.key, input_data)
        if args.output:
            with open(args.output, "wb") as output_file:
                output_file.write(compressed_signed_data)
        else:
            print(binascii.hexlify(compressed_signed_data).decode())

    elif args.command == "verify":
        with open(args.input, "rb") as input_file:
            compressed_signed_data = input_file.read()
        payload = vproof_verify(key, compressed_signed_data)
        if args.output:
            with open(args.output, "wt") as output_file:
                json.dump(payload, output_file, indent=4)
        else:
            print(json.dumps(payload, indent=4))


if __name__ == "__main__":
    main()
