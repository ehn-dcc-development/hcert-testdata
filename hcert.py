#!/usr/bin/env python3

import argparse
import base64
import binascii
import json
import logging
import time
import zlib
from datetime import datetime
from enum import Enum
from typing import Dict, Optional

import cbor2
import qrcode
import qrcode.image.pil
import qrcode.image.svg
from aztec_code_generator import AztecCode
from cose import EC2, CoseAlgorithms, CoseEllipticCurves, CoseMessage
from cose.attributes.headers import CoseHeaderKeys
from cose.keys.cosekey import CoseKey, KeyOps
from cose.messages.sign1message import Sign1Message
from cryptojwt.utils import b64d
from qrbase45 import base45decode, base45encode

SIGN_ALG = CoseAlgorithms.ES256
CONTENT_TYPE_CBOR = 60
CONTENT_TYPE_CWT = 61

logger = logging.getLogger(__name__)


class CwtClaims(Enum):
    ISS = 1
    SUB = 2
    AUD = 3
    EXP = 4
    NBF = 5
    IAT = 6
    CTI = 7
    HCERT = -65537


class HealthCertificateClaims(Enum):
    EU_HCERT_V1 = 1


def read_jwk(filename: str, private: bool = True, kid: Optional[str] = None) -> CoseKey:

    with open(filename, "rt") as jwk_file:
        jwk_dict = json.load(jwk_file)

    if jwk_dict["kty"] != "EC":
        raise ValueError("Only EC keys supported")

    if jwk_dict["crv"] != "P-256":
        raise ValueError("Only P-256 supported")

    return EC2(
        kid=(kid or jwk_dict["kid"]).encode(),
        key_ops=KeyOps.SIGN if private else KeyOps.VERIFY,
        alg=SIGN_ALG,
        crv=CoseEllipticCurves.P_256,
        x=b64d(jwk_dict["x"].encode()),
        y=b64d(jwk_dict["y"].encode()),
        d=b64d(jwk_dict["d"].encode()) if "d" in jwk_dict else None,
    )


def sign(
    private_key: CoseKey,
    alg: CoseAlgorithms,
    hcert: Dict,
    issuer: Optional[str] = None,
    ttl: Optional[int] = None,
) -> bytes:
    now = int(time.time())
    protected_header = {
        CoseHeaderKeys.ALG: alg.id,
        CoseHeaderKeys.CONTENT_TYPE: CONTENT_TYPE_CWT,
        CoseHeaderKeys.KID: private_key.kid.decode(),
    }
    unprotected_header = {}
    logger.info("Protected header: %s", protected_header)
    logger.info("Unprotected header: %s", unprotected_header)
    payload = {
        CwtClaims.ISS.value: issuer,
        CwtClaims.IAT.value: now,
        CwtClaims.EXP.value: now + ttl,
        CwtClaims.HCERT.value: {HealthCertificateClaims.EU_HCERT_V1.value: hcert},
    }
    sign1 = Sign1Message(phdr=protected_header, payload=cbor2.dumps(payload))
    return sign1.encode(private_key=private_key)


def verify(public_key: CoseKey, signed_data: bytes) -> Dict:
    now = int(time.time())
    cose_msg: Sign1Message = CoseMessage.decode(signed_data)
    logger.info("Protected header: %s", cose_msg.phdr)
    logger.info("Unprotected header: %s", cose_msg.uhdr)

    if not cose_msg.verify_signature(public_key=public_key):
        raise RuntimeError("Bad signature")

    decoded_payload = cbor2.loads(cose_msg.payload)

    if (iss := decoded_payload.get(CwtClaims.ISS.value)) is not None:
        logger.info("Signatured issued by: %s", iss)

    if (iat := decoded_payload.get(CwtClaims.IAT.value)) is not None:
        logger.info("Signatured issued at: %s", datetime.fromtimestamp(iat))

    if (exp := decoded_payload.get(CwtClaims.EXP.value)) is not None:
        if exp > now:
            logger.info("Signatured expires at: %s", datetime.fromtimestamp(exp))
        else:
            logger.info("Signatured expired at: %s", datetime.fromtimestamp(exp))
            raise RuntimeError("Signature expired")

    hcert = decoded_payload.get(CwtClaims.HCERT.value)
    return hcert.get(HealthCertificateClaims.EU_HCERT_V1.value)


def main():
    """ Main function"""

    parser = argparse.ArgumentParser(description="Electronic Health Certificate signer")

    parser.add_argument(
        "--encoding",
        metavar="encoding",
        help="Transport encoding",
        choices=["binary", "base45", "base64", "base85"],
        default="base45",
        required=False,
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output",
        required=False,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_sign = subparsers.add_parser("sign", help="Sign health cert")
    parser_sign.add_argument(
        "--key", metavar="filename", help="Private JWK filename", required=True
    )
    parser_sign.add_argument(
        "--issuer",
        metavar="issuer",
        help="Signature issuer",
        required=False,
    )
    parser_sign.add_argument(
        "--kid", metavar="kid", help="Key identifier", required=False
    )
    parser_sign.add_argument(
        "--ttl",
        metavar="seconds",
        help="Signature TTL",
        type=int,
        required=False,
    )
    parser_sign.add_argument(
        "--input",
        metavar="filename",
        help="JSON-encoded payload",
        required=True,
    )
    parser_sign.add_argument(
        "--output",
        metavar="filename",
        help="Compressed CBOR output",
        required=False,
    )
    parser_sign.add_argument(
        "--aztec",
        metavar="filename",
        help="Aztec output",
        required=False,
    )
    parser_sign.add_argument(
        "--qrcode",
        metavar="filename",
        help="QR output",
        required=False,
    )

    parser_verify = subparsers.add_parser("verify", help="Verify signed cert")
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
        help="JSON-encoded payload",
        required=False,
    )
    parser_verify.add_argument(
        "--decode",
        metavar="filename",
        help="Decode data before processing",
        required=False,
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)

    if args.command == "sign":
        key = read_jwk(args.key, private=True, kid=args.kid)
        with open(args.input, "rt") as input_file:
            input_data = json.load(input_file)
        signed_data = sign(
            private_key=key,
            alg=SIGN_ALG,
            hcert=input_data,
            issuer=args.issuer,
            ttl=args.ttl,
        )
        compressed_data = zlib.compress(signed_data)

        logger.info("Raw CWT: %d bytes", len(signed_data))
        logger.info("Compressed CWT: %d bytes", len(compressed_data))

        if args.encoding == "binary":
            encoded_data = compressed_data
        elif args.encoding == "base45":
            encoded_data = base45encode(compressed_data)
        elif args.encoding == "base64":
            encoded_data = base64.b64encode(compressed_data)
        elif args.encoding == "base85":
            encoded_data = base64.b85encode(compressed_data)
        else:
            raise RuntimeError("Invalid encoding")

        logger.info("Encoded data: %d bytes (%s)", len(encoded_data), args.encoding)

        if args.output:
            with open(args.output, "wb") as output_file:
                output_file.write(signed_data)
        else:
            logger.info("Output: %s", binascii.hexlify(signed_data).decode())

        if args.aztec:
            AztecCode(encoded_data).save(args.aztec, 4)

        if args.qrcode:
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_Q,
                box_size=4,
                border=4,
            )
            if args.qrcode.endswith(".png"):
                image_factory = qrcode.image.pil.PilImage
            elif args.qrcode.endswith(".svg"):
                image_factory = qrcode.image.svg.SvgImage
            else:
                raise ValueError("Unknown QRcode image format")
            qr.add_data(encoded_data)
            qr.make(fit=True)
            img = qr.make_image(image_factory=image_factory)
            with open(args.qrcode, "wb") as qr_file:
                img.save(qr_file)

    elif args.command == "verify":
        key = read_jwk(args.key, private=False)
        with open(args.input, "rb") as input_file:
            encoded_data = input_file.read()

        if args.decode:
            if args.encoding == "binary":
                compressed_data = encoded_data
            elif args.encoding == "base45":
                compressed_data = base45decode(encoded_data.encode())
            elif args.encoding == "base64":
                compressed_data = base64.b64decode(encoded_data)
            elif args.encoding == "base85":
                compressed_data = base64.b85decode(encoded_data)
            else:
                raise RuntimeError("Invalid encoding")
            signed_data = zlib.decompress(compressed_data)
        else:
            signed_data = encoded_data

        payload = verify(public_key=key, signed_data=signed_data)
        if args.output:
            with open(args.output, "wt") as output_file:
                json.dump(payload, output_file, indent=4)
        else:
            logger.info("Verified payload: %s", json.dumps(payload, indent=4))


if __name__ == "__main__":
    main()
