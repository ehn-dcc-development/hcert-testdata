"""Created JWKS from list of Certificates"""

import argparse
import json
import sys
import time

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.x509 import import_public_key_from_pem_data
from cryptojwt.jws.jws import JWS
from cryptojwt.jwx import key_from_jwk_dict
from cryptojwt.utils import b64d, b64e

START_DELIMITER = "-----BEGIN CERTIFICATE-----"
END_DELIMITER = "-----END CERTIFICATE-----"

KID_SIZE = 16


def pem_to_jwk_dict(pem_data: str):
    public_key = import_public_key_from_pem_data(pem_data)
    if isinstance(public_key, rsa.RSAPublicKey):
        jwk = RSAKey().load_key(public_key)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        jwk = ECKey().load_key(public_key)
    else:
        raise ValueError("Unknown key type")
    jwk_dict = jwk.serialize()
    cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())
    fp = cert.fingerprint(hashes.SHA256())
    jwk_dict["kid"] = b64e(fp[:8]).decode()
    jwk_dict["x5t#S256"] = b64e(fp).decode()
    jwk_dict["x5a"] = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": cert.serial_number,
    }
    return jwk_dict


def read_certs(file) -> []:
    res = []
    cert_data = None
    for line in file.readlines():
        if line.startswith(START_DELIMITER):
            cert_data = line
        elif line.startswith(END_DELIMITER):
            cert_data += line
            res.append(pem_to_jwk_dict(cert_data))
            cert_data = None
        elif cert_data is not None:
            cert_data += line
    return res


def main():
    """Main function"""

    parser = argparse.ArgumentParser(description="Create JWKS from certificates")

    parser.add_argument(
        "--sign",
        metavar="private JWK filename",
        help="Sign with private key (JWK)",
        required=False,
    )
    parser.add_argument(
        "--issuer",
        metavar="issuer",
        help="Signature issuer",
        required=False,
    )
    parser.add_argument(
        "--alg",
        metavar="alg",
        help="Signature algorithm",
        required=False,
        default="ES256",
    )
    parser.add_argument(
        "--lifetime",
        metavar="filename",
        help="Signature lifetime",
        type=int,
        required=False,
        default=3600,
    )

    args = parser.parse_args()

    jwks_dict = {"keys": [jwk_dict for jwk_dict in read_certs(sys.stdin)]}

    if args.sign:
        with open(args.sign, "rt") as signer_keyfile:
            signer_key_dict = json.load(signer_keyfile)
        signer_keys = [key_from_jwk_dict(signer_key_dict)]

        now = int(time.time())
        protected_headers = {
            "alg": args.alg,
            "crit": ["exp"],
            "iat": now,
            "nbf": now,
            "exp": now + args.lifetime,
        }
        if args.issuer:
            protected_headers["iss"] = args.issuer
        unprotected_headers = {}
        message = json.dumps(jwks_dict, sort_keys=True)
        headers = [(protected_headers, unprotected_headers)]
        jws = JWS(msg=message, alg=args.alg)
        signed_jwks_json = jws.sign_json(
            keys=signer_keys, headers=headers, flatten=False
        )
        print(signed_jwks_json)
    else:
        print(json.dumps(jwks_dict, indent=4))


if __name__ == "__main__":
    main()
