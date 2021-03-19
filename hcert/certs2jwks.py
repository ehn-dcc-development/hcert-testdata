"""Created JWKS from list of Certificates"""

import json
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.x509 import import_public_key_from_pem_data
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
        raise ValueError("Uknown key type")
    jwk_dict = jwk.serialize()
    jwk_dict["kid"] = b64e(b64d(jwk.thumbprint("SHA-256"))[:KID_SIZE]).decode()
    cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())
    jwk_dict["x509"] = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": cert.serial_number,
        "fingerprint": b64e(cert.fingerprint(hashes.SHA256())).decode(),
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

    jwks_dict = {"keys": [jwk_dict for jwk_dict in read_certs(sys.stdin)]}
    print(json.dumps(jwks_dict, indent=4))


if __name__ == "__main__":
    main()
