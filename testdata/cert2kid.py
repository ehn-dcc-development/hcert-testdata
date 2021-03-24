import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptojwt.utils import b64e

pem_data = sys.stdin.read()
cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())
fp = cert.fingerprint(hashes.SHA256())
print(b64e(fp[:8]).decode())
