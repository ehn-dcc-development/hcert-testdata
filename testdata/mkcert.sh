#!/bin/bash

for n in 1 2 3 4; do
	openssl req -new -x509 -nodes \
		-newkey ec:<(openssl ecparam -name secp256r1) \
		-keyout issuer${n}.key -out issuer${n}.crt \
		-days 1000 -subj "/C=SE/O=Kirei AB/OU=hcert/CN=issuer${n}"
done

