#!/bin/sh

ISSUER=issuer
TTL=7776000

PRIVATE_KEY=private_key.json
PUBLIC_KEY=public_key.json

for payload in hcert_example_minimal.json hcert_example_typical.json hcert_example_large.json; do
	prefix=`basename $payload .json`

	output_txt="${prefix}.txt"
	output_bin="${prefix}.bin"
	output_aztec="${prefix}_aztec.png"
	output_qr="${prefix}_qr.png"

	echo "Signing ${payload}"
	hcert --verbose --encoding base45 sign \
		--key $PRIVATE_KEY  \
		--issuer $ISSUER --ttl $TTL \
		--input $payload --output $output_bin \
		--aztec $output_aztec --qrcode $output_qr
	echo ""

	echo "Verify ${payload}"
	hcert --verbose --encoding base45 verify \
		--key $PUBLIC_KEY \
		--input $output_bin --output $output_txt
	echo ""
done
