#!/bin/sh

ISSUER=XX
KID=7Ma02Zk3w6Y
TTL=7776000

PRIVATE_KEY=private_key.json
PUBLIC_KEY=public_key.json

for payload in hcert_example_minimal.json hcert_example_typical.json hcert_example_large.json; do
	prefix=`basename $payload .json`

	output_txt="${prefix}.txt"
	output_bin="${prefix}.bin"
	output_png="${prefix}.png"

	echo "Signing ${payload}"
	hcert --verbose sign \
		--key $PRIVATE_KEY  \
		--issuer $ISSUER --kid $KID --ttl $TTL \
		--input $payload --output $output_bin \
		--qrcode $output_png
	echo ""

	echo "Verify ${payload}"
	hcert --verbose verify \
		--key $PUBLIC_KEY --kid $KID \
		--input $output_bin --output $output_txt
	echo ""
done
