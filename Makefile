PRIVATE_KEY=	private_key.json
PUBLIC_KEY=	public_key.json

PAYLOAD_SCHEMA_YAML=	hcert_schema.yaml
PAYLOAD_SCHEMA_JSON=	hcert_schema.json
PAYLOAD_EXAMPLE_JSON=	hcert_example.json

METADATA_SCHEMA_YAML=	metadata_schema.yaml
METADATA_SCHEMA_JSON=	metadata_schema.json
METADATA_EXAMPLE_JSON=	metadata_example.json

ISSUER=		xyzzy

KEYS=		$(PRIVATE_KEY) $(PUBLIC_KEY)
SCHEMA=		$(PAYLOAD_SCHEMA_YAML) $(PAYLOAD_SCHEMA_JSON)

PAYLOAD=	hcert_example_typical.json

ISSUER=		issuer
KID=		test2021
TTL=		7776000 # 90 days

CLEANFILES=	$(PAYLOAD_SCHEMA_JSON) $(METADATA_SCHEMA_JSON) \
		hcert_example_*.{bin,txt,png} \
		size_*.{bin,txt,png}


all: $(KEYS) $(SCHEMA)

verify:
	python3 schemacheck.py --input hcert_example_minimal.json $(PAYLOAD_SCHEMA_YAML)
	python3 schemacheck.py --input hcert_example_typical.json $(PAYLOAD_SCHEMA_YAML)
	python3 schemacheck.py --input hcert_example_large.json   $(PAYLOAD_SCHEMA_YAML)

test: $(KEYS) verify
	sh test.sh

size: $(KEYS) size_qztec size_qrcode

size_qztec:
	hcert --encoding binary sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --aztec size_aztec_bin.png
	hcert --encoding base45 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --aztec size_aztec_b45.png
	hcert --encoding base64 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --aztec size_aztec_b64.png
	hcert --encoding base85 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --aztec size_aztec_b85.png

size_qrcode:
	hcert --encoding binary sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --qrcode size_qr_bin.png
	hcert --encoding base45 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --qrcode size_qr_b45.png
	hcert --encoding base64 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --qrcode size_qr_b64.png
	hcert --encoding base85 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --qrcode size_qr_b85.png

$(PRIVATE_KEY):
	jwkgen --kty EC --crv P-256 --kid $(KID) > $@

$(PUBLIC_KEY): $(PRIVATE_KEY)
	jq 'del(.d)' < $< >$@

schema: $(PAYLOAD_SCHEMA_JSON) $(METADATA_SCHEMA_JSON)

metadata:
	python3 schemacheck.py --input $(METADATA_EXAMPLE_JSON) $(METADATA_SCHEMA_YAML)

$(PAYLOAD_SCHEMA_JSON): $(PAYLOAD_SCHEMA_YAML)
	python3 schemacheck.py --json $< >$@

$(METADATA_SCHEMA_JSON): $(METADATA_SCHEMA_YAML)
	python3 schemacheck.py --json $< >$@

reformat:
	isort *.py
	black *.py

clean:
	rm -f $(PRIVATE_KEY) $(PUBLIC_KEY) $(CLEANFILES)
