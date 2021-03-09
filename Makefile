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

PAYLOAD=	hcert_example.json

OUTPUT_BIN=	test.bin
OUTPUT_PNG=	test.png
OUTPUT_TXT=	test.txt

ISSUER=		"se"
KID=		test2021
TTL=		7776000 # 90 days

CLEANFILES=	$(PAYLOAD_SCHEMA_JSON) $(METADATA_SCHEMA_JSON) \
		$(OUTPUT_BIN) $(OUTPUT_PNG) $(OUTPUT_TXT) size*


all: $(KEYS) $(SCHEMA)

test: $(KEYS)
	python3 schemacheck.py --input $(PAYLOAD_EXAMPLE_JSON) $(PAYLOAD_SCHEMA_YAML)
	python3 hcert.py --encoding base85 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output $(OUTPUT_BIN) --aztec $(OUTPUT_PNG)
	python3 hcert.py --encoding base85 verify --key $(PUBLIC_KEY) --input $(OUTPUT_BIN) --output $(OUTPUT_TXT)

size: $(KEYS) size_qztec size_qrcode

size_qztec:
	python3 hcert.py --encoding binary sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.bin --aztec size_aztec_bin.png
	python3 hcert.py --encoding base45 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.b45 --aztec size_aztec_b45.png
	python3 hcert.py --encoding base64 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.b64 --aztec size_aztec_b64.png
	python3 hcert.py --encoding base85 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.b85 --aztec size_aztec_b85.png

size_qrcode:
	python3 hcert.py --encoding binary sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.bin --qr size_qr_bin.png
	python3 hcert.py --encoding base45 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.b45 --qr size_qr_b45.png
	python3 hcert.py --encoding base64 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.b64 --qr size_qr_b64.png
	python3 hcert.py --encoding base85 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.b85 --qr size_qr_b85.png

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
