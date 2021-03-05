PRIVATE_KEY=	private_key.json
PUBLIC_KEY=	public_key.json

PAYLOAD_SCHEMA_YAML=	vproof_schema.yaml
PAYLOAD_SCHEMA_JSON=	vproof_schema.json
PAYLOAD_EXAMPLE_JSON=	vproof_example.json

METADATA_SCHEMA_YAML=	metadata_schema.yaml
METADATA_SCHEMA_JSON=	metadata_schema.json
METADATA_EXAMPLE_JSON=	metadata_example.json

ISSUER=		xyzzy

KEYS=		$(PRIVATE_KEY) $(PUBLIC_KEY)
SCHEMA=		$(PAYLOAD_SCHEMA_YAML) $(PAYLOAD_SCHEMA_JSON)

PAYLOAD=	vproof_example.json

OUTPUT_BIN=	test.bin
OUTPUT_PNG=	test.png
OUTPUT_TXT=	test.txt

ISSUER=		"se"
KID=		test2021
TTL=		7776000 # 90 days

CLEANFILES=	$(PAYLOAD_SCHEMA_JSON) $(METADATA_SCHEMA_JSON) \
		$(OUTPUT_BIN) $(OUTPUT_PNG) $(OUTPUT_TXT) size_*


all: $(KEYS) $(SCHEMA)

test: $(KEYS)
	python3 schemacheck.py --input $(PAYLOAD_EXAMPLE_JSON) $(PAYLOAD_SCHEMA_YAML)
	python3 vproof.py --encoding base85 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output $(OUTPUT_BIN) --aztec $(OUTPUT_PNG)
	python3 vproof.py --encoding base85 verify --key $(PUBLIC_KEY) --input $(OUTPUT_BIN) --output $(OUTPUT_TXT)

size: $(KEYS)
	python3 vproof.py --encoding binary sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.bin --aztec size_bin.png
	python3 vproof.py --encoding base64 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.b64 --aztec size_b64.png
	python3 vproof.py --encoding base85 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.b85 --aztec size_b85.png

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
