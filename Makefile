PRIVATE_KEY=	private_key.json
PUBLIC_KEY=	public_key.json

SCHEMA_YAML=	vproof_schema.yaml
SCHEMA_JSON=	vproof_schema.json

ISSUER=		xyzzy

KEYS=		$(PRIVATE_KEY) $(PUBLIC_KEY)
SCHEMA=		$(SCHEMA_YAML) $(SCHEMA_JSON)

PAYLOAD=	vproof_example.json
OUTPUT=		test.bin
OUTPUT_PNG=	test.png

ISSUER=		"se"
KID=		test2021
TTL=		7776000 # 90 days

CLEANFILES=	$(SCHEMA_JSON) $(OUTPUT) $(OUTPUT_PNG) size_*


all: $(KEYS) $(SCHEMA)

test: $(KEYS)
	python3 schemacheck.py --input vproof_example.json vproof_schema.yaml
	python3 vproof.py --encoding base85 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output $(OUTPUT) --aztec $(OUTPUT_PNG)
	python3 vproof.py --encoding base85 verify --key $(PUBLIC_KEY) --input $(OUTPUT)

size: $(KEYS)
	python3 vproof.py --encoding binary sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.bin --aztec size_bin.png
	python3 vproof.py --encoding base64 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.b64 --aztec size_b64.png
	python3 vproof.py --encoding base85 sign --key $(PRIVATE_KEY) --issuer $(ISSUER) --kid $(KID) --ttl $(TTL) --input $(PAYLOAD) --output size.b85 --aztec size_b85.png

$(PRIVATE_KEY):
	jwkgen --kty EC --crv P-256 --kid $(KID) > $@

$(PUBLIC_KEY): $(PRIVATE_KEY)
	jq 'del(.d)' < $< >$@

schema: vproof_schema.json

$(SCHEMA_JSON): $(SCHEMA_YAML)
	python3 schemacheck.py --json $< >$@

reformat:
	isort *.py
	black *.py

clean:
	rm -f $(PRIVATE_KEY) $(PUBLIC_KEY) $(CLEANFILES)
