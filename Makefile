PRIVATE_KEY=	private_key.json
PUBLIC_KEY=	public_key.json

SCHEMA_YAML=	vproof_schema.yaml
SCHEMA_JSON=	vproof_schema.json

KEYS=		$(PRIVATE_KEY) $(PUBLIC_KEY)
SCHEMA=		$(SCHEMA_YAML) $(SCHEMA_JSON)

PAYLOAD=	vproof_example.json
OUTPUT=		test.bin


CLEANFILES=	$(OUTPUT) $(SCHEMA_JSON)


all: $(KEYS) $(SCHEMA)

test: $(KEYS)
	python3 vproof.py sign --key $(PRIVATE_KEY) --input $(PAYLOAD) --output $(OUTPUT)
	python3 vproof.py verify --key $(PUBLIC_KEY) --input $(OUTPUT)

$(PRIVATE_KEY):
	jwkgen --kty EC --crv P-256  > $@

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
