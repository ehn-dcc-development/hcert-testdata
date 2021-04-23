PRIVATE_KEY=	private_key.json
PUBLIC_KEY=	public_key.json

ISSUER=		XX
KID=		7Ma02Zk3w6Y

KEYS=		$(PRIVATE_KEY) $(PUBLIC_KEY)

ISSUER=		issuer
KID=		test2021
TTL=		7776000 # 90 days

CLEANFILES=	example-*.{bin,txt,png,*.json}

EXAMPLES_BASE=	https://raw.githubusercontent.com/ehn-digital-green-development/ehn-dgc-schema/next/examples
EXAMPLES=	contrived-all-options.json \
		contrived-translit.json \
		rec.json \
		test-naa.json \
		test-rat.json \
		vac.json

all: $(KEYS)

test: $(KEYS) examples
	sh test.sh

examples::
	for f in $(EXAMPLES); do curl -o example-$$f $(EXAMPLES_BASE)/$$f; done

$(PRIVATE_KEY):
	jwkgen --kty EC --crv P-256 --kid $(KID) > $@

$(PUBLIC_KEY): $(PRIVATE_KEY)
	jq 'del(.d)' < $< >$@

reformat:
	isort hcert *.py
	black hcert *.py

clean:
	rm -f $(PRIVATE_KEY) $(PUBLIC_KEY) $(CLEANFILES)
