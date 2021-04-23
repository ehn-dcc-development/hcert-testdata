TEST_SOURCE=	https://raw.githubusercontent.com/ehn-digital-green-development/ehn-dgc-schema/next/examples/vac.json

CERTS=		issuer1.crt issuer2.crt issuer3.crt issuer4.crt
KEYS=		issuer1.key issuer2.key issuer3.key issuer4.key

JWKS=		jwks.json
JWKS_SIGNED=	jwks_signed.json
JWKS_PRIVATE=	jwks_signer_private.json
JWKS_PUBLIC=	jwks_signer_public.json

TEST_KEY_FILE=	issuer1.key
TEST_CRT_FILE=	issuer1.crt
TEST_KEY_KID=	$(shell python3 cert2kid.py < issuer1.crt)
TEST_PAYLOAD=	test1.json
TEST_TTL=	31536000
TEST_OUTPUT=	test1
TEST_ISSUER=	XX


all: certs sign verify

certs:
	bash mkcert.sh

sign: $(JWKS_PRIVATE) $(JWKS_SIGNED)
	curl -o $(TEST_PAYLOAD) $(TEST_SOURCE)
	hcert --verbose sign \
		--issuer $(TEST_ISSUER) \
		--key $(TEST_KEY_FILE) \
		--kid $(TEST_KEY_KID) --ttl $(TEST_TTL) \
		--input $(TEST_PAYLOAD) \
		--output $(TEST_OUTPUT).bin \
		--qrcode $(TEST_OUTPUT).png \

verify:
	hcert --verbose verify \
		--key $(TEST_CRT_FILE) \
		--kid $(TEST_KEY_KID) \
		--input $(TEST_OUTPUT).bin

verify_jwks:
	python3 ../tools/jws_verify.py --trusted $(JWKS_PUBLIC) --input $(JWKS_SIGNED)

$(JWKS_PRIVATE):
	jwkgen --kty EC > $@
	
$(JWKS_PUBLIC): $(JWKS_PRIVATE)
	jq 'del(.d)' < $< >$@

$(JWKS_SIGNED): $(JWKS_PRIVATE) $(CERTS)
	cat issuer*.crt | python3 ../tools/certs2jwks.py --sign $(JWKS_PRIVATE) > $@

$(JWKS): $(JWKS_SIGNED)
	python3 ../tools/jws_verify.py --trusted $(JWKS_PUBLIC) --input $< --output $@

clean:
	rm -f $(JWS) $(JWKS) $(TEST_OUTPUT)*

realclean: clean
	rm -f $(CERTS) $(KEYS) $(JWKS_PRIVATE) $(JWKS_PUBLIC)
