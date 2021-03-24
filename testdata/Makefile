CERTS=		issuer1.crt issuer2.crt issuer3.crt issuer4.crt
KEYS=		issuer1.key issuer2.key issuer3.key issuer4.key

JWS=		jws.json
JWKS=		jwks.json
JWKS_PRIVATE=	jwks_signer_private.json
JWKS_PUBLIC=	jwks_signer_public.json

TEST_KEY_FILE=	issuer1.key
TEST_CRT_FILE=	issuer1.crt
TEST_KEY_KID=	$(shell python3 cert2kid.py < issuer1.crt)
TEST_PAYLOAD=	../hcert_example_typical.json
TEST_TTL=	31536000
TEST_OUTPUT=	test1


all: certs sign verify

certs:
	bash mkcert.sh

sign: $(JWKS_PRIVATE) $(JWS)
	hcert --verbose sign \
		--key $(TEST_KEY_FILE) \
		--kid $(TEST_KEY_KID) --ttl $(TEST_TTL) \
		--input $(TEST_PAYLOAD) \
		--output $(TEST_OUTPUT).bin \
		--aztec $(TEST_OUTPUT)_aztec.png \
		--qrcode $(TEST_OUTPUT)_qt.png \

verify: $(JWKS_PUBLIC) $(JWKS)
	hcert --verbose verify \
		--key $(TEST_CRT_FILE) \
		--kid $(TEST_KEY_KID) \
		--input $(TEST_OUTPUT).bin

$(JWKS_PRIVATE):
	jwkgen --kty EC > $@
	
$(JWKS_PUBLIC): $(JWKS_PRIVATE)
	jq 'del(.d)' < $< >$@

$(JWS): $(JWKS_PRIVATE) $(CERTS)
	cat issuer*.crt | certs2jwks --sign $(JWKS_PRIVATE) > $@

$(JWKS): $(JWS)
	python3 jws_verify.py --trusted $(JWKS_PUBLIC) --input $< --output $@

clean:
	rm -f $(JWS) $(JWKS) $(TEST_OUTPUT)*

realclean: clean
	rm -f $(CERTS) $(KEYS) $(JWKS_PRIVATE) $(JWKS_PUBLIC)
