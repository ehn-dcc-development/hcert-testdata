FROM fedora:latest

RUN dnf install -y make git jq python3 python3-pip python3-cryptography
RUN pip3 install poetry
WORKDIR /tmp
COPY pyproject.toml poetry.lock /tmp/
COPY hcert/* /tmp/hcert/
RUN poetry install
COPY Makefile test.sh *.json schemacheck.py /tmp/
ENTRYPOINT poetry run make test
