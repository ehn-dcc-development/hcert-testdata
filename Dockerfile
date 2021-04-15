FROM fedora:latest

RUN dnf install -y make git jq python3 python3-pip python3-cryptography
RUN pip3 install poetry
WORKDIR /tmp
COPY pyproject.toml poetry.lock /tmp/
RUN poetry install
COPY Makefile test.sh *.json /tmp/
ADD tools /tmp/tools/
ENTRYPOINT poetry run make test
