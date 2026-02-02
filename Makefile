.PHONY: gen-certs up build test

gen-certs:
\tchmod +x scripts/gen_certs.sh && scripts/gen_certs.sh

build:
\tdocker-compose -f infra/docker-compose.yml build

up:
\tdocker-compose -f infra/docker-compose.yml up --build

test:
\tpytest -q