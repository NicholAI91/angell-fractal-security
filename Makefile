.PHONY: all rust python extension test

all: test

rust:
	cargo fmt --all
	cargo clippy --all-targets
	cargo test --all

python:
	python -m pip install -e .
	angell-fractal info
	angell-fractal classify 0.1 0.2 --format json

extension:
	cd extension && zip -r ../angell-fractal-security-extension.zip .

test: rust python
