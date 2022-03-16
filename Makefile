all: check docs-pdf

check: fmt test lint

fmt:
	cargo fmt

build:
	cargo build --all-targets --all-features

test: build
	cargo test --all-features

lint:
	cargo clippy --all-features --tests --benches

docs-pdf:
	latexmk -cd docs/design.tex -pdf
	latexmk -cd docs/manual.tex -pdf
