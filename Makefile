all: fmt test lint docs

fmt:
	cargo fmt

build:
	cargo build --all-targets --all-features

test: build
	cargo test --all-features

lint:
	cargo clippy --all-features --tests --benches

docs: docs-html docs-pdf

docs-html:
	pandoc design.md -o target/doc/design.html -f markdown+latex_macros+header_attributes -t html --citeproc --toc --self-contained --standalone --lua-filter=diagram-generator.lua --katex
	pandoc manual.md -o target/doc/manual.html -f markdown+latex_macros+header_attributes -t html --citeproc --toc --self-contained --standalone --lua-filter=diagram-generator.lua --katex

docs-pdf:
	pandoc design.md -o target/doc/design.pdf -f markdown+latex_macros+header_attributes -t pdf --citeproc --toc --self-contained --standalone --lua-filter=diagram-generator.lua --katex
	pandoc manual.md -o target/doc/manual.pdf -f markdown+latex_macros+header_attributes -t pdf --citeproc --toc --self-contained --standalone --lua-filter=diagram-generator.lua --katex