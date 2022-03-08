all: fmt test lint

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
	pandoc design.md -o design.html -f markdown+latex_macros+header_attributes -t html --toc --self-contained --standalone --lua-filter=diagram-generator.lua --katex
	pandoc manual.md -o manual.html -f markdown+latex_macros+header_attributes -t html --toc --self-contained --standalone --lua-filter=diagram-generator.lua --katex

docs-pdf:
	pandoc design.md -o design.pdf -f markdown+latex_macros+header_attributes -t pdf --toc --self-contained --standalone --lua-filter=diagram-generator.lua --katex
	pandoc manual.md -o manual.pdf -f markdown+latex_macros+header_attributes -t pdf --toc --self-contained --standalone --lua-filter=diagram-generator.lua --katex