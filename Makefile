.PHONY: submodule-update parity-oss parity-enterprise parity-all parity-refresh

submodule-update:
	git submodule update --init --recursive coder

parity-oss: submodule-update
	cargo run -p coder-parity -- inventory \
		--go-root coder --rust-root . --scope oss \
		--output docs/parity-matrix.md

parity-enterprise: submodule-update
	cargo run -p coder-parity -- inventory \
		--go-root coder --rust-root . --scope enterprise \
		--output docs/parity-matrix-enterprise.md

parity-all: submodule-update
	cargo run -p coder-parity -- inventory \
		--go-root coder --rust-root . --scope all \
		--output docs/parity-matrix-all.md

parity-refresh: parity-oss parity-enterprise parity-all
	@echo "All parity matrices regenerated."
