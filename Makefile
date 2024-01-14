.PHONY: build build-proofs lint clean clean-proofs

build-proofs: ## Build zero knowledge proofs
	cd ./proofs && cargo build --release

build-contracts: ## Build smart contracts
	cd ./contracts/subscriptions && cargo contract build --release

build: build-proofs build-contracts ## build all

lint: ## Run the linter
	cargo +nightly fmt
	cargo +nightly clippy --release -- -D warnings

test-proofs: ## Run unit tests for zero knowledge proofs
	cd ./proofs && cargo test

clean: clean-proofs clean-contracts ## Clean all temporary files

clean-proofs: ## Clean all temporary files for the zero knowledge proofs
	cd ./proofs && cargo clean
	
clean-contracts: ## Clean all temporary files for smart contracts
	cargo clean --manifest-path ./contracts/subscriptions/Cargo.toml

help: ## Displays this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[1;36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[1;36m%-25s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

