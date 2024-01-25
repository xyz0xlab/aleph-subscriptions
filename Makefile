.PHONY: build build-proofs build-clients lint clean clean-proofs clean-clients test test-proofs test-clients test-contracts

build-proofs: ## Build zero knowledge proofs
	cd ./proofs && cargo build --release

build-clients: ## Build aleph zero chain client applications
	cd ./subscriptions-client && cargo build --release

build-contracts: ## Build smart contracts
	cd ./contracts/subscriptions && cargo contract build --release

build: build-proofs build-contracts ## build all

lint: ## Run the linter
	cargo +nightly fmt
	cargo +nightly clippy --release -- -D warnings

test-proofs: ## Run unit tests for zero knowledge proofs
	cd ./proofs && cargo test

test-clients: ## Run unit tests for aleph zero chain client applications
	cd ./subscriptions-client && cargo test

test-contracts: ## Run unit tests for smart contracts
	cd ./contracts/subscriptions && cargo test

test: test-proofs test-clients test-contracts ## Run all unit tests

clean: clean-proofs clean-clients clean-contracts ## Clean all temporary files

clean-proofs: ## Clean all temporary files for the zero knowledge proofs
	cd ./proofs && cargo clean

clean-clients: ## Clean all temporary files for aleph zero client applications
	cd ./subscriptions-client && cargo clean
	
clean-contracts: ## Clean all temporary files for smart contracts
	cargo clean --manifest-path ./contracts/subscriptions/Cargo.toml

help: ## Displays this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[1;36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[1;36m%-25s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

