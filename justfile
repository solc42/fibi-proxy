alias cc := coverage
alias cc-txt := coverage-txt
alias cc-html := coverage-html-open

alias b := build
alias br := build-release
alias bp := build-release

alias c := clippy

alias t := test
alias tv := test-no-capture

alias dup := docker-compose-up

build-release:
	cargo build --profile release

build:
	cargo build

test:
	cargo test 
clippy:
	cargo clippy

test-no-capture:
	cargo test -- --nocapture


# potential prerequisites for local run:
#  cargo +stable install cargo-llvm-cov --locked
#  rustup component add llvm-tools-preview
coverage-clean-def:
	rm -rf target/llvm-cov-target

coverage: coverage-clean-def
	cargo llvm-cov --summary-only

coverage-html-open: coverage-clean-def
	rm -rf target/llvm-cov-target
	cargo llvm-cov --html --open

coverage-txt: coverage-clean-def
	rm -rf target/llvm-cov-target
	cargo llvm-cov --text
	
docker-compose-up:
	docker-compose up -d
	docker-compose ps

