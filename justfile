alias cov := coverage-md-print
alias cc := coverage-md-print

alias cov-html := coverage-html
alias cc-html := coverage-html

alias b := build
alias br := build-release
alias bp := build-release

alias t := test
alias tv := test-no-capture

alias dup := docker-compose-up

build-release:
	cargo build --profile release

build:
	cargo build

test:
	cargo test 

test-no-capture:
	cargo test -- --nocapture


# potential prerequisites:
#  cargo install grcov
#  rustup component add llvm-tools-preview
coverage-md-html:
	rm -rf ./target/coverage_profile
	rm -rf ./target/coverage
	mkdir -p ./target/coverage
	CARGO_INCREMENTAL=0 RUSTFLAGS='-Cinstrument-coverage' LLVM_PROFILE_FILE='target/coverage_profile/cargo-test-%p-%m.profraw' cargo test
	grcov ./target/coverage_profile/ --binary-path ./target/debug/deps/ --source-dir . --output-types markdown,html --branch --keep-only 'src/*' -o target/coverage/
	tree ./target/coverage

coverage-md-print: coverage-md-html
	cat ./target/coverage/markdown.md

#TODO: open file via borwser in linux/macos way?
coverage-html: coverage-md-html
	open ./target/coverage/html/index.html
	
docker-compose-up:
	docker-compose up -d
	docker-compose ps
