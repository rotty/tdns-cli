MAN_HEADER = "tdns-update Manual"
MAN_SOURCE = tdns-update.1.md
MAN_SECTION = 1

all: tdns-update.1 tdns-update.1.html target/release/tdns-update

target/release/tdns-update: .FORCE
	cargo build --release

tdns-update.1: $(MAN_SOURCE) Makefile
	pandoc -s -M header='$(MAN_HEADER)' -M section=$(MAN_SECTION) -t man $< -o $@

tdns-update.1.html: $(MAN_SOURCE) Makefile
	pandoc -s -M header='$(MAN_HEADER)' -M section=$(MAN_SECTION) -t html $< -o $@

.PHONY: .FORCE
