MAN_HEADER = "tdns Manual"
MAN_SOURCES = tdns.1.md tdns-query.1.md tdns-update.1.md
MAN_HTML_OUTPUT = $(patsubst %.1.md,%.1.html,$(MAN_SOURCES))
MAN_TROFF_OUTPUT = $(patsubst %.1.md,%.1,$(MAN_SOURCES))

MAN_SECTION = 1

PANDOC_HTML_OPTIONS =

all: man target/release/tdns

man: $(MAN_TROFF_OUTPUT) $(MAN_HTML_OUTPUT)

clean: man-clean
	cargo clean

man-clean:
	rm -f $(MAN_TROFF_OUTPUT) $(MAN_HTML_OUTPUT)

coverage:
	cargo tarpaulin --exclude-files 'src/bin/*' src/open.rs 'tests/*' --out Xml \
	  && pycobertura show -f html cobertura.xml > cobertura.html

target/release/tdns: .FORCE
	cargo build --release

%.1: %.1.md Makefile
	pandoc -s -M header='$(MAN_HEADER)' -M section=$(MAN_SECTION) -t man $< -o $@

%.1.html: %.1.md Makefile
	pandoc -s -M header='$(MAN_HEADER)' -M section=$(MAN_SECTION) -t html $(PANDOC_HTML_OPTIONS) $< -o $@

.PHONY: .FORCE clean coverage man man-clean
