all: install

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

install:
	mkdir -p $(DESTDIR)$(BINDIR)
	install -Dm755 src/pwdgen $(DESTDIR)$(BINDIR)
	install -Dm755 src/pwdinfo $(DESTDIR)$(BINDIR)

.PHONY: all install

