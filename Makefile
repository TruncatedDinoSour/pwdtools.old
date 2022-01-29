all: install

PREFIX ?= /usr/local
BINDIR := $(DESTDIR)$(PREFIX)/bin

install:
	install -Dm755 src/pwdgen $(BINDIR)
	install -Dm755 src/pwdinfo $(BINDIR)

.PHONY: all install

