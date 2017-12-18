SUBDIRS = src test

EXTRA_DIST = README.md dist/openssl.cnf.sample

install-exec-hook:
	find $(DESTDIR) -name "*.la" -delete
