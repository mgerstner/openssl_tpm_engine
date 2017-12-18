SUBDIRS = src test

EXTRA_DIST = LICENSE README.md dist/openssl.cnf.sample

install-exec-hook:
	find $(DESTDIR) -name "*.la" -delete
