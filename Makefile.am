SUBDIRS=. test

EXTRA_DIST = README  openssl.cnf.sample

bin_PROGRAMS=create_tpm_key
openssl_enginedir=@libdir@/openssl/engines

engine_libs=-lcrypto -lc -ltspi
engine_sources=e_tpm.c e_tpm.h e_tpm_err.c
engine_ldflags=-avoid-version -module -shared -export-dynamic

# in OpenSSL 1.1 engine modules have been stripped of the lib prefix so we
# need to adust the library name accordingly.
#
# sadly there seems to be no elegant way to change the library name based on a
# configure check outcome, so we have to explicitly define both variants like
# this
if OPENSSL_11
engine_base=tpm.la
tpm_la_LIBADD=$(engine_libs)
tpm_la_LDFLAGS=$(engine_ldflags)
tpm_la_SOURCES=$(engine_sources)
else
engine_base=libtpm.la
libtpm_la_LIBADD=$(engine_libs)
libtpm_la_LDFLAGS=$(engine_ldflags)
libtpm_la_SOURCES=$(engine_sources)
endif

openssl_engine_LTLIBRARIES=$(engine_base)

create_tpm_key_SOURCES=create_tpm_key.c
create_tpm_key_LDADD=-ltspi -lcrypto
