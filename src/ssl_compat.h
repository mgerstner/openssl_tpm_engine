#ifndef _SSL_COMPAT_H
#define _SSL_COMPAT_H

// C std. headers
#include <stdlib.h>

// OpenSSL
#include <openssl/rsa.h>
#include <openssl/opensslv.h>

/*
 * Matthias Gerstner
 * Copyright (C) SUSE Linux GmbH 2017
 * mgerstner@suse.de
 *
 * This header provides a compatibility layer for being able to compile
 * against OpenSSL 1.0 as well as OpenSSL 1.1 versions. In OpenSSL 1.1 various
 * data structures have been made opaque and can no longer be accessed
 * directly.
 *
 * This header provides wrapper functions that do the right thing
 */

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
#	define USE_OPENSSL_OPAQUE_API
#	define HAVE_OPENSSL_110
// this flag was removed in 1.1.0, no longer needed, see commit OpenSSL
// 19c6d3ea2d3b4e0ad3e978e42cc7cbdf0c09891f
#	define RSA_FLAG_SIGN_VER 0
#endif

/*
 * the RAND_METHOD seed function has got an error return type in OpenSSL
 * 1.1.0.
 *
 * these defines help dealing with it.
 */
#ifdef HAVE_OPENSSL_110
#	define RAND_SEED_RET_TYPE int
#	define RAND_SEED_GOOD_RETURN 1
#	define RAND_SEED_BAD_RETURN 0
#else
#	define RAND_SEED_RET_TYPE void
#	define RAND_SEED_GOOD_RETURN
#	define RAND_SEED_BAD_RETURN
#endif

/*
 * callback function pointer typedefs
 */

typedef int (*func_rsa_pub_enc)(int, const unsigned char *, unsigned char *,
		RSA *, int);
typedef int (*func_rsa_pub_dec)(int, const unsigned char *, unsigned char *,
		RSA *, int);
typedef int (*func_rsa_priv_enc)(int, const unsigned char *, unsigned char *,
		RSA *, int);
typedef int (*func_rsa_priv_dec)(int, const unsigned char *, unsigned char *,
		RSA *, int);
typedef int (*func_rsa_mod_exp)(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
		BN_CTX *ctx);
typedef int (*func_rsa_bn_mod_exp)(BIGNUM *, const BIGNUM *, const BIGNUM *,
	       const BIGNUM *, BN_CTX *, BN_MONT_CTX *);
typedef int (*func_rsa_init)(RSA *rsa);
typedef int (*func_rsa_finish)(RSA *rsa);
typedef int (*func_rsa_keygen)(RSA *, int, BIGNUM *, BN_GENCB *);

/*
 * wrapper functions which provide the OpenSSL 1.1 accessor functions to
 * OpenSSL 1.0.
 */

#ifndef USE_OPENSSL_OPAQUE_API
RSA_METHOD* RSA_meth_new(const char *name, int flags)
{
	RSA_METHOD *ret = malloc(sizeof(RSA_METHOD));
	if (ret) {
		ret->name = name;
		ret->flags = flags;
	}

	return ret;
}

void RSA_meth_free(RSA_METHOD *meth)
{
	free(meth);
}

int RSA_meth_set_flags(RSA_METHOD *method, int flags)
{
	method->flags = flags;
	return 1;
}

int RSA_meth_set_pub_enc(RSA_METHOD *method, func_rsa_pub_enc pub_enc)
{
	method->rsa_pub_enc = pub_enc;
	return 1;
}

func_rsa_pub_enc RSA_meth_get_pub_enc(const RSA_METHOD *method)
{
	return method->rsa_pub_enc;
}

int RSA_meth_set_pub_dec(RSA_METHOD *method, func_rsa_pub_dec pub_dec)
{
	method->rsa_pub_dec = pub_dec;
	return 1;
}

func_rsa_pub_dec RSA_meth_get_pub_dec(const RSA_METHOD *method)
{
	return method->rsa_pub_dec;
}

int RSA_meth_set_priv_enc(RSA_METHOD *method, func_rsa_priv_enc priv_enc)
{
	method->rsa_priv_enc = priv_enc;
	return 1;
}

func_rsa_priv_enc RSA_meth_get_priv_enc(const RSA_METHOD *method)
{
	return method->rsa_priv_enc;
}

int RSA_meth_set_priv_dec(RSA_METHOD *method, func_rsa_priv_dec priv_dec)
{
	method->rsa_priv_dec = priv_dec;
	return 1;
}

func_rsa_priv_dec RSA_meth_get_priv_dec(const RSA_METHOD *method)
{
	return method->rsa_priv_dec;
}

int RSA_meth_set_mod_exp(RSA_METHOD *method, func_rsa_mod_exp mod_exp)
{
	method->rsa_mod_exp = mod_exp;
	return 1;
}

func_rsa_mod_exp RSA_meth_get_mod_exp(const RSA_METHOD *method)
{
	return method->rsa_mod_exp;
}

int RSA_meth_set_bn_mod_exp(RSA_METHOD *method,
		func_rsa_bn_mod_exp bn_mod_exp)
{
	method->bn_mod_exp = bn_mod_exp;
	return 1;
}

int RSA_meth_set_init(RSA_METHOD *method, func_rsa_init init)
{
	method->init = init;
	return 1;
}

int RSA_meth_set_finish(RSA_METHOD *method, func_rsa_finish finish)
{
	method->finish = finish;
	return 1;
}

int RSA_meth_set_keygen(RSA_METHOD *method, func_rsa_keygen keygen)
{
	method->rsa_keygen = keygen;
	return 1;
}

int RSA_set0_key(RSA *key, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
	if (key->n == NULL && n == NULL)
		return 0;
	if (key->e == NULL && e == NULL)
		return 0;

	if (n != NULL) {
		BN_free(key->n);
		key->n = n;
	}
	if (e != NULL) {
		BN_free(key->e);
		key->e = e;
	}
	if (d != NULL) {
		BN_free(key->d);
		key->d = d;
	}

	return 1;
}

void RSA_get0_key(RSA *key, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
	if (n)
		*n = key->n;
	if (e)
		*e = key->e;
	if (d)
		*d = key->d;
}

void RSA_get0_factors(RSA *key, const BIGNUM **p, const BIGNUM **q)
{
	if (p)
		*p = key->p;
	if (q)
		*q = key->q;
}

int RSA_set_method(RSA *key, const RSA_METHOD *method)
{
	key->meth = method;
	/* call our local init function here, the original RSA_set_method()
	 * does this internally */
	key->meth->init(key);
	return 1;
}

RSA* EVP_PKEY_get0_RSA(EVP_PKEY *key)
{
	return key->pkey.rsa;
}

#endif // ! USE_OPENSSL_OPAQUE_API

#ifndef HAVE_OPENSSL_110

const RSA_METHOD* RSA_PKCS1_OpenSSL()
{
	// was renamed in 1.1.0
	return RSA_PKCS1_SSLeay();
}

#endif // ! HAVE_OPENSSL_110

#endif // include guard
