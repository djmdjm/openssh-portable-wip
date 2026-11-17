/* $OpenBSD$ */
/*
 * Copyright (c) 2026 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* draft-ietf-sshm-composite-sigs-00 */

#include "includes.h"

#if defined(USE_MLDSA) && defined(WITH_OPENSSL)

#include "openbsd-compat/openssl-compat.h"

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include "crypto_api.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "log.h"

#define COMPOSITE_LABEL			"COMPSIG-MLDSA87-ECDSA-P384-SHA512"
#define SSH_MLDSA87_P384_ALG_NAME	"ssh-mldsa87-p384"

/* sshkey integration */

static void
ssh_mldsa87_p384_cleanup(struct sshkey *k)
{
	freezero(k->mldsa87_pk, MLDSA87_PUBLICKEYBYTES);
	freezero(k->mldsa87_sk, MLDSA87_SEEDBYTES);
	k->mldsa87_pk = NULL;
	k->mldsa87_sk = NULL;
	EVP_PKEY_free(k->pkey);
	k->pkey = NULL;
}

static int
ssh_mldsa87_p384_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a->mldsa87_pk == NULL || b->mldsa87_pk == NULL ||
	    a->pkey == NULL || b->pkey == NULL)
		return 0;
	if (memcmp(a->mldsa87_pk, b->mldsa87_pk,
	    MLDSA87_PUBLICKEYBYTES) != 0)
		return 0;
	if (EVP_PKEY_cmp(a->pkey, b->pkey) != 1)
		return 0;
	return 1;
}

static int
ssh_mldsa87_p384_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	struct sshbuf *pkbuf = NULL;
	int r;

	if (key->mldsa87_pk == NULL || key->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((pkbuf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_put(pkbuf, key->mldsa87_pk,
	    MLDSA87_PUBLICKEYBYTES)) != 0 ||
	    (r = sshbuf_put_ec_pkey(pkbuf, key->pkey)) != 0 ||
	    (r = sshbuf_put_stringb(b, pkbuf)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(pkbuf);
	return r;
}

static int
ssh_mldsa87_p384_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	struct sshbuf *skbuf = NULL;
	const EC_KEY *ec;
	const BIGNUM *priv;
	int r;

	if (key->mldsa87_sk == NULL || key->pkey == NULL ||
	    (ec = EVP_PKEY_get0_EC_KEY(key->pkey)) == NULL ||
	    (priv = EC_KEY_get0_private_key(ec)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!sshkey_is_cert(key)) {
		if ((r = ssh_mldsa87_p384_serialize_public(key,
		    b, opts)) != 0)
			return r;
	}
	if ((skbuf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_put(skbuf, key->mldsa87_sk,
	    MLDSA87_SEEDBYTES)) != 0 ||
	    (r = sshbuf_put_bignum2(skbuf, priv)) != 0 ||
	    (r = sshbuf_put_stringb(b, skbuf)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(skbuf);
	return r;
}

static int
ssh_mldsa87_p384_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	struct sshbuf *pkbuf = NULL;
	u_char *mldsa_pk = NULL;
	EC_KEY *ec = NULL;
	EVP_PKEY *pkey = NULL;
	int r;

	if ((r = sshbuf_froms(b, &pkbuf)) != 0)
		return r;
	if (sshbuf_len(pkbuf) < MLDSA87_PUBLICKEYBYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((mldsa_pk = malloc(MLDSA87_PUBLICKEYBYTES)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(mldsa_pk, sshbuf_ptr(pkbuf), MLDSA87_PUBLICKEYBYTES);
	if ((r = sshbuf_consume(pkbuf, MLDSA87_PUBLICKEYBYTES)) != 0)
		goto out;
	if ((ec = EC_KEY_new_by_curve_name(NID_secp384r1)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_get_eckey(pkbuf, ec)) != 0)
		goto out;
	if (sshbuf_len(pkbuf) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshkey_ec_validate_public(EC_KEY_get0_group(ec),
	    EC_KEY_get0_public_key(ec)) != 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}
	if ((pkey = EVP_PKEY_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	freezero(key->mldsa87_pk, MLDSA87_PUBLICKEYBYTES);
	key->mldsa87_pk = mldsa_pk;
	mldsa_pk = NULL;
	EVP_PKEY_free(key->pkey);
	key->pkey = pkey;
	pkey = NULL;
	/* success */
	r = 0;
 out:
	sshbuf_free(pkbuf);
	freezero(mldsa_pk, MLDSA87_PUBLICKEYBYTES);
	EC_KEY_free(ec);
	EVP_PKEY_free(pkey);
	return r;
}

static int
ssh_mldsa87_p384_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	struct sshbuf *skbuf = NULL;
	u_char *mldsa_sk = NULL;
	BIGNUM *exponent = NULL;
	EC_KEY *ec = NULL;
	int r;

	if (!sshkey_is_cert(key)) {
		if ((r = ssh_mldsa87_p384_deserialize_public(ktype,
		    b, key)) != 0)
			return r;
	}
	if ((r = sshbuf_froms(b, &skbuf)) != 0)
		goto out;
	if (sshbuf_len(skbuf) < MLDSA87_SEEDBYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((mldsa_sk = malloc(MLDSA87_SEEDBYTES)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(mldsa_sk, sshbuf_ptr(skbuf), MLDSA87_SEEDBYTES);
	if ((r = sshbuf_consume(skbuf, MLDSA87_SEEDBYTES)) != 0 ||
	    (r = sshbuf_get_bignum2(skbuf, &exponent)) != 0)
		goto out;
	if (sshbuf_len(skbuf) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((ec = EVP_PKEY_get1_EC_KEY(key->pkey)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EC_KEY_set_private_key(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((r = sshkey_ec_validate_private(ec)) != 0)
		goto out;
	if (EVP_PKEY_set1_EC_KEY(key->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	freezero(key->mldsa87_sk, MLDSA87_SEEDBYTES);
	key->mldsa87_sk = mldsa_sk;
	mldsa_sk = NULL; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(skbuf);
	freezero(mldsa_sk, MLDSA87_SEEDBYTES);
	BN_clear_free(exponent);
	EC_KEY_free(ec);
	return r;
}

static int
ssh_mldsa87_p384_generate(struct sshkey *k, int bits)
{
	uint8_t mldsa_sk_expanded[MLDSA87_SECRETKEYBYTES];
	EC_KEY *ec = NULL;
	EVP_PKEY *pkey = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	ssh_mldsa87_p384_cleanup(k);
	if ((k->mldsa87_pk = malloc(MLDSA87_PUBLICKEYBYTES)) == NULL ||
	    (k->mldsa87_sk = malloc(MLDSA87_SEEDBYTES)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	arc4random_buf(k->mldsa87_sk, MLDSA87_SEEDBYTES);
	if (crypto_sign_mldsa87_keypair_seeded(k->mldsa87_pk,
	    mldsa_sk_expanded, k->mldsa87_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		goto out;
	}

	if ((ec = EC_KEY_new_by_curve_name(NID_secp384r1)) == NULL ||
	    (pkey = EVP_PKEY_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EC_KEY_generate_key(ec) != 1 ||
	    EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	k->pkey = pkey;
	pkey = NULL;
	r = 0;
 out:
	explicit_bzero(mldsa_sk_expanded, sizeof(mldsa_sk_expanded));
	EC_KEY_free(ec);
	EVP_PKEY_free(pkey);
	if (r != 0)
		ssh_mldsa87_p384_cleanup(k);
	return r;
}

static int
ssh_mldsa87_p384_copy_public(const struct sshkey *from, struct sshkey *to)
{
	const EC_KEY *ec_from;
	EC_KEY *ec_to = NULL;
	EVP_PKEY *pkey = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	if (from->mldsa87_pk == NULL || from->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((ec_from = EVP_PKEY_get0_EC_KEY(from->pkey)) == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;

	ssh_mldsa87_p384_cleanup(to);
	if ((to->mldsa87_pk = malloc(MLDSA87_PUBLICKEYBYTES)) == NULL ||
	    (ec_to = EC_KEY_new_by_curve_name(NID_secp384r1)) == NULL ||
	    (pkey = EVP_PKEY_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(to->mldsa87_pk, from->mldsa87_pk, MLDSA87_PUBLICKEYBYTES);
	if (EC_KEY_set_public_key(ec_to,
	    EC_KEY_get0_public_key(ec_from)) != 1 ||
	    EVP_PKEY_set1_EC_KEY(pkey, ec_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	to->pkey = pkey;
	pkey = NULL;
	r = 0;
 out:
	EC_KEY_free(ec_to);
	EVP_PKEY_free(pkey);
	if (r != 0)
		ssh_mldsa87_p384_cleanup(to);
	return r;
}

static int
ssh_mldsa87_p384_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin,
    u_int compat)
{
	uint8_t *m_prime = NULL;
	size_t m_prime_len = 0;
	uint8_t mldsa_sk[MLDSA87_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA87_PUBLICKEYBYTES];
	uint8_t mldsa_sig[MLDSA87_SIGBYTES];
	ECDSA_SIG *esig = NULL;
	u_char *ecdsa_sig = NULL;
	const u_char *psig;
	size_t ecdsa_sig_len = 0;
	const BIGNUM *sig_r, *sig_s;
	struct sshbuf *b = NULL, *csig = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_MLDSA87_P384 ||
	    key->mldsa87_sk == NULL || key->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((r = ssh_mldsa_composite_m_prime(&m_prime, &m_prime_len,
	    COMPOSITE_LABEL, data, datalen, NULL, 0)) != 0)
		goto out;

	/* Expand ML-DSA-87 key from seed and sign */
	if (crypto_sign_mldsa87_keypair_seeded(mldsa_pk_dummy, mldsa_sk,
	    key->mldsa87_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		goto out;
	}
	if (crypto_sign_mldsa87(mldsa_sig, m_prime, m_prime_len,
	    (const uint8_t *)COMPOSITE_LABEL, sizeof(COMPOSITE_LABEL) - 1,
	    mldsa_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		goto out;
	}

	/* Sign with ECDSA-P384 (SHA-384) */
	if ((r = sshkey_pkey_digest_sign(key->pkey, SSH_DIGEST_SHA384,
	    &ecdsa_sig, &ecdsa_sig_len, m_prime, m_prime_len)) != 0)
		goto out;
	psig = ecdsa_sig;
	if ((esig = d2i_ECDSA_SIG(NULL, &psig, ecdsa_sig_len)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	if ((csig = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put(csig, mldsa_sig, sizeof(mldsa_sig))) != 0 ||
	    (r = sshbuf_put_bignum2(csig, sig_r)) != 0 ||
	    (r = sshbuf_put_bignum2(csig, sig_s)) != 0)
		goto out;
	if ((r = sshbuf_put_cstring(b, SSH_MLDSA87_P384_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_stringb(b, csig)) != 0)
		goto out;

	if (sigp != NULL) {
		if ((*sigp = malloc(sshbuf_len(b))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	if (lenp != NULL)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	free(m_prime);
	explicit_bzero(mldsa_sk, sizeof(mldsa_sk));
	explicit_bzero(mldsa_sig, sizeof(mldsa_sig));
	freezero(ecdsa_sig, ecdsa_sig_len);
	ECDSA_SIG_free(esig);
	sshbuf_free(csig);
	sshbuf_free(b);
	return r;
}

static int
ssh_mldsa87_p384_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen, const u_char *data, size_t dlen,
    const char *alg, u_int compat, struct sshkey_sig_details **detailsp)
{
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;
	const u_char *mldsa_sig;
	BIGNUM *sig_r = NULL, *sig_s = NULL;
	ECDSA_SIG *esig = NULL;
	u_char *sigb = NULL, *cp;
	int derlen = 0;
	uint8_t *m_prime = NULL;
	size_t m_prime_len = 0;
	int r = SSH_ERR_INTERNAL_ERROR;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_MLDSA87_P384 ||
	    key->mldsa87_pk == NULL || key->pkey == NULL ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_get_cstring(b, &ktype, NULL)) != 0 ||
	    (r = sshbuf_froms(b, &sigbuf)) != 0)
		goto out;
	if (strcmp(SSH_MLDSA87_P384_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	if (sshbuf_len(sigbuf) < MLDSA87_SIGBYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	mldsa_sig = sshbuf_ptr(sigbuf);
	if ((r = sshbuf_consume(sigbuf, MLDSA87_SIGBYTES)) != 0 ||
	    (r = sshbuf_get_bignum2(sigbuf, &sig_r)) != 0 ||
	    (r = sshbuf_get_bignum2(sigbuf, &sig_s)) != 0)
		goto out;
	if (sshbuf_len(sigbuf) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	if ((r = ssh_mldsa_composite_m_prime(&m_prime, &m_prime_len,
	    COMPOSITE_LABEL, data, dlen, NULL, 0)) != 0)
		goto out;

	/* Verify ML-DSA-87 */
	if (crypto_sign_mldsa87_verify(mldsa_sig, m_prime, m_prime_len,
	    (const uint8_t *)COMPOSITE_LABEL, sizeof(COMPOSITE_LABEL) - 1,
	    key->mldsa87_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	/* Verify ECDSA-P384 (SHA-384) */
	if ((esig = ECDSA_SIG_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	sig_r = sig_s = NULL; /* transferred */

	if ((derlen = i2d_ECDSA_SIG(esig, NULL)) <= 0) {
		derlen = 0;
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((sigb = calloc(1, derlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	if (i2d_ECDSA_SIG(esig, &cp) != derlen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((r = sshkey_pkey_digest_verify(key->pkey, SSH_DIGEST_SHA384,
	    m_prime, m_prime_len, sigb, derlen)) != 0)
		goto out;

	r = 0;
 out:
	free(m_prime);
	freezero(sigb, derlen);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	free(ktype);
	return r;
}

const struct sshkey_impl_funcs sshkey_mldsa87_p384_funcs = {
	/* .size = */		NULL,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_mldsa87_p384_cleanup,
	/* .equal = */		ssh_mldsa87_p384_equal,
	/* .ssh_serialize_public = */ ssh_mldsa87_p384_serialize_public,
	/* .ssh_deserialize_public = */ ssh_mldsa87_p384_deserialize_public,
	/* .ssh_serialize_private = */ ssh_mldsa87_p384_serialize_private,
	/* .ssh_deserialize_private = */ ssh_mldsa87_p384_deserialize_private,
	/* .generate = */	ssh_mldsa87_p384_generate,
	/* .copy_public = */	ssh_mldsa87_p384_copy_public,
	/* .sign = */		ssh_mldsa87_p384_sign,
	/* .verify = */		ssh_mldsa87_p384_verify,
};

const struct sshkey_impl sshkey_mldsa87_p384_impl = {
	/* .name = */		"ssh-mldsa87-p384",
	/* .shortname = */	"MLDSA87-P384",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_MLDSA87_P384,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	640, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa87_p384_funcs,
};

const struct sshkey_impl sshkey_mldsa87_p384_cert_impl = {
	/* .name = */		"ssh-mldsa87-p384-cert",
	/* .shortname = */	"MLDSA87-P384-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_MLDSA87_P384_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	640, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa87_p384_funcs,
};
#endif /* defined(USE_MLDSA) && defined(WITH_OPENSSL) */
