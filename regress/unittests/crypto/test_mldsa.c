/* 	$OpenBSD: test_mldsa.c,v 1.4 2026/06/22 12:28:48 dtucker Exp $ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#include "includes.h"

#ifdef USE_MLDSA

#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../test_helper/test_helper.h"
#include "crypto_api.h"
#include "xmalloc.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "sshkey.h"

/* in tests.c */
struct sshbuf *load_text_file(const char *name);
char *get_json_string(struct sshbuf *content, const char *key, int consume);

void mldsa_tests(void);

struct kat {
	char *seed;
	char *pk_hash;
	char *sk_hash;
	char *msg;
	char *rand;
	char *sig_hash;
};

static void
load_kats(const char *file, struct kat ***katsp, size_t *nkatsp)
{
	struct sshbuf *json_buf;
	struct kat *kat = NULL, **kats = NULL;
	size_t nkats = 0;

	json_buf = load_text_file(file);
	while (sshbuf_find(json_buf, 0, "key_generation_seed",
	    strlen("key_generation_seed"), NULL) == 0) {
		kat = xcalloc(1, sizeof(*kat));
		kat->seed = get_json_string(json_buf, "key_generation_seed", 1);
		kat->pk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_verification_key", 1);
		kat->sk_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signing_key", 1);
		kat->msg = get_json_string(json_buf, "message", 1);
		kat->rand = get_json_string(json_buf, "signing_randomness", 1);
		kat->sig_hash = get_json_string(json_buf,
		    "sha3_256_hash_of_signature", 1);
		kats = xrecallocarray(kats, nkats, nkats + 1, sizeof(*kats));
		kats[nkats++] = kat;
	}
	*katsp = kats;
	*nkatsp = nkats;
	sshbuf_free(json_buf);
}

static void
free_kats(struct kat **kats, size_t nkats)
{
	size_t i;
	struct kat *kat;

	for (i = 0; i < nkats; i++) {
		kat = kats[i];
		free(kat->seed);
		free(kat->pk_hash);
		free(kat->sk_hash);
		free(kat->msg);
		free(kat->rand);
		free(kat->sig_hash);
		free(kat);
	}
	free(kats);
}

static void
composite_m_prime_test(void)
{
	static const uint8_t kat1_expected[127] = {
		/* "CompositeAlgorithmSignatures2025" (32) */
		'C', 'o', 'm', 'p', 'o', 's', 'i', 't',
		'e', 'A', 'l', 'g', 'o', 'r', 'i', 't',
		'h', 'm', 'S', 'i', 'g', 'n', 'a', 't',
		'u', 'r', 'e', 's', '2', '0', '2', '5',
		/* "COMPSIG-MLDSA44-Ed25519-SHA512" (30) */
		'C', 'O', 'M', 'P', 'S', 'I', 'G', '-',
		'M', 'L', 'D', 'S', 'A', '4', '4', '-',
		'E', 'd', '2', '5', '5', '1', '9', '-',
		'S', 'H', 'A', '5', '1', '2',
		/* len(ctx) = 0 (1) */
		0x00,
		/* SHA512("abc") (64) */
		0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
		0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
		0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
		0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
		0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
		0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
		0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
		0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
	};
	static const uint8_t kat2_expected[137] = {
		/* "CompositeAlgorithmSignatures2025" (32) */
		'C', 'o', 'm', 'p', 'o', 's', 'i', 't',
		'e', 'A', 'l', 'g', 'o', 'r', 'i', 't',
		'h', 'm', 'S', 'i', 'g', 'n', 'a', 't',
		'u', 'r', 'e', 's', '2', '0', '2', '5',
		/* "COMPSIG-MLDSA87-ECDSA-P384-SHA512" (33) */
		'C', 'O', 'M', 'P', 'S', 'I', 'G', '-',
		'M', 'L', 'D', 'S', 'A', '8', '7', '-',
		'E', 'C', 'D', 'S', 'A', '-', 'P', '3',
		'8', '4', '-', 'S', 'H', 'A', '5', '1', '2',
		/* len(ctx) = 7, "testctx" (8) */
		0x07, 't', 'e', 's', 't', 'c', 't', 'x',
		/* SHA512("") (64) */
		0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
		0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
		0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
		0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
		0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
		0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
		0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
		0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
	};
	uint8_t *m_prime = NULL;
	size_t m_prime_len = 0;
	uint8_t maxctx[255], overctx[256];

	TEST_START("ssh_mldsa_composite_m_prime");
	ASSERT_INT_EQ(ssh_mldsa_composite_m_prime(&m_prime, &m_prime_len,
	    "COMPSIG-MLDSA44-Ed25519-SHA512", (const uint8_t *)"abc", 3,
	    NULL, 0), 0);
	ASSERT_SIZE_T_EQ(m_prime_len, sizeof(kat1_expected));
	ASSERT_MEM_EQ(m_prime, kat1_expected, sizeof(kat1_expected));
	free(m_prime);

	ASSERT_INT_EQ(ssh_mldsa_composite_m_prime(&m_prime, &m_prime_len,
	    "COMPSIG-MLDSA87-ECDSA-P384-SHA512", NULL, 0,
	    (const uint8_t *)"testctx", 7), 0);
	ASSERT_SIZE_T_EQ(m_prime_len, sizeof(kat2_expected));
	ASSERT_MEM_EQ(m_prime, kat2_expected, sizeof(kat2_expected));
	free(m_prime);

	memset(maxctx, 0xa5, sizeof(maxctx));
	ASSERT_INT_EQ(ssh_mldsa_composite_m_prime(&m_prime, &m_prime_len,
	    "COMPSIG-MLDSA87-ECDSA-P384-SHA512", (const uint8_t *)"abc", 3,
	    maxctx, sizeof(maxctx)), 0);
	ASSERT_SIZE_T_EQ(m_prime_len, 32 + 33 + 1 + 255 + 64);
	ASSERT_U8_EQ(m_prime[65], 255);
	ASSERT_MEM_EQ(m_prime + 66, maxctx, 255);
	ASSERT_MEM_EQ(m_prime + 66 + 255, kat1_expected + 63, 64);
	free(m_prime);
	m_prime = NULL;

	memset(overctx, 0xa5, sizeof(overctx));
	ASSERT_INT_EQ(ssh_mldsa_composite_m_prime(&m_prime, &m_prime_len,
	    "COMPSIG-MLDSA87-ECDSA-P384-SHA512", (const uint8_t *)"abc", 3,
	    overctx, sizeof(overctx)), SSH_ERR_INVALID_ARGUMENT);
	ASSERT_PTR_EQ(m_prime, NULL);
	ASSERT_SIZE_T_EQ(m_prime_len, 0);

	ASSERT_INT_EQ(ssh_mldsa_composite_m_prime(&m_prime, &m_prime_len,
	    NULL, (const uint8_t *)"abc", 3, NULL, 0),
	    SSH_ERR_INVALID_ARGUMENT);
	ASSERT_PTR_EQ(m_prime, NULL);
	ASSERT_SIZE_T_EQ(m_prime_len, 0);

	ASSERT_INT_EQ(ssh_mldsa_composite_m_prime(&m_prime, &m_prime_len,
	    "", (const uint8_t *)"abc", 3, NULL, 0),
	    SSH_ERR_INVALID_ARGUMENT);
	ASSERT_PTR_EQ(m_prime, NULL);
	ASSERT_SIZE_T_EQ(m_prime_len, 0);

	ASSERT_INT_EQ(ssh_mldsa_composite_m_prime(&m_prime, &m_prime_len,
	    "COMPSIG-MLDSA87-ECDSA-P384-SHA512", (const uint8_t *)"abc", 3,
	    NULL, 1), SSH_ERR_INVALID_ARGUMENT);
	ASSERT_PTR_EQ(m_prime, NULL);
	ASSERT_SIZE_T_EQ(m_prime_len, 0);

	ASSERT_INT_EQ(ssh_mldsa_composite_m_prime(&m_prime, &m_prime_len,
	    "COMPSIG-MLDSA87-ECDSA-P384-SHA512", NULL, 1, NULL, 0),
	    SSH_ERR_INVALID_ARGUMENT);
	ASSERT_PTR_EQ(m_prime, NULL);
	ASSERT_SIZE_T_EQ(m_prime_len, 0);
	TEST_DONE();
}

static void
mldsa87_roundtrip_test(void)
{
	uint8_t pk[MLDSA87_PUBLICKEYBYTES];
	uint8_t sk[MLDSA87_SECRETKEYBYTES];
	uint8_t sig[MLDSA87_SIGBYTES];
	const uint8_t msg[] = "ML-DSA-87 composite test message";
	const uint8_t ctx[] = "COMPSIG-MLDSA87-ECDSA-P384-SHA512";

	TEST_START("ML-DSA 87 round-trip");
	ASSERT_INT_EQ(crypto_sign_mldsa87_keypair(pk, sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa87(sig, msg, sizeof(msg) - 1,
	    ctx, sizeof(ctx) - 1, sk), 0);
	ASSERT_INT_EQ(crypto_sign_mldsa87_verify(sig, msg, sizeof(msg) - 1,
	    ctx, sizeof(ctx) - 1, pk), 0);
	sig[0] ^= 0x01;
	ASSERT_INT_EQ(crypto_sign_mldsa87_verify(sig, msg, sizeof(msg) - 1,
	    ctx, sizeof(ctx) - 1, pk), -1);
	explicit_bzero(sk, sizeof(sk));
	TEST_DONE();
}

void
mldsa_tests(void)
{
	uint8_t pk[MLDSA44_PUBLICKEYBYTES];
	uint8_t sk[MLDSA44_SECRETKEYBYTES];
	uint8_t sig[MLDSA44_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32];
	uint8_t expected_sig_hash[32];
	uint8_t seed[32], rand[32];
	uint8_t *msg;
	size_t nkats, i, msglen;
	struct kat **kats, *kat;

	TEST_START("ML-DSA 44 KATs");
	load_kats("nistkats-44.json", &kats, &nkats);
	for (i = 0; i < nkats; i++) {
		kat = kats[i];
		test_subtest_info("vector %zu", i);

		hex2bin(seed, kat->seed, 32);
		hex2bin(expected_pk_hash, kat->pk_hash, 32);
		hex2bin(expected_sk_hash, kat->sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(crypto_sign_mldsa44_keypair_seeded(pk,
		    sk, seed), 0);

		sha3_256(pk_hash, pk, sizeof(pk));
		sha3_256(sk_hash, sk, sizeof(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = strlen(kat->msg) / 2;
		ASSERT_PTR_NE(msg = malloc(msglen), NULL);
		hex2bin(msg, kat->msg, msglen);
		hex2bin(rand, kat->rand, 32);
		hex2bin(expected_sig_hash, kat->sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(crypto_sign_mldsa44_seeded(sig, msg,
		    msglen, NULL, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, sizeof(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(crypto_sign_mldsa44_verify(sig, msg,
		    msglen, NULL, 0, pk), 0);
		free(msg);
	}
	free_kats(kats, nkats);
	TEST_DONE();

	mldsa87_roundtrip_test();
	composite_m_prime_test();
}
#endif /* USE_MLDSA */
