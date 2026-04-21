/* 	$OpenBSD$ */
/*
 * Regress test for ML-DSA
 *
 * Placed in the public domain
 */

#include "includes.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../test_helper/test_helper.h"
#include "libcrux-mlkem-mldsa.h"
#include "crypto_api.h"

struct mldsa65_kat {
	const char *seed;
	const char *pk_hash;
	const char *sk_hash;
	const char *msg;
	const char *rand;
	const char *sig_hash;
};

static const struct mldsa65_kat mldsa65_kats[] = {
	{
		"7c9935a0b07694aa0c6d10e4db6b1add2fd81a25"
		"ccb148032dcd739936737f2d",
		"67099a6aed1ca9dd645a73261cead798ba29e4a1"
		"5ede3a469ad4cb620b0296be",
		"bf3a87a7854f5734d73f9130d76ab6d25f9677c3"
		"0e2398a1268507997d0bd1dc",
		"d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957"
		"e835ad55b22e75bf57bb556ac8",
		"8626ed79d451140800e03b59b956f8210e556067"
		"407d13dc90fa9e8b872bfb8f",
		"190a7e1432955924b6fede77eddf4d6cd9eab49a"
		"7d254cd8bca8b7d6fd8d7ac6"
	},
	{
		"4b622de1350119c45a9f2e2ef3dc5df50a759d13"
		"8cdfbd64c81cc7cc2f513345",
		"114dbfea406d98227a7e962050ed302be8b3be65"
		"e246416cc15465e07bcc39cf",
		"d64d4b4d0e55508a5520ad2ad9453da553dd2c31"
		"652574fd1981790df01e9547",
		"225d5ce2ceac61930a07503fb59f7c2f936a3e07"
		"5481da3ca299a80f8c5df922"
		"3a073e7b90e02ebf98ca2227eba38c1ab2568209"
		"e46dba961869c6f83983b17dcd49",
		"e82fcc97ca60ccb27bf6938c975658aeb8b4d37c"
		"ffbde25d97e561f36c219ade",
		"e1fa1f379451b6acae60c25c5e0a56254ee8e3ed"
		"3e6040b0d1f782fb0a547d34"
	},
	{
		"1d836e889e46259bcd1ccd2b369583c5b47cfbb9"
		"19ec2b72c280247cb15a5569",
		"dcad3c37aa5fa8c3b7d2ff78d98c7bcdbd9c7a44"
		"091f28a5e85bda9831279856",
		"dc0800502b0fb99a53414637e7c64b5b87413a7e"
		"2abaaf4dfaf8998cee95a68b",
		"2b8c4b0f29363eaee469a7e33524538aa066ae98"
		"980eaa19d1f10593203da214"
		"3b9e9e1973f7ff0e6c6aaa3c0b900e50d003412e"
		"fe96deece3046d8c46bc7709"
		"228789775abdf56aed6416c90033780cb7a49848"
		"15da1b14660dcf34aa34bf82cebbcf",
		"f333d36590910e7a5a6cbe567bcdd154137eef62"
		"b92bf8dc1fdc900e7c194e5f",
		"a78eb70c8cd092f86fc98d7ffb80fdfd2ecacf2f"
		"80aa17c8da452173d5d29cce"
	},
	{
		"539577cb7f2088fbedff1b53f235d607321857db"
		"32bba645f8df3a89dd426552",
		"2737f34481756da4e5ac813117a68d8d3cc70560"
		"0df3d8e1cecab3554ec5bee8",
		"a90a7c5420121a3ea1012d9535ddb2499bb71853"
		"0d77963bca350e6a438fd64d",
		"2f7af5b52a046471efcd720c9384919be05a61cd"
		"e8e8b01251c5ab885e820fd3"
		"6ed9ff6fdf45783ec81a86728cbb74b426adff96"
		"123c08fac2bc6c58a9c0dd71"
		"761292262c65f20df47751f0831770a6bb7b3760"
		"bb7f5efffb6e11ac35f353a6"
		"f24400b80b287834e92c9cf0d3c949d6dca31b0b"
		"94e0e3312e8bd02174b170c2ca9355fe",
		"f52a43f5358999ddbe311866dedcf629fbd5ae94"
		"919abde9fdebdaf93bb0c847",
		"f644f588237fce0d20aacf7147eb4d6e36eee0da"
		"44b79ad279e1e67265e07fa0"
	},
	{
		"2ca59c6cf33c53803749f69ef5abfa9482fcee7e"
		"fd87fbf17135ecc3ff3fd7f7",
		"02c5c3af108fefbe00d706bef947cc8550e6af31"
		"de2f38b7c30d11d0c468ff3f",
		"1dfdd366de63ad9b4dccbbe5df4c8826c3e47abe"
		"e46fe08b2ecd87dda60d65b7",
		"1cdf0ae1124780a8ff00318f779a3b86b3504d05"
		"9ca7ab3fe4d6eae9fd46428d"
		"1dabb704c0735a8fe8708f409741017b723d9a30"
		"4e54fdc5789a7b0748c2464b"
		"7308ac9665115644c569ae253d5205751342574c"
		"03346dddc1950a6273546616"
		"b96d0c5ece0a044af0edefbe445f9ae37da5afb8"
		"d22a56d9fd1801425a0a276f"
		"48431d7af039521e549551481391fe5f4ebfb764"
		"4d9f9782d83a95137e84ea3aeb3c2f8099",
		"a685acf5e2640f2d085efd1c9cebe815e042482a"
		"79694c32e28e97fad3bef590",
		"841ad87bff6ab73ddd2460bd453d60a809054cbf"
		"3a0764f1fccdb2991c0b13ee"
	}
};

void mldsa_tests(void);

static void
hex2bin(uint8_t *bin, const char *hex, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		sscanf(hex + i * 2, "%02hhx", &bin[i]);
}

void
mldsa_tests(void)
{
	uint8_t pk[MLDSA65_PUBLICKEYBYTES];
	uint8_t sk[MLDSA65_SECRETKEYBYTES];
	uint8_t sig[MLDSA65_SIGBYTES];
	uint8_t pk_hash[32], sk_hash[32], sig_hash[32];
	uint8_t expected_pk_hash[32], expected_sk_hash[32], expected_sig_hash[32];
	uint8_t seed[32], rand[32];
	uint8_t *msg;
	size_t i, msglen;

	TEST_START("ML-DSA 65 KATs");
	for (i = 0; i < sizeof(mldsa65_kats) / sizeof(mldsa65_kats[0]); i++) {
		test_subtest_info("vector %zu", i);

		hex2bin(seed, mldsa65_kats[i].seed, 32);
		hex2bin(expected_pk_hash, mldsa65_kats[i].pk_hash, 32);
		hex2bin(expected_sk_hash, mldsa65_kats[i].sk_hash, 32);

		/* Keypair generation */
		ASSERT_INT_EQ(mldsa65_keypair_seeded(pk, sk, seed), 0);

		sha3_256(pk_hash, pk, sizeof(pk));
		sha3_256(sk_hash, sk, sizeof(sk));

		ASSERT_MEM_EQ(pk_hash, expected_pk_hash, 32);
		ASSERT_MEM_EQ(sk_hash, expected_sk_hash, 32);

		msglen = strlen(mldsa65_kats[i].msg) / 2;
		msg = malloc(msglen);
		hex2bin(msg, mldsa65_kats[i].msg, msglen);
		hex2bin(rand, mldsa65_kats[i].rand, 32);
		hex2bin(expected_sig_hash, mldsa65_kats[i].sig_hash, 32);

		/* Signing */
		ASSERT_INT_EQ(mldsa65_sign_seeded(sig, msg,
		    msglen, NULL, 0, sk, rand), 0);

		sha3_256(sig_hash, sig, sizeof(sig));
		ASSERT_MEM_EQ(sig_hash, expected_sig_hash, 32);

		/* Verification */
		ASSERT_INT_EQ(mldsa65_verify(sig, msg,
		    msglen, NULL, 0, pk), 0);
		free(msg);
	}
	TEST_DONE();
}
