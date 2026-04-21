/* 	$OpenBSD$ */
/*
 * Regress test for MLDSA65-Ed25519 composite signature
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
#include "ssherr.h"
#include "sshkey.h"
#include "sshbuf.h"

static const char *composite_kat_pk =
    "9491ea15c863e26fa3c4ba30e00446cff560af06b486922b3cc813381c7a0e8b"
    "8f99d3b43fcf2e9c258c0ed1b864591102482191d5f3b0d4cda97ccdc2cfcfca"
    "90f8c3cea5f8a38607f0eb00931964afd8de7762e8ff8640f6ec3aeff2a1a1db"
    "89214f6f5839e0f07d1763f1b4d8f622f0f05e6c7ff7ac1e230a5ffc580acdb7"
    "b94ba000f3019f4be079e58574ffff8f976c4f3a21a3b3a7fe5e222bc22d5a2e"
    "c9b5b118d3d9952a9d71971b02b709b3850e74f2ade47865196b095bd3018b64"
    "92110c65b0fb34c2fa1e10fa2e9c9101f766f0329cbda4927a439d7f42883dd0"
    "4943475fe414b95cea16dd25334831e611af0ae01de3d31f157597480e31fda9"
    "71ab789a47e3caeecc2fcff944703628624bd8d9459264837919adb9c1317110"
    "4c27cce420b1f7fb14e119bb5951d23e41ac6924481db71948ddf1073816f99b"
    "dd68fedef9219ca9d57af8a4d449994e3249dcdbefd5a59fafb8bf0001471829"
    "09e7b20d33452916a60351c6d2a9b82899c29a127c5d8615daebe384ef67ace9"
    "4329bc12e873644cb42428ccccfb917763823d09b826922f4709ec78967a2037"
    "53d20da38bfa45228d93757cecd529a27a60b200f4864d03d40f70c33975af6d"
    "3ba770e03e6c26d7a6fe8d6c2b5911221904b6f45c7dd687ac6b8eadba292131"
    "fdc58841a76263b97976b9a6ff7a0516459b9200bd3a18bac07fd59d7adc5df1"
    "e830b259751877eac0fc4bb6064c18d9e70410aa312a537799b7e1d9fcc53253"
    "8600175d1eba758eca110ac7bddab5695e0c48a56ea6e02e602f9a1d090b712e"
    "0af3d840811ef698cd3fafb648a4d24cf4b7166549be5c704725731624a247d6"
    "9edea6026e2a294c75bbe0b3593cfabb8087ba3d00585c45f83fff6feb6018b1"
    "de2e39a41ff3fc54459b846d0c720509ca032870fe1fb996a304828467749045"
    "c82b29790505295d4f4e929f0f3c7ff2fb49c0aa249c462b089d8b3ea942d1d8"
    "05508705cb94fd8cc183b957c9a17d8bd97c081f0fa68526abde22940df16c3a"
    "b72e96364f4e870b7e085a3bb50bfbbe8f7664ee4fd6730001d2de8757fb0fb1"
    "9fbde26a04b45f2df6ebfa3249976c636e3b51fd515c1004456295a257259c0f"
    "4ea51ad8f47d4783259ad39870d465c39c58af0164ac2ceea9a8e85cd8c16e67"
    "e9298c96398d0956d4859e731616b55873c5d2509510598ac04b2b9e7fd0051c"
    "e446d67a908d97a382a62e65e3d4fc4d4d4325b672e15c588392a24eea01def6"
    "731ece04a9bdb957842707baf1037dd937c7cd15fc5e5250ef4243933c9f47f8"
    "77c0e50004df11472bd6a2d50711e098f3a7afbe78a1bd958020c50bc2e78c8b"
    "2cca141ada70f662f488017f437960a7dd649f4ff9075149b0a83a9f48b8f38a"
    "3c7c7c4595c3156f977f37da9062fbaa655d6a8e332bb358748c1212037c4c98"
    "a2ae667532bc95633943a4789df2b3e4531a39a67ebe025bfe7b14155bbf6155"
    "1bcdd88eb148f597d6fc5972e306dab4a4d74f2132bb2db83093be9791f20f56"
    "410093d591830d8e67d78f18380f0a960b2905692ee66df1f27e95313c3c4ebe"
    "ff33c9078d97bde63a7510caf31b1705d81fdb573690516b9d63ffaa1d8f559d"
    "6305c75a5bc85f4cb2786da97fb9fed79a9e6b9b7f4b6ef42955d5d13a40f983"
    "f7bee107bccaae9cb10c5e8458b5cfbc42418a1c6035320ee092d73b43066264"
    "3c5b733a8c9376bb507af33f5562c7b0676450f1aea83531ca53c142f4d77d88"
    "e3a01c34c9bca257edb7f99c562df2f52fb50ed7e9f53f53887bc373a26260c8"
    "93aa9a6a1d40764ddda8cc1f102649e3f520c8dcf439794c23cd047e0c216fa2"
    "50243552fb73e937555b8e00ef0fc2dde6710c7f25b55b6c4d9960bdb4dbc458"
    "8b93e2c3c2540c0376abe9c6fb45ddca1b64327a03531f31573acf6d0bcd9a1a"
    "59e4a962b5af4ef29f4de5891567eacd80f575f9fba578620d2ae54af0656c32"
    "13a2e0312b2a0ed02255ce196ce45bfe88329318389e770951690db2a5c2aecd"
    "38d2a6ab3794c2069559efdbd7ae3892749d9f20dca60d12e3d45edfedbde106"
    "b5d9f1ec8353db5601b22eea34a9d0529abf980641c51e24e996bea818a7c1a9"
    "faa3656302c275b208bc89b3296a8e76c746b81f9a9ba34d6220eddefba81681"
    "1df54b8bc35bdc2b31330988d7556696be0fc786985ddb4a9f1690f5e6ab0934"
    "6fdb8e095f0d0a5ef8b88e5fa8c16a7c0dd2d0dc91407d998df36a83733d4968"
    "e4eb695dae309166b1f23503a420d76e8bea55b4a5376323fffb316b43cd36ad"
    "c5b009bd3099ae1184550612ced253d9a2eb51c80e62b98e88e1fa5690cab676"
    "289a76e2246847339e3a1aa3b08e837d53dd60305e9bd8095f923c7eb0fb7233"
    "2525017263927510df9509cccb06c651660dd97957a505745240654511422508"
    "2b00e0d65db826d2ba3abe2596149c909dfb086b6353c4b0b047b4f42fd29d35"
    "c73fad6e50c81e09f2a16555088d933ad27c32c6ae005f734c5d37a4033fe3e1"
    "4beb2b26dfcae7962a2889f1dc269876a67c52ca90d8dba008ead042739727c5"
    "07ad85edab0213d46252999c0066a0f43cee7fe4e7df930c8abfca4f594c24ca"
    "a6c8ee35f2e2fc0e7accceb30e35e4c452a8af92ff6672f236964f7b0c034305"
    "72c2beafd3345fcf6718e51aef30c60f4fac9f9580ced1429e3ff3f08eb4499b"
    "aa86c6cd1413bf183aa8ff83af3dfe7e221422fb16c255b2c479373fcea02992"
    "42c814ea188183f83627b13c96303ae121c8dc1e1f1badfcc83ffbd5d8504fda";
    static const char *composite_kat_sk =
    "23a578205289555e65ddf567601cb4715fb593a7796a8f71d668c3bca876d937"
    "60e9741f5fb8a68b3c490b93e4aa0e5d82206ef3b8e2242e1bcf4729f2e146aa";

void mldsa_eddsa_tests(void);

static void
hex2bin(uint8_t *bin, const char *hex, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		sscanf(hex + i * 2, "%02hhx", &bin[i]);
}

void
mldsa_eddsa_tests(void)
{
	uint8_t pk[MLDSA65_ED25519_PK_SZ];
	uint8_t sk[MLDSA65_ED25519_SK_SZ];
	uint8_t sig[MLDSA65_ED25519_SIG_SZ];
	const uint8_t msg[] = "hello world";
	size_t msglen = sizeof(msg) - 1;
	const uint8_t ctx[] = "context";
	size_t ctxlen = sizeof(ctx) - 1;
	struct sshkey *k, *k2, *pk_key;
	u_char *sigblob, *keyblob;
	size_t siglen, keylen;

	TEST_START("MLDSA65-Ed25519-SHA512 raw self-consistency");
	ASSERT_INT_EQ(raw_mldsa65_ed25519_keygen(pk, sk), 0);
	ASSERT_INT_EQ(raw_mldsa65_ed25519_sign(sig, msg, msglen, ctx, ctxlen, sk), 0);
	ASSERT_INT_EQ(raw_mldsa65_ed25519_verify(sig, msg, msglen, ctx, ctxlen, pk), 0);
	TEST_DONE();

	TEST_START("MLDSA65-Ed25519-SHA512 raw KAT key expansion");
	uint8_t pk_expanded[MLDSA65_ED25519_PK_SZ];
	uint8_t sk_expanded[MLDSA65_ED25519_SK_SZ];
	uint8_t kat_sk[MLDSA65_ED25519_SK_SZ];
	uint8_t expected_pk[MLDSA65_ED25519_PK_SZ];

	hex2bin(kat_sk, composite_kat_sk, sizeof(kat_sk));
	hex2bin(expected_pk, composite_kat_pk, sizeof(expected_pk));

	ASSERT_INT_EQ(raw_mldsa65_ed25519_keygen_seeded(pk_expanded, sk_expanded,
	    kat_sk, kat_sk + 32), 0);
	ASSERT_MEM_EQ(pk_expanded, expected_pk, sizeof(pk_expanded));
	TEST_DONE();

	TEST_START("MLDSA65-Ed25519-SHA512 sshkey generate");
	ASSERT_INT_EQ(sshkey_generate(KEY_MLDSA65_ED25519, 0, &k), 0);
	ASSERT_PTR_NE(k, NULL);
	ASSERT_INT_EQ(k->type, KEY_MLDSA65_ED25519);
	TEST_DONE();

	TEST_START("MLDSA65-Ed25519-SHA512 sshkey equal");
	ASSERT_INT_EQ(sshkey_generate(KEY_MLDSA65_ED25519, 0, &k2), 0);
	ASSERT_INT_EQ(sshkey_equal(k, k), 1);
	ASSERT_INT_EQ(sshkey_equal(k, k2), 0);
	TEST_DONE();

	TEST_START("MLDSA65-Ed25519-SHA512 sshkey serialize/deserialize public");
	ASSERT_INT_EQ(sshkey_to_blob(k, &keyblob, &keylen), 0);
	ASSERT_INT_EQ(sshkey_from_blob(keyblob, keylen, &pk_key), 0);
	ASSERT_INT_EQ(sshkey_equal(k, pk_key), 1);
	free(keyblob);
	sshkey_free(pk_key);
	TEST_DONE();

	TEST_START("MLDSA65-Ed25519-SHA512 sshkey sign/verify");
	ASSERT_INT_EQ(sshkey_sign(k, &sigblob, &siglen, msg, msglen, NULL, NULL, NULL, 0), 0);
	ASSERT_INT_EQ(sshkey_verify(k, sigblob, siglen, msg, msglen, NULL, 0, NULL), 0);
	/* verify with wrong message */
	ASSERT_INT_EQ(sshkey_verify(k, sigblob, siglen, (const u_char *)"wrong", 5, NULL, 0, NULL), SSH_ERR_SIGNATURE_INVALID);
	free(sigblob);
	TEST_DONE();

	sshkey_free(k);
	sshkey_free(k2);
}
