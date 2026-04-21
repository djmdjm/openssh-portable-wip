/* 	$OpenBSD$ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#include "includes.h"

void mldsa_tests(void);
void mlkem_tests(void);
void ed25519_tests(void);
void mldsa_eddsa_tests(void);

void
tests(void)
{
	mldsa_tests();
	mlkem_tests();
	ed25519_tests();
	mldsa_eddsa_tests();
}

void
benchmarks(void)
{
	/* none */
}
