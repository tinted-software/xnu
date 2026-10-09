/* Independently implemented kernel crypto memory utilities. */
#include <libkern/crypto/cc_abi.h>

void
cc_clear(size_t nbytes, void *memory)
{
	volatile unsigned char *p = memory;
	while (nbytes--) {
		*p++ = 0;
	}
}

int
cc_cmp_safe(size_t nbytes, const void *a, const void *b)
{
	const volatile unsigned char *pa = a;
	const volatile unsigned char *pb = b;
	unsigned int difference = 0;
	for (size_t i = 0; i < nbytes; i++) {
		difference |= pa[i] ^ pb[i];
	}
	return (int)((difference | (0u - difference)) >> (sizeof(difference) * 8 - 1));
}
