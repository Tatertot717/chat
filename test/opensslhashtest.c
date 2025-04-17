#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

int main() {
	const char *password = "my_password";
	const unsigned char *salt = (unsigned char *)"random_salt";
	int iterations = 100000;
	int keylen = 32;
	unsigned char hash[32];

	if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, strlen((char *)salt),
						  iterations, EVP_sha256(), keylen, hash) != 1) {
		fprintf(stderr, "Error during PBKDF2\n");
		return 1;
						  }

	printf("Derived key: ");
	for (int i = 0; i < keylen; i++)
		printf("%02x", hash[i]);
	printf("\n");

	return 0;
}
