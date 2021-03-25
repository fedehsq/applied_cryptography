#include <string>
#include <stdlib.h>
#include <stdio.h> 
#include <string.h> 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "error.h"

static const int BUF_SIZE = 512;
static const int BLOCK_SIZE = 16;

unsigned char *generate_iv(int iv_size);

void encrypt(FILE *f_in, FILE *f_out, 
   unsigned char *ciphertext, unsigned char *plaintext,
   unsigned char *key, unsigned char *iv);

void decrypt(FILE *f_in, FILE *f_out, 
   unsigned char *ciphertext, unsigned char *plaintext,
   unsigned char *key, unsigned char *iv);