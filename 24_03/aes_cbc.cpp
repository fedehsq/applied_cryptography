#include "aes_cbc.h"

unsigned char *generate_iv(int iv_size) {
   handle_negative_ssl((RAND_poll), "RAND_poll");
   // generate iv
   unsigned char *iv;
   handle_null(iv = (unsigned char *)calloc(iv_size, sizeof(unsigned char)), "calloc");
   handle_negative_ssl(RAND_bytes(iv, iv_size), "RAND_bytes");
   return iv;
}

void encrypt(FILE *f_in, FILE *f_out, 
   unsigned char *ciphertext, unsigned char *plaintext,
   unsigned char *key, unsigned char *iv) {
   // Create and initialise the context
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   handle_negative_ssl(EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv), "init")
   int read, written;
   // write iv to file
   handle_zero(fwrite(iv, 1, BLOCK_SIZE, f_out), "fwrite");
   // Store bytes read from file in plaintext
   for (read = fread(plaintext, 1, BUF_SIZE, f_in); read > 0; 
            read = fread(plaintext, 1, BUF_SIZE, f_in)) {
      // Encrypt that bytes 
      handle_negative_ssl(EVP_EncryptUpdate(ctx, ciphertext, &written, plaintext, read), "update");
      // Save ciphertext to file
      fwrite(ciphertext, 1, written, f_out);
   }
   // something go wrong, abort
   if (!feof(f_in)) {
      fprintf(stderr, "error on reading");
      exit (EXIT_FAILURE);
   }
   handle_negative_ssl(EVP_EncryptFinal(ctx, ciphertext, &written), "final");
   handle_zero(fwrite(ciphertext, 1, written, f_out), "fwrite");
   EVP_CIPHER_CTX_free(ctx);
}


void decrypt(FILE *f_in, FILE *f_out, 
   unsigned char *ciphertext, unsigned char *plaintext,
   unsigned char *key, unsigned char *iv) {
      // Create and initialise the context
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   // Encrypt init
   handle_negative_ssl(EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv), "init")
   int read, written;
   // Store bytes read from file in ciphertext
   for (read = fread(ciphertext, 1, BUF_SIZE, f_in); read > 0; 
            read = fread(ciphertext, 1, BUF_SIZE, f_in)) {
      // Encrypt that bytes 
      handle_negative_ssl(EVP_DecryptUpdate(ctx, plaintext, &written, ciphertext, read), "update");
      // Save ciphertext to file
      fwrite(plaintext, 1, written, f_out);
   }
   // something go wrong, abort
   if (!feof(f_in)) {
      fprintf(stderr, "error on reading");
      exit (EXIT_FAILURE);
   }
   handle_negative_ssl(EVP_DecryptFinal(ctx, plaintext, &written), "final");
   handle_zero(fwrite(plaintext, 1, written, f_out), "fwrite");
   EVP_CIPHER_CTX_free(ctx);
}
