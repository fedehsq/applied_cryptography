#include "aes_cbc.h"
#include "shared_key.h"
using namespace std;

int main() {
   FILE *f_in, *f_out;
   handle_null(f_in = fopen("file.txt", "rb"), "fopen");
   handle_null(f_out = fopen("file.txt.enc", "wb"), "fopen");
   // TEMPORARY ARRAY, IS NOT NECESSARY TO READ ENTIRE FILE! 
   unsigned char *plaintext;
   handle_null(plaintext = (unsigned char *)calloc(BUF_SIZE, sizeof(unsigned char)), "calloc");
   // TEMPORARY ARRAY, IS NOT NECESSARY TO READ ENTIRE FILE! 
   unsigned char *ciphertext;
   handle_null(ciphertext = (unsigned char *)calloc(BUF_SIZE + BLOCK_SIZE, sizeof(unsigned char)), "calloc");
   unsigned char *iv = generate_iv(BLOCK_SIZE);
   //BIO_dump_fp (stdout, (const char *)iv, strlen((const char *)iv));
   encrypt(f_in, f_out, ciphertext, plaintext, key, iv);
   puts("Encryption done!");
   memset(plaintext, 0, BUF_SIZE);
   free(plaintext);
   memset(iv, 0, BLOCK_SIZE);
   free(iv);
   memset(ciphertext, 0, BUF_SIZE + BLOCK_SIZE);
   free(ciphertext);
   fclose(f_in);
   fclose(f_out);
   return EXIT_SUCCESS;
}