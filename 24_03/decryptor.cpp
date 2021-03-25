#include "aes_cbc.h"
#include "shared_key.h"

using namespace std;

int main() {
   FILE *f_in, *f_out;
   handle_null(f_in = fopen("file.txt.enc", "rb"), "fopen");
   handle_null(f_out = fopen("file.txt.enc.dec", "wb"), "fopen");
   unsigned char *plaintext;
   // TEMPORARY ARRAY, IS NOT NECESSARY TO READ ENTIRE FILE! 
   handle_null(plaintext = (unsigned char *)calloc(BUF_SIZE + BLOCK_SIZE, sizeof(unsigned char)), "calloc");
   // TEMPORARY ARRAY, IS NOT NECESSARY TO READ ENTIRE FILE! 
   unsigned char *ciphertext;
   handle_null(ciphertext = (unsigned char *)calloc(BUF_SIZE + BLOCK_SIZE, sizeof(unsigned char)), "calloc");
   unsigned char *iv;
   handle_null(iv = (unsigned char *)calloc(BLOCK_SIZE, sizeof(unsigned char)), "calloc");
   // read iv (keeeping)
   handle_zero(fread(iv, 1, BLOCK_SIZE, f_in), "fread");
   //BIO_dump_fp (stdout, (const char *)iv, strlen((const char *)iv));
   decrypt(f_in, f_out, ciphertext, plaintext, key, iv);
   puts("Decryption done!");
   // before deallocating, refresh the memory!
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