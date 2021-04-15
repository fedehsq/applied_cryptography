#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
typedef unsigned char* bytes;
typedef unsigned char byte;
using namespace std; 

const int PADDING = 16;

int main() {

    /* 
    first thing to read is encrypted symmetric key, which size is
    equals to size of private key
    */
   
    /* open private key file */
    FILE* fp_private_key = fopen("private_key.pem", "r");
    if (!fp_private_key) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    /* read private key from file */
    EVP_PKEY* private_key = PEM_read_PrivateKey(fp_private_key, NULL, NULL, NULL);
    if (!private_key) {
        cout << "reading private key";
        ERR_print_errors_fp(stderr);
        fclose(fp_private_key);
        exit(EXIT_FAILURE);
    }

    /* close private key file */
    fclose(fp_private_key);

    /* iv len depends of cypher type */
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

    /* allocate buffer where to store iv taken from file */
    bytes iv = (bytes) calloc(iv_len + 1, sizeof(byte));
    if (!iv) {
        EVP_PKEY_free(private_key);
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    /* encrypted_symmetric_key_size depends of private key size */
    int encrypted_symmetric_key_size = EVP_PKEY_size(private_key);

    /* allocate buffer where to store encrypted_symmetric_key
    taken from file */
    bytes encrypted_symmetric_key = 
    (bytes) calloc(encrypted_symmetric_key_size + 1, sizeof(byte));
    if (!encrypted_symmetric_key) {
        EVP_PKEY_free(private_key);
        free(iv);
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    /* open ciphertext file */
    FILE* fp_input = fopen("encr.txt", "rb");
    if (!fp_input) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    /* read encrypted symmetric key from file */
    int read = fread(encrypted_symmetric_key, 1,
     encrypted_symmetric_key_size,  fp_input);
    if (!read){
        fclose(fp_input);
        EVP_PKEY_free(private_key);
        free(iv);
        free(encrypted_symmetric_key);
        perror("fread 91");
        exit(EXIT_FAILURE);
    }

    /* read iv from file */
    read = fread(iv, 1, iv_len, fp_input);
    if (!read){
        fclose(fp_input);
        EVP_PKEY_free(private_key);
        free(iv);
        perror("fread 78");
        exit(EXIT_FAILURE);
    }



    /* 
    NOW I HAVE THE FP ON FIRST BYTE OF CIPHERTEXT,
    move fp from this point to end of file 
    */
    /* get the position of fp */
    int fp_cipher_start_position = ftell(fp_input);
    if (fp_cipher_start_position == -1) {
        fclose(fp_input);
        EVP_PKEY_free(private_key);
        free(iv);
        free(encrypted_symmetric_key);
        perror("ftell");
        exit(EXIT_FAILURE);
    }
    
    /* move fp to the end to compute ct len */
    if (fseek(fp_input, SEEK_CUR, SEEK_END) == -1) {
        fclose(fp_input);
        EVP_PKEY_free(private_key);
        free(iv);
        free(encrypted_symmetric_key);
        perror("fseek");
        exit(EXIT_FAILURE);
    }

    /* get the position of fp */
    int fp_cipher_end_position = ftell(fp_input);

    if (fp_cipher_end_position == -1) {
        fclose(fp_input);
        EVP_PKEY_free(private_key);
        free(iv);
        free(encrypted_symmetric_key);
        perror("ftell");
        exit(EXIT_FAILURE);
    }

    /* compute ciphertext len */
    int ciphertext_len = fp_cipher_end_position - fp_cipher_start_position - 1;

    /* allocate space for ct */
    bytes ciphertext = (bytes)calloc(ciphertext_len + 1, sizeof(byte));
    if (!ciphertext_len) {
        fclose(fp_input);
        EVP_PKEY_free(private_key);
        free(iv);
        free(encrypted_symmetric_key);
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    /* move file pointer to 1st ct byte */
    if (fseek(fp_input, fp_cipher_start_position, SEEK_SET) == -1) {
        fclose(fp_input);
        EVP_PKEY_free(private_key);
        free(iv);
        free(ciphertext);
        free(encrypted_symmetric_key);
        perror("fseek");
        exit(EXIT_FAILURE);
    }
    
    /* save into buffer all bytes of ct from file */
    read = fread(ciphertext, 1, ciphertext_len, fp_input);
    if (!read){
        fclose(fp_input);
        EVP_PKEY_free(private_key);
        free(iv);
        free(ciphertext);
        free(encrypted_symmetric_key);
        perror("fread 165");
        exit(EXIT_FAILURE);
    }

    /* close input file */
    fclose(fp_input);

    /* allocate buffer where to store plaintext
    generated by open_update (max size == ct size)*/
    char* plaintext = (char*) calloc(ciphertext_len, sizeof(char));
    if (!plaintext) {
        EVP_PKEY_free(private_key);
        free(iv);
        free(ciphertext);
        free(encrypted_symmetric_key);
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    /* allocate the cipher context */
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (!context) {
        EVP_PKEY_free(private_key);
        free(iv);
        free(ciphertext);
        free(encrypted_symmetric_key);
        free(plaintext);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }


    /* decrypt symmetric key and iv using private key */
    int ret = EVP_OpenInit(context, EVP_aes_128_cbc(), 
     encrypted_symmetric_key, encrypted_symmetric_key_size, iv,
     private_key); 

    if (!ret){
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(private_key);
        free(iv);
        free(encrypted_symmetric_key);
        free(ciphertext);
        free(plaintext);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    /* real bytes written from open update */
    int written;
    /* len of ciphertext given from open update */
    int plaintext_len;

    /* decrypt ct */
    ret = EVP_OpenUpdate(context, (bytes)plaintext, &written, 
     ciphertext, ciphertext_len);
    if (!ret){
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(private_key);
        free(iv);
        free(plaintext);
        free(encrypted_symmetric_key);
        free(ciphertext);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    plaintext_len = written;

    /* finalize decruption, remove padding */
    ret = EVP_OpenFinal(context, (bytes)&plaintext[written], &written);
    if (!ret){
        EVP_PKEY_free(private_key);
        free(iv);
        free(plaintext);
        free(encrypted_symmetric_key);
        free(ciphertext);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    /* update len */
    plaintext_len += written;

    /* clean private key */
    EVP_PKEY_free(private_key);

    /* clean cipher context */
    EVP_CIPHER_CTX_free(context);

    /* not needed anymore */
    free(iv);
    free(encrypted_symmetric_key);
    free(ciphertext);

    /* open output file */
    FILE* fp_decrypted = fopen("decr.txt", "w");
    if (!fp_decrypted){
        free(plaintext);
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    /* write encrypted symmetric key to file */
    written = fwrite(plaintext, 1, plaintext_len, fp_decrypted);
    if (!written) {
        free(plaintext);
        perror("fwrite");
        exit(EXIT_FAILURE);
    }

    /* destroy pt */
    free(plaintext);
}