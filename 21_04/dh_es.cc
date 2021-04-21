#include <stdio.h>
#include <string.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

static DH *get_dh2048(void) {
    static unsigned char dhp_2048[] = {
        0x95, 0x8C, 0x60, 0x2D, 0x83, 0xDA, 0x2B, 0xB2, 0xEE, 0x97,
        0xA0, 0x91, 0xCA, 0x74, 0x5F, 0x51, 0x0A, 0x3D, 0xF4, 0xD5,
        0x0E, 0xED, 0x11, 0xC3, 0x09, 0x96, 0x2B, 0x38, 0x6B, 0xC4,
        0x40, 0xEA, 0xE6, 0x28, 0xC5, 0x8F, 0x89, 0xF2, 0xF6, 0xA5,
        0x12, 0x2C, 0x0A, 0xC1, 0x5B, 0xAE, 0x53, 0x9A, 0x86, 0xBE,
        0xA4, 0x2D, 0xBA, 0x3F, 0xA5, 0x3F, 0xDD, 0x64, 0x32, 0x64,
        0x7E, 0x52, 0xD7, 0x60, 0xF3, 0x33, 0xD0, 0x88, 0x87, 0x7A,
        0x2B, 0xC5, 0xCD, 0x9A, 0x65, 0x76, 0x0E, 0x5E, 0x76, 0x28,
        0x1F, 0xC7, 0x0C, 0x95, 0xC3, 0x62, 0x0D, 0xCA, 0xF6, 0x85,
        0xDC, 0x7E, 0x3C, 0xDA, 0x1E, 0xB2, 0x86, 0x70, 0xB7, 0xD5,
        0xBE, 0x7E, 0x38, 0x5B, 0x1C, 0x4F, 0x8D, 0x6E, 0x96, 0x73,
        0xDA, 0x3F, 0x18, 0x89, 0x3E, 0xB5, 0x97, 0xD4, 0xF3, 0x74,
        0xA5, 0x5E, 0x84, 0xCC, 0x9A, 0xE3, 0x52, 0x7B, 0x50, 0xB6,
        0x4F, 0x3A, 0x24, 0x40, 0x23, 0x2F, 0xC7, 0x1B, 0xA4, 0x71,
        0x84, 0xE1, 0xFF, 0xAF, 0xAE, 0x5E, 0xDD, 0x4E, 0x17, 0x68,
        0x2B, 0x03, 0x15, 0xE5, 0x26, 0x67, 0x5E, 0x5E, 0xED, 0xD7,
        0xA8, 0x8E, 0xE0, 0xE5, 0xCC, 0xF3, 0x45, 0xC2, 0xD0, 0x47,
        0x88, 0x54, 0xDD, 0x25, 0xDC, 0xFE, 0x10, 0x64, 0x27, 0x73,
        0x21, 0x4F, 0x7D, 0x16, 0x71, 0xE7, 0x9C, 0xE0, 0xB4, 0x61,
        0x13, 0x8C, 0xA9, 0x75, 0x91, 0x32, 0xD4, 0x87, 0x67, 0xD2,
        0x3B, 0xF6, 0x0E, 0x92, 0xAD, 0x12, 0x1F, 0x9B, 0x39, 0xC6,
        0x8D, 0x50, 0x1F, 0xDF, 0x30, 0x1E, 0xA7, 0xCF, 0x5F, 0x89,
        0x81, 0x53, 0xD0, 0xF2, 0x66, 0x20, 0xA6, 0x3C, 0x79, 0xAD,
        0x9F, 0xB1, 0x7B, 0x8F, 0xBF, 0x4A, 0x9A, 0xCA, 0xB4, 0x80,
        0x3E, 0xF5, 0xEF, 0x7D, 0x08, 0x0F, 0xE3, 0xFF, 0xAC, 0x7E,
        0xAF, 0x64, 0x6E, 0x31, 0x3A, 0xF3
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}

class ByteMessage {
    unsigned char *message;
    size_t len;
public:
    ByteMessage(unsigned char *message, size_t len) {
        this -> message = 
            (unsigned char *)calloc(len + 1, sizeof(unsigned char));
        this -> len = len;
        for (size_t i = 0; i < len; i++) {
            this -> message[i] = message[i];
        }
    }

    ByteMessage(size_t len) {
        this -> message = 
            (unsigned char *)calloc(len + 1, sizeof(unsigned char));
        this -> len = len;
    }

    // Shallow copy
    unsigned char *getByteMessage() {
        return this -> message;
    }

    size_t getLen() {
        return this -> len;
    }

    void setLen(size_t len) {
        this -> len = len;
    }

    ~ByteMessage() {
        free(this -> message);
    }
};

// Encrypt a plaintext and return ciphertext
ByteMessage *encrypt(ByteMessage *plaintext, ByteMessage *key) {

    ByteMessage *ciphertext = new ByteMessage(
        plaintext -> getLen() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    int written;
    if (!ciphertext) {
        delete plaintext;
        delete key;
        std::cerr << strerror(errno);
    }

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context) {
        delete plaintext;
        delete ciphertext;
        delete key;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!EVP_EncryptInit(context, EVP_aes_128_cbc(), key -> getByteMessage(), NULL)) {
        delete plaintext;
        delete ciphertext;
        delete key;
        EVP_CIPHER_CTX_free(context);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!EVP_EncryptUpdate(context, ciphertext -> getByteMessage(), &written, 
        plaintext -> getByteMessage(), plaintext -> getLen())) {
        delete plaintext;
        delete ciphertext;
        delete key;       
        EVP_CIPHER_CTX_free(context);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    ciphertext -> setLen(written);

    if (!EVP_EncryptFinal(context, ciphertext -> getByteMessage() + written, &written)) {
        delete plaintext;
        delete ciphertext;
        delete key;       
        EVP_CIPHER_CTX_free(context);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    ciphertext -> setLen(ciphertext -> getLen()+ written);
    EVP_CIPHER_CTX_free(context);

    return ciphertext;

}


// Decrypt a ciphertext and return decrypted
ByteMessage *decrypt(ByteMessage *ciphertext, ByteMessage *key) {

    ByteMessage *decrypted = new ByteMessage(ciphertext -> getLen());
    int written;
    if (!decrypted) {
        delete ciphertext;
        delete key;
        std::cerr << strerror(errno);
    }

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context) {
        delete ciphertext;
        delete decrypted;
        delete key;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!EVP_DecryptInit(context, EVP_aes_128_cbc(), key -> getByteMessage(), NULL)) {
        delete ciphertext;
        delete decrypted;
        delete key;
        EVP_CIPHER_CTX_free(context);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!EVP_DecryptUpdate(context, decrypted -> getByteMessage(), &written, 
        ciphertext -> getByteMessage(), ciphertext -> getLen())) {
        delete ciphertext;
        delete decrypted;
        delete key;       
        EVP_CIPHER_CTX_free(context);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    decrypted -> setLen(written);

    if (!EVP_DecryptFinal(context, decrypted -> getByteMessage() + written, &written)) {
        delete ciphertext;
        delete decrypted;
        delete key;       
        EVP_CIPHER_CTX_free(context);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    decrypted -> setLen(decrypted -> getLen()+ written);
    EVP_CIPHER_CTX_free(context);

    return decrypted;
}

// Read text from file
ByteMessage *read_bytes_from_file(const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        std::cerr << strerror(errno);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) == -1) {
        fclose(fp);
        std::cerr << strerror(errno); 
        return NULL;
    }

    int text_len = ftell(fp);

    if (!text_len) {
        fclose(fp);
        std::cerr << strerror(errno); 
        return NULL;
    }
    
    rewind(fp);

    // Allocatetext and fill it
    unsigned char *text = 
        (unsigned char *)calloc(text_len + 1, sizeof(unsigned char));
    if (!text) {
        fclose(fp);
        std::cerr << strerror(errno);
        return NULL;
    } 

    if (!fread(text, 1, text_len, fp)) {
        fclose(fp);
        free(text);
        std::cerr << strerror(errno); 
        return NULL;
    }
    fclose(fp);
    
    ByteMessage *bm = new ByteMessage(text, text_len);
    if (!bm) {
        free(text);
        std::cerr << strerror(errno); 
        return NULL;
    }
    free(text);
    return bm;
}


int main() {
    EVP_PKEY *dh_params = EVP_PKEY_new();
    if (!dh_params) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Copies the low-level DH parameters
    // into high-level DH parameters (dh_params) (1 on success).
    DH *dh = get_dh2048();
    if (!EVP_PKEY_set1_DH(dh_params, dh)) {
        DH_free(dh);
        EVP_PKEY_free(dh_params);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    DH_free(dh);

    // In this case EVP_PKEY_CTX_new() is called with dh parameters, 
    // so the opeation is a key generation
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(dh_params, NULL);
    if (!context) {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(context);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Where to save prvk
    EVP_PKEY *m_private_key = NULL;

    // Initializes a context for dh key generation (1 on success)
    if (!EVP_PKEY_keygen_init(context)) {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(context);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // To generate a new key pair from the parameters:
    // Generate a dh private key and store in **pkey (1 on success)
    if (!EVP_PKEY_keygen(context, &m_private_key)) {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(context);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Saves a DH public key on a .PEM file,
    // if pkey is a DH private key, it extracts 
    // the public key and save this (1 on success)
    std::cout << "Insert filename where to save pk: ";
    std::string filename;
    std::cin >> filename;
    FILE *fp_dh_public_key = fopen(filename.c_str(), "w");
    if (!fp_dh_public_key) {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(m_private_key);
        std::cerr << strerror(errno);
        exit(EXIT_FAILURE);
    }
    PEM_write_PUBKEY(fp_dh_public_key, m_private_key);
    EVP_PKEY_CTX_free(context);
    fclose(fp_dh_public_key);

    // --------------------------
    // Retrieve pubkey of peer and store it in pbk
    // Load public key from file (EVP_PKEY strut, or NULL if error)
    std::cout << "Insert filename from where to load pk: ";
    std::cin >> filename;
    fp_dh_public_key = fopen(filename.c_str(), "r");
    if (!fp_dh_public_key) {        
        EVP_PKEY_free(dh_params);
        EVP_PKEY_free(m_private_key);
        std::cerr << strerror(errno);
        exit(EXIT_FAILURE);
    }
    EVP_PKEY *peer_public_key = PEM_read_PUBKEY(fp_dh_public_key, 
        NULL, NULL, NULL);
    if (!peer_public_key) {        
        EVP_PKEY_free(dh_params);
        EVP_PKEY_free(m_private_key);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    fclose(fp_dh_public_key);

    
    // In this case EVP_PKEY_CTX_new() is called with private key, 
    // so the opeation is a secret derivation (session key)
    // Initialize shared secret derivation context
    EVP_PKEY_CTX *secret_context = EVP_PKEY_CTX_new(m_private_key, NULL);
    if (!secret_context) {        
        EVP_PKEY_free(dh_params);
        EVP_PKEY_free(m_private_key);
        EVP_PKEY_free(peer_public_key);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Derive the shared secret from my private key and the peer’s
    // public key: (1 on success)
    if (!EVP_PKEY_derive_init(secret_context)) {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_free(m_private_key);
        EVP_PKEY_free(peer_public_key);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!EVP_PKEY_derive_set_peer(secret_context, peer_public_key)) {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_free(m_private_key);
        EVP_PKEY_free(peer_public_key);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    size_t key_len;
    // Get secret's length (1 on success)
    if (!EVP_PKEY_derive(secret_context, NULL, &key_len)) {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_free(m_private_key);
        EVP_PKEY_free(peer_public_key);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // Secret (session key)
    unsigned char *session_key = (unsigned char *)calloc(key_len + 1, 
        sizeof(unsigned char));
    if (!session_key) {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_free(m_private_key);
        EVP_PKEY_free(peer_public_key);
        std::cerr << strerror(errno);
        exit(EXIT_FAILURE);
    }
    // Fill secret
    if (!EVP_PKEY_derive(secret_context, session_key, &key_len)) {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_free(m_private_key);
        EVP_PKEY_free(peer_public_key);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    EVP_PKEY_free(dh_params);
    EVP_PKEY_free(peer_public_key);
    EVP_PKEY_free(m_private_key);
    EVP_PKEY_CTX_free(secret_context);

    // Read message from file and encrypt it
    std::cout << "Type file to encrypt: ";
    std::cin >> filename;

    ByteMessage *plaintext = read_bytes_from_file(filename.c_str());
    
    ByteMessage *secret = new ByteMessage(session_key, 16);
    // Encrypt message
    ByteMessage *ciphertext = encrypt(plaintext, secret);

    // Write encrypted to file
    filename.append(".enc");
    FILE *fp = fopen(filename.c_str(), "wb");
    if (!fp) {
        free(session_key);
        delete plaintext;
        delete secret;
        delete ciphertext;
        std::cerr << strerror(errno);
        exit(EXIT_FAILURE);
    }
    
    if (!fwrite(ciphertext -> getByteMessage(), 1, ciphertext -> getLen(), fp)) {
        free(session_key);
        delete plaintext;
        delete secret;
        delete ciphertext;
        fclose(fp);
        std::cerr << strerror(errno);
        exit(EXIT_FAILURE);
    }
    fclose(fp);

    delete plaintext;
    delete ciphertext;

    std::cout << "Encrypted in " << filename << "\n";

    // Read file to decrypt
    std::cout << "Type file to decrypt: ";
    std::cin >> filename;
    ciphertext = read_bytes_from_file(filename.c_str());
    plaintext = decrypt(ciphertext, secret);

    BIO_dump_fp(stdout, (char*)plaintext -> getByteMessage(), plaintext -> getLen());

    delete plaintext;
    delete ciphertext;
    delete secret;
    free(session_key);
    return 0;
}
