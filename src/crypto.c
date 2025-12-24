/*
 * Signalforge Dotenv Extension - Cryptography Implementation
 *
 * Uses libsodium for all cryptographic operations:
 * - Argon2id for password-based key derivation
 * - XSalsa20-Poly1305 (secretbox) for authenticated encryption
 */

#include "crypto.h"
#include "../php_signalforge_dotenv.h"
#include <string.h>

/* Static flag to track initialization */
static volatile int crypto_initialized = 0;

sf_crypto_error_t sf_crypto_init(void)
{
    if (crypto_initialized) {
        return SF_CRYPTO_OK;
    }

    if (sodium_init() < 0) {
        return SF_CRYPTO_ERR_INIT;
    }

    crypto_initialized = 1;
    return SF_CRYPTO_OK;
}

bool sf_crypto_is_encrypted(const unsigned char *data, size_t len)
{
    if (len < SF_CRYPTO_HEADER_SIZE) {
        return false;
    }

    /* Check magic bytes */
    return sodium_memcmp(data, SF_DOTENV_MAGIC, SF_DOTENV_MAGIC_LEN) == 0;
}

size_t sf_crypto_ciphertext_len(size_t plaintext_len)
{
    return SF_CRYPTO_HEADER_SIZE + plaintext_len + crypto_secretbox_MACBYTES;
}

size_t sf_crypto_plaintext_max_len(size_t ciphertext_len)
{
    if (ciphertext_len < SF_CRYPTO_MIN_SIZE) {
        return 0;
    }
    return ciphertext_len - SF_CRYPTO_HEADER_SIZE - crypto_secretbox_MACBYTES;
}

sf_crypto_error_t sf_crypto_encrypt(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *passphrase,
    size_t passphrase_len,
    unsigned char *ciphertext,
    size_t *ciphertext_len,
    size_t max_len)
{
    sf_dotenv_header_t header;
    unsigned char key[crypto_secretbox_KEYBYTES];
    size_t required_len;
    int result;

    if (!crypto_initialized) {
        return SF_CRYPTO_ERR_INIT;
    }

    if (passphrase == NULL || passphrase_len == 0) {
        return SF_CRYPTO_ERR_INVALID_KEY;
    }

    required_len = sf_crypto_ciphertext_len(plaintext_len);
    if (max_len < required_len) {
        return SF_CRYPTO_ERR_MEMORY;
    }

    /* Initialize header */
    memcpy(header.magic, SF_DOTENV_MAGIC, SF_DOTENV_MAGIC_LEN);
    header.version = SF_DOTENV_VERSION_1;
    memset(header.reserved, 0, sizeof(header.reserved));

    /* Generate random salt and nonce */
    randombytes_buf(header.salt, sizeof(header.salt));
    randombytes_buf(header.nonce, sizeof(header.nonce));

    /* Derive key from passphrase using Argon2id */
    result = crypto_pwhash(
        key,
        sizeof(key),
        (const char *)passphrase,
        passphrase_len,
        header.salt,
        SF_CRYPTO_OPSLIMIT,
        SF_CRYPTO_MEMLIMIT,
        crypto_pwhash_ALG_ARGON2ID13
    );

    if (result != 0) {
        sodium_memzero(key, sizeof(key));
        return SF_CRYPTO_ERR_ENCRYPT_FAILED;
    }

    /* Copy header to output */
    memcpy(ciphertext, &header, SF_CRYPTO_HEADER_SIZE);

    /* Encrypt with secretbox */
    result = crypto_secretbox_easy(
        ciphertext + SF_CRYPTO_HEADER_SIZE,
        plaintext,
        plaintext_len,
        header.nonce,
        key
    );

    /* Secure cleanup */
    sodium_memzero(key, sizeof(key));

    if (result != 0) {
        sodium_memzero(ciphertext, required_len);
        return SF_CRYPTO_ERR_ENCRYPT_FAILED;
    }

    *ciphertext_len = required_len;
    return SF_CRYPTO_OK;
}

sf_crypto_error_t sf_crypto_decrypt(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char *passphrase,
    size_t passphrase_len,
    unsigned char *plaintext,
    size_t *plaintext_len,
    size_t max_len)
{
    sf_dotenv_header_t header;
    unsigned char key[crypto_secretbox_KEYBYTES];
    size_t encrypted_len;
    size_t decrypted_len;
    int result;

    if (!crypto_initialized) {
        return SF_CRYPTO_ERR_INIT;
    }

    if (passphrase == NULL || passphrase_len == 0) {
        return SF_CRYPTO_ERR_INVALID_KEY;
    }

    if (ciphertext_len < SF_CRYPTO_MIN_SIZE) {
        return SF_CRYPTO_ERR_INVALID_DATA;
    }

    /* Verify and parse header */
    memcpy(&header, ciphertext, SF_CRYPTO_HEADER_SIZE);

    if (sodium_memcmp(header.magic, SF_DOTENV_MAGIC, SF_DOTENV_MAGIC_LEN) != 0) {
        return SF_CRYPTO_ERR_NOT_ENCRYPTED;
    }

    if (header.version != SF_DOTENV_VERSION_1) {
        return SF_CRYPTO_ERR_VERSION_UNSUPPORTED;
    }

    encrypted_len = ciphertext_len - SF_CRYPTO_HEADER_SIZE;
    decrypted_len = encrypted_len - crypto_secretbox_MACBYTES;

    if (max_len < decrypted_len) {
        return SF_CRYPTO_ERR_MEMORY;
    }

    /* Derive key from passphrase */
    result = crypto_pwhash(
        key,
        sizeof(key),
        (const char *)passphrase,
        passphrase_len,
        header.salt,
        SF_CRYPTO_OPSLIMIT,
        SF_CRYPTO_MEMLIMIT,
        crypto_pwhash_ALG_ARGON2ID13
    );

    if (result != 0) {
        sodium_memzero(key, sizeof(key));
        return SF_CRYPTO_ERR_DECRYPT_FAILED;
    }

    /* Decrypt with secretbox */
    result = crypto_secretbox_open_easy(
        plaintext,
        ciphertext + SF_CRYPTO_HEADER_SIZE,
        encrypted_len,
        header.nonce,
        key
    );

    /* Secure cleanup */
    sodium_memzero(key, sizeof(key));

    if (result != 0) {
        /* Authentication failed - tampering detected */
        sodium_memzero(plaintext, max_len);
        return SF_CRYPTO_ERR_DECRYPT_FAILED;
    }

    *plaintext_len = decrypted_len;
    return SF_CRYPTO_OK;
}

const char *sf_crypto_error_str(sf_crypto_error_t err)
{
    switch (err) {
        case SF_CRYPTO_OK:
            return "Success";
        case SF_CRYPTO_ERR_INIT:
            return "Cryptography subsystem initialization failed";
        case SF_CRYPTO_ERR_INVALID_KEY:
            return "Invalid or missing encryption key";
        case SF_CRYPTO_ERR_INVALID_DATA:
            return "Invalid encrypted data format";
        case SF_CRYPTO_ERR_DECRYPT_FAILED:
            return "Decryption failed: wrong key or tampered data";
        case SF_CRYPTO_ERR_ENCRYPT_FAILED:
            return "Encryption failed";
        case SF_CRYPTO_ERR_VERSION_UNSUPPORTED:
            return "Unsupported encryption format version";
        case SF_CRYPTO_ERR_MEMORY:
            return "Insufficient buffer space";
        case SF_CRYPTO_ERR_NOT_ENCRYPTED:
            return "Data is not encrypted";
        default:
            return "Unknown error";
    }
}

void sf_crypto_secure_zero(void *ptr, size_t len)
{
    sodium_memzero(ptr, len);
}

int sf_crypto_compare(const void *a, const void *b, size_t len)
{
    return sodium_memcmp(a, b, len);
}

void sf_crypto_random_bytes(void *buf, size_t len)
{
    randombytes_buf(buf, len);
}
