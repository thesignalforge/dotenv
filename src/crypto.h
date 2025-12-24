/*
 * Signalforge Dotenv Extension - Cryptography
 *
 * Encryption/decryption using libsodium:
 * - Argon2id for key derivation (password-based)
 * - XSalsa20-Poly1305 for authenticated encryption
 * - Versioned header format for future compatibility
 *
 * File Format:
 * +------------------+
 * | Magic (8 bytes)  |  "SFDOTENV"
 * +------------------+
 * | Version (1 byte) |  0x01
 * +------------------+
 * | Reserved (3 b)   |  0x00 0x00 0x00
 * +------------------+
 * | Salt (16 bytes)  |  crypto_pwhash_SALTBYTES
 * +------------------+
 * | Nonce (24 bytes) |  crypto_secretbox_NONCEBYTES
 * +------------------+
 * | Ciphertext       |  Variable length (includes MAC)
 * +------------------+
 *
 * Total header size: 8 + 1 + 3 + 16 + 24 = 52 bytes
 */

#ifndef SF_DOTENV_CRYPTO_H
#define SF_DOTENV_CRYPTO_H

#include "php.h"
#include <sodium.h>
#include <stdbool.h>

/* Header size calculation */
#define SF_CRYPTO_HEADER_SIZE (SF_DOTENV_MAGIC_LEN + 1 + 3 + crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES)

/* Minimum ciphertext size (header + MAC) */
#define SF_CRYPTO_MIN_SIZE (SF_CRYPTO_HEADER_SIZE + crypto_secretbox_MACBYTES)

/* Argon2id parameters for key derivation */
#define SF_CRYPTO_OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE
#define SF_CRYPTO_MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE

/* Result codes */
typedef enum {
    SF_CRYPTO_OK = 0,
    SF_CRYPTO_ERR_INIT,
    SF_CRYPTO_ERR_INVALID_KEY,
    SF_CRYPTO_ERR_INVALID_DATA,
    SF_CRYPTO_ERR_DECRYPT_FAILED,
    SF_CRYPTO_ERR_ENCRYPT_FAILED,
    SF_CRYPTO_ERR_VERSION_UNSUPPORTED,
    SF_CRYPTO_ERR_MEMORY,
    SF_CRYPTO_ERR_NOT_ENCRYPTED
} sf_crypto_error_t;

/**
 * Initialize cryptography subsystem
 *
 * Must be called once during MINIT.
 *
 * @return SF_CRYPTO_OK on success, error code otherwise
 */
sf_crypto_error_t sf_crypto_init(void);

/**
 * Check if data appears to be encrypted
 *
 * @param data Data buffer
 * @param len Data length
 * @return true if data has valid encryption header
 */
bool sf_crypto_is_encrypted(const unsigned char *data, size_t len);

/**
 * Encrypt plaintext using a passphrase
 *
 * Derives a key from the passphrase using Argon2id, then encrypts
 * with XSalsa20-Poly1305.
 *
 * @param plaintext Input plaintext
 * @param plaintext_len Length of plaintext
 * @param passphrase Encryption passphrase
 * @param passphrase_len Length of passphrase
 * @param ciphertext Output buffer (caller allocated)
 * @param ciphertext_len Output: actual ciphertext length
 * @param max_len Maximum output buffer size
 * @return SF_CRYPTO_OK on success, error code otherwise
 */
sf_crypto_error_t sf_crypto_encrypt(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *passphrase,
    size_t passphrase_len,
    unsigned char *ciphertext,
    size_t *ciphertext_len,
    size_t max_len
);

/**
 * Decrypt ciphertext using a passphrase
 *
 * @param ciphertext Input ciphertext (with header)
 * @param ciphertext_len Length of ciphertext
 * @param passphrase Decryption passphrase
 * @param passphrase_len Length of passphrase
 * @param plaintext Output buffer (caller allocated)
 * @param plaintext_len Output: actual plaintext length
 * @param max_len Maximum output buffer size
 * @return SF_CRYPTO_OK on success, error code otherwise
 */
sf_crypto_error_t sf_crypto_decrypt(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char *passphrase,
    size_t passphrase_len,
    unsigned char *plaintext,
    size_t *plaintext_len,
    size_t max_len
);

/**
 * Calculate required ciphertext buffer size for encryption
 *
 * @param plaintext_len Length of plaintext
 * @return Required buffer size
 */
size_t sf_crypto_ciphertext_len(size_t plaintext_len);

/**
 * Calculate maximum plaintext size from ciphertext
 *
 * @param ciphertext_len Length of ciphertext
 * @return Maximum plaintext size (actual may be smaller)
 */
size_t sf_crypto_plaintext_max_len(size_t ciphertext_len);

/**
 * Get error message for error code
 *
 * @param err Error code
 * @return Human-readable error message
 */
const char *sf_crypto_error_str(sf_crypto_error_t err);

/**
 * Securely zero memory
 *
 * Uses sodium_memzero for constant-time zeroing.
 *
 * @param ptr Pointer to memory
 * @param len Length of memory
 */
void sf_crypto_secure_zero(void *ptr, size_t len);

/**
 * Constant-time comparison
 *
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return 0 if equal, non-zero otherwise
 */
int sf_crypto_compare(const void *a, const void *b, size_t len);

/**
 * Generate random bytes
 *
 * @param buf Output buffer
 * @param len Number of bytes to generate
 */
void sf_crypto_random_bytes(void *buf, size_t len);

#endif /* SF_DOTENV_CRYPTO_H */
