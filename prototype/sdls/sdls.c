#include "security_association.h"

transferFrame* ApplySecurity(securityAssociation** sa_array, unsigned int sa_array_size, unsigned int GVCID, unsigned int GMAP_ID, unsigned char* plaintext, int plaintext_len) {
  // Find the appropriate SA
  securityAssociation* sa = FindSA(sa_array, sa_array_size, GVCID, GMAP_ID);

  // Initialise a transfer frame and its security header (ApplySecurity Return)
  transferFrame* tf = malloc(sizeof(transferFrame));
  tf->sh = malloc(sizeof(securityHeader));

  // If the SA service type is encryption only
  if (sa->SA_service_type == 1) {
    // Initialise OpenSSL context and variables
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int update_len;
    int total_len;

    // Buffer for ciphertext with space for padding
    unsigned char ciphertext[plaintext_len + EVP_CIPHER_block_size(sa->SA_encryption_algorithm)];

    // Initialise encryption
    EVP_EncryptInit_ex(ctx, sa->SA_encryption_algorithm, NULL, sa->SA_encryption_key, sa->SA_initialization_vector);

    // Pass the plaintext to the encryption
    EVP_EncryptUpdate(ctx, ciphertext, &update_len, plaintext, plaintext_len);
    total_len = update_len;

    // Finalise encryption
    EVP_EncryptFinal_ex(ctx, ciphertext + update_len, &update_len);
    total_len += update_len;

    // Free context
    EVP_CIPHER_CTX_free(ctx);

    // Octet-align the security header fields
    // TODO: Waiting on Henry's function

    // Populate data_field
    tf->data_field = malloc(total_len);
    memcpy(tf->data_field, ciphertext, total_len);
  }

  // Return the transfer frame
  return tf;
}
