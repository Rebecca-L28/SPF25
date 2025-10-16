#include "security_association.h"
#include "sdls_helper.h"

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
    handleOctetPadding(tf, sa, total_len - plaintext_len, 1, 1, 1, 0, NULL);

    // Populate data_field
    tf->data_field = malloc(total_len);
    memcpy(tf->data_field, ciphertext, total_len);
  }
  // If the SA service type is authentication only
  else if (sa->SA_service_type == 0) {
    // Populate security header and data_field
    handleOctetPadding(tf, sa, 0, 1, 1, 1, 0, NULL);
    tf->data_field = malloc(plaintext_len);
    memcpy(tf->data_field, plaintext, plaintext_len);

    // Build security header + data_field for authentication data_field
    size_t auth_len = 2 + sa->SA_length_IV/8 + sa->SA_length_SN/8 + sa->SA_length_PL/8 + plaintext_len;
    unsigned char* auth_payload = malloc(auth_len);
    unsigned char* auth_ptr = auth_payload;
    memcpy(auth_ptr, tf->sh->SPI, 2);
    auth_ptr += 2;
    memcpy(auth_ptr, tf->sh->IV, sa->SA_length_IV / 8);
    auth_ptr += sa->SA_length_IV / 8;
    memcpy(auth_ptr, tf->sh->SN, sa->SA_length_SN / 8);
    auth_ptr += sa->SA_length_SN / 8;
    memcpy(auth_ptr, tf->sh->PL, sa->SA_length_PL / 8);
    auth_ptr += sa->SA_length_PL / 8;
    memcpy(auth_ptr, tf->data_field, plaintext_len);

    // Apply the bit mask in a bitwise-AND op
    for (int i = 0; i < auth_len; i++) {
      auth_payload[i] = auth_payload[i] & sa->SA_authentication_mask;
    }

    // Initialise OpenSSL
    EVP_MAC_CTX* mctx = EVP_MAC_CTX_new(sa->SA_authentication_algorithm);

    // Construct the OSSL parameters for the digest to utilise
    OSSL_PARAM params[4], *p = params;
    // TODO: Change to be dynamic based on algorithm
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", strlen("SHA256"));
    *p = OSSL_PARAM_construct_end();

    // Initialise MAC
    EVP_MAC_init(mctx, sa->SA_authentication_key, strlen((char*)sa->SA_authentication_key), params);

    // Process the data_field data
    EVP_MAC_update(mctx, auth_payload, auth_len);

    // Gather the MAC's length
    size_t mac_len;
    EVP_MAC_final(mctx, NULL, &mac_len, 0);

    // Gather the MAC
    unsigned char* mac_value = malloc(mac_len);
    EVP_MAC_final(mctx, mac_value, &mac_len, mac_len);

    // Allocate security trailer
    size_t sa_mac_length = sa->SA_length_MAC/8;
    tf->st = malloc(sizeof(securityTrailer));
    tf->st->MAC = malloc(sa_mac_length);

    // Handle padding/truncating
    if (mac_len > sa_mac_length){
      mac_len = sa_mac_length;
    }
    memcpy(tf->st->MAC, mac_value, mac_len);
    if (mac_len < sa_mac_length){
      memset(tf->st->MAC + mac_len, 0x00, sa_mac_length - mac_len);
    }

    // Free memory
    free(mac_value);
    free(auth_payload);
    EVP_MAC_CTX_free(mctx);
  }

  // Return the transfer frame
  return tf;
}

processSecurityReturn* ProcessSecurity(securityAssociation** sa_array, unsigned int sa_array_size, transferFrame* tf, unsigned int GVCID, unsigned int GMAP_ID) {
  // Find the SA associated with GVCID/GMAP_ID
  securityAssociation* sa = FindSA(sa_array, sa_array_size, GVCID, GMAP_ID);

    // Check that the Security Header's SPI is same as found SA
    uint32_t spi = handleOctetPaddingReceive(tf, sa, 1, 0, 0);
    if (sa->SPI != spi){
        printf("SPI mismatch\n");
        return NULL;
    }
    printf("SPI verified\n");

  // Initialise return structure
  processSecurityReturn* psr = malloc(sizeof(processSecurityReturn));
  psr->verified = 0;
  size_t data_field_len = strlen(tf->data_field);

  // If the SA service type is encryption only
  if (sa->SA_service_type == 1) {
    // Initialise OpenSSL context and variables
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int updateLen;
    int totalLen;

    // Buffer for plaintext
    unsigned char plaintext[data_field_len];

    // Initialise decryption
    EVP_DecryptInit_ex(ctx, sa->SA_encryption_algorithm, NULL, sa->SA_encryption_key, sa->SA_initialization_vector);

    // Decrypt the ciphertext
    EVP_DecryptUpdate(ctx, plaintext, &updateLen, tf->data_field, data_field_len);
    totalLen = updateLen;

    // Finalise decryption
    EVP_DecryptFinal_ex(ctx, plaintext + updateLen, &updateLen);
    totalLen += updateLen;

    // Free context
    EVP_CIPHER_CTX_free(ctx);

    // Populate return structure
    psr->data_field = malloc(totalLen);
    memcpy(psr->data_field, plaintext, totalLen);
    psr->verified = 1;
  }
    // If the SA service type is authentication only
    if (sa->SA_service_type == 0){
        // Build security header + data_field for authentication data_field
        size_t auth_len = 2 + sa->SA_length_IV/8 + sa->SA_length_SN/8 + sa->SA_length_PL/8 + strlen(tf->data_field);
        unsigned char* auth_payload = malloc(auth_len);
        unsigned char* auth_ptr = auth_payload;
        memcpy(auth_ptr, tf->sh->SPI, 2);
        auth_ptr += 2;
        memcpy(auth_ptr, tf->sh->IV, sa->SA_length_IV / 8);
        auth_ptr += sa->SA_length_IV / 8;
        memcpy(auth_ptr, tf->sh->SN, sa->SA_length_SN / 8);
        auth_ptr += sa->SA_length_SN / 8;
        memcpy(auth_ptr, tf->sh->PL, sa->SA_length_PL / 8);
        auth_ptr += sa->SA_length_PL / 8;
        memcpy(auth_ptr, tf->data_field, strlen(tf->data_field));

        // Apply the bit mask in a bitwise-AND op
        for (int i = 0; i < auth_len; i++) {
            auth_payload[i] = auth_payload[i] & sa->SA_authentication_mask;
        }

        // Initialise OpenSSL
        EVP_MAC_CTX* mctx = EVP_MAC_CTX_new(sa->SA_authentication_algorithm);

        // Construct the OSSL parameters for the digest to utilise
        OSSL_PARAM params[4], *p = params;
        *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", strlen("SHA256"));
        *p = OSSL_PARAM_construct_end();

        // Initialise MAC
        EVP_MAC_init(mctx, sa->SA_authentication_key, strlen((char*)sa->SA_authentication_key), params);

        // Process the data_field data
        EVP_MAC_update(mctx, auth_payload, auth_len);

        // Gather the MAC's length
        size_t mac_len;
        EVP_MAC_final(mctx, NULL, &mac_len, 0);

        // Gather the MAC
        unsigned char* mac_value = malloc(mac_len);
        EVP_MAC_final(mctx, mac_value, &mac_len, mac_len);

        // If the MACs match, the data_field is verified
        if (memcmp(mac_value, tf->st->MAC, sa->SA_length_MAC / 8) == 0) {
            psr->verified = 1;
            printf("MAC verified\n");
        } else {
            printf("MAC verification failed\n");
        }

        // Gather the sequence number
        uint32_t sn = handleOctetPaddingReceive(tf, sa, 0, 1, 0);
        if (sn > sa->SA_sequence_number) {
            if (sn - sa->SA_sequence_number <= sa->SA_window_size) {
                sa->SA_sequence_number = sn;
                printf("Sequence number verified\n");
            } else {
                psr->verified = 0;
                printf("Sequence number outside window\n");
            }
        } else {
            psr->verified = 0;
            printf("Sequence number too low\n");
        }

        // Populate return structure
        psr->data_field = malloc(data_field_len);
        memcpy(psr->data_field, tf->data_field, data_field_len);

        // Free memory
        free(auth_payload);
    }

  // Return the process security return structure
  return psr;
}
