#pragma once
#include "security_association.h"
#include "sdls_helper.h"

transferFrame* ApplySecurity(securityAssociation** sa_array, unsigned int sa_array_size, unsigned int GVCID, unsigned int GMAP_ID, unsigned char* plaintext, int plaintext_len, unsigned char* SPP, size_t SPP_len, int usingTM, int usingTC, int usingTC_SH) {
  printf("\nApplySecurity()...\n");

  // Find the appropriate SA
  securityAssociation* sa = FindSA(sa_array, sa_array_size, GVCID, GMAP_ID);
  if (sa == NULL){
    printf("[ERROR] No SA was found\n");
    return NULL;
  }

  // Initialise memory management array (change size if more is needed in function)
  void* memory[9];

  // Initialise a transfer frame and its security header (ApplySecurity Return)
  transferFrame* tf = malloc(sizeof(transferFrame));
  if (tf == NULL){
    printf("[ERROR] Failed to allocate transferFrame\n");
    return NULL;
  }
  memory[0] = tf;
  tf->sh = malloc(sizeof(securityHeader));
  if (tf->sh == NULL){
    printf("[ERROR] Failed to allocate securityHeader\n");
    freeMemory(memory);
    return NULL;
  }
  memory[1] = tf->sh;

  // If the SA service type is encryption only
  if (sa->SA_service_type == 1) {
    // Logging print
    printf("Performing encryption only...\n");
    printf("Plaintext provided (%d bytes): \"%s\"\n", plaintext_len, plaintext);

    // Initialise OpenSSL context and variables
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL){
      printf("[ERROR] Failed to initialise OpenSSL context\n");
      freeMemory(memory);
      return NULL;
    }
    int update_len;
    int total_len;

    // Buffer for ciphertext with space for padding
    unsigned char ciphertext[plaintext_len + EVP_CIPHER_block_size(sa->SA_encryption_algorithm)];

    // Initialise encryption
    if (EVP_EncryptInit_ex(ctx, sa->SA_encryption_algorithm, NULL, sa->SA_encryption_key, sa->SA_initialization_vector) != 1){
      printf("[ERROR] Failed to initialise encryption\n");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Pass the plaintext to the encryption
    if (EVP_EncryptUpdate(ctx, ciphertext, &update_len, plaintext, plaintext_len) != 1){
      printf("[ERROR] Failed to update encryption\n");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }
    total_len = update_len;

    // Finalise encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + update_len, &update_len) != 1){
      printf("[ERROR] Failed to finalise encryption\n");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL; 
    }
    total_len += update_len;

    // Free context
    EVP_CIPHER_CTX_free(ctx);

    // Populate the Security Header
    if (processSPI(tf, sa) != 0){
      printf("[ERROR] Failed to populate SPI\n");
      freeMemory(memory);
      return NULL;
    }
    if (processIV(tf, sa, 0) != 0){
      printf("[ERROR] Failed to populate IV\n");
      freeMemory(memory);
      return NULL;
    }
    memory[2] = tf->sh->IV;
    if (processPL(tf, sa, total_len - plaintext_len) != 0){
      printf("[ERROR] Failed to populate PL\n");
      freeMemory(memory);
      return NULL;
    }
    memory[3] = tf->sh->PL;
    
    // Populate data_field
    tf->data_field = malloc(total_len);
    if (tf->data_field == NULL){
      printf("[ERROR] Failed to allocate data_field\n");
      freeMemory(memory);
      return NULL;
    }
    memcpy(tf->data_field, ciphertext, total_len);
    memory[4] = tf->data_field;

    // Logging print
    printf("Finished encryption only.\n");
  }
  // If the SA service type is authentication only
  else if (sa->SA_service_type == 0) {
    // Logging print
    printf("Performing authentication only...\n");
    printf("Plaintext provided (%d bytes): \"%s\"\n", plaintext_len, plaintext);

    // Handle sequence number increment and rollover
    sa->SA_sequence_number++;

    // Populate Security Header
    if (processSPI(tf, sa) != 0){
      printf("[ERROR] Failed to populate SPI\n");
      freeMemory(memory);
      return NULL;
    }
    if (processSN(tf, sa) != 0){
      printf("[ERROR] Failed to populate SN\n");
      freeMemory(memory);
      return NULL;
    }
    memory[2] = tf->sh->SN;

    // Populate data_field
    tf->data_field = malloc(plaintext_len);
    if (tf->data_field == NULL){
      printf("[ERROR] Failed to allocate data_field\n");
      freeMemory(memory);
      return NULL;
    }
    memcpy(tf->data_field, plaintext, plaintext_len);
    memory[3] = tf->data_field;

    // Build security header + data_field for authentication data_field
    size_t auth_len = 2 + sa->SA_length_SN + sa->SA_length_PL + plaintext_len;
    if (SPP_len > 0){
      auth_len += SPP_len;
    }
    unsigned char* auth_payload = malloc(auth_len);
    if (auth_payload == NULL){
      printf("[ERROR] Failed to allocate auth_payload\n");
      freeMemory(memory);
      return NULL;
    }
    unsigned char* auth_ptr = auth_payload;
    if (SPP_len > 0){
      memcpy(auth_ptr, SPP, SPP_len);
      auth_ptr += SPP_len;
    }
    memcpy(auth_ptr, &tf->sh->SPI, 2);
    auth_ptr += 2;
    memcpy(auth_ptr, tf->sh->SN, sa->SA_length_SN);
    auth_ptr += sa->SA_length_SN;
    memcpy(auth_ptr, tf->sh->PL, sa->SA_length_PL);
    auth_ptr += sa->SA_length_PL;
    memcpy(auth_ptr, tf->data_field, plaintext_len);
    memory[4] = auth_payload;

    // Apply the bit mask
    applyBitmask(auth_payload, auth_len, sa, 0, usingTM, usingTC, usingTC_SH);

    // Initialise OpenSSL
    EVP_MAC_CTX* mctx = EVP_MAC_CTX_new(sa->SA_authentication_algorithm);
    if (mctx == NULL){
      printf("[ERROR] Failed to initialise OpenSSL context\n");
      freeMemory(memory);
      return NULL;
    }

    // Construct the OSSL parameters for the digest to utilise
    OSSL_PARAM params[4], *p = params;
    // If HMAC, get SHA256
    if (sa->SA_authentication_algorithm == EVP_MAC_fetch(NULL, "HMAC", NULL)){
      *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", strlen("SHA256"));
    // IF CMAC, get AES-256-CBC
    } else {
      *p++ = OSSL_PARAM_construct_utf8_string("cipher", "AES-256-CBC", strlen("AES-256-GCM"));
    }
    *p = OSSL_PARAM_construct_end();

    // Initialise MAC
    if (EVP_MAC_init(mctx, sa->SA_authentication_key, strlen((char*)sa->SA_authentication_key), params) != 1){
      printf("[ERROR] Failed to initialise MAC\n]");
      freeMemory(memory);
      EVP_MAC_CTX_free(mctx);
      return NULL;
    }

    // Process the data_field data
    if (EVP_MAC_update(mctx, auth_payload, auth_len) != 1){
      printf("[ERROR] Failed to update MAC\n]");
      freeMemory(memory);
      EVP_MAC_CTX_free(mctx);
      return NULL;
    }

    // Gather the MAC's length
    size_t mac_len;
    if (EVP_MAC_final(mctx, NULL, &mac_len, 0) != 1){
      printf("[ERROR] Failed to finalise MAC\n]");
      freeMemory(memory);
      EVP_MAC_CTX_free(mctx);
      return NULL;
    }

    // Gather the MAC
    unsigned char* mac_value = malloc(mac_len);
    if (mac_value == NULL){
      printf("[ERROR] Failed to allocate mac_value\n]");
      freeMemory(memory);
      EVP_MAC_CTX_free(mctx);
      return NULL;
    }
    memory[5] = mac_value;
    if (EVP_MAC_final(mctx, mac_value, &mac_len, mac_len) != 1){
      printf("[ERROR] Failed to finalise MAC\n]");
      freeMemory(memory);
      EVP_MAC_CTX_free(mctx);
      return NULL;
    }

    // Allocate security trailer
    tf->st = malloc(sizeof(securityTrailer));
    if (tf->st == NULL){
      printf("[ERROR] Failed to allocate securityTrailer\n]");
      freeMemory(memory);
      EVP_MAC_CTX_free(mctx);
      return NULL;
    }
    memory[6] = tf->st;

    // Allocate MAC
    size_t sa_mac_length = sa->SA_length_MAC;
    tf->st->MAC = malloc(sa_mac_length);
    if (tf->st->MAC == NULL){
      printf("[ERROR] Failed to allocate MAC\n]");
      freeMemory(memory);
      EVP_MAC_CTX_free(mctx);
      return NULL;
    }
    memory[7] = tf->st->MAC;

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

    // Logging print
    printf("Finished authentication only.\n");
  }
  // If the SA service type is authenticated encryption
  else if (sa->SA_service_type == 2){
    // Logging print
    printf("Performing authenticated encryption...\n");
    printf("Plaintext provided (%d bytes): \"%s\"\n", plaintext_len, plaintext);

    // Handle sequence number increment and rollover
    // [TO TEST OUTSIDE WINDOW, MAKE SURE TO DO THE DEBUG ONE ON PROCESSECURITY]
    sa->SA_sequence_number++;

    // Populate Security Header
    if (processSPI(tf, sa) != 0){
      printf("[ERROR] Failed to populate SPI\n]");
      freeMemory(memory);
      return NULL;
    }
    if (processIV(tf, sa, 1) != 0){
      printf("[ERROR] Failed to populate IV\n]");
      freeMemory(memory);
      return NULL;
    }
    memory[2] = tf->sh->IV;
    if (processPL(tf, sa, 0) != 0){
      printf("[ERROR] Failed to populate PL\n]");
      freeMemory(memory);
      return NULL;
    }
    memory[3] = tf->sh->PL;

    // Build security header + data_field for authentication data_field
    size_t auth_len = 2 + sa->SA_length_IV + sa->SA_length_PL;
    if (SPP_len > 0){
      auth_len += SPP_len;
    }
    unsigned char* auth_payload = malloc(auth_len);
    if (auth_payload == NULL){
      printf("[ERROR] Failed to allocate auth_payload\n]");
      freeMemory(memory);
      return NULL;
    }
    memory[4] = auth_payload;
    unsigned char* auth_ptr = auth_payload;
    if (SPP_len > 0){
      memcpy(auth_ptr, SPP, SPP_len);
      auth_ptr += SPP_len;
    }
    memcpy(auth_ptr, &tf->sh->SPI, 2);
    auth_ptr += 2;
    memcpy(auth_ptr, tf->sh->IV, sa->SA_length_IV);
    auth_ptr += sa->SA_length_IV;
    memcpy(auth_ptr, tf->sh->PL, sa->SA_length_PL);
    auth_ptr += sa->SA_length_PL;

    // Apply authentication bit mask
    applyBitmask(auth_payload, auth_len, sa, 1, usingTM, usingTC, usingTC_SH);

    // Initialise OpenSSL context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL){
      printf("[ERROR] Failed to initialise OpenSSL context\n]");
      freeMemory(memory);
      return NULL;
    }
    int len;
    int ciphertext_len;

    // Initialise encryption
    if (EVP_EncryptInit_ex(ctx, sa->SA_encryption_algorithm, NULL, NULL, NULL) != 1){
      printf("[ERROR] Failed to initialise encryption\n]");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Change IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sa->SA_length_IV, NULL) != 1){
      printf("[ERROR] Failed to set IV length\n]");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Initialise key and IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, sa->SA_encryption_key, tf->sh->IV) != 1){
      printf("[ERROR] Failed to initialise key and IV\n]");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Provide AAD
    if (EVP_EncryptUpdate(ctx, NULL, &len, auth_payload, auth_len) != 1){
      printf("[ERROR] Failed to provide AAD\n]");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Buffer for ciphertext with space for padding
    unsigned char ciphertext[plaintext_len + EVP_CIPHER_block_size(sa->SA_encryption_algorithm)];

    // Provide the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1){
      printf("[ERROR] Failed to provide plaintext\n]");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }
    ciphertext_len = len;

    // Finalise encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1){
      printf("[ERROR] Failed to finalise encryption\n]");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }
    ciphertext_len += len;

    // Get the tag
    unsigned char* tag = malloc(sa->SA_length_MAC);
    if (tag == NULL){
      printf("[ERROR] Failed to allocate tag\n]");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }
    memory[5] = tag;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sa->SA_length_MAC, tag) != 1){
      printf("[ERROR] Failed to get tag\n]");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Free memory
    EVP_CIPHER_CTX_free(ctx);

    // Store the ciphertext
    tf->data_field = malloc(ciphertext_len);
    if (tf->data_field == NULL){
      printf("[ERROR] Failed to allocate data_field\n]");
      freeMemory(memory);
      return NULL;
    }
    memcpy(tf->data_field, ciphertext, ciphertext_len);
    memory[6] = tf->data_field;

    // Allocate Security Trailer
    tf->st = malloc(sizeof(securityTrailer));
    if (tf->st == NULL){
      printf("[ERROR] Failed to allocate securityTrailer");
      freeMemory(memory);
      return NULL;
    }
    memory[7] = tf->st;

    // Allocate MAC
    size_t sa_mac_length = sa->SA_length_MAC;
    tf->st->MAC = malloc(sa_mac_length);
    if (tf->st->MAC == NULL){
      printf("[ERROR] Failed to allocate MAC");
      freeMemory(memory);
      return NULL;
    }
    memory[8] = tf->st->MAC;

    // Handle padding/truncating
    size_t mac_len = strlen(tag);
    if (mac_len > sa_mac_length){
      mac_len = sa_mac_length;
    }
    memcpy(tf->st->MAC, tag, mac_len);
    if (mac_len < sa_mac_length){
      memset(tf->st->MAC + mac_len, 0x00, sa_mac_length - mac_len);
    }

    // Free memory
    free(tag);
    free(auth_payload);

    // Logging print
    printf("Finished authenticated encryption.\n");
  }
  // Return the transfer frame
  return tf;
}

processSecurityReturn* ProcessSecurity(securityAssociation** sa_array, unsigned int sa_array_size, transferFrame* tf, unsigned int GVCID, unsigned int GMAP_ID, unsigned char* SPP, size_t SPP_len, int usingTM, int usingTC, int usingTC_SH) {
  printf("\nProcessSecurity()...\n");

  // Initialise memory management array (change size if more is needed in function)
  void* memory[3];

  // Initialise return structure
  processSecurityReturn* psr = malloc(sizeof(processSecurityReturn));
  if (psr == NULL){
    printf("[ERROR] Failed to allocate processSecurityReturn\n");
    return NULL;
  }
  psr->verification_status = 0;
  size_t data_field_len = strlen(tf->data_field);
  memory[0] = psr;

  // Find the SA associated with GVCID/GMAP_ID
  securityAssociation* sa = FindSA(sa_array, sa_array_size, GVCID, GMAP_ID);

  // Check that the Security Header's SPI is same as found SA
  if (sa->SPI != tf->sh->SPI){
    printf("[ERROR] SPI verification failed\n");
    psr->verification_code = 1;
    return psr;
  }
  printf("SPI verified\n");

  // If the SA service type is encryption only
  if (sa->SA_service_type == 1) {
    // Logging print 
    printf("Receiving encryption only...\n");

    // Initialise OpenSSL context and variables
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL){
      printf("[ERROR] Failed to initialise OpenSSL context\n");
      freeMemory(memory);
      return NULL;
    }
    int updateLen;
    int totalLen;

    // Buffer for plaintext
    unsigned char plaintext[data_field_len];

    // Initialise decryption
    if (EVP_DecryptInit_ex(ctx, sa->SA_encryption_algorithm, NULL, sa->SA_encryption_key, sa->SA_initialization_vector) != 1){
      printf("[ERROR] Failed to initialise decryption\n");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &updateLen, tf->data_field, data_field_len) != 1){
      printf("[ERROR] Failed to update decryption\n");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }
    totalLen = updateLen;

    // Finalise decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + updateLen, &updateLen) != 1){
      printf("[ERROR] Failed to finalise decryption\n");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }
    totalLen += updateLen;

    // Free context
    EVP_CIPHER_CTX_free(ctx);

    // Populate return structure
    psr->data_field = malloc(totalLen);
    if (psr->data_field == NULL){
      printf("[ERROR] Failed to allocate data_field\n");
      freeMemory(memory);
      return NULL;
    }
    memcpy(psr->data_field, plaintext, totalLen);
    psr->verification_status = 1;
    psr->verification_code = 0;

    // Logging print
    printf("Finished receiving encryption only.\n");
  }
  // If the SA service type is authentication only
  if (sa->SA_service_type == 0){
    // Logging print
    printf("Receiving authentication only...\n");

    // Build security header + data_field for authentication data_field
    size_t auth_len = 2 + sa->SA_length_SN + sa->SA_length_PL + strlen(tf->data_field);
    if (SPP_len > 0){
      auth_len += SPP_len;
    }
    unsigned char* auth_payload = malloc(auth_len);
    if (auth_payload == NULL){
      printf("[ERROR] Failed to allocate auth_payload\n");
      freeMemory(memory);
      return NULL;
    }
    memory[1] = auth_payload;
    unsigned char* auth_ptr = auth_payload;
    if (SPP_len > 0){
      memcpy(auth_ptr, SPP, SPP_len);
      auth_ptr += SPP_len;
    }
    memcpy(auth_ptr, &tf->sh->SPI, 2);
    auth_ptr += 2;
    memcpy(auth_ptr, tf->sh->SN, sa->SA_length_SN);
    auth_ptr += sa->SA_length_SN;
    memcpy(auth_ptr, tf->sh->PL, sa->SA_length_PL);
    auth_ptr += sa->SA_length_PL;
    memcpy(auth_ptr, tf->data_field, data_field_len);

    // Apply the bit mask
    applyBitmask(auth_payload, auth_len, sa, 0, usingTM, usingTC, usingTC_SH);

    // Initialise OpenSSL
    EVP_MAC_CTX* mctx = EVP_MAC_CTX_new(sa->SA_authentication_algorithm);
    if (mctx == NULL){
      printf("[ERROR] Failed to initialise OpenSSL context\n");
      freeMemory(memory);
      return NULL;
    }

    // Construct the OSSL parameters for the digest to utilise
    OSSL_PARAM params[4], *p = params;
    // If HMAC, get SHA256
    if (sa->SA_authentication_algorithm == EVP_MAC_fetch(NULL, "HMAC", NULL)){
      *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", strlen("SHA256"));
    // IF CMAC, get AES-256-CBC
    } else {
      *p++ = OSSL_PARAM_construct_utf8_string("cipher", "AES-256-CBC", strlen("AES-256-GCM"));
    }
    *p = OSSL_PARAM_construct_end();

    // Initialise MAC
    if (EVP_MAC_init(mctx, sa->SA_authentication_key, strlen((char*)sa->SA_authentication_key), params) != 1){
      printf("[ERROR] Failed to initialise MAC\n");
      freeMemory(memory);
      EVP_MAC_CTX_free(mctx);
      return NULL;
    }

    // Process the data_field data
    if (EVP_MAC_update(mctx, auth_payload, auth_len) != 1){
      printf("[ERROR] Failed to update MAC\n");
      freeMemory(memory);
      EVP_MAC_CTX_free(mctx);
      return NULL;
    }

    // Gather the MAC's length
    size_t mac_len;
    if (EVP_MAC_final(mctx, NULL, &mac_len, 0) != 1){
      printf("[ERROR] Failed to finalise MAC\n");
      freeMemory(memory);
      EVP_MAC_CTX_free(mctx);
      return NULL;
    }

    // Gather the MAC
    unsigned char* mac_value = malloc(mac_len);
    if (EVP_MAC_final(mctx, mac_value, &mac_len, mac_len) != 1){
      printf("[ERROR] Failed to finalise MAC\n");
      freeMemory(memory);
      EVP_MAC_CTX_free(mctx);
      return NULL;
    }
    memory[2] = mac_value;

    // If the MACs match, the data_field is verified
    if (memcmp(mac_value, tf->st->MAC, sa->SA_length_MAC) == 0) {
      printf("MAC verified\n");
    } else {
      printf("[ERROR] MAC verification failed\n");
      psr->verification_status = 0;
      psr->verification_code = 2;
      free(auth_payload);
      free(mac_value);
      EVP_MAC_CTX_free(mctx);
      return psr;
    }

    // Free memory
    EVP_MAC_CTX_free(mctx);

    // Gather the sequence number
    uint64_t sn = receiveSN(tf, sa, 0);
    if (sn == 0){
      printf("[ERROR] Failed to receive sequence number or rollover occurred, handle accordingly\n");
    }
    // TODO: For testing with 1 SA in file, remove after.
    sa->SA_sequence_number--;

    // Check for proper SN
    if (sn > sa->SA_sequence_number) {
      if (sn - sa->SA_sequence_number <= sa->SA_window_size) {
        sa->SA_sequence_number = sn;
        printf("Sequence number verified\n");
      } else {
        printf("[ERROR] Sequence number outside window\n");
        psr->verification_status = 0;
        psr->verification_code = 3;
        free(auth_payload);
        free(mac_value);
        return psr;
      }
    } else {
      printf("[ERROR] Sequence number lower than current one\n");
      psr->verification_status = 0;
      psr->verification_code = 3;
      free(auth_payload);
      free(mac_value);
      return psr;
    }

    // Populate return structure
    psr->data_field = malloc(data_field_len + 1);
    if (psr->data_field == NULL){
      printf("[ERROR] Failed to allocate data_field\n");
      freeMemory(memory);
      return NULL;
    }
    memcpy(psr->data_field, tf->data_field, data_field_len);
    psr->data_field[data_field_len] = '\0';
    psr->verification_code = 0;
    psr->verification_status = 1;

    // Free memory
    free(auth_payload);
    free(mac_value);

    // Logging print
    printf("Finished receiving authentication only.\n");
  }
  // If the SA service type is encrypted authentication
  if (sa->SA_service_type == 2){
    // Logging print
    printf("Performing authenticated encryption...\n");

    // Build security header + data_field for authentication data_field
    size_t auth_len = 2 + sa->SA_length_IV + sa->SA_length_PL;
    if (SPP_len > 0){
      auth_len += SPP_len;
    }
    unsigned char* auth_payload = malloc(auth_len);
    if (auth_payload == NULL){
      printf("[ERROR] Failed to allocate auth_payload\n");
      freeMemory(memory);
      return NULL;
    }
    memory[1] = auth_payload;
    unsigned char* auth_ptr = auth_payload;
    if (SPP_len > 0){
      memcpy(auth_ptr, SPP, SPP_len);
      auth_ptr += SPP_len;
    }
    memcpy(auth_ptr, &tf->sh->SPI, 2);
    auth_ptr += 2;
    memcpy(auth_ptr, tf->sh->IV, sa->SA_length_IV);
    auth_ptr += sa->SA_length_IV;
    memcpy(auth_ptr, tf->sh->PL, sa->SA_length_PL);
    auth_ptr += sa->SA_length_PL;

    // Apply authentication bit mask
    applyBitmask(auth_payload, auth_len, sa, 1, usingTM, usingTC, usingTC_SH);

    // Initialise OpenSSL context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL){
      printf("[ERROR] Failed to initialise OpenSSL context");
      freeMemory(memory);
      return NULL;
    }
    int len;
    int plaintext_len;
    int ciphertext_len = strlen(tf->data_field);

    // Initialise encryption
    if (EVP_DecryptInit_ex(ctx, sa->SA_encryption_algorithm, NULL, NULL, NULL) != 1){
      printf("[ERROR] Failed to initialise encryption");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Change IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sa->SA_length_IV, NULL) != 1){
      printf("[ERROR] Failed to set IV length");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Initialise key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, sa->SA_encryption_key, tf->sh->IV) != 1){
      printf("[ERROR] Failed to initialise key and IV");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Provide AAD
    if (EVP_DecryptUpdate(ctx, NULL, &len, auth_payload, auth_len) != 1){
      printf("[ERROR] Failed to provide AAD");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Buffer for ciphertext with space for padding
    unsigned char plaintext[strlen(tf->data_field) + EVP_CIPHER_block_size(sa->SA_encryption_algorithm)];

    // Provide the plaintext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, tf->data_field, ciphertext_len) != 1){
      printf("[ERROR] Failed to provide ciphertext");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }
    plaintext_len = len;

    // Set expected MAC/tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sa->SA_length_MAC, tf->st->MAC) != 1){
      printf("[ERROR] Failed to set MAC/tag");
      freeMemory(memory);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Finalise encryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1){
      printf("[ERROR] MAC verification failed");
      psr->verification_status = 0;
      psr->verification_code = 2;
      free(auth_payload);
      EVP_CIPHER_CTX_free(ctx);
      return psr;
    }
    printf("MAC verified\n");
    plaintext_len += len;

    // Free memory
    EVP_CIPHER_CTX_free(ctx);

    // Gather the sequence number
    uint64_t sn = receiveSN(tf, sa, 1);
    if (sn == 0){
      printf("[ERROR] Failed to receive sequence number or rollover occurred, handle accordingly\n");
    }
    // TODO: For testing with 1 SA in file, remove after.
    sa->SA_sequence_number--;

    // Check for proper SN
    if (sn > sa->SA_sequence_number) {
      if (sn - sa->SA_sequence_number <= sa->SA_window_size) {
        sa->SA_sequence_number = sn;
        printf("Sequence number verified\n");
      } else {
        printf("[ERROR] Sequence number outside window\n");
        psr->verification_status = 0;
        psr->verification_code = 3;
        free(auth_payload);
        return psr;
      }
    } else {
      printf("[ERROR] Sequence number lower than current one\n");
      psr->verification_status = 0;
      psr->verification_code = 3;
      free(auth_payload);
      return psr;
    }

    // Store the ciphertext
    psr->data_field = malloc(plaintext_len);
    if (psr->data_field == NULL){
      printf("[ERROR] Failed to allocate data_field");
      freeMemory(memory);
      return NULL;
    }
    memcpy(psr->data_field, plaintext, plaintext_len);
    psr->verification_status = 1;
    psr->verification_code = 0;

    // Free memory
    free(auth_payload);

    // Logging print
    printf("Finished authenticated encryption.\n");
  }
  // Return the process security return structure
  return psr;
}
