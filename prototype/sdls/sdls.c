#include "security_association.h"
#include "sdls_helper.h"

transferFrame* ApplySecurity(securityAssociation** sa_array, unsigned int sa_array_size, unsigned int GVCID, unsigned int GMAP_ID, unsigned char* plaintext, int plaintext_len) {
  printf("ApplySecurity()...\n");

  // Find the appropriate SA
  securityAssociation* sa = FindSA(sa_array, sa_array_size, GVCID, GMAP_ID);
  if (sa == NULL){
    printf("[ERROR] No SA was found\n");
    return NULL;
  }

  // Initialise a transfer frame and its security header (ApplySecurity Return)
  transferFrame* tf = malloc(sizeof(transferFrame));
  if (tf == NULL){
    printf("[ERROR] Failed to allocate transferFrame\n");
    return NULL;
  }
  tf->sh = malloc(sizeof(securityHeader));
  if (tf->sh == NULL){
    printf("[ERROR] Failed to allocate securityHeader\n");
    free(tf);
    return NULL;
  }

  // If the SA service type is encryption only
  if (sa->SA_service_type == 1) {
    // Logging print
    printf("Performing encryption only...\n");
    printf("Plaintext provided (%d bytes): \"%s\"\n", plaintext_len, plaintext);

    // Initialise OpenSSL context and variables
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL){
      printf("[ERROR] Failed to initialise OpenSSL context\n");
      free(tf->sh);
      free(tf);
      return NULL;
    }
    int update_len;
    int total_len;

    // Buffer for ciphertext with space for padding
    unsigned char ciphertext[plaintext_len + EVP_CIPHER_block_size(sa->SA_encryption_algorithm)];

    // Initialise encryption
    if (EVP_EncryptInit_ex(ctx, sa->SA_encryption_algorithm, NULL, sa->SA_encryption_key, sa->SA_initialization_vector) != 1){
      printf("[ERROR] Failed to initialise encryption\n");
      free(tf->sh);
      free(tf);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Pass the plaintext to the encryption
    if (EVP_EncryptUpdate(ctx, ciphertext, &update_len, plaintext, plaintext_len) != 1){
      printf("[ERROR] Failed to update encryption\n");
      free(tf->sh);
      free(tf);
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }
    total_len = update_len;

    // Finalise encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + update_len, &update_len) != 1){
      printf("[ERROR] Failed to finalise encryption\n");
      free(tf->sh);
      free(tf);
      EVP_CIPHER_CTX_free(ctx);
      return NULL; 
    }
    total_len += update_len;

    // Free context
    EVP_CIPHER_CTX_free(ctx);

    // Populate the Security Header
    processSPI(tf, sa);
    processIV(tf, sa, 0);
    processPL(tf, sa, total_len - plaintext_len);
    
    // Populate data_field
    tf->data_field = malloc(total_len);
    if (tf->data_field == NULL){
      printf("[ERROR] Failed to allocate data_field\n");
      free(tf->sh);
      free(tf);
      return NULL;
    }
    memcpy(tf->data_field, ciphertext, total_len);

    // Logging print
    printf("Finished encryption only.\n");
  }
  // If the SA service type is authentication only
  else if (sa->SA_service_type == 0) {
    // Logging print
    printf("Performing authentication only...\n");
    printf("Plaintext provided (%d bytes): \"%s\"\n", plaintext_len, plaintext);

    // Handle sequence number increment and rollover
    // TODO: Do we want to do anything with SN rollover?
    sa->SA_sequence_number++;

    // Populate Security Header
    processSPI(tf, sa);
    processSN(tf, sa);
    // TODO: Make sure that all padding are correct
    processPL(tf, sa, 0);

    // Populate data_field
    tf->data_field = malloc(plaintext_len);
    if (tf->data_field == NULL){
      p_error("Failed to allocate data_field");
    }
    memcpy(tf->data_field, plaintext, plaintext_len);

    // Build security header + data_field for authentication data_field
    // TODO: Incorporate SPP protocol headers (TM, TC, etc)
    size_t auth_len = 2 + sa->SA_length_SN + sa->SA_length_PL + plaintext_len;
    unsigned char* auth_payload = malloc(auth_len);
    if (auth_payload == NULL){
      p_error("Failed to allocate auth_payload");
    }
    unsigned char* auth_ptr = auth_payload;
    memcpy(auth_ptr, &tf->sh->SPI, 2);
    auth_ptr += 2;
    memcpy(auth_ptr, tf->sh->SN, sa->SA_length_SN);
    auth_ptr += sa->SA_length_SN;
    memcpy(auth_ptr, tf->sh->PL, sa->SA_length_PL);
    auth_ptr += sa->SA_length_PL;
    memcpy(auth_ptr, tf->data_field, plaintext_len);

    // Since no IV, not bit mask required. (Until SPP protocol headers are implemented)

    // Initialise OpenSSL
    EVP_MAC_CTX* mctx = EVP_MAC_CTX_new(sa->SA_authentication_algorithm);
    if (mctx == NULL){
      p_error("Failed to initialise OpenSSL context");
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
      p_error("Failed to initialise MAC");
    }

    // Process the data_field data
    if (EVP_MAC_update(mctx, auth_payload, auth_len) != 1){
      p_error("Failed to update MAC");
    }

    // Gather the MAC's length
    size_t mac_len;
    if (EVP_MAC_final(mctx, NULL, &mac_len, 0) != 1){
      p_error("Failed to finalise MAC");
    }

    // Gather the MAC
    unsigned char* mac_value = malloc(mac_len);
    if (mac_value == NULL){
      p_error("Failed to allocate mac_value");
    }
    if (EVP_MAC_final(mctx, mac_value, &mac_len, mac_len) != 1){
      p_error("Failed to finalise MAC");
    }

    // Allocate security trailer
    tf->st = malloc(sizeof(securityTrailer));
    if (tf->st == NULL){
      p_error("Failed to allocate securityTrailer");
    }

    // Allocate MAC
    size_t sa_mac_length = sa->SA_length_MAC;
    tf->st->MAC = malloc(sa_mac_length);
    if (tf->st->MAC == NULL){
      p_error("Failed to allocate MAC");
    }

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
    processSPI(tf, sa);
    processIV(tf, sa, 1);
    processPL(tf, sa, 0);

    // Build security header + data_field for authentication data_field
    size_t auth_len = 2 + sa->SA_length_IV + sa->SA_length_PL;
    unsigned char* auth_payload = malloc(auth_len);
    if (auth_payload == NULL){
      p_error("Failed to allocate auth_payload");
    }
    unsigned char* auth_ptr = auth_payload;
    memcpy(auth_ptr, &tf->sh->SPI, 2);
    auth_ptr += 2;
    memcpy(auth_ptr, tf->sh->IV, sa->SA_length_IV);
    auth_ptr += sa->SA_length_IV;
    memcpy(auth_ptr, tf->sh->PL, sa->SA_length_PL);
    auth_ptr += sa->SA_length_PL;

    // Apply authentication bit mask
    applyBitmask(auth_payload, auth_len, sa, 1);

    // Initialise OpenSSL context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL){
      p_error("Failed to initialise OpenSSL context");
    }
    int len;
    int ciphertext_len;

    // Initialise encryption
    if (EVP_EncryptInit_ex(ctx, sa->SA_encryption_algorithm, NULL, NULL, NULL) != 1){
      p_error("Failed to initialise encryption");
    }

    // Change IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sa->SA_length_IV, NULL) != 1){
      p_error("Failed to set IV length");
    }

    // Initialise key and IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, sa->SA_encryption_key, tf->sh->IV) != 1){
      p_error("Failed to initialise key and IV");
    }

    // Provide AAD
    if (EVP_EncryptUpdate(ctx, NULL, &len, auth_payload, auth_len) != 1){
      p_error("Failed to provide AAD");
    }

    // Buffer for ciphertext with space for padding
    unsigned char ciphertext[plaintext_len + EVP_CIPHER_block_size(sa->SA_encryption_algorithm)];

    // Provide the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1){
      p_error("Failed to provide plaintext");
    }
    ciphertext_len = len;

    // Finalise encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1){
      p_error("Failed to finalise encryption");
    }
    ciphertext_len += len;

    // Get the tag
    unsigned char* tag = malloc(sa->SA_length_MAC);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sa->SA_length_MAC, tag) != 1){
      p_error("Failed to get tag");
    }

    // Free memory
    EVP_CIPHER_CTX_free(ctx);

    // Store the ciphertext
    tf->data_field = malloc(ciphertext_len);
    if (tf->data_field == NULL){
      p_error("Failed to allocate data_field");
    }
    memcpy(tf->data_field, ciphertext, ciphertext_len);

    // Allocate Security Trailer
    tf->st = malloc(sizeof(securityTrailer));
    if (tf->st == NULL){
      p_error("Failed to allocate securityTrailer");
    }

    // Allocate MAC
    size_t sa_mac_length = sa->SA_length_MAC;
    tf->st->MAC = malloc(sa_mac_length);
    if (tf->st->MAC == NULL){
      p_error("Failed to allocate MAC");
    }

    // Handle padding/truncating
    size_t mac_len = strlen(tag);
    if (mac_len > sa_mac_length){
      mac_len = sa_mac_length;
    }
    memcpy(tf->st->MAC, tag, mac_len);
    if (mac_len < sa_mac_length){
      memset(tf->st->MAC + mac_len, 0x00, sa_mac_length - mac_len);
    }

    // Logging print
    printf("Finished authenticated encryption.\n");
  }
  // Return the transfer frame
  return tf;
}

processSecurityReturn* ProcessSecurity(securityAssociation** sa_array, unsigned int sa_array_size, transferFrame* tf, unsigned int GVCID, unsigned int GMAP_ID) {
  printf("ProcessSecurity()...\n");

  // Initialise return structure
  processSecurityReturn* psr = malloc(sizeof(processSecurityReturn));
  if (psr == NULL){
    p_error("Failed to allocate processSecurityReturn");
  }
  psr->verification_status = 0;
  size_t data_field_len = strlen(tf->data_field);

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
      p_error("Failed to initialise OpenSSL context");
    }
    int updateLen;
    int totalLen;

    // Buffer for plaintext
    unsigned char plaintext[data_field_len];

    // Initialise decryption
    if (EVP_DecryptInit_ex(ctx, sa->SA_encryption_algorithm, NULL, sa->SA_encryption_key, sa->SA_initialization_vector) != 1){
      p_error("Failed to initialise decryption");
    }

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &updateLen, tf->data_field, data_field_len) != 1){
      p_error("Failed to update decryption");
    }
    totalLen = updateLen;

    // Finalise decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + updateLen, &updateLen) != 1){
      p_error("Failed to finalise decryption");
    }
    totalLen += updateLen;

    // Free context
    EVP_CIPHER_CTX_free(ctx);

    // Populate return structure
    psr->data_field = malloc(totalLen);
    if (psr->data_field == NULL){
      p_error("Failed to allocate data_field");
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
    // TODO: handle SPP protocol headers
    size_t auth_len = 2 + sa->SA_length_SN + sa->SA_length_PL + strlen(tf->data_field);
    unsigned char* auth_payload = malloc(auth_len);
    if (auth_payload == NULL){
      p_error("Failed to allocate auth_payload");
    }
    unsigned char* auth_ptr = auth_payload;
    memcpy(auth_ptr, &tf->sh->SPI, 2);
    auth_ptr += 2;
    memcpy(auth_ptr, tf->sh->SN, sa->SA_length_SN);
    auth_ptr += sa->SA_length_SN;
    memcpy(auth_ptr, tf->sh->PL, sa->SA_length_PL);
    auth_ptr += sa->SA_length_PL;
    memcpy(auth_ptr, tf->data_field, data_field_len);

    // Since no IV, no bit mask needed (Until SPP protocol headers)

    // Initialise OpenSSL
    EVP_MAC_CTX* mctx = EVP_MAC_CTX_new(sa->SA_authentication_algorithm);
    if (mctx == NULL){
      p_error("Failed to initialise OpenSSL context");
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
      p_error("Failed to initialise MAC");
    }

    // Process the data_field data
    if (EVP_MAC_update(mctx, auth_payload, auth_len) != 1){
      p_error("Failed to update MAC");
    }

    // Gather the MAC's length
    size_t mac_len;
    if (EVP_MAC_final(mctx, NULL, &mac_len, 0) != 1){
      p_error("Failed to finalise MAC");
    }

    // Gather the MAC
    unsigned char* mac_value = malloc(mac_len);
    if (EVP_MAC_final(mctx, mac_value, &mac_len, mac_len) != 1){
      p_error("Failed to finalise MAC");
    }

    // If the MACs match, the data_field is verified
    if (memcmp(mac_value, tf->st->MAC, sa->SA_length_MAC) == 0) {
      printf("MAC verified\n");
    } else {
      printf("[ERROR] MAC verification failed\n");
      psr->verification_status = 0;
      psr->verification_code = 2;
      return psr;
    }

    // Gather the sequence number
    uint64_t sn = receiveSN(tf, sa, 0);
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
        return psr;
      }
    } else {
      printf("[ERROR] Sequence number lower than current one\n");
      psr->verification_status = 0;
      psr->verification_code = 3;
      return psr;
    }

    // Populate return structure
    psr->data_field = malloc(data_field_len + 1);
    if (psr->data_field == NULL){
      p_error("Failed to allocate data_field");
    }
    memcpy(psr->data_field, tf->data_field, data_field_len);
    psr->data_field[data_field_len] = '\0';
    psr->verification_code = 0;
    psr->verification_status = 1;

    // Free memory
    free(auth_payload);

    // Logging print
    printf("Finished receiving authentication only.\n");
  }
  // If the SA service type is encrypted authentication
  if (sa->SA_service_type == 2){
    // Logging print
    printf("Performing authenticated encryption...\n");

    // Build security header + data_field for authentication data_field
    // TODO: handle SPP protocol headers
    size_t auth_len = 2 + sa->SA_length_IV + sa->SA_length_PL;
    unsigned char* auth_payload = malloc(auth_len);
    if (auth_payload == NULL){
      p_error("Failed to allocate auth_payload");
    }
    unsigned char* auth_ptr = auth_payload;
    memcpy(auth_ptr, &tf->sh->SPI, 2);
    auth_ptr += 2;
    memcpy(auth_ptr, tf->sh->IV, sa->SA_length_IV);
    auth_ptr += sa->SA_length_IV;
    memcpy(auth_ptr, tf->sh->PL, sa->SA_length_PL);
    auth_ptr += sa->SA_length_PL;

    // Apply authentication bit mask
    applyBitmask(auth_payload, auth_len, sa, 1);

    // Initialise OpenSSL context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL){
      p_error("Failed to initialise OpenSSL context");
    }
    int len;
    int plaintext_len;
    int ciphertext_len = strlen(tf->data_field);

    // Initialise encryption
    if (EVP_DecryptInit_ex(ctx, sa->SA_encryption_algorithm, NULL, NULL, NULL) != 1){
      p_error("Failed to initialise encryption");
    }

    // Change IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sa->SA_length_IV, NULL) != 1){
      p_error("Failed to set IV length");
    }

    // Initialise key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, sa->SA_encryption_key, tf->sh->IV) != 1){
      p_error("Failed to initialise key and IV");
    }

    // Provide AAD
    if (EVP_DecryptUpdate(ctx, NULL, &len, auth_payload, auth_len) != 1){
      p_error("Failed to provide AAD");
    }

    // Buffer for ciphertext with space for padding
    unsigned char plaintext[strlen(tf->data_field) + EVP_CIPHER_block_size(sa->SA_encryption_algorithm)];

    // Provide the plaintext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, tf->data_field, ciphertext_len) != 1){
      p_error("Failed to provide ciphertext");
    }
    plaintext_len = len;

    // Set expected MAC/tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sa->SA_length_MAC, tf->st->MAC) != 1){
      p_error("Failed to set MAC/tag");
    }

    // Finalise encryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1){
      printf("[ERROR] MAC verification failed");
      psr->verification_status = 0;
      psr->verification_code = 2;
      return psr;
    }
    printf("MAC verified\n");
    plaintext_len += len;

    // Free memory
    EVP_CIPHER_CTX_free(ctx);

    // Gather the sequence number
    uint64_t sn = receiveSN(tf, sa, 1);
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
        return psr;
      }
    } else {
      printf("[ERROR] Sequence number lower than current one\n");
      psr->verification_status = 0;
      psr->verification_code = 3;
      return psr;
    }

    // Store the ciphertext
    psr->data_field = malloc(plaintext_len);
    if (psr->data_field == NULL){
      p_error("Failed to allocate data_field");
    }
    memcpy(psr->data_field, plaintext, plaintext_len);
    psr->verification_status = 1;
    psr->verification_code = 0;

    // Logging print
    printf("Finished authenticated encryption.\n");
  }
  // Return the process security return structure
  return psr;
}

int main(){
  // Initialise Security Association (auth-enc, AES-256-GCM)
  securityAssociation* sa = malloc(sizeof(securityAssociation));
  sa->SPI = 1;
  sa->SA_sequence_number = 0;
  sa->SA_encryption_algorithm = EVP_aes_256_gcm();
  sa->SA_encryption_key = (unsigned char*) "01234567890123456789012345678901"; // 256 bit key
  sa->SA_initialization_vector = (unsigned char*) "0123456700000000";// 128 bit IV
  sa->SA_authentication_mask = 0x00;
  sa->SA_service_type = 2;
  sa->SA_window_size = 1;
  sa->SA_length_SN = 8;
  sa->SA_length_IV = 16;
  sa->SA_length_PL = 2;
  sa->SA_length_MAC = 16;
  sa->GVCID = 1;
  sa->GMAP_ID = 1;

  // Initialise Security Association (auth/enc)
  // securityAssociation* sa = malloc(sizeof(securityAssociation));
  // sa->SPI = 1;
  // sa->SA_sequence_number = 0;
  // sa->SA_authentication_algorithm = EVP_MAC_fetch(NULL, "HMAC", NULL);
  // sa->SA_encryption_algorithm = EVP_aes_256_ctr();
  // sa->SA_authentication_key = (unsigned char*) "01234567890123456789012345678901"; // 256 bit key
  // sa->SA_encryption_key = (unsigned char*) "01234567890123456789012345678901"; // 256 bit key
  // sa->SA_initialization_vector = (unsigned char*) "0123456700000000"; // 128 bit IV
  // sa->SA_authentication_mask = 0x00;
  // sa->SA_service_type = 0; 
  // sa->SA_window_size = 1;
  // sa->SA_length_SN = 8;
  // sa->SA_length_IV = 16;
  // sa->SA_length_PL = 2;
  // sa->SA_length_MAC = 16;
  // sa->GVCID = 1;
  // sa->GMAP_ID = 1;

  // Duplicate the sa into a second sa for testing
  securityAssociation* sa2 = malloc(sizeof(securityAssociation));
  memcpy(sa2, sa, sizeof(securityAssociation));

  // Make an array of security associations
  securityAssociation* sa_array[2];
  sa_array[0] = sa;
  sa_array[1] = sa2;
  
  // Message to encrypt
  unsigned char* plaintext = (unsigned char*) "Shuuniichido Classmate wo Kau Hanashi: Futari no Jikan, Iiwake no Gosen Yen";
  int plaintext_len = strlen((char*)plaintext);

  // Encrypt the plaintext
  transferFrame* tf = ApplySecurity(sa_array, 2, 1, 1, plaintext, plaintext_len);

  // Print entire security transfer frame
  printf("\n__Transfer Frame__\n");
  printf("Security Header:\n");
  printf("  SPI: ");
  BIO_dump_fp (stdout, (const char *)&tf->sh->SPI, 2);
  if (sa->SA_service_type == 1 || sa->SA_service_type == 2) {
    printf("  IV: ");
    BIO_dump_fp (stdout, (const char *)tf->sh->IV, sa->SA_length_IV);
  }
  if (sa->SA_service_type == 0) {
    printf("  SN: ");
    BIO_dump_fp (stdout, (const char *)tf->sh->SN, sa->SA_length_SN);
  }
  printf("  PL: ");
  BIO_dump_fp (stdout, (const char *)tf->sh->PL, sa->SA_length_PL);
  printf("Transfer Data Field (%d bytes):\n", strlen(tf->data_field));
  BIO_dump_fp (stdout, (const char *)tf->data_field, strlen(tf->data_field));
  if (sa->SA_service_type == 0 || sa->SA_service_type == 2) {
    printf("Security Trailer:\n");
    printf("  MAC: ");
    BIO_dump_fp (stdout, (const char *)tf->st->MAC, sa->SA_length_MAC);
  }
  printf("\n");

  // Decrypt the ciphertext
  processSecurityReturn* psr = ProcessSecurity(sa_array, 2, tf, 1, 1);
  
  // Print the entire ProcessSecurity Return
  printf("\nProcessSecurity Return:\n");
  printf("Decrypted Data Field (%d bytes): %s\n", strlen(psr->data_field), psr->data_field);
  printf("Verified: %d\n", psr->verification_status);
  printf("Verification Code: %d\n", psr->verification_code);

  // Free memory
  if (sa->SA_service_type == 0){
    free(tf->st);
  }
  free(tf->sh);
  free(tf->data_field);
  free(sa);
  free(sa2);
  free(tf);
  free(psr->data_field);
  free(psr);
  return 0;
}