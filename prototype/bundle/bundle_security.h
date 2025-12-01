#pragma once
#include "bundle_canocalization.h"

// keys for the protocol, HMAC and AES are hardcoded since management of them is out of scope

// hardcoded HMAC key, 32 bytes
const unsigned char* HMAC_KEY = (unsigned char*)"01234567890123456789012345678901";
// hardcoded AES key, 16 bytes
const unsigned char* AES_KEY  = (unsigned char*)"0123456789012345";
// public key for PIB
EVP_PKEY* RSA_KEYS;

// bundle security (BAB, PIB, and PCB)

// applies the integrity with PIB, encryption with PCB to the payload, or hop-by-hop authentication with BAB
void applyBundleSecurity(bundle* b, int use_bab, int use_pib, int use_pcb) {
    // apply BAB
    if (use_bab){
        // allocate and initialise the 1st BAB
        b->bab = malloc(sizeof(bundleSecurityBlock));
        // block type is 2 for BAB
        b->bab->block_type = BLOCK_TYPE_BAB; 
        // for now no flags
        b->bab->proc_flags = 0;
        // ciphersuite ID is 1 for BAB
        b->bab->ciphersuite_id = 1;
        // correlator field to link with 2nd BAB
        b->bab->correlator = 45;

        // allocate and initialise the 2nd BAB
        b->bab2 = malloc(sizeof(bundleSecurityBlock));
        // block type is 2 for BAB
        b->bab2->block_type = BLOCK_TYPE_BAB; 
        // for now no flags
        b->bab2->proc_flags = 0;
        // ciphersuite ID is 1 for BAB
        b->bab2->ciphersuite_id = 1;
        // correlator field to link with 1st BAB
        b->bab2->correlator = 45;

        // create ciphersuite parameter for key-information (AES key)
        // NOTE: key is sent in the clear, massive security flaw but key management is out of scope, so it's abstracted for the purposes of this prototype
        ciphersuite_params* key_info = malloc(sizeof(ciphersuite_params));
        key_info->type = 3;
        key_info->len = 32;
        key_info->value = malloc(33);
        memcpy(key_info->value, HMAC_KEY, 32);
        key_info->value[32] = '\0';
        b->bab->ciphersuite_params[0] = key_info;

        // ciphersuite_flags (0000110) and (0000011)
        b->bab->ciphersuite_flags = 6;
        b->bab2->ciphersuite_flags = 3;

        // NOTE: lengths have been abstracted until de/serializing has been implemented properly
        b->bab->block_length = 0;
        b->bab2->block_length = 0;

        // pre-allocate result for HMAC-SHA1 (20 bytes)
        b->bab2->security_result_len = 20; 
        b->bab2->security_result = malloc(b->bab2->security_result_len); 

        // strict canocalize the bundle
        uint8_t* strict;
        size_t strict_len = 0;
        canonicalizeStrict(b, b->bab->ciphersuite_id, &strict, &strict_len);

        // compute the HMAC-SHA1 over the payload
        // fetch the HMAC implementation
        EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        // create new MAC
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string("digest", "SHA1", strlen("SHA1")),
                OSSL_PARAM_construct_end()
        };

        // initialize with the key and digest
        EVP_MAC_init(ctx, HMAC_KEY, strlen((char*)HMAC_KEY), params);
        // feed in the strictly canocalized bundle
        EVP_MAC_update(ctx, strict, strict_len);
    
        // finalize and store the MAC
        size_t mac_len = 0;
        // get the output length
        EVP_MAC_final(ctx, NULL, &mac_len, 0);
        // write the MAC output
        EVP_MAC_final(ctx, b->bab2->security_result, &mac_len, mac_len);

        // clean up allocated memory
        free(strict);
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);

    }
    // apply PCB
    if (use_pcb) {
        // allocate and initialize the PCB
        b->pcb = malloc(sizeof(bundleSecurityBlock));
        // block type is 4 for PCB
        b->pcb->block_type = BLOCK_TYPE_PCB;
        // for now, no flags
        b->pcb->proc_flags = 0;
        // ciphersuite ID is 3 for PCB
        b->pcb->ciphersuite_id = 3;
        // // NOTE: length has been abstracted until de/serializing has been implemented properly
        b->pcb->block_length = 0;
        // ciphersuite flags (0000101)
        b->pcb->ciphersuite_flags = 5;

        // generate initialization vector (IV) for AES-GCM
        // 96-bit IV for GCM
        unsigned char iv[12];
        // use random for secure IV
        RAND_bytes(iv, sizeof(iv));

        // set up AES-128-GCM encryption
        // create cipher
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        // initialize cipher type
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
        // set IV length
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
        // set encryption key and IV
        EVP_EncryptInit_ex(ctx, NULL, NULL, AES_KEY, iv);

        // encrypt the payload
        int len = 0;
        // allocate space for ciphertext
        unsigned char* ciphertext = malloc(b->payload->payload_len + EVP_CIPHER_block_size(EVP_aes_128_gcm()));
        // encrypt the payload
        EVP_EncryptUpdate(ctx, ciphertext, &len, b->payload->payload, b->payload->payload_len);
        int ciphertext_len = len;
        // finalize the encryption
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
        ciphertext_len += len;

        // extract the authentication tag which is used for checking integrity during decryption
        unsigned char tag[16];
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);

        // create a ciphersuite parameter for salt (first 4 bytes of IV)
        ciphersuite_params* salt = malloc(sizeof(ciphersuite_params));
        salt->type = 7;
        salt->len = 4;
        salt->value = malloc(4);
        memcpy(salt->value, iv, 4);

        // create a ciphersuite parameter for IV (remaining bytes of IV)
        ciphersuite_params* iv_param = malloc(sizeof(ciphersuite_params));
        iv_param->type = 1;
        iv_param->len = 8;
        iv_param->value = malloc(8);
        memcpy(iv_param->value, iv + 4, 8);

        // create ciphersuite parameter for key-information (AES key)
        // NOTE: key is sent in the clear, massive security flaw but key management is out of scope, so it's abstracted for the purposes of this prototype
        ciphersuite_params* key_info = malloc(sizeof(ciphersuite_params));
        key_info->type = 3;
        key_info->len = 16;
        key_info->value = malloc(16);
        memcpy(key_info->value, AES_KEY, 16);

        // NOTE: length has been abstracted until de/serializing has been implemented properly
        b->pcb->ciphersuite_params_len = 0;

        // populate ciphersuite_arams
        b->pcb->ciphersuite_params[0] = salt;
        b->pcb->ciphersuite_params[1] = iv_param;
        b->pcb->ciphersuite_params[2] = key_info;

        // store the tag in the PCB block
        b->pcb->security_result_len = sizeof(tag);
        b->pcb->security_result = malloc(b->pcb->security_result_len);
        memcpy(b->pcb->security_result, tag, sizeof(tag));

        // replace the original payload with the encrypted version
        free(b->payload->payload);
        b->payload->payload = malloc(ciphertext_len);
        memcpy(b->payload->payload, ciphertext, ciphertext_len);
        b->payload->payload_len = ciphertext_len;

        // clean up the ciphertext
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
    }
    // apply PIB
    if (use_pib) {
        // allocate and initialize the PIB
        b->pib = malloc(sizeof(bundleSecurityBlock));
        // if block type is 3, PIB
        b->pib->block_type = BLOCK_TYPE_PIB;
        // for now, no flags
        b->pib->proc_flags = 0;
        // ciphersuite ID is 
        b->pib->ciphersuite_id = 2;
        // EID-reference to security-source to abstract SignedData type's SignerInfo
        b->pib->eid_reference_list = malloc(sizeof(eid_reference_list));
        b->pib->eid_reference_list->security_source = strdup(b->primary->source_eid);
        // ciphersuite flags (0010001)
        b->pib->ciphersuite_flags = 17;

        // NOTE: length has been abstracted until de/serializing has been implemented properly
        b->pib->block_length = 0;

        // set security_result_len to 0 for canocalization
        b->pib->security_result_len = 0;

        // mutable canocalize the bundle
        uint8_t* mutable;
        size_t mutable_len = 0;
        canonicalizeMut(b, &mutable, &mutable_len);

        // setup RSA variables
        RSA_KEYS = EVP_RSA_gen(1024);
        EVP_PKEY* signing_key = RSA_KEYS;

        // setup hash context
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

        // setup and initialise RSA with the RSA signing key
        EVP_PKEY_CTX* pctx = NULL;
        EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, signing_key);

        // set padding to PKCS1
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);

        // provide the mutable canocalization
        EVP_DigestSignUpdate(mdctx, mutable, mutable_len);

        // get the output length
        size_t siglen = 0;
        EVP_DigestSignFinal(mdctx, NULL, &siglen);
        uint8_t* sig = malloc(siglen);

        // write the signature output
        EVP_DigestSignFinal(mdctx, sig, &siglen);
        b->pib->security_result = malloc(siglen);
        memcpy(b->pib->security_result, sig, siglen);
        b->pib->security_result_len = siglen;

        // clean up allocated memory
        free(mutable);
        free(sig);
        EVP_MD_CTX_free(mdctx);
    }
}

// verifies the integrity and/or decrypts the payload
int processBundleSecurity(bundle* b, int verify_bab, int verify_pib, int decrypt_pcb) {
    // verify BAB
    if (verify_bab && b->bab && b->bab2) {
        // strict canocalize the bundle
        uint8_t* strict;
        size_t strict_len = 0;
        canonicalizeStrict(b, b->bab->ciphersuite_id, &strict, &strict_len);

        // get the key
        uint8_t* key = malloc(32);
        memcpy(key, b->bab->ciphersuite_params[0]->value, 32);

        // recompute the HMAC over strict
        EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string("digest", "SHA1", strlen("SHA1")),
                OSSL_PARAM_construct_end()
        };

        EVP_MAC_init(ctx, key, 32, params);
        EVP_MAC_update(ctx, strict, strict_len);

        // finalize and compare with the stored MAC
        size_t mac_len = 0;
        unsigned char* computed_mac = malloc(b->bab2->security_result_len);
        EVP_MAC_final(ctx, computed_mac, &mac_len, b->bab2->security_result_len);

        // constant time comparision
        int verified = memcmp(computed_mac, b->bab2->security_result, mac_len) == 0;
        free(computed_mac);
        free(strict);
        free(key);
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);

        // if integrity check fails, MAC verification fails
        if (!verified) {
            fprintf(stderr, "[ERROR] Bundle Authentication Block: MAC verification failed\n");
            return -1;
        }
        // else the MAC is verified
        else {
            printf("Bundle Authentication Block: MAC verified\n");
        }

    }
    // verify PIB
    if (verify_pib && b->pib) {
        // get the correct RSA public key
        // NOTE: hardcoded for now to simulate key management
        if (strcmp(b->pib->eid_reference_list->security_source, "dtn://hubble-telescope-1/app/data-logger") != 0){
            RSA_KEYS = EVP_RSA_gen(1024);
        }

        // store original values
        uint8_t* sig = malloc(b->pib->security_result_len);
        memcpy(sig, b->pib->security_result, b->pib->security_result_len);
        size_t sig_len = b->pib->security_result_len;

        // prepare for canocalisation
        b->pib->security_result_len = 0;
        b->pib->security_result = NULL;
        
        // mutable canocalize the bundle
        uint8_t* mutable;
        size_t mutable_len;
        canonicalizeMut(b, &mutable, &mutable_len);

        // restore canocalization preparation
        b->pib->security_result_len = sig_len;
        b->pib->security_result = sig;

        // setup hash context
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

        // setup RSA variables
        EVP_PKEY* verify_key = RSA_KEYS;

        // setup and initialise RSA with the RSA signing key
        EVP_PKEY_CTX* pctx = NULL;
        EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha256(), NULL, RSA_KEYS);

        // set padding to PKCS1
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);

        // provide mutable canocalization
        EVP_DigestVerifyUpdate(mdctx, mutable, mutable_len);

        // perform verification
        int verified = EVP_DigestVerifyFinal(mdctx, b->pib->security_result, b->pib->security_result_len);
        free(mutable);
        EVP_MD_CTX_free(mdctx);

        // check the verification status
        if (!verified) {
            fprintf(stderr, "[ERROR] Payload Integrity Block: Signature verification failed\n");
            return -1;
        }
        else {
            printf("Payload Integrity Block: Signature verification successful\n");
        }
    }
    // verify PCB
    if (decrypt_pcb && b->pcb) {
        // get the IV
        uint8_t* iv = malloc(12);
        memcpy(iv, b->pcb->ciphersuite_params[0]->value, 4);
        memcpy(iv + 4, b->pcb->ciphersuite_params[1]->value, 8);

        // get the key
        uint8_t* key = b->pcb->ciphersuite_params[2]->value;

        // get the tag
        uint8_t* tag = b->pcb->security_result;

        // extract the ciphertext from the payload
        unsigned char* ciphertext = b->payload->payload;
        int ciphertext_len = b->payload->payload_len;

        // set up AES-GCM decryption
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

        // decrypt the ciphertext
        unsigned char* plaintext = malloc(ciphertext_len);
        int len = 0;
        int plaintext_len = 0;
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
        plaintext_len += len;

        // finalize the decryption and verify the tag
        // if this executes, authentication has failed
        if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
            fprintf(stderr, "[ERROR] Payload Confidentiality Block: ICV verification failed\n");
            free(plaintext);
            free(iv);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        // replace the encrypted payload with plaintext
        free(b->payload->payload);
        b->payload->payload = malloc(plaintext_len + 1);
        memcpy(b->payload->payload, plaintext, plaintext_len);
        b->payload->payload_len = plaintext_len;
        b->payload->payload[plaintext_len] = '\0';

        // clean up allocated memory
        free(plaintext);
        free(iv);
        EVP_CIPHER_CTX_free(ctx);
        // print a success message
        printf("Payload Confidentiality Block: Decryption successful\n");
    }

    return 0;
}