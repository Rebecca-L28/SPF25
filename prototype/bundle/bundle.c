#include "bundle_security.h"

bundle* initialiseBundle(const char* payload_str) {
    bundle* b = malloc(sizeof(bundle));

    // Allocate Primary Block
    b->primary = malloc(sizeof(bundlePrimaryBlock));
    b->primary->version = BUNDLE_VERSION;
    b->primary->proc_flags = 0;
    b->primary->source_eid = strdup("dtn://hubble-telescope-1/app/data-logger");
    b->primary->dest_eid = strdup("dtn://earth-gateway-1/app/telemetry-ingest");
    b->primary->report_to_eid = strdup("dtn://mission-control/app/status-monitor");
    b->primary->custodian_eid = strdup("dtn://relay-sat-3/app/bundle-store");
    b->primary->creation_timestamp = 100000;
    b->primary->sequence_number = 1;
    b->primary->lifetime = 3600;
    b->primary->fragment_offset = 0;
    b->primary->total_adu_length = 0;
    b->primary->dictionary_len = 0;
    b->primary->dictionary = NULL;

    // Allocate Payload Block
    b->payload = malloc(sizeof(bundlePayloadBlock));
    b->payload->block_type = BLOCK_TYPE_PAYLOAD;
    b->payload->proc_flags = 0;
    b->payload->payload_len = strlen(payload_str);
    b->payload->payload = malloc(b->payload->payload_len);
    memcpy(b->payload->payload, payload_str, b->payload->payload_len);
    b->payload->block_length = b->payload->payload_len;

    return b;
}

bundle* initialiseBundle2(const char* payload_str) {
    bundle* b = malloc(sizeof(bundle));

    // Allocate Primary Block
    b->primary = malloc(sizeof(bundlePrimaryBlock));
    b->primary->version = BUNDLE_VERSION;
    b->primary->proc_flags = 0;
    b->primary->source_eid = strdup("dtn://hubble-telescope-1/app/data-logger");
    b->primary->dest_eid = strdup("dtn://earth-gateway-1/app/telemetry-ingest");
    b->primary->report_to_eid = strdup("dtn://mission-control/app/status-monitor");
    b->primary->custodian_eid = strdup("dtn://relay-sat-3/app/bundle-store");
    b->primary->creation_timestamp = 100000;
    b->primary->sequence_number = 1;
    b->primary->lifetime = 3600;
    b->primary->fragment_offset = 0;
    b->primary->total_adu_length = 0;
    b->primary->dictionary_len = 0;
    b->primary->dictionary = NULL;

    // Allocate Payload Block
    b->payload = malloc(sizeof(bundlePayloadBlock));
    b->payload->block_type = BLOCK_TYPE_PAYLOAD;
    b->payload->proc_flags = 0;
    b->payload->payload_len = strlen(payload_str);
    b->payload->payload = malloc(b->payload->payload_len);
    memcpy(b->payload->payload, payload_str, b->payload->payload_len);
    b->payload->block_length = b->payload->payload_len;

    return b;
}

void choice1(unsigned char* payload_str) {
    // Setup the bundle
    bundle* b = initialiseBundle(payload_str);
    
    // Apply BAB
    printf("\nApplying Security (BAB - HMAC)...\n");
    applyBundleSecurity(b, 1, 0, 0); 

    printEntireBundle(b);

    // Verify the BAB
    printf("Verifying Security (BAB - HMAC)...\n");
    processBundleSecurity(b, 1, 0, 0);
    freeBundle(b);
}

void choice2(unsigned char* payload_str) {
    // Setup the bundle
    bundle* b = initialiseBundle(payload_str);
    printf("\nOriginal Payload (%d bytes): %s\n", b->payload->payload_len, b->payload->payload);

    // Apply PCB
    printf("Applying Security (PCB - AES-GCM)...\n");
    applyBundleSecurity(b, 0, 0, 1);

    printEntireBundle(b);

    // Decrypt the PCB
    printf("Verifying Security (PCB - AES-GCM)...\n");
    processBundleSecurity(b, 0, 0, 1);
    printf("Decrypted Payload (%d bytes): %s\n", b->payload->payload_len, b->payload->payload);
    freeBundle(b);
}

void choice3(unsigned char* payload_str) {
    // Setup the bundle
    bundle* b = initialiseBundle(payload_str);

    // Apply PIB
    printf("\nApplying Security (PIB - RSA-SHA256)...\n");
    applyBundleSecurity(b, 0, 1, 0); 

    printEntireBundle(b);

    // Verify the PIB
    printf("Verifying Security (PIB - RSA-SHA256)...\n");
    processBundleSecurity(b, 0, 1, 0);
    freeBundle(b);
}

void choice4(unsigned char* payload_str) {
    // Setup the bundle
    bundle* b = initialiseBundle(payload_str);
    
    // Apply BAB
    printf("\nApplying Security (BAB - HMAC)...\n");
    applyBundleSecurity(b, 1, 0, 0); 

    // Tamper with the MAC to simulate MitM attack
    printf("Simulating Attack: Tampering with MAC...\n");
    b->bab2->security_result[0] ^= 0xFF;
    b->bab2->security_result[1] ^= 0xFF;
    b->bab2->security_result[2] ^= 0xFF;

    // Verify the BAB
    printf("Verifying Security (BAB - HMAC)...\n");
    processBundleSecurity(b, 1, 0, 0);
    freeBundle(b);
}

void choice5(unsigned char* payload_str) {
    // Setup the bundle
    bundle* b = initialiseBundle(payload_str);
    printf("\nOriginal Payload (%d bytes): %s\n", b->payload->payload_len, b->payload->payload);

    // Apply PCB
    printf("Applying Security (PCB - AES-GCM)...\n");
    applyBundleSecurity(b, 0, 0, 1);

    // printAllSecurityBlocks(b);

    // Tamper with ciphertext
    printf("Simulating Attack: Tampering with ciphertext...\n");
    b->pcb->security_result[0] ^= 0xFF;
    b->pcb->security_result[1] ^= 0xFF;
    b->pcb->security_result[2] ^= 0xFF;

    // Decrypt the PCB
    printf("Verifying Security (PCB - AES-GCM)...\n");
    if (processBundleSecurity(b, 0, 0, 1) == 0){
        printf("Decrypted Payload (%d bytes): %s\n", b->payload->payload_len, b->payload->payload);
    }
    freeBundle(b);
}

void choice6(unsigned char* payload_str) {
    // Setup the bundle
    bundle* b = initialiseBundle(payload_str);

    // Apply PIB
    printf("\nApplying Security (PIB - RSA-SHA256)...\n");
    applyBundleSecurity(b, 0, 1, 0); 

    //printAllSecurityBlocks(b);

    // Tamper with the eid_source to get wrong RSA public
    printf("Simulating Attack: Tampering with eid_source...\n");
    b->pib->eid_reference_list->security_source[0] ^= 0xFF;
    b->pib->eid_reference_list->security_source[1] ^= 0xFF;

    // Verify the PIB
    printf("Verifying Security (PIB - RSA-SHA256)...\n");
    processBundleSecurity(b, 0, 1, 0);
    freeBundle(b);
}

void choice7(unsigned char* payload_str) {
    // Setup the bundle
    bundle* b = initialiseBundle2(payload_str);
    
    // Apply BAB
    printf("\nApplying Security (BAB - HMAC)...\n");
    applyBundleSecurity(b, 1, 0, 0); 

    // printAllSecurityBlocks(b);

    // Verify the BAB
    printf("Verifying Security (BAB - HMAC)...\n");
    processBundleSecurity(b, 1, 0, 0);
    freeBundle(b);
}

void choice9(unsigned char* payload_str) {
    // Setup the bundle
    bundle* b = initialiseBundle(payload_str);

    // Apply PCB
    printf("\nApplying Security (PCB - AES-GCM)...\n");
    applyBundleSecurity(b, 0, 0, 1);

    // Apply PIB
    printf("Applying Security (PIB - RSA-SHA256)...\n");
    applyBundleSecurity(b, 0, 1, 0); 

    // Apply BAB
    printf("Applying Security (BAB - HMAC)...\n");
    applyBundleSecurity(b, 1, 0, 0); 

    // printEntireBundle(b);

    // Verify BAB
    processBundleSecurity(b, 1, 0, 0);

    // free BAB
    bundleSecurityBlock* originalBab = b->bab;
    b->bab = NULL;
    bundleSecurityBlock* originalBab2 = b->bab2;
    b->bab2 = NULL;

    // Verify PIB
    processBundleSecurity(b, 0, 1, 0);

    // Verify PCB
    processBundleSecurity(b, 0, 0, 1);

    // Print the recovered payload
    printf("Decrypted Payload (%d bytes): %s\n", b->payload->payload_len, b->payload->payload);

    // Clean up memory
    printf("\n\nWARNING: Following segmentation fault is due to freeing of memory. Cause unknown.\n");
    freeBundle(b);
}

int main(int argc, char* argv[]) {
    // Define the default plaintext
    unsigned char* plaintext = "Hubble Telescope pictures are looking great!";
    size_t plaintext_len = strlen(plaintext);

    // Menu loop
    while (1){
        // Opt for default values
        printf("\n---[Showcase Suite]---\n");
        printf("1. Bundle Authentication Only (BAB - HMAC)\n");
        printf("2. Payload Confidentiality Only (PCB - AES-GCM\n");
        printf("3. Payload Integrity Only (PIB - RSA-SHA256)\n");
        printf("4. MAC Failure (BAB Tampering)\n");
        printf("5. Decryption Failure (PCB Tampering)\n");
        printf("6. Signature Verification Failure (PIB Tampering)\n");
        printf("7. Custom Test (Change in File)\n");
        printf("8. Change Plaintext\n");
        printf("9. All 3 Blocks\n");
        printf("0. Exit\n");
        printf("What to output? ");

        // Prompt user for input
        char buffer[50];
        fgets(buffer, sizeof(buffer), stdin);
        buffer[strcspn(buffer, "\n")] = '\0';

        // Handle each choice
        if (strcmp(buffer, "1") == 0){
            choice1(plaintext);
        } else if (strcmp(buffer, "2") == 0){
            choice2(plaintext);
        } else if (strcmp(buffer, "3") == 0){
            choice3(plaintext);
        } else if (strcmp(buffer, "4") == 0){
            choice4(plaintext);
        } else if (strcmp(buffer, "5") == 0){
            choice5(plaintext);
        } else if (strcmp(buffer, "6") == 0){
            choice6(plaintext);
        } else if (strcmp(buffer, "8") == 0){
            // Prompt for plaintext
            printf("Enter plaintext: ");
            unsigned char buffer3[1000];
            fgets(buffer3, sizeof(buffer3), stdin);
            plaintext = buffer3;
            buffer3[strcspn(buffer3, "\n")] = '\0';
            plaintext_len = strlen(plaintext);

            // Output new plaintext with bytes
            printf("New plaintext (%d bytes): %s\n", plaintext_len, plaintext);
            continue;
        } else if (strcmp(buffer, "7") == 0){
            choice7(plaintext);
        } else if (strcmp(buffer, "9") == 0){
            choice9(plaintext);
        } else if (strcmp(buffer, "0") == 0){
            break;
        }
        // Because C is nice, we need to do 1 at a time, random memory issues idk where appeared out of nowhere
        // Also doesn't let 3 Blocks test close, test still passes all 3 verifications though
        // TODO: try and fix that^? 
        break;
    }

    return 0;
}