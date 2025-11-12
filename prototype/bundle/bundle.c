// bundle.c will have the main function to run our BSP helper functions
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bundle.h"
#include "bundle_helper.h"

int main() {

    // 1) create a new bundle structure
    // allocate memory for the bundle container
    bundle* b = malloc(sizeof(bundle));
    // check if the allocation fails
    if (b == NULL) {
        fprintf(stderr, "Failed to allocate bundle\n");
        return EXIT_FAILURE;
    }

    // allocate and populate primary block
    // allocate memory for the primary block
    b->primary = malloc(sizeof(bundlePrimaryBlock));
    // set version to the version constant
    b->primary->version = BUNDLE_VERSION;
    // initialize processing flags
    b->primary->proc_flags = 0;
    // set source endpoint ID
    b->primary->source_eid = strdup("dtn://hubble-telescope-1/app/data-logger");
    // set destination endpoint ID
    b->primary->dest_eid = strdup("dtn://earth-gateway-1/app/telemetry-ingest");
    // set report to endpoint ID
    b->primary->report_to_eid = strdup("dtn://mission-control/app/status-monitor");
    // set custodian endpoint ID
    b->primary->custodian_eid = strdup("dtn://relay-sat-3/app/bundle-store");
    // set creation timestamp (seconds since year 2000)
    b->primary->creation_timestamp = 100000;
    // set sequence number to 1
    b->primary->sequence_number = 1;
    // bundle lifetime is in seconds (3600 secs = 1 hour)
    b->primary->lifetime = 3600;
    // no fragmentation, 0
    b->primary->fragment_offset = 0;
    // not fragment, total ADU length is 0
    b->primary->total_adu_length = 0;
    // no dictionary for this
    b->primary->dictionary = NULL;
    // dictionary length is 0
    b->primary->dictionary_len = 0;

    // allocate and initialize the payload block which is the data being transferred
    // allocate memory for the payload block
    b->payload = malloc(sizeof(bundlePayloadBlock));
    // set the block type to be the payload block type constant
    b->payload->block_type = BLOCK_TYPE_PAYLOAD;
    // set flags to 0: no special flags
    b->payload->proc_flags = 0;
    // define the payload message, it can be anything
    const char* msg = "Hubble Telescope pictures are looking great!";
    // set the payload length to be the length of the message
    b->payload->payload_len = strlen(msg);
    // allocate memory for the payload data
    b->payload->payload = malloc(b->payload->payload_len);
    // copy the message into the payload
    memcpy(b->payload->payload, msg, b->payload->payload_len);
    // set the block payload length to match the payload
    b->payload->block_length = b->payload->payload_len;

    // 2) apply the security blocks which are: PIB(Payload Integrity Block) and PCB(Payload Confidentiality Block)
    // apply integrity and encryption to the bundle
    applyBundleSecurity(b, 1, 1);

    // 3) serialize the bundle into a byte stream to be transmitted or stored
    // make a variable to hold the length of the serialized data
    size_t serialized_len;
    // serialize the bundle by calling serializeBundle function
    uint8_t* serialized = serializeBundle(b, &serialized_len);
    // print the serialized bundle length
    printf("\nSerialized Bundle (%zu bytes):\n", serialized_len);
    // print the serialized bundle, this will be in hex format
    for (size_t i = 0; i < serialized_len; i++) {
        printf("%02x ", serialized[i]);
        // there should be a newline every 16 bytes to read the bundle data better
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // 4) deserialize the byte stream into a bundle structure
    // call deserializeBundle on the serialized data to parse it
    bundle* parsed = deserializeBundle(serialized, serialized_len);
    printf("\nDeserialized Bundle:\n");
    // print the parsed bundle to see its contents
    printBundle(parsed);

    // 5) verify and process the security blocks which are PIB and PCB
    // check to attempt integrity verification and decryption
    if (!processBundleSecurity(parsed, 1, 1)) {
        // report a failure if branch executes
        fprintf(stderr, "Security verification failed\n");
        // clean up the serialized buffer
        free(serialized);
        // free the original bundle
        freeBundle(b);
        // free the parsed bundle
        freeBundle(parsed);
        // exits with an error
        return EXIT_FAILURE;
    }

    // 6) print the decrypted payload to make sure that it was decrypted successfully
    printf("\nDecrypted Payload (%zu bytes): %.*s\n\n",
            // have the payload length
           parsed->payload->payload_len,
            // cast payload length to int for the printf
           (int)parsed->payload->payload_len,
            // print the payload as a string
           parsed->payload->payload);

    // 7) clean up all the allocated memory
    // free the serialized bytes
    free(serialized);
    // free the original bundle and blocks
    freeBundle(b);
    // free the parsed bundle and blocks
    freeBundle(parsed);

    return 0;
}
