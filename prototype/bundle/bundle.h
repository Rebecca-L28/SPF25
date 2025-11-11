#pragma once

#include <stdint.h>
#include <stdlib.h>

// SOURCE: https://www.rfc-editor.org/rfc/pdfrfc/rfc5050.txt.pdf


// define the bundle protocol constants

// define the bundle version
// the RFC 5050 PDF uses version 6
#define BUNDLE_VERSION 6

// define the block type code for the payload block
// the RFC 5050 PDF says this should always be 1
#define BLOCK_TYPE_PAYLOAD 1


// define the bundle primary block using the RFC 5050 PDF specs

typedef struct {

    /*
     A 1-byte field indicating the version of the bundle
     protocol that constructed this block.
    */
    uint8_t version;
    // bundle processing control flags
    uint64_t proc_flags;
    /*
      The Block Length field is an SDNV that contains the
      aggregate length of all remaining fields of the block.
    */
    uint64_t block_length;

    // endpoint IDs
    // destination endpoint ID - the endpoint containing the node(s) at which the bundle is to be delivered
    char* dest_eid;
    // source endpoint ID - the endpoint nominally containing the node from which the bundle was initially transmitted
    char* source_eid;
    // report to endpoint ID - the endpoint to which status reports pertaining to the forwarding and delivery of this
    // bundle are to be transmitted
    char* report_to_eid;
    // custodian endpoint ID - the endpoint whose membership include the node that most recently accepted custody of
    // the bundle upon forwarding this bundle
    char* custodian_eid;

    // the creation timestamp is measured in seconds since the year 2000
    uint64_t creation_timestamp;
    // the other part of the creation timestamp is the creation timestamp sequence number
    // this value is the latest value of a monotonically increasing positive integer counter managed by the source
    // node's bundle protocol agent that may be reset to zero whenever the current time advances by one second
    uint64_t sequence_number;

    // the lifetime is the time at which the bundle's payload will no longer be useful, encoded as a number of seconds
    // past the creation time
    uint64_t lifetime;

    // the dictionary length field has the length of the dictionary byte array
    size_t dictionary_len;
    // the dictionary field is an array of bytes formed by concatenating the null-terminated scheme names and SSPs
    // of all endpoint IDs referenced by any fields in the primary block
    uint8_t* dictionary;

    // if the bundle processing control flags of the primary block indicate that the bundle is a fragment
    // the fragment offset field indicates the offset from the start of the original application data unit at which
    // the bytes comprising the payload of this bundle were located
    // else, the fragment offset is omitted
    uint64_t fragment_offset;
    // total application data unit length
    // if the flags indicate that the bundle is a fragment, the total adu length indicates the total length of the
    // original application data unit
    // else, the total ADU length is omitted
    uint64_t total_adu_length;
} bundlePrimaryBlock;


// define the bundle payload block using the RFC 5050 PDF specs

typedef struct {
    /*
      The Block Type field is a 1-byte field that indicates
      the type of the block.  For the bundle payload block, this field
      contains the value 1.
    */
    uint8_t block_type;
    // bundle processing control flags
    uint64_t proc_flags;
    // block length contains the length of the bundle's payload
    uint64_t block_length;
    // the payload contains the application data carried by the bundle
    uint8_t* payload;
    // extra field for the payload length
    size_t payload_len;
} bundlePayloadBlock;


// bundle security block

typedef struct {
    // this is the block type, 2 is for PID, 3 is for PCB
    uint8_t block_type;
    // bundle processing control flags
    uint64_t proc_flags;
    // this is the block length
    uint64_t block_length;
    // this is the security data, it will be a MAC tag or ciphertext
    uint8_t* security_data;
    // this is the security data length which is the length of the above field
    size_t security_data_len;
} bundleSecurityBlock;



// define the full bundle structure

typedef struct {
    // the primary block
    bundlePrimaryBlock* primary;
    // the payload block
    bundlePayloadBlock* payload;
    // pib is for integrity
    bundleSecurityBlock* pib;
    // pcb is for encryption and confidentiality
    bundleSecurityBlock* pcb;
} bundle;