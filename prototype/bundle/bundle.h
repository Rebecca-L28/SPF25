#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

// SOURCE: https://www.rfc-editor.org/rfc/pdfrfc/rfc5050.txt.pdf
/*
  NOTE: 
  Abstracted version of BSP. Core features are present, but more intricate details have been left out.
  Structures contain most of the fields, but implementation might not use them all.
  Reason: Time constraints.
*/

// define the bundle protocol constants

// define the bundle version
// the RFC 5050 PDF uses version 6
#define BUNDLE_VERSION 6

// define the block type code for the payload block
// the RFC 5050 PDF says this should always be 1
#define BLOCK_TYPE_PAYLOAD 1
#define BLOCK_TYPE_BAB 2
#define BLOCK_TYPE_PIB 3
#define BLOCK_TYPE_PCB 4

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

// eid-reference list structure
typedef struct {
    // block security-source, if omitted, the bundle's is assumed
    char* security_source;
    // block security-destination, if omitted, the bundle's is assumed
    char* security_dest;
} eid_reference_list;

// ciphersuite params structure
typedef struct {
  // type of parameter
  // 1: IV
  // 3: key-information
  // 4: fragment-range (offset and length as a pair of SDNVs)
  // 5: integrity signature
  // 6: unassigned
  // 7: salt
  // 8: PCB integrity check value (GCM tag)
  // 10: encapsulated block
  // 11: block type of encapsulated block
  // other values are reserved for future use
  uint8_t type;
  // length of parameter value (SDNV)
  size_t len;
  // parameter value
  uint8_t* value;
} ciphersuite_params;

// bundle security block
typedef struct {
    // this is the block type, 2 is for BAB, 3 is for PIB, 4 is for PCB, 9 is for ESB
    uint8_t block_type;
    // block processing control flags (SDNV)
    // --> left to right -->
    // 6th bit: block contains an eid-reference field
    // 5th bit: was forwarded without being processed
    // 4th bit: discard block if it can't be processed
    // 3rd bit: last block
    // 2nd bit: delete bundle if block can't be processed
    // 1st bit: transmit status report if block can't be processed
    // 0th bit: block must be replicated in every fragment
    uint64_t proc_flags;
    // eid-reference list (optional)
    eid_reference_list* eid_reference_list;
    // this is the block length (SDNV)
    uint64_t block_length;

    // ciphersuite ID (SDNV)
    // 1: BAB
    // 2: PIB
    // 3: PCB
    // 4: ESB
    uint8_t ciphersuite_id;
    // ciphersuite flags (SDNV)
    // --> left to right -->
    // 6th bit: reserved
    // 5th bit: reserved
    // 4th bit: eid security-source is present
    // 3rd bit: eid security-destination is present
    // 2nd bit: ciphersuite-params-len and ciphersuite-params are present
    // 1st bit: correlator is present
    // 0th bit: sec-result-len and sec-result are present
    uint8_t ciphersuite_flags;
    // correlator (SDNV) (optional)
    uint8_t correlator;
    // ciphersuite params length (SDNV) (optional)
    size_t ciphersuite_params_len;
    // ciphersuite params (optional)
    ciphersuite_params* ciphersuite_params[3];
    // security-result data length (SDNV) (optional)
    size_t security_result_len;
    // security-result data
    uint8_t* security_result;
} bundleSecurityBlock;

// define the full bundle structure
// NOTE: Supports standard order of Encrypt->Sign->BAB at one instance each. ESB is not supported.
typedef struct {
    // the primary block
    bundlePrimaryBlock* primary;
    // bab for authentication
    bundleSecurityBlock* bab;
    // pib is for integrity
    bundleSecurityBlock* pib;
    // pcb is for encryption and confidentiality
    bundleSecurityBlock* pcb;
    // the payload block
    bundlePayloadBlock* payload;
    // // esb for extra security not related to payload
    // bundleSecurityBlock* esb;
    // bab 2 for authentication
    bundleSecurityBlock* bab2;
} bundle;