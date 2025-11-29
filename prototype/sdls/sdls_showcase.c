#include "sdls.h"

void printTF(transferFrame* tf, securityAssociation* sa){
  // Print entire security transfer frame
  printf("\n__Transfer Frame__\n");
  if (tf == NULL){
    printf("[ERROR] Failed to apply security\n");
    exit(EXIT_FAILURE);
  }
  printf("Security Header:\n");
  printf("  SPI: ");
  BIO_dump_fp (stdout, (const char *)&tf->sh->SPI, 2);
  if (sa->SA_service_type == 1 || sa->SA_service_type == 2 && sa->SA_length_IV > 0) {
    printf("  IV: ");
    BIO_dump_fp (stdout, (const char *)tf->sh->IV, sa->SA_length_IV);
  }
  if (sa->SA_service_type == 0 && sa->SA_length_SN > 0) {
    printf("  SN: ");
    BIO_dump_fp (stdout, (const char *)tf->sh->SN, sa->SA_length_SN);
  }
  if (sa->SA_length_PL > 0){
    printf("  PL: ");
    BIO_dump_fp (stdout, (const char *)tf->sh->PL, sa->SA_length_PL);
  }
  printf("Transfer Data Field (%d bytes):\n", strlen(tf->data_field));
  BIO_dump_fp (stdout, (const char *)tf->data_field, strlen(tf->data_field));
  if (sa->SA_service_type == 0 || sa->SA_service_type == 2) {
    printf("Security Trailer:\n");
    printf("  MAC: ");
    BIO_dump_fp (stdout, (const char *)tf->st->MAC, sa->SA_length_MAC);
  }
}

void printPSR(processSecurityReturn* psr){
  // Print the entire ProcessSecurity Return
  printf("\nProcessSecurity Return:\n");
  if (psr == NULL){
    printf("[ERROR] Failed to process security\n");
    exit(EXIT_FAILURE);
  }
  if (psr->verification_status == 1){
    printf("Decrypted Data Field (%d bytes): %s\n", strlen(psr->data_field), psr->data_field);
  }
  printf("Verified: %d\n", psr->verification_status);
  printf("Verification Code: %d\n", psr->verification_code);
}

void choice1(unsigned char* plaintext, size_t plaintext_len, unsigned char* SPP, securityAssociation* sa, securityAssociation** sa_array){
    // Setup SA
    sa->SPI = 1;
    sa->SA_encryption_algorithm = EVP_aes_256_ctr();
    sa->SA_encryption_key = (unsigned char*) "01234567890123456789012345678901"; // 256 bit key
    sa->SA_initialization_vector = (unsigned char*) "0123456700000000"; // 128 bit IV
    sa->SA_service_type = 1; 
    sa->SA_length_IV = 16;
    sa->SA_length_PL = 0;
    sa->GVCID = 1;
    sa->GMAP_ID = 1;

    // ApplySecurity
    transferFrame* tf = ApplySecurity(sa_array, 2, 1, 1, plaintext, plaintext_len, SPP, sizeof(SPP), 1, 0, 0);

    // Print TF
    printTF(tf, sa);

    // ProcessSecurity
    processSecurityReturn* psr = ProcessSecurity(sa_array, 2, tf, 1, 1, SPP, sizeof(SPP), 1, 0, 0);

    // Print PSR
    printPSR(psr);

    // Free memory
    free(tf->sh->IV);
    free(tf->sh->PL);
    free(tf->sh);
    free(tf->data_field);
    free(tf);
    if (psr->verification_status == 1){
        free(psr->data_field);
    }
    free(psr);
}

void choice2(unsigned char* plaintext, size_t plaintext_len, unsigned char* SPP, securityAssociation* sa, securityAssociation** sa_array){
    // Setup SA
    sa->SPI = 1;
    sa->SA_sequence_number = 0;
    sa->SA_authentication_algorithm = EVP_MAC_fetch(NULL, "CMAC", NULL);
    sa->SA_authentication_key = (unsigned char*) "01234567890123456789012345678901"; // 256 bit key
    sa->SA_authentication_mask = 0x00;
    sa->SA_service_type = 0; 
    sa->SA_window_size = 1;
    sa->SA_length_SN = 4;
    sa->SA_length_MAC = 16;
    sa->GVCID = 1;
    sa->GMAP_ID = 1;

    // ApplySecurity
    transferFrame* tf = ApplySecurity(sa_array, 2, 1, 1, plaintext, plaintext_len, SPP, sizeof(SPP), 0, 1, 1);

    // Print TF
    printTF(tf, sa);

    // ProcessSecurity
    processSecurityReturn* psr = ProcessSecurity(sa_array, 2, tf, 1, 1, SPP, sizeof(SPP), 0, 1, 1);

    // Print PSR
    printPSR(psr);

    // Free memory
    free(tf->st->MAC);
    free(tf->st);
    free(tf->sh->SN);
    free(tf->sh);
    free(tf->data_field);
    free(tf);
    if (psr->verification_status == 1){
        free(psr->data_field);
    }
    free(psr);
}

void choice3(unsigned char* plaintext, size_t plaintext_len, unsigned char* SPP, securityAssociation* sa, securityAssociation** sa_array){
    // Setup SA
    sa->SPI = 1;
    sa->SA_sequence_number = 0;
    sa->SA_encryption_algorithm = EVP_aes_256_gcm();
    sa->SA_encryption_key = (unsigned char*) "01234567890123456789012345678901"; // 256 bit key
    sa->SA_initialization_vector = (unsigned char*) "012300000000";// 96 bit IV
    sa->SA_authentication_mask = 0x00;
    sa->SA_service_type = 2;
    sa->SA_window_size = 1;
    sa->SA_length_SN = 8;
    sa->SA_length_IV = 12;
    sa->SA_length_MAC = 16;
    sa->GVCID = 1;
    sa->GMAP_ID = 1;

    // ApplySecurity
    transferFrame* tf = ApplySecurity(sa_array, 2, 1, 1, plaintext, plaintext_len, SPP, sizeof(SPP), 1, 0, 0);

    // Print TF
    printTF(tf, sa);

    // ProcessSecurity
    processSecurityReturn* psr = ProcessSecurity(sa_array, 2, tf, 1, 1, SPP, sizeof(SPP), 1, 0, 0);

    // Print PSR
    printPSR(psr);

    // Free memory
    free(tf->st->MAC);
    free(tf->st);
    free(tf->sh->IV);
    free(tf->sh);
    free(tf->data_field);
    free(tf);
    if (psr->verification_status == 1){
        free(psr->data_field);
    }
    free(psr);
}

void choice4(unsigned char* plaintext, size_t plaintext_len, unsigned char* SPP, securityAssociation* sa, securityAssociation** sa_array){
    // Setup SA
    sa->SPI = 1;
    sa->SA_encryption_algorithm = EVP_aes_256_ctr();
    sa->SA_encryption_key = (unsigned char*) "01234567890123456789012345678901"; // 256 bit key
    sa->SA_initialization_vector = (unsigned char*) "0123456700000000"; // 128 bit IV
    sa->SA_service_type = 1; 
    sa->SA_length_IV = 16;
    sa->SA_length_PL = 0;
    sa->GVCID = 1;
    sa->GMAP_ID = 1;

    // ApplySecurity
    transferFrame* tf = ApplySecurity(sa_array, 2, 1, 1, plaintext, plaintext_len, SPP, sizeof(SPP), 1, 0, 0);

    // Print TF
    printTF(tf, sa);

    printf("\nChanging SPI...\n");
    sa->SPI = 5;

    // ProcessSecurity
    processSecurityReturn* psr = ProcessSecurity(sa_array, 2, tf, 1, 1, SPP, sizeof(SPP), 1, 0, 0);

    // Print PSR
    printPSR(psr);

    // Free memory
    free(tf->sh->IV);
    free(tf->sh->PL);
    free(tf->sh);
    free(tf->data_field);
    free(tf);
    if (psr->verification_status == 1){
        free(psr->data_field);
    }
    free(psr);
}

void choice5(unsigned char* plaintext, size_t plaintext_len, unsigned char* SPP, securityAssociation* sa, securityAssociation** sa_array){
    // Setup SA
    sa->SPI = 1;
    sa->SA_sequence_number = 0;
    sa->SA_authentication_algorithm = EVP_MAC_fetch(NULL, "CMAC", NULL);
    sa->SA_authentication_key = (unsigned char*) "01234567890123456789012345678901"; // 256 bit key
    sa->SA_authentication_mask = 0x00;
    sa->SA_service_type = 0; 
    sa->SA_window_size = 1;
    sa->SA_length_SN = 4;
    sa->SA_length_MAC = 16;
    sa->GVCID = 1;
    sa->GMAP_ID = 1;

    // ApplySecurity
    transferFrame* tf = ApplySecurity(sa_array, 2, 1, 1, plaintext, plaintext_len, SPP, sizeof(SPP), 0, 1, 1);

    // Print TF
    printTF(tf, sa);

    printf("\nTampering with MAC...\n");
    tf->st->MAC[0] = 0x44;
    tf->st->MAC[1] = 0x44;
    tf->st->MAC[2] = 0x44;
    tf->st->MAC[3] = 0x44;
    tf->st->MAC[4] = 0x44;

    // ProcessSecurity
    processSecurityReturn* psr = ProcessSecurity(sa_array, 2, tf, 1, 1, SPP, sizeof(SPP), 0, 1, 1);

    // Print PSR
    printPSR(psr);

    // Free memory
    free(tf->st->MAC);
    free(tf->st);
    free(tf->sh->SN);
    free(tf->sh);
    free(tf->data_field);
    free(tf);
    if (psr->verification_status == 1){
        free(psr->data_field);
    }
    free(psr);
}

void choice6(unsigned char* plaintext, size_t plaintext_len, unsigned char* SPP, securityAssociation* sa, securityAssociation** sa_array){
    // Setup SA
    sa->SPI = 1;
    sa->SA_sequence_number = 0;
    sa->SA_encryption_algorithm = EVP_aes_256_gcm();
    sa->SA_encryption_key = (unsigned char*) "01234567890123456789012345678901"; // 256 bit key
    sa->SA_initialization_vector = (unsigned char*) "012300000000";// 96 bit IV
    sa->SA_authentication_mask = 0x00;
    sa->SA_service_type = 2;
    sa->SA_window_size = 1;
    sa->SA_length_SN = 8;
    sa->SA_length_IV = 12;
    sa->SA_length_MAC = 16;
    sa->GVCID = 1;
    sa->GMAP_ID = 1;

    // ApplySecurity
    transferFrame* tf = ApplySecurity(sa_array, 2, 1, 1, plaintext, plaintext_len, SPP, sizeof(SPP), 1, 0, 0);

    // Print TF
    printTF(tf, sa);

    printf("\nChanging Sequence Number...\n");
    sa->SA_sequence_number = 50;

    // ProcessSecurity
    processSecurityReturn* psr = ProcessSecurity(sa_array, 2, tf, 1, 1, SPP, sizeof(SPP), 1, 0, 0);

    // Print PSR
    printPSR(psr);

    // Free memory
    free(tf->st->MAC);
    free(tf->st);
    free(tf->sh->IV);
    free(tf->sh);
    free(tf->data_field);
    free(tf);
    if (psr->verification_status == 1){
        free(psr->data_field);
    }
    free(psr);
}

void choice7(unsigned char* plaintext, size_t plaintext_len, unsigned char* SPP, securityAssociation* sa, securityAssociation** sa_array){
    // Setup SA
    sa->SPI = 1;
    sa->SA_sequence_number = 1;
    sa->SA_authentication_algorithm = EVP_MAC_fetch(NULL, "CMAC", NULL);
    sa->SA_authentication_key = (unsigned char*) "01234567890123456789012345678901"; // 256 bit key
    sa->SA_authentication_mask = 0x00;
    sa->SA_window_size = 0;
    sa->SA_length_SN = 4;
    sa->SA_length_MAC = 16;
    sa->GVCID = 1;
    sa->GMAP_ID = 1;

    // ApplySecurity
    transferFrame* tf = ApplySecurity(sa_array, 2, 1, 1, plaintext, plaintext_len, SPP, sizeof(SPP), 0, 1, 1);

    // Print TF
    printTF(tf, sa);

    printf("\nSetting Window Size to 0...\n");
    sa->SA_window_size = 0;

    // ProcessSecurity
    processSecurityReturn* psr = ProcessSecurity(sa_array, 2, tf, 1, 1, SPP, sizeof(SPP), 0, 1, 1);

    // Print PSR
    printPSR(psr);

    // Free memory
    free(tf->st->MAC);
    free(tf->st);
    free(tf->sh->SN);
    free(tf->sh);
    free(tf->data_field);
    free(tf);
    if (psr->verification_status == 1){
        free(psr->data_field);
    }
    free(psr);
}

void choice8(unsigned char* plaintext, size_t plaintext_len, unsigned char* SPP, securityAssociation* sa, securityAssociation** sa_array){
    // Setup SA
    sa->GVCID = 1;
    sa->GMAP_ID = 1;    
    sa->SPI = 1;
    sa->SA_service_type = 2; 
    sa->SA_length_SN = 8;
    sa->SA_length_IV = 12;
    sa->SA_length_PL = 0;
    sa->SA_length_MAC = 16;
    sa->SA_authentication_algorithm = EVP_MAC_fetch(NULL, "CMAC", NULL);
    sa->SA_authentication_key = (unsigned char*) "01234567890123456789012345678901"; // 256 bit key
    sa->SA_authentication_mask = 0x00;
    sa->SA_sequence_number = 0;
    sa->SA_window_size = 1;
    sa->SA_encryption_algorithm = EVP_aes_256_gcm();
    sa->SA_encryption_key = (unsigned char*) "01234567890123456789012345678901"; // 256 bit key
    sa->SA_initialization_vector = (unsigned char*) "012300000000";// 96 bit IV

    // ApplySecurity
    transferFrame* tf = ApplySecurity(sa_array, 2, 1, 1, plaintext, plaintext_len, SPP, sizeof(SPP), 0, 1, 1);

    // Print TF
    printTF(tf, sa);

    // ProcessSecurity
    processSecurityReturn* psr = ProcessSecurity(sa_array, 2, tf, 1, 1, SPP, sizeof(SPP), 0, 1, 1);

    // Print PSR
    printPSR(psr);

    // Free memory
    if (sa->SA_service_type == 0 || sa->SA_service_type == 2) {
        free(tf->st->MAC);
        free(tf->st);
    }
    if (sa->SA_service_type == 0){
        free(tf->sh->SN);
    }
    if (sa->SA_service_type == 1){
        free(tf->sh->PL);
    }
    if (sa->SA_service_type == 1 || sa->SA_service_type == 2){
        free(tf->sh->IV);
    }
    free(tf->sh);
    free(tf->data_field);
    free(tf);
    if (psr->verification_status == 1){
        free(psr->data_field);
    }
    free(psr);
}

int main(int argc, char* argv[]){
  // Define the TM and TC headers
  unsigned char TM[] = {0xAA, 0xFF, 0xBB, 0xCC, 0x11, 0xDD}; // TM
  unsigned char TM_2nd[] = {0xAA, 0xFF, 0xBB, 0xCC, 0x91, 0xDD, 0x42, 0x5E, 0xC0}; // TM with SH
  unsigned char TC[] = {0xAA, 0xFF, 0xBB, 0xCC, 0x11}; // TC
  unsigned char TC_2nd[] = {0xAA, 0xFF, 0xBB, 0xCC, 0x11, 0xDD}; // TC with SH

  // Define the default plaintext
  unsigned char* plaintext = "Cryptographic Protocol Analysis and Verification (v6)";
  size_t plaintext_len = strlen((char*)plaintext);

  // Define the security association and arrays
  securityAssociation* sa = malloc(sizeof(securityAssociation));
  securityAssociation* sa_array[1];
  sa_array[0] = sa;

  // Menu loop
  while (1){
    // Opt for default values
    printf("---[Showcase Suite]---\n");
    printf("1. Default Encryption Only\n");
    printf("2. Default Authentication Only\n");
    printf("3. Default Authenticated Encryption\n");
    printf("4. SPI Failure\n");
    printf("5. MAC Failure\n");
    printf("6. Sequence Number Failure (Too Low/Same)\n");
    printf("7. Sequence Number Failure (Outside Window)\n");
    printf("8. Custom Test (Change in File)\n");
    printf("What to output? ");

    // Prompt user for input
    char buffer[50];
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = '\0';

    // Prompt user for plaintext
    printf("Default plaintext? (y/n) ");
    char buffer2[50];
    fgets(buffer2, sizeof(buffer2), stdin);
    buffer2[strcspn(buffer2, "\n")] = '\0';

    // Populate plaintext depending on choice
    if (strcmp(buffer2, "n") == 0){
      printf("Enter plaintext: ");
      unsigned char buffer3[1000];
      fgets(buffer3, sizeof(buffer3), stdin);
      plaintext = buffer3;
      buffer3[strcspn(buffer3, "\n")] = '\0';
      plaintext_len = strlen(plaintext);
      printf("plaintext_len: %d\n", plaintext_len);
    }

    // Handle each choice
    if (strcmp(buffer, "1") == 0){
      choice1(plaintext, plaintext_len, TM, sa, sa_array);
    } else if (strcmp(buffer, "2") == 0){
      choice2(plaintext, plaintext_len, TC_2nd, sa, sa_array);
    } else if (strcmp(buffer, "3") == 0){
      choice3(plaintext, plaintext_len, TM_2nd, sa, sa_array);
    } else if (strcmp(buffer, "4") == 0){
      choice4(plaintext, plaintext_len, TM, sa, sa_array);
    } else if (strcmp(buffer, "5") == 0){
      choice5(plaintext, plaintext_len, TC_2nd, sa, sa_array);
    } else if (strcmp(buffer, "6") == 0){
      choice6(plaintext, plaintext_len, TC_2nd, sa, sa_array);
    } else if (strcmp(buffer, "7") == 0){
      choice7(plaintext, plaintext_len, TC_2nd, sa, sa_array);
    } else if (strcmp(buffer, "8") == 0){
      // Change SPP to whatever for custom
      choice8(plaintext, plaintext_len, TM_2nd, sa, sa_array);
    }
  
    break;
  }

  // Free memory
  free(sa);
  return 0;
}
