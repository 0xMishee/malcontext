#include <stdio.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <windows.h>
#include <b64/cdecode.h>

#include "help_custom.h"
#include "virustotal.h"
#include "unpac_me.h"
#include "config.h"
#include "context.h"
#include "ansi_colours.h"
#include "hybridanalysis.h"
#include "search.h"
#include "malshare.h"
#include "malpedia.h"
#include "miscellaneous.h"

#define VIRUS_HASH "cba8d79949adc3c56c02fee56644f4084b7471bc5aed1c81803054f017240a72"
#define VIRUS_HASH_2 "df7b92b717abe121fb536a0eeb8e323cc9153f70250656dfc670c9650776afa7"
#define VIRUS_HASH_3 "02e9f0fbb7f3acea4fcf155dc7813e15c1c8d1c77c3ae31252720a9fa7454292"


int main(int argc, char *argv[]) {
    printf(ANSI_BLUE " __   __  _______  ___      _     _  _______  ______    _______    _______  _______  __    _  _______  _______  __   __  _______  \n");
    printf("|  |_|  ||   _   ||   |    | | _ | ||   _   ||    _ |  |       |  |       ||       ||  |  | ||       ||       ||  |_|  ||       |           \n");
    printf("|       ||  |_|  ||   |    | || || ||  |_|  ||   | ||  |    ___|  |       ||   _   ||   |_| ||_     _||    ___||       ||_     _|           \n");
    printf("|       ||       ||   |    |       ||       ||   |_||_ |   |___   |       ||  | |  ||       |  |   |  |   |___ |       |  |   |             \n");
    printf("|       ||       ||   |___ |       ||       ||    __  ||    ___|  |      _||  |_|  ||  _    |  |   |  |    ___| |     |   |   |             \n");
    printf("| ||_|| ||   _   ||       ||   _   ||   _   ||   |  | ||   |___   |     |_ |       || | |   |  |   |  |   |___ |   _   |  |   |             \n");
    printf("|_|   |_||__| |__||_______||__| |__||__| |__||___|  |_||_______|  |_______||_______||_|  |__|  |___|  |_______||__| |__|  |___|             \n\n\n " ANSI_RESET);


    if (argc < 2 || !argv[1]){ 
        printf(ANSI_RED"[!] Error: No arguments provided\n\n\n" ANSI_RESET); 
        return 1;
    };


    if (strcmp(argv[1], "pedia") == 0) {
        char* api_key = get_api_key_value("malpedia");
        char* response = malpedia_check_api_key(api_key);
        char* response_2 = malpedia_search_malware(api_key, VIRUS_HASH_2);

        if (malpedia_validate_key_hash(api_key, VIRUS_HASH_3) == FALSE){
            fprintf(stderr, ANSI_RED"[!] Error: Failed to validate the key and hash\n" ANSI_RESET);
            return 1;
        } else {
            printf(ANSI_GREEN"[+] Successfully validated the key and hash\n" ANSI_RESET);
        };

        return 0;
    };

    if (strcmp(argv[1], "mal") == 0) {
        char* api_key = get_api_key_value("malshare");
        char* return_string = malshare_sample_test(api_key, VIRUS_HASH);
        char* return_string_2 = malshare_get_rate_limit(api_key);
        free(api_key);
        free(return_string);
    }

    if (strcmp(argv[1], "-d") == 0) {
        char* api_name; 

        if (check_api_name(argv[2]) == FALSE){
            api_name = "default";
        } else {
            api_name = argv[2];

        };

        if ((hash_sample_validation(VIRUS_HASH) || hash_sample_validation(VIRUS_HASH)) == TRUE) {
            BOOL value = download_malware(api_name, VIRUS_HASH);
            return 0;
        } else {
            printf(ANSI_RED"[!] Error: Invalid hash. Correct lengths are 32 || 64.\n\n\n" ANSI_RESET);
            return 1;
        };
    };

    // temp to check api
    if (strcmp(argv[1], "hybrid") == 0) {
        char* api_key = get_api_key_value("hybridanalysis");
        char* return_string = hybridanalysis_search(api_key, VIRUS_HASH);
        cJSON *hybrid_json = cJSON_Parse(return_string);
        char* hybrid_json_str = cJSON_Print(hybrid_json); // Convert cJSON object to string
        printf("This is what returned...\n%s\n", hybrid_json_str);
        free(api_key);
        free(return_string);
        free(hybrid_json_str); // Free the string after use
        cJSON_Delete(hybrid_json);

        return 0;
    };


    // Search for a sample hash
    if(strcmp(argv[1], "-search") == 0 && argc == 3) {
        //search_sample_available(argv[2]);
        search_sample_available(VIRUS_HASH);
    } else if(strcmp(argv[1], "-search") == 0 && argc != 3) {
        printf(ANSI_RED"[!] Error: No hash provided\n\n\n" ANSI_RESET);
        return 1;
    };

    if(strcmp(argv[1], "-context") == 0) {


        return 0;
    };

    if (strcmp(argv[1], "json") == 0) {

        char* api_key = get_api_key_value("virustotal");
        free(api_key);
        return 0;
    };

    return 0;
};




