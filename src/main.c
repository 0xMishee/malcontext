#include <stdio.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <windows.h>
#include <b64/cdecode.h>

//
#include "help_custom.h"
#include "virustotal.h"
#include "malware_download.h"
#include "unpac_me.h"
#include "config.h"
#include "context.h"
#include "ansi_colours.h"
#include "hybridanalysis.h"
#include "search.h"
#include "malshare.h"
#include "malpedia.h"
#include "miscellaneous.h"
#include "malwarebazaar.h"

// Used for debugging
#define VIRUS_HASH_1 "cba8d79949adc3c56c02fee56644f4084b7471bc5aed1c81803054f017240a72"
#define VIRUS_HASH_2 "df7b92b717abe121fb536a0eeb8e323cc9153f70250656dfc670c9650776afa7"
#define VIRUS_HASH_3 "02e9f0fbb7f3acea4fcf155dc7813e15c1c8d1c77c3ae31252720a9fa7454292"
#define VIRUS_HASH_4 "002ed5ec84f3a40fae4ceeaf5b023fe866bab5ac8cacc1bc8a9425626d4ce91c" // Exist on Malware Bazaar
#define VIRUS_HASH_5 "a1d48085658f342ad2c03c13a47bbc07b009399c4bacd91694a69419649de14b" // Exist on Malshare

int main(int argc, char *argv[]) {
    printf(ANSI_BLUE " __   __  _______  ___      _     _  _______  ______    _______    _______  _______  __    _  _______  _______  __   __  _______  \n");
    printf("|  |_|  ||   _   ||   |    | | _ | ||   _   ||    _ |  |       |  |       ||       ||  |  | ||       ||       ||  |_|  ||       |           \n");
    printf("|       ||  |_|  ||   |    | || || ||  |_|  ||   | ||  |    ___|  |       ||   _   ||   |_| ||_     _||    ___||       ||_     _|           \n");
    printf("|       ||       ||   |    |       ||       ||   |_||_ |   |___   |       ||  | |  ||       |  |   |  |   |___ |       |  |   |             \n");
    printf("|       ||       ||   |___ |       ||       ||    __  ||    ___|  |      _||  |_|  ||  _    |  |   |  |    ___| |     |   |   |             \n");
    printf("| ||_|| ||   _   ||       ||   _   ||   _   ||   |  | ||   |___   |     |_ |       || | |   |  |   |  |   |___ |   _   |  |   |             \n");
    printf("|_|   |_||__| |__||_______||__| |__||__| |__||___|  |_||_______|  |_______||_______||_|  |__|  |___|  |_______||__| |__|  |___|             \n " ANSI_RESET);
    printf("\n");

    if (argc < 2 || !argv[1]){ 
        printf(ANSI_RED"[!] Error: No arguments provided\n\n\n" ANSI_RESET); 
        return 1;
    };

    printf("Number of arguments given %d\n", argc);

    if (strcmp(argv[1], "-first_seen_db") == 0) {
        char* api_key = get_api_key_value("malwarebazaar");
        char* response = malwarebazaar_search(argv[2]);
        cJSON* response_json = cJSON_Parse(response);
        cJSON* response_json_array = cJSON_GetArrayItem(response_json, 1);
        cJSON* response_json_second_array = cJSON_GetArrayItem(response_json_array, 0);
        cJSON* date = cJSON_GetObjectItem(response_json_second_array, "first_seen");




        printf("%s\n", date->valuestring);



        free(response);
        free(api_key);

        return 0;
    };

    //Testing malpedia API beep boop
    if (strcmp(argv[1], "-mp_debug") == 0) {
        char* api_key = get_api_key_value("malpedia");
        char* response = malpedia_check_api_key(api_key);
        char* response_2 = malpedia_search_malware(api_key, VIRUS_HASH_2);
        download_malware("-mp", VIRUS_HASH_3);
        
        
        free(api_key);
        free(response);
        free(response_2);
        return 0;
    };

    //Testing beep boop
    if (strcmp(argv[1], "-ms_debug") == 0) {
        char* api_key = get_api_key_value("malshare");

        if (malshare_download_file(api_key, VIRUS_HASH_5) == TRUE) {
            printf(ANSI_GREEN"[+] File successfully downloaded\n\n\n" ANSI_RESET);
            return 0;
        }
        
        
        free(api_key);
        return 0;
    }

    if(strcmp(argv[1], "-mb_debug") == 0 && argc == 2) {

        /* 
        {"query_status": "hash_not_found"}
        */


        char* api_key = get_api_key_value("malwarebazaar");
        malwarebazaar_download_file(VIRUS_HASH_3);

        free(api_key);
        return 0;
    };

        // temp to check api
    if (strcmp(argv[1], "-ha_debug") == 0) {
        char* api_key = get_api_key_value("hybridanalysis");
        char* return_string = hybridanalysis_search(api_key, VIRUS_HASH_1);
        cJSON *hybrid_json = cJSON_Parse(return_string);
        char* hybrid_json_str = cJSON_Print(hybrid_json); // Convert cJSON object to string
        printf("This is what returned...\n%s\n", hybrid_json_str);
       
        free(api_key);
        free(return_string);
        free(hybrid_json_str); // Free the string after use
        cJSON_Delete(hybrid_json);
        return 0;
    };
    
    // Hey, something that might work...!?
    if (strcmp(argv[1], "-d") == 0 && (argc == 3 || argc == 4)) {
        char* api_name;
        char* sample_hash;

        if (check_api_name(argv[2]) == FALSE){
            api_name = "default";
        } else {
            api_name = argv[2];
        };

        if (hash_sample_validation(argv[2]) == TRUE){
            sample_hash = argv[2];
        } else if (hash_sample_validation(argv[3]) == TRUE) {
            sample_hash = argv[3];
        } else {
            printf(ANSI_RED"[!] Error: Invalid hash. Correct lengths are 32 || 64.\n\n\n" ANSI_RESET);
            return 1;
        }

        BOOL download_return_status = download_malware(api_name, sample_hash);

        if (download_return_status != TRUE) {
            return 1;
        } else {
            return 0;
        }

    };

    // Search for a sample hash
    if(strcmp(argv[1], "-s") == 0 && argc == 3) {
        search_sample_available(argv[2]);
        //search_sample_available(VIRUS_HASH_1);
    } else if(strcmp(argv[1], "-search") == 0 && argc != 3) {
        printf(ANSI_RED"[!] Error: No hash provided\n\n\n" ANSI_RESET);
        return 1;
    };

    if(strcmp(argv[1], "-c") == 0 && argc == 3) {
        return 0;
    };

    if(strcmp(argv[1], "-h") == 0 && argc == 2) {
        print_help_pages();
        return 0;
    }

    return 0;
};




