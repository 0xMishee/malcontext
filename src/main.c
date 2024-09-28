#include <stdio.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <windows.h>
#include <b64/cdecode.h>

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
    } else if(strcmp(argv[1], "-search") == 0 && argc != 3) {
        printf(ANSI_RED"[!] Error: No hash provided\n\n\n" ANSI_RESET);
        return 1;
    };

    if(strcmp(argv[1], "-c") == 0 && argc == 3) {
        if (hash_sample_validation(argv[2]) == FALSE){
            printf(ANSI_RED"[!] Error: Invalid hash. Correct lengths are 32 || 64.\n\n\n" ANSI_RESET);
            return 1;
        } else {
            context_malware_summary(argv[2]);
            return 0;
        }
    };

    if(strcmp(argv[1], "-h") == 0 && argc == 2) {
        print_help_pages();
        return 0;
    };

    return 0;
};




