#include <stdio.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <windows.h>

#include "help_custom.h"
#include "virustotal.h"
#include "unpac_me.h"
#include "config.h"
#include "context.h"
#include "ansi_colours.h"
#include "search.h"
#include "malshare.h"

#define VIRUS_HASH "b1f2068201c29f3b00aeedc0911498043d7c204a860ca16b3fef47fc19fc2b22"


// TEMP Testing purposes only!
#define FILE_PATH_DIR "E:\\malware overview re-write\\malware_context\\yara-x rules"

int main(int argc, char *argv[]) {
    printf(ANSI_BLUE " __   __  _______  ___      _     _  _______  ______    _______    _______  _______  __    _  _______  _______  __   __  _______ \n");
    printf("|  |_|  ||   _   ||   |    | | _ | ||   _   ||    _ |  |       |  |       ||       ||  |  | ||       ||       ||  |_|  ||       |\n");
    printf("|       ||  |_|  ||   |    | || || ||  |_|  ||   | ||  |    ___|  |       ||   _   ||   |_| ||_     _||    ___||       ||_     _|\n");
    printf("|       ||       ||   |    |       ||       ||   |_||_ |   |___   |       ||  | |  ||       |  |   |  |   |___ |       |  |   |  \n");
    printf("|       ||       ||   |___ |       ||       ||    __  ||    ___|  |      _||  |_|  ||  _    |  |   |  |    ___| |     |   |   |  \n");
    printf("| ||_|| ||   _   ||       ||   _   ||   _   ||   |  | ||   |___   |     |_ |       || | |   |  |   |  |   |___ |   _   |  |   |  \n");
    printf("|_|   |_||__| |__||_______||__| |__||__| |__||___|  |_||_______|  |_______||_______||_|  |__|  |___|  |_______||__| |__|  |___|  \n\n\n " ANSI_RESET);


    if (argc < 2 || !argv[1]){ 
        printf(ANSI_RED"[!] Error: No arguments provided\n\n\n" ANSI_RESET); 
        return 1;
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




