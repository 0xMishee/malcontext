#include <stdio.h>
#include <string.h>

#include "help_custom.h"
#include "virustotal.h"

#include <cjson/cJSON.h>
#include <windows.h>
#include "config.h"
#include "context.h"
#include "ansi_colours.h"

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

    if(strcmp(argv[1], "-context") == 0) {
        printf(ANSI_BOLD_GRAY "Contextualizing malware sample...\n"ANSI_RESET);


        // Get API key and get the file report
        char* api_key = get_api_key_value("virustotal");
        char* virustotal_json_string = virustotal_get_file_report(api_key, VIRUS_HASH);

        context_virustotal_file_print(virustotal_json_string);

        // Cleanup
        free(api_key);
        return 0;
    };

    if (strcmp(argv[1], "json") == 0) {

        char* api_key = get_api_key_value("virustotal");
        free(api_key);
        return 0;
    };







    //Don't look at it, it's trash.
    switch (argv[1][1]) {
        printf("checking");
        case 'h':
            if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
                print_help_pages();
                return 0;
            };
            break; 
        case 'y':
            if (strcmp(argv[1], "-y") == 0 || strcmp(argv[1], "--yara") == 0 || strcmp(argv[1], "--yara-x") == 0) {
                return 0;
            };
            break;
        case 'm':
            if (strcmp(argv[1], "-m") == 0 || strcmp(argv[1], "--malshare") == 0) {                
                return 0;
            };
            break;
        default:
            printf("[!] Error: Invalid argument\n\n\n");
            return 1;
    };

    return 0;
};




