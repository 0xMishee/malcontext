#include <stdio.h>
#include <string.h>

#include "help_custom.h"
#include "virustotal.h"

// TEMP Testing purposes only!
#define FILE_PATH_DIR "E:\\malware overview re-write\\malware_context\\yara-x rules"



int main(int argc, char *argv[]) {
    printf(" __   __  _______  ___      _     _  _______  ______    _______    _______  _______  __    _  _______  _______  __   __  _______ \n");
    printf("|  |_|  ||   _   ||   |    | | _ | ||   _   ||    _ |  |       |  |       ||       ||  |  | ||       ||       ||  |_|  ||       |\n");
    printf("|       ||  |_|  ||   |    | || || ||  |_|  ||   | ||  |    ___|  |       ||   _   ||   |_| ||_     _||    ___||       ||_     _|\n");
    printf("|       ||       ||   |    |       ||       ||   |_||_ |   |___   |       ||  | |  ||       |  |   |  |   |___ |       |  |   |  \n");
    printf("|       ||       ||   |___ |       ||       ||    __  ||    ___|  |      _||  |_|  ||  _    |  |   |  |    ___| |     |   |   |  \n");
    printf("| ||_|| ||   _   ||       ||   _   ||   _   ||   |  | ||   |___   |     |_ |       || | |   |  |   |  |   |___ |   _   |  |   |  \n");
    printf("|_|   |_||__| |__||_______||__| |__||__| |__||___|  |_||_______|  |_______||_______||_|  |__|  |___|  |_______||__| |__|  |___|  \n\n\n");


    if (argc < 2 || !argv[1]){ 
        printf("[!] Error: No arguments provided\n\n\n"); 
        return 1;
    };

    //Don't look at it, it's trash.
    switch (argv[1][1]) {
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
                virustotal_get();
                
                return 0;
            };
            break;
        default:
            printf("[!] Error: Invalid argument\n\n\n");
            return 1;
    };

    return 0;
};




