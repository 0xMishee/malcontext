#include <stdio.h>
#include <windows.h>

#include "yara_x.h"
#include "dirent.h"

#define MAX_FILES 100


// Loads directory with yara-x files. 
BOOL load_yara_ruleset(char* dir) {

    struct dirent* entry;

    // Open directory
    DIR* dir_ptr = opendir(dir);
    if (!dir_ptr) {
        perror("[!] Could not open directory");
        return FALSE;
    }

/*    struct YRX_COMPILER* compiler;
    enum YRX_RESULT result = yrx_compiler_create(0, &compiler);
    if (!result) {
        fprintf(stderr, "[!] Could not create YARA-X compiler\n");
        closedir(dir_ptr);
        return FALSE;
    }*/



    while ((entry = readdir(dir_ptr)) != NULL) {
        if (entry->d_type == DT_REG) {
            printf("File: %s\n", entry->d_name);
        }
    }





    closedir(dir_ptr);
    return TRUE;
};