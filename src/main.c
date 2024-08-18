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

#define VIRUS_HASH "b1f2068201c29f3b00aeedc0911498043d7c204a860ca16b3fef47fc19fc2b22"


// TEMP Testing purposes only!
#define FILE_PATH_DIR "E:\\malware overview re-write\\malware_context\\yara-x rules"

volatile BOOL loading = TRUE;

DWORD WINAPI get_vt_file_behaviour(LPVOID lpParam){
    char* api_key = get_api_key_value("virustotal");
    char* virustotal_json_string_file_behaviour = virustotal_get_behaviour_report(api_key, VIRUS_HASH);
    context_virustotal_file_behaviour_print(virustotal_json_string_file_behaviour);
    free(api_key);
    loading = FALSE;
    return 0;
};

// Thread function for the loading animation
DWORD WINAPI LoadingAnimationFunc(LPVOID lpParam) {
    const char* animation = "|/-\\";
    int i = 0;
    while (loading) {
        printf(ANSI_BOLD_GRAY"\rContextualizing malware sample... %c"ANSI_RESET, animation[i++ % 4]);
        fflush(stdout);
        Sleep(100);
    }
    return 0;
}

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

    if(strcmp(argv[1], "-search") == 0){
        //search_sample_available(VIRUS_HASH);
        char* api_key = get_api_key_value("unpacme");
        char* unpac_me_response = unpac_me_sample_availability(api_key, VIRUS_HASH);
        cJSON* unpac_me_json = cJSON_Parse(unpac_me_response);
        cJSON* matched_analysis = cJSON_GetObjectItem(unpac_me_json, "matched_analysis");
        if (!cJSON_IsObject(matched_analysis)) {
            printf(ANSI_GREEN"[+] Sample found on Unpac.me\n"ANSI_RESET);
        } else {
            printf(ANSI_RED"[!] Sample not found on Unpac.me\n"ANSI_RESET);
        };
        free(api_key);

    };

    if(strcmp(argv[1], "-context") == 0) {
        HANDLE hVT_File_Behaviour_Thread, hLoadingThread;
        DWORD dwVT_File_Behaviour_Thread, dwLoadingThreadId;


        
        // Create a thread for the loading animation
        hLoadingThread = CreateThread(NULL, 0, LoadingAnimationFunc, NULL, 0, &dwLoadingThreadId);
        if (hLoadingThread == NULL) {
            printf(ANSI_RED"[!] Error: Failed to create loading animation thread\n"ANSI_RESET);
            return 1;
        }

        hVT_File_Behaviour_Thread = CreateThread(NULL, 0, get_vt_file_behaviour, NULL, 0, &dwVT_File_Behaviour_Thread);
        if (hVT_File_Behaviour_Thread == NULL) {
            printf(ANSI_RED"[!] Error: Failed to create thread\n"ANSI_RESET);
            return 1;
        }

        WaitForSingleObject(hVT_File_Behaviour_Thread, INFINITE);
        CloseHandle(hVT_File_Behaviour_Thread);

        WaitForSingleObject(hLoadingThread, INFINITE);
        CloseHandle(hLoadingThread);

        // Get API key and get the file report
        //char* api_key = get_api_key_value("virustotal");
        //char* virustotal_json_string_file_report = virustotal_get_file_report(api_key, VIRUS_HASH);

        //char* virustotal_json_string_file_behaviour = virustotal_get_behaviour_report(api_key, VIRUS_HASH);

        //context_virustotal_file_print(virustotal_json_string);
        //context_virustotal_file_behaviour_print(virustotal_json_string_file_behaviour);
        //context_virustotal_file_print(virustotal_json_string_file_report);


        // Cleanup
        //free(api_key);
        return 0;
    };

    if (strcmp(argv[1], "json") == 0) {

        char* api_key = get_api_key_value("virustotal");
        free(api_key);
        return 0;
    };

    return 0;
};




