#include  <stdio.h>
#include  <Windows.h>

#include "config.h"
#include "virustotal.h"
#include "unpac_me.h"
#include "malshare.h"
#include "ansi_colours.h"

volatile BOOL search_virustotal = TRUE;
volatile BOOL search_unpac_me = TRUE;
volatile BOOL search_malshare = TRUE;

DWORD WINAPI search_virustotal_available(LPVOID lpParam){
    char* api_key = get_api_key_value("virustotal");
    char* virustotal_json_string = virustotal_sample_availability(api_key, lpParam);

    free(api_key);
    free(virustotal_json_string);
    search_virustotal = FALSE;
    return 0;
};


DWORD WINAPI search_unpac_me_available(LPVOID lpParam){
    //search_sample_available(VIRUS_HASH);
    char* api_key = get_api_key_value("unpacme");
    char* unpac_me_response = unpac_me_sample_availability(api_key, lpParam);
    cJSON* unpac_me_json = cJSON_Parse(unpac_me_response);
    cJSON* matched_analysis = cJSON_GetObjectItem(unpac_me_json, "matched_analysis");
    if (!cJSON_IsObject(matched_analysis)) {
        printf(ANSI_GREEN"[+] Sample found on Unpac.me\n"ANSI_RESET);
    } else {
        printf(ANSI_RED"[!] Sample not found on Unpac.me\n"ANSI_RESET);
    };
    free(api_key);
    
    search_unpac_me = FALSE;
    return 0;
};

DWORD WINAPI search_malshare_available(LPVOID lpParam){
    char* api_key = get_api_key_value("malshare");
    //char* malshare_json_string = malshare_sample_availability(api_key, lpParam);

    free(api_key);
    //free(malshare_json_string);
    search_malshare = FALSE;
    return 0;
};

// Thread function for the loading animation
DWORD WINAPI LoadingAnimationFuncMany(LPVOID lpParam) {
    const char* animation = "|/-\\";
    int i = 0;
    while (search_malshare, search_unpac_me, search_virustotal) {
        printf(ANSI_BOLD_GRAY"\rSearching for sample availability... %c"ANSI_RESET, animation[i++ % 4]);
        fflush(stdout);
        Sleep(100);
    }
    return 0;
}

// Search for the sample availability on the different platforms
void search_sample_available(char* sample_hash){
    HANDLE hThread_virustotal, hThread_unpac_me, hThread_malshare, hThread_loading;
    DWORD dwThreadId_virustotal, dwThreadId_unpac_me, dwThreadId_malshare, dwThreadId_loading;

    hThread_loading = CreateThread(NULL, 0, LoadingAnimationFuncMany, NULL, 0, &dwThreadId_loading);
    hThread_virustotal = CreateThread(NULL, 0, search_virustotal_available, sample_hash, 0, &dwThreadId_virustotal);
    hThread_unpac_me = CreateThread(NULL, 0, search_unpac_me_available, sample_hash, 0, &dwThreadId_unpac_me);
    hThread_malshare = CreateThread(NULL, 0, search_malshare_available, sample_hash, 0, &dwThreadId_malshare);

    HANDLE threads[] = {hThread_virustotal, hThread_unpac_me, hThread_malshare};
    WaitForMultipleObjects(3, threads, TRUE, INFINITE);
    

    // Cleanup
    CloseHandle(hThread_virustotal);
    CloseHandle(hThread_unpac_me);
    CloseHandle(hThread_malshare);


    return;
};