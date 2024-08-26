#include <stdio.h>
#include <stdlib.h> 
#include <windows.h>
#include <string.h> 



#include "config.h"
#include "search.h"
#include "virustotal.h"
#include "unpac_me.h"
#include "malshare.h"
#include "ansi_colours.h"

// Global variables for the loading animation
BOOL loading_animation_virustotal = TRUE;
BOOL loading_animation_unpac_me = TRUE;
BOOL loading_animation_malshare = TRUE;

// Global variables for the search results
volatile BOOL search_virustotal_found = FALSE;
volatile BOOL search_unpac_me_found = FALSE;
volatile BOOL search_malshare_found = FALSE;

DWORD WINAPI search_virustotal_available(LPVOID lpParam){
    ThreadData* thread_data = (ThreadData*)lpParam;
    HANDLE hMutex = thread_data->hMutex;
    char* sample_hash = thread_data->sample_hash;

    char* api_key = get_api_key_value("virustotal");
    char* virustotal_response = virustotal_sample_availability(api_key, sample_hash);
    cJSON* virustotal_json = cJSON_Parse(virustotal_response);
    if (!strcmp(cJSON_GetArrayItem(virustotal_json,0)->string,"error") == 0){
        search_virustotal_found = TRUE;
    } 

    // Cleanup
    free(virustotal_response);
    free(api_key);
    cJSON_Delete(virustotal_json);

    WaitForSingleObject(hMutex, INFINITE);
    loading_animation_virustotal = FALSE;

    return 0;
}

DWORD WINAPI search_unpac_me_available(LPVOID lpParam){
    ThreadData* thread_data = (ThreadData*)lpParam;
    HANDLE hMutex = thread_data->hMutex;
    char* sample_hash = thread_data->sample_hash;

    char* api_key = get_api_key_value("unpacme");
    char* unpac_me_response = unpac_me_sample_availability(api_key, sample_hash);
    cJSON* unpac_me_json = cJSON_Parse(unpac_me_response);
    cJSON* matched_analysis = cJSON_GetArrayItem(unpac_me_json, 0);
    if (strcmp(matched_analysis->string, "first_seen") == 0){
        search_unpac_me_found = TRUE;
    } 

    // Cleanup
    free(unpac_me_response);
    free(api_key);
    cJSON_Delete(unpac_me_json);

    WaitForSingleObject(hMutex, INFINITE);
    loading_animation_unpac_me = FALSE;

    return 0;
};

DWORD WINAPI search_malshare_available(LPVOID lpParam){
    ThreadData* thread_data = (ThreadData*)lpParam;
    HANDLE hMutex = thread_data->hMutex;
    char* sample_hash = thread_data->sample_hash;

    //search_sample_available(VIRUS_HASH);
    char* api_key = get_api_key_value("malshare");
    char* malshare_response = malshare_sample_availability(api_key, sample_hash);
    cJSON* malshare_json = cJSON_Parse(malshare_response);
    cJSON* malshare_data = cJSON_GetArrayItem(malshare_json, 0);
    if (!strcmp(malshare_data->string, "ERROR") == 0){
        search_malshare_found = TRUE;
    } 

    // Cleanup
    free(malshare_response);
    free(api_key);
    cJSON_Delete(malshare_json);

    WaitForSingleObject(hMutex, INFINITE);
    loading_animation_malshare = FALSE;

    return 0;
};

// Thread function for the loading animation
DWORD WINAPI LoadingAnimationFuncMany(LPVOID lpParam) {
    HANDLE hMutex = (HANDLE)lpParam;
    const char* animation = "|/-\\";
    int i = 0;
    while (TRUE ) {
        WaitForSingleObject(hMutex, INFINITE);
        BOOL loading_animation = loading_animation_virustotal || loading_animation_unpac_me || loading_animation_malshare;
        ReleaseMutex(hMutex);

        if (!loading_animation) {
            break;
        }

        printf(ANSI_BOLD_GRAY"\rSearching for sample availability... %c"ANSI_RESET, animation[i++ % 4]);
        fflush(stdout);
        Sleep(100);
    }
    printf("\n");
    return 0;
}

// Search for the sample availability on the different platforms
void search_sample_available(char* sample_hash){
    if (!sample_hash){
        printf(ANSI_RED"[!] Error: No sample hash provided\n"ANSI_RESET);
        return;
    };

    HANDLE hMutex_api_answer = CreateMutex(NULL, FALSE, NULL);
    if(hMutex_api_answer == NULL){
        printf(ANSI_RED"[!] Error: Failed to create mutex\n"ANSI_RESET);
        return;
    };

    ThreadData thread_data;
    thread_data.hMutex = hMutex_api_answer;
    thread_data.sample_hash = sample_hash;


    HANDLE hThread_virustotal, hThread_unpac_me, hThread_malshare, hThread_loading;
    DWORD dwThreadId_virustotal, dwThreadId_unpac_me, dwThreadId_malshare, dwThreadId_loading;

    
    hThread_loading = CreateThread(NULL, 0, LoadingAnimationFuncMany, hMutex_api_answer, 0, &dwThreadId_loading);
    if(hThread_loading == NULL){
        printf(ANSI_RED"[!] Error: Failed to create loading animation thread\n"ANSI_RESET);
        return;
    };

    hThread_virustotal = CreateThread(NULL, 0, search_virustotal_available, &thread_data, 0, &dwThreadId_virustotal);
    if(hThread_virustotal == NULL){
        printf(ANSI_RED"[!] Error: Failed to create Virustotal thread\n"ANSI_RESET);
        return;
    };

    hThread_unpac_me = CreateThread(NULL, 0, search_unpac_me_available, &thread_data, 0, &dwThreadId_unpac_me);
    if(hThread_unpac_me == NULL){
        printf(ANSI_RED"[!] Error: Failed to create Unpac.me thread\n"ANSI_RESET);
        return;
    };

    hThread_malshare = CreateThread(NULL, 0, search_malshare_available, &thread_data, 0, &dwThreadId_malshare);
    if(hThread_malshare == NULL){
        printf(ANSI_RED"[!] Error: Failed to create Malshare thread\n"ANSI_RESET);
        return;
    };

    WaitForSingleObject(hThread_loading, INFINITE);

    HANDLE threads[] = {hThread_unpac_me, hThread_virustotal};
    DWORD waitResult = WaitForMultipleObjects(2, threads, TRUE, INFINITE);
    if (waitResult == WAIT_FAILED) {
        printf(ANSI_RED"[!] Error: WaitForMultipleObjects failed\n"ANSI_RESET);
    }

    if(search_malshare_found){
        printf(ANSI_GREEN"[+] Sample found on Malshare\n"ANSI_RESET);
    } else {
        printf(ANSI_RED"[!] Sample not found on Malshare\n"ANSI_RESET);
    };

    if (search_unpac_me_found){
        printf(ANSI_GREEN"[+] Sample found on Unpac.me\n"ANSI_RESET);
    } else {
        printf(ANSI_RED"[!] Sample not found on Unpac.me\n"ANSI_RESET);
    };

    if (search_virustotal_found){
        printf(ANSI_GREEN"[+] Sample found on Virustotal\n"ANSI_RESET);
    } else {
        printf(ANSI_RED"[!] Sample not found on Virustotal\n"ANSI_RESET);
    };


    // Cleanup
    CloseHandle(hThread_virustotal);
    CloseHandle(hThread_unpac_me);
    CloseHandle(hThread_malshare);
    CloseHandle(hThread_loading);
    
    CloseHandle(hMutex_api_answer);
    return;
};