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

DWORD WINAPI search_virustotal_available(LPVOID lpParam){
    ThreadSearchData* thread_data = (ThreadSearchData*)lpParam;
    if (!thread_data){
        fprintf(stderr, ANSI_RED"[!] Error: No thread data provided\n"ANSI_RESET);
        return 1;
    };

    HANDLE hMutex = thread_data->hMutex;
    char* sample_hash = thread_data->sample_hash;
    LoadingAnimationFlags* loading_animation_flags = thread_data->loading_animation_flags;
    SearchAPIResponse* search_api_response = thread_data->search_api_response;

    char* api_key = get_api_key_value("virustotal");
    char* virustotal_response = virustotal_sample_availability(api_key, sample_hash);
    cJSON* virustotal_json = cJSON_Parse(virustotal_response);
    if (!(strcmp(cJSON_GetArrayItem(virustotal_json,0)->string,"error") == 0)){
        WaitForSingleObject(hMutex, INFINITE);
        search_api_response->search_virustotal_found = TRUE;
        ReleaseMutex(hMutex);
    } 

    // Cleanup
    free(virustotal_response);
    free(api_key);
    cJSON_Delete(virustotal_json);

    WaitForSingleObject(hMutex, INFINITE);
    loading_animation_flags->loading_animation_virustotal = FALSE;
    ReleaseMutex(hMutex);
    return 0;
}

DWORD WINAPI search_unpac_me_available(LPVOID lpParam){
    ThreadSearchData* thread_data = (ThreadSearchData*)lpParam;
    if (!thread_data){
        fprintf(stderr, ANSI_RED"[!] Error: No thread data provided\n"ANSI_RESET);
        return 1;
    };

    HANDLE hMutex = thread_data->hMutex; 
    char* sample_hash = thread_data->sample_hash;
    LoadingAnimationFlags* loading_animation_flags = thread_data->loading_animation_flags;
    SearchAPIResponse* search_api_response = thread_data->search_api_response;

    char* api_key = get_api_key_value("unpacme");
    char* unpac_me_response = unpac_me_sample_availability(api_key, sample_hash);
    cJSON* unpac_me_json = cJSON_Parse(unpac_me_response);
    cJSON* matched_analysis = cJSON_GetArrayItem(unpac_me_json, 0);
    if (strcmp(matched_analysis->string, "first_seen") == 0){
        WaitForSingleObject(hMutex, INFINITE);
        search_api_response->search_unpac_me_found = TRUE;
        ReleaseMutex(hMutex);
    } 

    // Cleanup
    free(unpac_me_response);
    free(api_key);
    cJSON_Delete(unpac_me_json);

    WaitForSingleObject(hMutex, INFINITE);
    loading_animation_flags->loading_animation_unpac_me = FALSE;
    ReleaseMutex(hMutex);

    return 0;
};

DWORD WINAPI search_malshare_available(LPVOID lpParam){
    ThreadSearchData* thread_data = (ThreadSearchData*)lpParam;
    if (!thread_data){
        fprintf(stderr, ANSI_RED"[!] Error: No thread data provided\n"ANSI_RESET);
        return 1;
    };

    HANDLE hMutex = thread_data->hMutex;
    char* sample_hash = thread_data->sample_hash;
    LoadingAnimationFlags* loading_animation_flags = thread_data->loading_animation_flags;
    SearchAPIResponse* search_api_response = thread_data->search_api_response;

    //search_sample_available(VIRUS_HASH);
    char* api_key = get_api_key_value("malshare");
    char* malshare_response = malshare_sample_availability(api_key, sample_hash);
    cJSON* malshare_json = cJSON_Parse(malshare_response);
    cJSON* malshare_data = cJSON_GetArrayItem(malshare_json, 0);
    if (!(strcmp(malshare_data->string, "ERROR") == 0)){
        WaitForSingleObject(hMutex, INFINITE);
        search_api_response->search_malshare_found = TRUE;
        ReleaseMutex(hMutex);
    } 
    
    // Cleanup
    free(malshare_response);
    free(api_key);
    cJSON_Delete(malshare_json);

    WaitForSingleObject(hMutex, INFINITE);
    loading_animation_flags->loading_animation_malshare = FALSE;
    ReleaseMutex(hMutex);

    return 0;
};

// Thread function for the loading animation
DWORD WINAPI LoadingAnimationFuncMany(LPVOID lpParam) {
    ThreadSearchData* thread_data = (ThreadSearchData*)lpParam;
    HANDLE hMutex = thread_data->hMutex;
    LoadingAnimationFlags* loading_animation_flags = thread_data->loading_animation_flags;

    // debug printf("time to define some stuff\n");
    const char* animation = "|/-\\";
    int i = 0;
    // debug printf("checking while true!\n");
    while (TRUE) {
        WaitForSingleObject(hMutex, INFINITE);
        BOOL loading_animation = loading_animation_flags->loading_animation_malshare || loading_animation_flags->loading_animation_unpac_me || loading_animation_flags->loading_animation_malshare;
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

    HANDLE hMutex = CreateMutex(NULL, FALSE, NULL);
    if(!hMutex){
        printf(ANSI_RED"[!] Error: Failed to create mutex\n"ANSI_RESET);
        return;
    };

    LoadingAnimationFlags loading_flags = { TRUE, TRUE, TRUE };
    SearchAPIResponse search_api_response = { FALSE, FALSE, FALSE };

    ThreadSearchData thread_data;
    thread_data.hMutex = hMutex;
    thread_data.sample_hash = sample_hash;
    thread_data.loading_animation_flags = &loading_flags;
    thread_data.search_api_response = &search_api_response;

    HANDLE hThread_virustotal, hThread_unpac_me, hThread_malshare, hThread_loading;
    DWORD dwThreadId_virustotal, dwThreadId_unpac_me, dwThreadId_malshare, dwThreadId_loading;

    hThread_loading = CreateThread(NULL, 0, LoadingAnimationFuncMany, &thread_data, 0, &dwThreadId_loading);
    if(!hThread_loading){
        printf(ANSI_RED"[!] Error: Failed to create loading animation thread\n"ANSI_RESET);
        return;
    };

    hThread_virustotal = CreateThread(NULL, 0, search_virustotal_available, &thread_data, 0, &dwThreadId_virustotal);
    if(!hThread_virustotal){
        printf(ANSI_RED"[!] Error: Failed to create Virustotal thread\n"ANSI_RESET);
        return;
    };

    hThread_unpac_me = CreateThread(NULL, 0, search_unpac_me_available, &thread_data, 0, &dwThreadId_unpac_me);
    if(!hThread_unpac_me){
        printf(ANSI_RED"[!] Error: Failed to create Unpac.me thread\n"ANSI_RESET);
        return;
    };

    hThread_malshare = CreateThread(NULL, 0, search_malshare_available, &thread_data, 0, &dwThreadId_malshare);
    if(!hThread_malshare){
        printf(ANSI_RED"[!] Error: Failed to create Malshare thread\n"ANSI_RESET);
        return;
    };

    // debug printf("Waiting for the loading thread to finish\n");
    WaitForSingleObject(hThread_loading, INFINITE);
    // debug printf("Im back from the loading thread\n");

    HANDLE threads[] = {hThread_unpac_me, hThread_virustotal};
    DWORD waitResult = WaitForMultipleObjects(2, threads, TRUE, INFINITE);
    if (waitResult == WAIT_FAILED) {
        printf(ANSI_RED"[!] Error: WaitForMultipleObjects failed\n"ANSI_RESET);
    }

    // debug printf("Im back from the search threads, time to print results!\n");
    if(thread_data.search_api_response->search_malshare_found){
        printf(ANSI_GREEN"[+] Sample found on Malshare\n"ANSI_RESET);
    } else {
        printf(ANSI_RED"[!] Sample not found on Malshare\n"ANSI_RESET);
    };

    if (thread_data.search_api_response->search_unpac_me_found){
        printf(ANSI_GREEN"[+] Sample found on Unpac.me\n"ANSI_RESET);
    } else {
        printf(ANSI_RED"[!] Sample not found on Unpac.me\n"ANSI_RESET);
    };

    if (thread_data.search_api_response->search_virustotal_found){
        printf(ANSI_GREEN"[+] Sample found on Virustotal\n"ANSI_RESET);
    } else {
        printf(ANSI_RED"[!] Sample not found on Virustotal\n"ANSI_RESET);
    };

    // Cleanup
    CloseHandle(hThread_virustotal);
    CloseHandle(hThread_unpac_me);
    CloseHandle(hThread_malshare);
    CloseHandle(hThread_loading);
    CloseHandle(hMutex);
    return;
};