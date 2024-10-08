#include <stdio.h>
#include <stdlib.h> 
#include <windows.h>
#include <string.h> 
#include <cjson/cJSON.h>

#include "config.h"
#include "search.h"
#include "virustotal.h"
#include "unpac_me.h"
#include "malshare.h"
#include "malpedia.h"
#include "ansi_colours.h"
#include "miscellaneous.h"
#include "malwarebazaar.h"


DWORD WINAPI search_malwarebazaar_available(LPVOID lpParam){
    ThreadSearchData* thread_data = (ThreadSearchData*)lpParam;
    if (!thread_data){
        fprintf(stderr, ANSI_RED"[!] Error: No thread data provided\n"ANSI_RESET);
        return 1;
    };

    HANDLE hMutex = thread_data->hMutex;
    char* sample_hash = thread_data->sample_hash;
    LoadingAnimationFlags* loading_animation_flags = thread_data->loading_animation_flags;
    SearchAPIResponse* search_api_response = thread_data->search_api_response;
    SampleSubmissionDates* sample_submission_dates = thread_data->sample_submission_dates;

    char* malwarebazaar_response = malwarebazaar_search(sample_hash);
    cJSON* malwarebazaar_json = cJSON_Parse(malwarebazaar_response);

    if (strcmp(cJSON_GetArrayItem(malwarebazaar_json,0)->valuestring,"ok") == 0){

        // 🫣 What is this inception of arrays...
        sample_submission_dates->mb_first_date = (char*)malloc(20*sizeof(char));
        cJSON* response_json_array = cJSON_GetArrayItem(malwarebazaar_json, 1);
        cJSON* response_json_second_array = cJSON_GetArrayItem(response_json_array, 0);
        cJSON* date = cJSON_GetObjectItem(response_json_second_array, "first_seen");


        WaitForSingleObject(hMutex, INFINITE);
        strcpy_s(sample_submission_dates->mb_first_date, 20*sizeof(char), date->valuestring); 
        search_api_response->search_malwarebazaar_found = TRUE;
        ReleaseMutex(hMutex);
    } 

    // Cleanup
    free(malwarebazaar_response);
    cJSON_Delete(malwarebazaar_json);

    WaitForSingleObject(hMutex, INFINITE);
    loading_animation_flags->loading_animation_malwarebazaar = FALSE;
    ReleaseMutex(hMutex);
    return 0;
};

DWORD WINAPI search_malpedia_available(LPVOID lpParam){
    ThreadSearchData* thread_data = (ThreadSearchData*)lpParam;
    if (!thread_data){
        fprintf(stderr, ANSI_RED"[!] Error: No thread data provided\n"ANSI_RESET);
        return 1;
    };

    HANDLE hMutex = thread_data->hMutex;
    char* sample_hash = thread_data->sample_hash;
    LoadingAnimationFlags* loading_animation_flags = thread_data->loading_animation_flags;
    SearchAPIResponse* search_api_response = thread_data->search_api_response;


    char* api_key = get_api_key_value("malpedia");
    char* malpedia_response = malpedia_search_malware(api_key, sample_hash);
    cJSON* malpdia_json = cJSON_Parse(malpedia_response);

    if (!(strcmp(cJSON_GetArrayItem(malpdia_json,0)->valuestring,"No Sample matches the given query.") == 0)){
        WaitForSingleObject(hMutex, INFINITE);
        search_api_response->search_malpedia_found = TRUE;
        ReleaseMutex(hMutex);
    } 

    // Cleanup
    free(malpedia_response);
    free(api_key);
    cJSON_Delete(malpdia_json);

    WaitForSingleObject(hMutex, INFINITE);
    loading_animation_flags->loading_animation_malpedia = FALSE;
    ReleaseMutex(hMutex);
    return 0;
};

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
    SampleSubmissionDates* sample_submission_dates = thread_data->sample_submission_dates;


    char* api_key = get_api_key_value("virustotal");
    char* virustotal_response = virustotal_sample_availability(api_key, sample_hash);
    cJSON* virustotal_json = cJSON_Parse(virustotal_response);
    if (strcmp(cJSON_GetArrayItem(virustotal_json,0)->string,"data") == 0){

        sample_submission_dates->vt_first_date = (char*)malloc(20*sizeof(char));


        WaitForSingleObject(hMutex, INFINITE);
        convert_time_ts(virustotal_submission_date(virustotal_response), sample_submission_dates->vt_first_date, 20*sizeof(char));
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
    SampleSubmissionDates* sample_submission_dates = thread_data->sample_submission_dates;

    char* api_key = get_api_key_value("unpacme");
    char* unpac_me_response = unpac_me_search(api_key, sample_hash);
    cJSON* unpac_me_json = cJSON_Parse(unpac_me_response);
    cJSON* matched_analysis = cJSON_GetArrayItem(unpac_me_json, 0);
    if (strcmp(matched_analysis->string, "first_seen") == 0){

        sample_submission_dates->um_first_date = (char*)malloc(20*sizeof(char));

        WaitForSingleObject(hMutex, INFINITE);
        convert_time_ts(unpac_me_submission_date(unpac_me_response), sample_submission_dates->um_first_date, 20*sizeof(char));
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
    char* malshare_response = malshare_search(api_key, sample_hash);
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
    size_t i = 0;
    // debug printf("checking while true!\n");
    while (TRUE) {
        WaitForSingleObject(hMutex, INFINITE);
        // Starting to get out of control..lmao 
        BOOL loading_animation = loading_animation_flags->loading_animation_malshare || loading_animation_flags->loading_animation_unpac_me 
        || loading_animation_flags->loading_animation_malshare || loading_animation_flags->loading_animation_malpedia 
        || loading_animation_flags->loading_animation_malwarebazaar;
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

    LoadingAnimationFlags loading_flags = { TRUE, TRUE, TRUE, TRUE, TRUE };
    SearchAPIResponse search_api_response = { FALSE, FALSE, FALSE, FALSE, FALSE };
    SampleSubmissionDates sample_submission_dates = { NULL, NULL, NULL };

    ThreadSearchData thread_data;
    thread_data.hMutex = hMutex;
    thread_data.sample_hash = sample_hash;
    thread_data.loading_animation_flags = &loading_flags;
    thread_data.search_api_response = &search_api_response;
    thread_data.sample_submission_dates = &sample_submission_dates;

    HANDLE hThread_virustotal, hThread_unpac_me, hThread_malshare, hThread_loading, hThread_malpedia, hThread_malwarebazaar;
    DWORD dwThreadId_virustotal, dwThreadId_unpac_me, dwThreadId_malshare, dwThreadId_loading, dwThreadId_malpedia, dwThreadId_malwarebazaar;

    hThread_loading = CreateThread(NULL, 0, LoadingAnimationFuncMany, &thread_data, 0, &dwThreadId_loading);
    if(!hThread_loading){
        printf(ANSI_RED"[!] Error: Failed to create loading animation thread\n"ANSI_RESET);
        return;
    };

    hThread_malpedia = CreateThread(NULL, 0, search_malpedia_available, &thread_data, 0, &dwThreadId_malpedia);
    if(!hThread_malpedia){
        printf(ANSI_RED"[!] Error: Failed to create Malpedia thread\n"ANSI_RESET);
        return;
    };

    hThread_virustotal = CreateThread(NULL, 0, search_virustotal_available, &thread_data, 0, &dwThreadId_virustotal);
    if(!hThread_virustotal){
        printf(ANSI_RED"[!] Error: Failed to create Virustotal thread\n"ANSI_RESET);
        return;
    };

    hThread_malwarebazaar = CreateThread(NULL, 0, search_malwarebazaar_available, &thread_data, 0, &dwThreadId_malwarebazaar);
    if(!hThread_virustotal){
        printf(ANSI_RED"[!] Error: Failed to create MalwareBazaar thread\n"ANSI_RESET);
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

    HANDLE threads[] = {hThread_unpac_me, hThread_virustotal, hThread_malshare, hThread_malwarebazaar};
    DWORD waitResult = WaitForMultipleObjects(4, threads, TRUE, INFINITE);
    if (waitResult == WAIT_FAILED) {
        printf(ANSI_RED"[!] Error: WaitForMultipleObjects failed\n"ANSI_RESET);
    }

    // debug printf("Im back from the search threads, time to print results!\n");
    if(thread_data.search_api_response->search_malshare_found){
        printf(ANSI_GREEN"[+] Sample found on Malshare\n"ANSI_RESET);
        printf(ANSI_BOLD_GRAY"[-] Submission date not logged\n"ANSI_RESET);
    } else {
        printf(ANSI_RED"[!] Sample not found on Malshare\n"ANSI_RESET);
    };

    if (thread_data.search_api_response->search_unpac_me_found){
        printf(ANSI_GREEN"[+] Sample found on Unpac.me\n"ANSI_RESET);
        printf(ANSI_GREEN"[+] Submission date : %s\n"ANSI_RESET, thread_data.sample_submission_dates->um_first_date);

    } else {
        printf(ANSI_RED"[!] Sample not found on Unpac.me\n"ANSI_RESET);
    };

    if (thread_data.search_api_response->search_virustotal_found){
        printf(ANSI_GREEN"[+] Sample found on Virustotal\n"ANSI_RESET);
        printf(ANSI_GREEN"[+] Submission date : %s\n"ANSI_RESET, thread_data.sample_submission_dates->vt_first_date);
    } else {
        printf(ANSI_RED"[!] Sample not found on Virustotal\n"ANSI_RESET);
    };

    if (thread_data.search_api_response->search_malpedia_found){
        printf(ANSI_GREEN"[+] Sample found on Malpedia\n"ANSI_RESET);
        printf(ANSI_BOLD_GRAY"[-] Submission date not logged\n"ANSI_RESET);

    } else {
        printf(ANSI_RED"[!] Sample not found on Malpedia\n"ANSI_RESET);
    };

    if (thread_data.search_api_response->search_malwarebazaar_found){
        printf(ANSI_GREEN"[+] Sample found on MalwareBazaar\n"ANSI_RESET);
        printf(ANSI_GREEN"[+] Submission date : %s\n"ANSI_RESET, thread_data.sample_submission_dates->mb_first_date);

    } else {
        printf(ANSI_RED"[!] Sample not found on MalwareBazaar\n"ANSI_RESET);
    };

    // Cleanup
    free(sample_submission_dates.vt_first_date);
    free(sample_submission_dates.um_first_date);
    free(sample_submission_dates.mb_first_date);

    CloseHandle(hThread_virustotal);
    CloseHandle(hThread_unpac_me);
    CloseHandle(hThread_malshare);
    CloseHandle(hThread_malpedia);
    CloseHandle(hThread_loading);
    CloseHandle(hMutex);
    return;
};