#include <stdio.h>
#include <Windows.h>
#include <curl/curl.h>
#include "miscellaneous.h"
#include "ansi_colours.h"



char* malshare_sample_availability(char* api_key, char* sample_hash){

    CURL *hnd = curl_easy_init();

    // Dynamically allocate memory for the response
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_json_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&api_response);

    char api_url_header[256];
    sprintf(api_url_header, "https://malshare.com/api.php?api_key=%s&action=details&hash=%s", api_key, sample_hash);
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);
   
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, ANSI_RED"[!] Failed to perform curl request: %s\n"ANSI_RESET, curl_easy_strerror(ret));
        return NULL;
    };

    // Cleanup
    curl_easy_cleanup(hnd);
    //printf("This is what returned...%s\n", api_response.data);
    return api_response.data;
}


char* malshare_download_file(char* api_key, char* sample_hash){

    CURL *hnd = curl_easy_init();

    // Dynamically allocate memory for the response
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_json_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&api_response);

    char api_url_header[256];
    sprintf(api_url_header, "https://malshare.com/api.php?api_key=%s&action=details&hash=%s", api_key, sample_hash);
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);
   
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, ANSI_RED"[!] Failed to perform curl request: %s\n"ANSI_RESET, curl_easy_strerror(ret));
        return NULL;
    };

    // Cleanup
    curl_easy_cleanup(hnd);
    //printf("This is what returned...%s\n", api_response.data);
    return api_response.data;
}