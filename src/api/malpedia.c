#include <stdio.h>
#include <cjson/cJSON.h>
#include <windows.h>
#include "ansi_colours.h"


#include "curl/curl.h"
#include "miscellaneous.h"
/*  {"detail":"No Sample matches the given query."}
{"md5":"3034b61a52ddc30eabdb96f49334453b","sha256":"02e9f0fbb7f3acea4fcf155dc7813e15c1c8d1c77c3ae31252720a9fa7454292","status":"unpacked","family":"win.ransomhub","version":"","winapi1024v1":""}
*/


// Malpedia are cool enough to allow us to actually check if our api-key is valid. 
char* malpedia_check_api_key(char* api_key){
    CURL *hnd = curl_easy_init();
    api_call_response api_response;

    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_json_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&api_response);

    char* api_url_header = "https://malpedia.caad.fkie.fraunhofer.de/api/check/apikey";
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);

    struct curl_slist *headers = NULL;
    char* api_key_header = append_header_strings("Authorization: apitoken %s", api_key);
    headers = curl_slist_append(headers, api_key_header);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, "[!] Failed to perform curl request: %s\n", curl_easy_strerror(ret));
        return NULL;
    };
    curl_easy_cleanup(hnd);
    return api_response.data;
}

// Just searches for the hash in the malpedia database
// Returns; md5, sha256, status, family, version, winapi1024v1.
char* malpedia_search_malware(char* api_key, char* sample_hash){
    CURL *hnd = curl_easy_init();
    api_call_response api_response;

    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_json_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&api_response);

    char* api_url_header = append_header_strings("https://malpedia.caad.fkie.fraunhofer.de/api/get/sample/%s/info", sample_hash);
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);

    struct curl_slist *headers = NULL;
    char* api_key_header = append_header_strings("Authorization: apitoken %s", api_key);
    headers = curl_slist_append(headers, api_key_header);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

   
    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, "[!] Failed to perform curl request: %s\n", curl_easy_strerror(ret));
        return NULL;
    };

    curl_easy_cleanup(hnd);
    return api_response.data;
}

//Download the hash in .zip format
char* malpedia_download_malware(char* api_key, char* sample_hash){
    CURL *hnd = curl_easy_init();
    api_call_response api_response;

    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_data_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&api_response);

    char* api_url_header = append_header_strings("https://malpedia.caad.fkie.fraunhofer.de/api/get/sample/%s/zip", sample_hash);
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);

    struct curl_slist *headers = NULL;
    char* api_key_header = append_header_strings("Authorization: apitoken %s", api_key);
    headers = curl_slist_append(headers, api_key_header);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, "[!] Failed to perform curl request: %s\n", curl_easy_strerror(ret));
        return NULL;
    };

    curl_easy_cleanup(hnd);
    return api_response.data;
}

// Checks so the api key and hash both are valid; with valid hash here just means that if it exist on the website repo.
BOOL malpedia_validate_key_hash(char* api_key, char* sample_hash){
    if (!api_key | !sample_hash){
        printf(ANSI_RED "[!] Error: Invalid API key or hash\n" ANSI_RESET);
        return FALSE;
    };

    char* api_key_response = malpedia_check_api_key(api_key);
    cJSON* api_key_json = cJSON_Parse(api_key_response);
    cJSON* api_key_json_data = cJSON_GetArrayItem(api_key_json, 0);

    if (!api_key_response  || strcmp(api_key_json_data->valuestring, "Valid token.") != 0){
        printf(ANSI_RED "[!] Error: Invalid API key\n" ANSI_RESET);
        return FALSE;
    };

    char* sample_response = malpedia_search_malware(api_key, sample_hash);
    cJSON* sample_json = cJSON_Parse(sample_response);
    cJSON* sample_json_data = cJSON_GetArrayItem(sample_json, 0);

    if (!sample_response || strcmp(sample_json_data->valuestring, "No Sample matches the given query.") == 0){
        printf(ANSI_RED "[!] Error: Hash wasn't found on Malpedia\n" ANSI_RESET);
        return FALSE;
    };

    return TRUE;
}