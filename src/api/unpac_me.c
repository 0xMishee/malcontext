#include <stdio.h>
#include <Windows.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <stdlib.h>
#include <string.h>

#include "miscellaneous.h"

char* unpac_me_search(char* api_key, char* sample_hash){

    CURL *hnd = curl_easy_init();

    // Dynamically allocate memory for the response
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_json_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&api_response);

    char* api_url_header = "https://api.unpac.me/api/v1/private/search/term/sha256";
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    char* api_key_header = append_header_strings("Authorization: Key %s",api_key);
    headers = curl_slist_append(headers, api_key_header);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    // Create JSON data
    char json_data[128];
    snprintf(json_data, sizeof(json_data), "{\"value\": \"%s\", \"repo_type\": \"malware\"}", sample_hash);

    // Set POST fields
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, json_data);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, "[!] Failed to perform curl request: %s\n", curl_easy_strerror(ret));
        return NULL;
    };

    // Cleanup

    free(api_key_header);
    curl_easy_cleanup(hnd);
    return api_response.data;
};

char* unpac_me_get_batch_id(char* api_key, char* sample_hash){

    CURL *hnd = curl_easy_init();
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_data_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &api_response);

    char* api_url_header = "https://api.unpac.me/api/v1/private/batch/download";
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);
    
    struct curl_slist *headers = NULL;

    char auth_header[MAX_PATH];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Key %s", api_key);

    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    char json_data[MAX_PATH];
    sprintf(json_data, "{\"type\": \"hash\", \"dlist\": [\"%s\"]}", sample_hash);
    // Set POST fields
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, json_data);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, "[!] Failed to perform curl request: %s\n", curl_easy_strerror(ret));
        return NULL;
    };

    // Cleanup
    curl_easy_cleanup(hnd);
    return api_response.data;
};

char* unpac_me_get_url_batch_job(char* token, char* api_key){

    CURL *hnd = curl_easy_init();
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;
    
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_data_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &api_response);

    char api_url_header[MAX_PATH];
    sprintf(api_url_header,"https://api.unpac.me/api/v1/private/batch/download/%s", token);
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);
    
    struct curl_slist *headers = NULL;

    char auth_header[MAX_PATH];
    sprintf(auth_header, "Authorization: Key %s", api_key);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, "[!] Failed to perform curl request: %s\n", curl_easy_strerror(ret));
        return NULL;
    };

    // Cleanup
    curl_easy_cleanup(hnd);
    return api_response.data;
}

BOOL unpac_me_validate_hash(char* api_key, char* sample_hash) {

    char* response_data = unpac_me_search(api_key, sample_hash);
    cJSON* response_data_json = cJSON_Parse(response_data);
    cJSON* response_data_json_string = cJSON_GetArrayItem(response_data_json, 1);

    if (strcmp(response_data_json_string->valuestring, "generic_error") == 0){
        return FALSE;
    }
    return TRUE;
}


int unpac_me_submission_date(char* json_response){
    cJSON* json = cJSON_Parse(json_response);
    cJSON* submission_date = cJSON_GetArrayItem(json, 0);
    return submission_date->valueint;
}



