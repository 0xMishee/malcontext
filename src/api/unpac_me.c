#include <stdio.h>
#include <Windows.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <stdlib.h>
#include <string.h>

#include "miscellaneous.h"


char* unpac_me_sample_availability(char* api_key, char* sample_hash){

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

    //free(api_url_header);
    free(api_key_header);
    curl_easy_cleanup(hnd);
    
    return api_response.data;
};