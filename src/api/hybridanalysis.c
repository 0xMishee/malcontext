#include <stdio.h>
#include <curl/curl.h>
#include <windows.h>

#include "ansi_colours.h"
#include "miscellaneous.h"




char* hybridanalysis_search(char* api_key, char* sample_hash){
    CURL *hnd = curl_easy_init();
    if (!hnd) {
        fprintf(stderr, "[!] Failed to initialize curl\n");
        return NULL;
    };
    
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_json_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&api_response);

    char* url_header = "https://hybrid-analysis.com/api/v2/search/hash";
    curl_easy_setopt(hnd, CURLOPT_URL, url_header);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, CURL_AGENT);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    char* api_key_header = append_header_strings("api-key: %s", api_key);
    headers = curl_slist_append(headers, api_key_header);
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    char json_data[128];
    snprintf(json_data, sizeof(json_data), "hash=%s", sample_hash);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, json_data);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, "[!] Failed to perform curl request: %s\n", curl_easy_strerror(ret));
        return NULL;
    };

    //Cleanup
    curl_easy_cleanup(hnd);
    return api_response.data;
}
