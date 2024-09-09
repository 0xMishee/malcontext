#include <stdio.h>
#include "curl/curl.h"
#include "miscellaneous.h"
/*  {"detail":"No Sample matches the given query."}
{"md5":"3034b61a52ddc30eabdb96f49334453b","sha256":"02e9f0fbb7f3acea4fcf155dc7813e15c1c8d1c77c3ae31252720a9fa7454292","status":"unpacked","family":"win.ransomhub","version":"","winapi1024v1":""}
*/



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

    printf("This is what returned...%s\n", api_response.data);
    curl_easy_cleanup(hnd);
    return api_response.data;
}

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