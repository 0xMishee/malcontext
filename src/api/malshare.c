#include <stdio.h>
#include <Windows.h>
#include <curl/curl.h>
#include "miscellaneous.h"
#include "ansi_colours.h"
#include <cjson/cJSON.h>

char* malshare_search(char* api_key, char* sample_hash){

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
    return api_response.data;
}

BOOL malshare_download_file(char* api_key, char* sample_hash){

    CURL *hnd = curl_easy_init();
    api_call_response api_response;

    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_data_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &api_response);

    char api_url_header[256];
    sprintf(api_url_header, "https://malshare.com/api.php?api_key=%s&action=getfile&hash=%s", api_key, sample_hash);
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);

    curl_easy_setopt(hnd, CURLOPT_USERAGENT, CURL_AGENT);

    // Malshare requires redirects for some reason...took me way longer than I'd like to admit to figure this out.
    curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, ANSI_RED"[!] Failed to perform curl request: %s\n"ANSI_RESET, curl_easy_strerror(ret));
        return FALSE;
    };

     // Create file, apparently easier to do it this way. Logic is cleaner elsewhere then... smh
    char file_name[256];
    if (strcpy_s(file_name, sizeof(file_name), sample_hash) != 0) {
        fprintf(stderr, ANSI_RED"[!] Failed to copy sample hash to file name\n"ANSI_RESET);
        curl_easy_cleanup(hnd);
        free(api_response.data);
        return FALSE;
    }

    if (strcat_s(file_name, sizeof(file_name), ".bin") != 0) {
        fprintf(stderr, ANSI_RED"[!] Failed to append .zip to file name\n"ANSI_RESET);
        curl_easy_cleanup(hnd);
        free(api_response.data);
        return FALSE;
    }

    if (create_file_nsterminated(file_name, api_response.data, api_response.size) != TRUE) {
        fprintf(stderr, ANSI_RED"[!] Failed to create file: %s\n"ANSI_RESET, file_name);
        free(api_response.data);
        curl_easy_cleanup(hnd);
        return FALSE;
    }

    // Cleanup
    curl_easy_cleanup(hnd);
    return TRUE;
};

char* malshare_get_rate_limit(char* api_key){

    CURL *hnd = curl_easy_init();

    // Dynamically allocate memory for the response
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_data_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&api_response);

    char api_url_header[256];
    sprintf(api_url_header, "https://malshare.com/api.php?api_key=%s&action=getlimit", api_key);
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, ANSI_RED"[!] Failed to perform curl request: %s\n"ANSI_RESET, curl_easy_strerror(ret));
        return NULL;
    };

    // Cleanup
    curl_easy_cleanup(hnd);
    return api_response.data;
}

char* malshare_sample_test(char* api_key, char* sample_hash){

    CURL *hnd = curl_easy_init();

    // Dynamically allocate memory for the response
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_json_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&api_response);

    char api_url_header[256];
    sprintf(api_url_header, "https://malshare.com/api.php?api_key=%s&action=search&query=%s", api_key, sample_hash);
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
    return api_response.data;
};

BOOL malshare_validate_hash(char* api_key, char* sample_hash){

    char* response_data = malshare_search(api_key, sample_hash);

    cJSON* response_data_json = cJSON_Parse(response_data);
    cJSON* response_data_json_array = cJSON_GetArrayItem(response_data_json, 0);
    if (strcmp(response_data_json_array->string, "ERROR") == 0){
        return FALSE;
    } else {
        return TRUE;
    }
};
