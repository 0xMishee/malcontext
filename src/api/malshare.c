#include <stdio.h>
#include <Windows.h>
#include <curl/curl.h>
#include "miscellaneous.h"
#include "ansi_colours.h"

// Function to write the data to a file
size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    if (written != nmemb) {
        fprintf(stderr, "Error writing data to file\n");
        return 0;
    }
    return written;
}

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
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_data_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &api_response);

    char api_url_header[188];
    sprintf(api_url_header, "https://malshare.com/api.php?api_key=%s&action=getfile&hash=%s", api_key, sample_hash);
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);

    CURLcode ret = curl_easy_perform(hnd);
    printf("Curl request result: %s\n", curl_easy_strerror(ret));
    if(ret != CURLE_OK) {
        fprintf(stderr, ANSI_RED"[!] Failed to perform curl request: %s\n"ANSI_RESET, curl_easy_strerror(ret));
        return NULL;
    };

    // Cleanup
    curl_easy_cleanup(hnd);
    printf("This is what returned...%s\n", api_response.data);
    return api_response.data;
}


char* malshare_get_rate_limit(char* api_key){

    CURL *hnd = curl_easy_init();

    // Dynamically allocate memory for the response
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_json_callback);
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
