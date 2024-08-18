#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include <Windows.h>

#include <cjson/cJSON.h>
#include "virustotal.h"
#include "miscellaneous.h"



//Note to self, perhaps write a POST/GET function that can be used for all API calls..


// Get file availability status from VirusTotal
char* virustotal_sample_availability(char* api_key, char* hash){
    CURL *hnd = curl_easy_init();
    if (!hnd) {
        fprintf(stderr, "[!] Failed to initialize curl\n");
        return NULL;
    };

    // Dynamically allocate memory for the response
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_json_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&api_response);

    char* api_url_header = append_header_strings("https://www.virustotal.com/api/v3/files/%s", hash);
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");

    char* api_key_header = append_header_strings("x-apikey: %s",api_key);
    headers = curl_slist_append(headers, api_key_header);

    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, "[!] Failed to perform curl request: %s\n", curl_easy_strerror(ret));
        return NULL;
    };


    // Cleanup
    free(api_url_header);
    free(api_key_header);
    curl_easy_cleanup(hnd);

    return api_response.data;
}

void virustotal_get_ip(char ip_address, char* api_key) {

    CURL *hnd = curl_easy_init();

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/ip_addresses/ada");
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    char* api_key_header = append_header_strings("x-apikey: %s",api_key);
    headers = curl_slist_append(headers, api_key_header);

    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    free(api_key_header);
    return;
};

void virustotal_get_domain(char domain,char* api_key) {

    CURL *hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/domains/domain");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    
    char* api_key_header = append_header_strings("x-apikey: %s",api_key);
    headers = curl_slist_append(headers, api_key_header);    
    
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    free(api_key_header);
    return;
};

void virustotal_get_dns_resolution_object(char id, char* api_key) {

    CURL *hnd = curl_easy_init();

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/resolutions/id");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    
    char* api_key_header = append_header_strings("x-apikey: %s",api_key);
    headers = curl_slist_append(headers, api_key_header);    
    
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    free(api_key_header);
    return; 
};

// Get the file report from VirusTotal
char* virustotal_get_file_report(char* api_key, char* hash) {

    CURL *hnd = curl_easy_init();
    if (!hnd) {
        fprintf(stderr, "[!] Failed to initialize curl\n");
        return NULL;
    };

    // Dynamically allocate memory for the response
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_json_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&api_response);

    char* api_url_header = append_header_strings("https://www.virustotal.com/api/v3/files/%s", hash);
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");

    char* api_key_header = append_header_strings("x-apikey: %s",api_key);
    headers = curl_slist_append(headers, api_key_header);

    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, "[!] Failed to perform curl request: %s\n", curl_easy_strerror(ret));
        return NULL;
    };


    // Cleanup
    free(api_url_header);
    free(api_key_header);
    curl_easy_cleanup(hnd);

    return api_response.data;
};

void virustotal_post_file_rescan(char* api_key, char* hash) {
    CURL *hnd = curl_easy_init();


    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    
    char* api_url_header = append_header_strings("https://www.virustotal.com/api/v3/files/%s/analyse", hash);
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    
    char* api_key_header = append_header_strings("x-apikey: %s",api_key);
    headers = curl_slist_append(headers, api_key_header);

    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    free(api_url_header); //Lmao this is stupid
    free(api_key_header);
    return; 
};

char* virustotal_get_behaviour_report(char* api_key, char* hash) {

    CURL *hnd = curl_easy_init();
    if (!hnd) {
        fprintf(stderr, "[!] Failed to initialize curl\n");
        return NULL;
    };

    // Dynamically allocate memory for the response
    api_call_response api_response;
    api_response.data = (char *)malloc(1);
    api_response.size = 0;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_json_callback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&api_response);

    char* api_url_header = append_header_strings("https://www.virustotal.com/api/v3/files/%s/behaviour_summary", hash);
    curl_easy_setopt(hnd, CURLOPT_URL, api_url_header);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");

    char* api_key_header = append_header_strings("x-apikey: %s",api_key);
    headers = curl_slist_append(headers, api_key_header);

    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        fprintf(stderr, "[!] Failed to perform curl request: %s\n", curl_easy_strerror(ret));
        return NULL;
    };

    // Cleanup
    free(api_url_header);
    free(api_key_header);
    curl_easy_cleanup(hnd);

    return api_response.data;
};


void virustotal_post_URL(char url,char* api_key) {
    CURL *hnd = curl_easy_init();

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/urls");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    headers = curl_slist_append(headers, "content-type: application/x-www-form-urlencoded");
    char* api_key_header = append_header_strings("x-apikey: %s",api_key);
    headers = curl_slist_append(headers, api_key_header);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    free(api_key_header);
    return; 
}

void virustotal_get_url_analysis_report(char url,char* api_key){
    CURL *hnd = curl_easy_init();

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/urls/id");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    
    char* api_key_header = append_header_strings("x-apikey: %s",api_key);
    headers = curl_slist_append(headers, api_key_header);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    free(api_key_header);
    return;
};

void virustotal_post_url_rescan(char url,char* api_key) {
    CURL *hnd = curl_easy_init();

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/urls/id/analyse");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    char* api_key_header = append_header_strings("x-apikey: %s",api_key);
    headers = curl_slist_append(headers, api_key_header);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    free(api_key_header);
    return;
};
