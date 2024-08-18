#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include <Windows.h>

#include <cjson/cJSON.h>
#include "virustotal.h"


//Note to self, perhaps write a POST/GET function that can be used for all API calls..?

size_t write_json_callback(void *data, size_t size, size_t nmemb, void *userdata){
    size_t real_size = size * nmemb;
    api_call_response *api_response = (api_call_response *) userdata;
    char *ptr = realloc(api_response->data, api_response->size + real_size + 1);
    if (ptr == NULL) {
        fprintf(stderr, "[!] Failed to allocate memory for response\n");
        return 0;
    }
    api_response->data = ptr;
    memcpy(&(api_response->data[api_response->size]), data, real_size);
    api_response->size += real_size;
    api_response->data[api_response->size] = 0;
    return real_size;
};

// ID could be either URL, IP, File, Domain, or Hash
BOOL virustotal_print_file_report(char mode, char* api_key, char* hash){
    virustotal_get_file_report(api_key, hash);

    return TRUE;
};

// Appends header to string value.
// Don't forget to free the memory after using it.
char* append_header_strings(char* header, char* string){
    size_t header_length = strlen(header) + strlen(string) + 1;
    char *header_string = (char *)malloc(header_length);
    snprintf(header_string, header_length, header, string);
    return header_string;
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

void virustotal_get_behaviour_report(char id, char* api_key) {
    CURL *hnd = curl_easy_init();

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/behaviours/");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    char* api_key_header = append_header_strings("x-apikey: %s",api_key);
    headers = curl_slist_append(headers, api_key_header);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    free(api_key_header);
    return;
};

void virustotal_get_mitre_report(char id,char* api_key) {
    CURL *hnd = curl_easy_init();

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/files/id/behaviour_mitre_trees");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    char* api_key_header = append_header_strings("x-apikey: %s",api_key);
    headers = curl_slist_append(headers, api_key_header);
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    free(api_key_header);
    return;
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



char* parse_virustotal_file_output(const char* virustotal_json_return_data){
    cJSON *json = cJSON_Parse(virustotal_json_return_data);
    
    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "[!] Could not parse json file: %s\n", error_ptr);
            cJSON_Delete(json);
            return NULL;
        }
    }


    return NULL;
};
