#ifndef MISCELLANEOUS_H
#define MISCELLANEOUS_H

#include <stdio.h>
#include <windows.h>
#include <time.h>

#define CURL_AGENT "（づ￣3￣）づ╭❤️～" 

// Structure to store the response from the API call
typedef struct {
    char* data;
    size_t size;
} api_call_response;



// Callback function to write the response from the API call
size_t write_json_callback(void *data, size_t size, size_t nmemb, void *userdata);
size_t write_data_callback(void *ptr, size_t size, size_t nmemb, FILE *stream);
char* convert_time(int timestamp);
char* append_header_strings(char* header, char* string);
BOOL hash_sample_validation(char* hash);
BOOL check_api_name(char* api_name);
BOOL create_file(char* file_name, char* downloaded_file_data);
//void print_curl_request_details(CURL *hnd, struct curl_slist *headers);

#endif // MISCELLANEOUS_H