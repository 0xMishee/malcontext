#ifndef MISCELLANEOUS_H
#define MISCELLANEOUS_H

#include <stdio.h>
#include <windows.h>
#include <time.h>

// Structure to store the response from the API call
typedef struct {
    char* data;
    size_t size;
} api_call_response;

// Callback function to write the response from the API call
size_t write_json_callback(void *data, size_t size, size_t nmemb, void *userdata);
char* convert_time(int timestamp);
char* append_header_strings(char* header, char* string);
BOOL hash_sample_validation(char* hash);

#endif // MISCELLANEOUS_H