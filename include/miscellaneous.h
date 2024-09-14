#ifndef MISCELLANEOUS_H
#define MISCELLANEOUS_H

#include <stdio.h>
#include <windows.h>
#include <time.h>

// Macro definitions
#define BASE64_ENCODE_OUT_SIZE(s) ((((s) + 2) / 3) * 4)
#define BASE64_DECODE_OUT_SIZE(s) (((s) / 4) * 3)

// Sending love.
#define CURL_AGENT "（づ￣3￣）づ╭❤️～" 

// Structure to store the response from the API call
typedef struct {
    char* data;
    size_t size;
} api_call_response;

typedef struct {
    BOOL batch_job_wait;
    char* loading_string;
} ApiCallLoading;

typedef struct {
    char* data;
    size_t size;
} DecodedBase64BinaryData;

// Function prototypes
size_t write_json_callback(void *data, size_t size, size_t nmemb, void *userdata);
size_t write_data_callback(void *data, size_t size, size_t nmemb, void *userdata);
char* convert_time(int timestamp);
char* append_header_strings(char* header, char* string);
BOOL hash_sample_validation(char* hash);
BOOL check_api_name(char* api_name);
BOOL create_file_nsterminated(char* file_name, char* downloaded_file_data, size_t size);
BOOL create_file_sterminated(char* file_name, char* downloaded_file_data);
DWORD WINAPI LoadingAnimationSingleThread(LPVOID lpParam);
DecodedBase64BinaryData decode_base64(const char* input);
void hex_dump(const char *data, size_t size);

#endif // MISCELLANEOUS_H
