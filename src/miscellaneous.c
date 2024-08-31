#include <stdio.h>
#include <windows.h>
#include <time.h>
#include <curl/curl.h>

#include "ansi_colours.h"


// Structure to store the response from the API call
typedef struct {
    char* data;
    size_t size;
}api_call_response;


size_t write_data_callback (void *contents, size_t size, size_t nmemb, FILE *stream){
    size_t realsize = size * nmemb;
    api_call_response *mem = (api_call_response *)stream;

    char *ptr = realloc(mem->data, mem->size + realsize);
    if (ptr == NULL) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;

    // Dbg
    //printf("Received chunk of size: %zu\n", realsize);
    //printf("Total data size: %zu\n", mem->size);

    return realsize;
}

// Callback function to write the response from the API call.
size_t write_json_callback(void* data, size_t size, size_t nmemb, void* userdata){
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

// Function to convert timestamp to formatted time string
char* convert_time (int timestamp) {
    time_t time = timestamp;
    struct tm *timeinfo;
    static char buffer[20]; 
    timeinfo = localtime(&time);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

    if(timeinfo->tm_year == 70){
        char* error = "No date available";
        return error;
    }
    return buffer;
}

// Function to append strings to the header. 
char* append_header_strings(char* header, char* string){
    size_t header_length = strlen(header) + strlen(string) + 1;
    char *header_string = (char *)malloc(header_length);
    snprintf(header_string, header_length, header, string);
    return header_string;
}

// Check so it's a valid hash. Check so its 256/128 characters long and only contains alphanumerical characters.
BOOL hash_sample_validation(char* hash){
    if (strlen(hash) == 32 || strlen(hash) == 64){
        for (int i = 0; i < strlen(hash); i++){
            if (!isalnum(hash[i])){
                return FALSE;
            }
        }
        return TRUE;
    }
    return FALSE;
}

// Print the details of the curl request, for debugging purposes.
void print_curl_request_details(CURL *hnd, struct curl_slist *headers){
    struct curl_slist *temp = headers;
    while (temp) {
        printf("  %s\n", temp->data);
        temp = temp->next;
    }
}

//Checks if api_name is in the list of available APIs
BOOL check_api_name(char* api_name){
    char* available_apis[] = {"-um", "-mp", "-ms", "-ha"};
    for (int i = 0; i < 4; i++){
        if (strcmp(api_name, available_apis[i]) == 0){
            return TRUE;
        }
    }
    return FALSE;
}

// Creates....file?
BOOL create_file(char* file_name, char* downloaded_file_data){
    HANDLE hFile = CreateFile(file_name, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE){
        printf("THis is the error code: %d\n", GetLastError());
        return FALSE;
    }
    DWORD dwBytesWritten;
    BOOL write_to_file = WriteFile(hFile, downloaded_file_data, strlen(downloaded_file_data), &dwBytesWritten, NULL);
    if (write_to_file == FALSE){
        fprintf(stderr, ANSI_RED"[!] Error: Failed to write to file\n" ANSI_RESET);
        return FALSE;
    } else {
        free(downloaded_file_data);
        CloseHandle(hFile);
        return TRUE;
    }
    return FALSE;
}
