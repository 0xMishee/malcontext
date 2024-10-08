#include <stdio.h>
#include <windows.h>
#include <time.h>
#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <b64/cdecode.h>

#include "ansi_colours.h"
#include "miscellaneous.h"

// Debugging func : Hex dump function to print binary data
void hex_dump(const char *data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if (i % 16 == 0 && i != 0) {
            printf("\n");
        }
        printf("%02x ", (unsigned char)data[i]);
    }
    printf("\n");
}

// Not null terminated. 
size_t write_data_callback (void *data, size_t size, size_t nmemb, void *userdata){
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

    // Debugging: Print the current size and the added size
    //printf("Current size: %zu, Added size: %zu\n", api_response->size, real_size);
    // Debugging: Dump the allocated data
    //printf("Allocated data: %.*s\n", (int)real_size, (char *)data);
    // Print the first 1000 characters in the buffer
    // Debugging: Print a hex dump of the first 1000 bytes
    //size_t dump_size = api_response->size < 1000 ? api_response->size : 1000;
    //printf("Hex dump of the first 1000 bytes (or less):\n");
    //hex_dump(api_response->data, dump_size);


    return real_size;
}

// Callback function to write the response from the API call. Null terminates
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
char* convert_time(int timestamp) {
    time_t raw_time = timestamp;
    struct tm timeinfo;
    char* buffer = (char*)malloc(20 * sizeof(char));

    if (buffer == NULL) {
        printf(ANSI_RED "[!] Failed to allocate memory\n" ANSI_RESET);
        return NULL;
    }

    if (localtime_s(&timeinfo, &raw_time)) {
        printf(ANSI_RED "[!] Failed to convert timestamp to time\n" ANSI_RESET);
        free(buffer);
        return NULL;
    }
    strftime(buffer, 20, "%Y-%m-%d %H:%M:%S", &timeinfo);
    return buffer;
}

// MT-Safe version. 
int convert_time_ts(int timestamp, char* buffer, size_t buff_size){
    time_t time = timestamp;
    struct tm timeinfo;

    if (localtime_s(&timeinfo, &time) != 0) {
        printf(ANSI_RED"[!] Failed to convert timestamp to time\n"ANSI_RESET);
        return -1;
    }

    if (strftime(buffer, buff_size, "%Y-%m-%d %H:%M:%S", &timeinfo) == 0) {
        printf(ANSI_RED"[!] Failed to format time\n"ANSI_RESET);
        return -1;
    }
    return 0;
};

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
        for (size_t i = 0; i < strlen(hash); i++){
            if (!isalnum(hash[i])){
                return FALSE;
            }
        }
        return TRUE;
    }
    return FALSE;
};

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
    char* available_apis[] = {"-um", "-mp", "-ms", "-ha", "-mb"};
    for (size_t i = 0; i < 4; i++){
        if (strcmp(api_name, available_apis[i]) == 0){
            return TRUE;
        }
    }
    return FALSE;
};

// Creates....file?
BOOL create_file_sterminated(char* file_name, char* downloaded_file_data){
    HANDLE hFile = CreateFile(file_name, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE){
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
};

// Creates....file?
BOOL create_file_nsterminated(char* file_name, char* downloaded_file_data, size_t size) {
    HANDLE hFile = CreateFile(file_name, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    DWORD dwBytesWritten;
    BOOL write_to_file = WriteFile(hFile, downloaded_file_data, size, &dwBytesWritten, NULL);
    if (write_to_file == FALSE) {
        fprintf(stderr, ANSI_RED "[!] Error: Failed to write to file. Error code: %lu\n" ANSI_RESET, GetLastError());
        CloseHandle(hFile);  // Close handle on failure
        return FALSE;
    }
    
    free(downloaded_file_data);
    CloseHandle(hFile);  // Always close the file handle when done
    return TRUE;
};

// Thread function for the loading animation
DWORD WINAPI LoadingAnimationSingleThread(LPVOID lpParam) {
    ApiCallLoading* loading_animation = (ApiCallLoading*)lpParam;
    if (!loading_animation) {
        printf("Error: Invalid pointer\n");
        return 1; // Return an error code if the pointer is null
    }

    const char* animation = "|/-\\";
    size_t i = 0;

    while (loading_animation->batch_job_wait) {
        // Display loading animation
        printf("\r%s %c", loading_animation->loading_string, animation[i++ % 4]);
        fflush(stdout);
        Sleep(100);
    }

    // Clean up once the loading is complete
    printf("\n");
    return 0;
};

DecodedBase64BinaryData decode_base64(const char* input){
    size_t output_len = BASE64_DECODE_OUT_SIZE(strlen(input));
	char* output = (char*)malloc(output_len);
    if (output == NULL){
        fprintf(stderr, ANSI_RED"[!] Error: Failed to allocate memory for output\n" ANSI_RESET);
        return (DecodedBase64BinaryData){NULL, 0};
    }

	char* c = output;
	size_t count = 0;
	base64_decodestate state;

	base64_init_decodestate(&state);
	count = base64_decode_block(input, strlen(input), c, &state);
	c += count;
	
    return (DecodedBase64BinaryData){output, c - output};
};

int check_for_existence_of_file(const char* file_name){

    // Allocate memory for filename + extension (".zip")
    char* file_name_with_extension = (char*)malloc(strlen(file_name) + 5); // +5 for ".zip" and null terminator
    if (file_name_with_extension == NULL) {
        fprintf(stderr, ANSI_RED "[!] Error: Failed to allocate memory for file name\n" ANSI_RESET);
        return -1; 
    }

    strcpy_s(file_name_with_extension, strlen(file_name) + 5, file_name);
    strcat_s(file_name_with_extension, strlen(file_name) + 5, ".zip");

    // Try opening the file with .zip
    HANDLE hFile = CreateFile(file_name_with_extension, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        free(file_name_with_extension);
        return 0; // File exists
    }

    strcpy_s(file_name_with_extension, strlen(file_name) + 5, file_name);
    strcat_s(file_name_with_extension, strlen(file_name) + 5, ".bin");

    // Try opening the file with .bin
    hFile = CreateFile(file_name_with_extension, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        free(file_name_with_extension);
        return 0; // File exists
    }
    
    // Cleanup
    free(file_name_with_extension);
    CloseHandle(hFile);
    return 1; // File does not exist
}
