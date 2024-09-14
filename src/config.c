#include <stdio.h>
#include <Windows.h>
#include <ctype.h>
#include <io.h> 
#include <cjson/cJSON.h>
#include "ansi_colours.h"


char* open_configuration(const char* key_file) {

    HANDLE hFile;
    DWORD dwBytesRead;
    char *file_buffer;
    __int64 fileSize;

    hFile = CreateFileA(key_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf(ANSI_RED"[!] Couldn't not open configuration file : %lu \n"ANSI_RESET, GetLastError());
        return FALSE;
    }

    if (!GetFileSizeEx(hFile, (PLARGE_INTEGER)&fileSize)) {
        printf(ANSI_RED"[!] Couldn't not get file size : %lu \n"ANSI_RESET, GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    // Allocate buffer dynamically based on file size
    file_buffer = (char*)malloc((size_t)(fileSize + 1)); 

    if (file_buffer == NULL) {
        printf(ANSI_RED"[!] Failed to allocate memory for buffer\n"ANSI_RESET);
        free(file_buffer);
        CloseHandle(hFile);
        return FALSE;
    }

    // Read the entire file into the buffer
    if (!ReadFile(hFile, file_buffer, (DWORD)fileSize, &dwBytesRead, NULL)) {
        printf(ANSI_RED"[!] Failed to read the entire file\n"ANSI_RESET);
        free(file_buffer);
        CloseHandle(hFile);
        return FALSE;
    }

    file_buffer[dwBytesRead] = '\0'; // Append null terminator

    CloseHandle(hFile);
    return file_buffer;
};

// Fetches the api_key value from the keys.json file
char* get_api_key_value(const char* api_key_name){
    cJSON *json = cJSON_Parse(open_configuration("../../keys/keys.json"));

        if (!json) {
            const char *error_ptr = cJSON_GetErrorPtr();
            if (error_ptr != NULL) {
                fprintf(stderr, ANSI_RED"[!] Could not parse json file: %s\n"ANSI_RESET, error_ptr);
                cJSON_Delete(json);
                return NULL;
            }
        }

    cJSON *apiKeys = cJSON_GetObjectItemCaseSensitive(json, "apiKeys");

    if (cJSON_IsObject(apiKeys)) {
        cJSON *api_key = cJSON_GetObjectItemCaseSensitive(apiKeys, api_key_name);

        if (cJSON_IsString(api_key) && (api_key->valuestring != NULL)) {
            size_t api_key_size = strlen(api_key->valuestring) + 1;
            char* api_key_value = (char*)malloc(api_key_size);
            // for debug printf("Allocated this much space for the api_key: %llu\n", strlen(api_key->valuestring) + 1);
            // for debug printf("This is the api_key: %s\n", api_key->valuestring);
            
            if (!api_key_value) {
                fprintf(stderr, ANSI_RED"[!] Failed to allocate memory for API key\n"ANSI_RESET);
                cJSON_Delete(json);
                return NULL;
            }

            strcpy_s(api_key_value, api_key_size, api_key->valuestring);

            cJSON_Delete(json);
            return api_key_value;

        } else {
            const char *error_ptr = cJSON_GetErrorPtr();
            if (error_ptr) {
                fprintf(stderr, ANSI_RED"[!] Could not parse json file: %s\n"ANSI_RESET, error_ptr);
                cJSON_Delete(json);
                return NULL;
            }
        }   

    }
    cJSON_Delete(json);
    return NULL;
};