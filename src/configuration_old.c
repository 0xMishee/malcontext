#include <stdio.h>
#include <Windows.h>
#include <ctype.h>
#include <io.h> 
#include <cjson/cJSON.h>

#include "configuration_old.h"


BOOL configuration_check() {
    FILE* stream;
    errno_t config_file;
    char answer[1];

    config_file = fopen_s(&stream, "config.json", "r+");

    if (config_file) {
        printf("[!] Couldn't not locate configuration file : %d \n", GetLastError());
        printf("[?] Do you want to initialize a new configuration file? y/n : ");
        scanf_s(" %c", answer, (unsigned)_countof(answer));

        if (tolower(answer[0]) == 'n') {
            return FALSE;
        }
        else if (tolower(answer[0] == 'y')) {
            configuration_initialize();
        }
        else {
            printf("[!] Invalid input, please try again : : %d \n", GetLastError());
            return FALSE;
        }
    }
    if (stream !=0){ fclose(stream); }
    return TRUE;
}

BOOL configuration_print() {
    HANDLE hFile;
    DWORD dwBytesRead;
    char *buffer;
    __int64 fileSize;

    hFile = CreateFileA("config.json", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Couldn't not open configuration file : %d \n", GetLastError());
        return FALSE;
    }

    if (!GetFileSizeEx(hFile, (PLARGE_INTEGER)&fileSize)) {
        printf("[!] Couldn't not get file size : %d \n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    // Allocate buffer dynamically based on file size
    buffer = (char*)malloc((size_t)(fileSize + 1)); // +1 for null terminator

    if (buffer == NULL) {
        printf("[!] Failed to allocate memory for buffer\n");
        free(buffer);
        CloseHandle(hFile);
        return FALSE;
    }

    // Read the entire file into the buffer
    if (!ReadFile(hFile, buffer, (DWORD)fileSize, &dwBytesRead, NULL)) {
        printf("[!] Failed to read the entire file\n");
        free(buffer);
        CloseHandle(hFile);
        return FALSE;
    }

    buffer[dwBytesRead] = '\0'; // Append null terminator

    printf("%s", buffer);

    free(buffer);
    CloseHandle(hFile);
    return TRUE;
}

// Initialize the configuration file with default values.
BOOL configuration_initialize() {

    malshare_api malshare_struct = { "API_KEY" };
    virustotal_api virustotal_struct = { "API_KEY" };
    unpac_me_api unpac_me_struct = { "API_KEY" };

    ETWProvider providers[] = {
        {"Microsoft-Antimalware-NIS", "CFEB0608-330E-4410-B00D-56D8DA9986E6"},
        {"Microsoft-Antimalware-Protection", "CFEB0608-330E-4410-B00D-56D8DA9986E6"},
        {"Microsoft-Antimalware-RTP", "CFEB0608-330E-4410-B00D-56D8DA9986E6"},
        {"Microsoft-Antimalware-Scan-Interface", "CFEB0608-330E-4410-B00D-56D8DA9986E6"},
        {"Microsoft-Antimalware-Service", "CFEB0608-330E-4410-B00D-56D8DA9986E6"},
        {"Microsoft-Antimalware-ShieldProvider", "CFEB0608-330E-4410-B00D-56D8DA9986E6"}
    };

    // Implementation of the initialization of the configuration file
    cJSON *root = cJSON_CreateObject();
    if(!root) {
		printf("[!] Failed to initialize root object  %d\n", GetLastError());
		return FALSE;
	}

    cJSON *etw = cJSON_CreateObject();
    if (!etw) {
        printf("[!] Failed to initialize etw configuration : %d\n", GetLastError());
        cJSON_Delete(root);
        return FALSE;
    }
    cJSON_AddItemToObject(root, "ETW", etw);

    cJSON *etwProviders = cJSON_CreateArray();
    if (!etwProviders) {
        printf("[!] Failed to initialize etw configuration : %d\n", GetLastError());
        cJSON_Delete(root);
        return FALSE;
    }
    cJSON_AddItemToObject(etw, "ETWProviders", etwProviders);

    // Populate the ETWProviders array with provider objects
    for (int i = 0; i < sizeof(providers) / sizeof(ETWProvider); i++) {
        cJSON* provider = cJSON_CreateObject();
        if (!provider) {
            fprintf(stderr, "[!} Failed to initialize etw configuration : %d\n", GetLastError());
            cJSON_Delete(root);
            return FALSE;
        }
     
        cJSON_AddStringToObject(provider, "Name", providers[i].name);
        cJSON_AddStringToObject(provider, "Guid", providers[i].guid);
        cJSON_AddItemToArray(etwProviders, provider);
    }

    //Adding API keys to the configuration file

    cJSON *malshare = cJSON_CreateObject();
    if (!malshare) {
        printf("[!] Failed to initialize malshare api configuration : %d\n", GetLastError());
        cJSON_Delete(root);
        return FALSE;
    }
    cJSON_AddItemToObject(root, "MALSHARE", malshare);
    cJSON_AddStringToObject(malshare, "API_KEY", malshare_struct.api_key);

    cJSON* virustotal = cJSON_CreateObject();
    if (!virustotal) {
        printf("[!] Failed to initialize malshare api configuration : %d\n", GetLastError());
        cJSON_Delete(root);
        return FALSE;
    }
    cJSON_AddItemToObject(root, "VIRUSTOTAL", virustotal);
    cJSON_AddStringToObject(virustotal, "API_KEY", virustotal_struct.api_key);


    cJSON *unpac_me = cJSON_CreateObject();
    if (!unpac_me) {
        printf("[!] Failed to initialize unpac_me api configuration : %d\n", GetLastError());
        cJSON_Delete(root);
        return FALSE;
    }
    cJSON_AddItemToObject(root, "UNPAC_ME", unpac_me);
    cJSON_AddStringToObject(unpac_me, "API_KEY", unpac_me_struct.api_key);

    printf("[+] Configuration initialized.\n");

    // Save the configuration to file
    printf("[?] Do you want to save the configuration to file? y/n : ");
    char answer[1];
    scanf_s(" %c", answer, (unsigned)_countof(answer));

    if (tolower(answer[0]) == 'n') {
        return FALSE;
    }
    else if (tolower(answer[0]) == 'y') {

        HANDLE hFile = CreateFileA("config.json", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            printf("[!] Failed to create configuration file : %d\n", GetLastError());
            cJSON_Delete(root);
            return FALSE;
        }

        char* json_string = cJSON_Print(root);
        if (json_string) {
            DWORD bytesWritten;
            if (!WriteFile(hFile, json_string, (DWORD)strlen(json_string), &bytesWritten, NULL) || bytesWritten != (DWORD)strlen(json_string)) {
                printf("[!] Failed to write to configuration file.\n");
                free(json_string);
                CloseHandle(hFile);
                cJSON_Delete(root);
                return FALSE;
            }
            free(json_string);
        }

        CloseHandle(hFile);
    }

    printf("[+] Configuration file saved.\n");

    // Clean up the JSON objects
    cJSON_Delete(root);

    return TRUE;
}
