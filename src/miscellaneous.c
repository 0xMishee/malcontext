#include <stdio.h>
#include <windows.h>
#include <time.h>
#include <curl/curl.h>


// Structure to store the response from the API call
typedef struct {
    char* data;
    size_t size;
}api_call_response;

// Callback function to write the response from the API call.
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

// Check so it's a valid hash. TBD
BOOL hash_sample_validation(char* hash){
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