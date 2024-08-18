#pragma once

#ifndef VIRUSTOTAL_H
#define VIRUSTOTAL_H

#include <stdio.h>
#include <stdbool.h>
#include <windows.h>
#include <curl/curl.h>

enum Mode {
    file,
    ip,
    url,
    domain,
    hash
};
typedef struct {
    char* data;
    size_t size;
}api_call_response;

BOOL virustotal_print_file_report(char mode, char* api_key, char* hash);
void virustotal_get_ip(char ip_address,char* api_key);
void virustotal_get_domain(char domain, char* api_key);
void virustotal_get_dns_resolution_object(char id, char* api_key);
char* virustotal_get_file_report(char* api_key, char* hash);
void virustotal_post_file_rescan(char* api_key, char* hash);
void virustotal_get_behaviour_report(char id, char* api_key);
void virustotal_get_mitre_report(char id, char* api_key);
void virustotal_post_URL(char url, char* api_key);
void virustotal_get_url_analysis_report(char url, char* api_key);
void virustotal_post_url_rescan(char url, char* api_key);
char* append_header_strings(char* header, char* string);
char* parse_virustotal_file_output(const char* virustotal_json_return_data);

size_t write_json_callback(void *data, size_t size, size_t nmemb, void *userdata);

#endif // VIRUSTOTAL_H