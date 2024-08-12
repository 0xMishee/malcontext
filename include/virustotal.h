#pragma once

#ifndef VIRUSTOTAL_H
#define VIRUSTOTAL_H

#include <stdio.h>
#include <stdbool.h>

bool virustotal_print_report(char* mode);
char* virustotal_file_parse();
char* virustotal_ip_parse();
char* virustotal_url_parse();
char* virustotal_get_ip(const char* ip_address, const char* api_key);
char* virustotal_get_domain(const char* domain, const char* api_key);
char* virustotal_get_dns_resolution_object(const char* id, const char* api_key);
char* virustotal_get_file_report(const char* id, const char* api_key);
char* virustotal_post_file_rescan(const char* id, const char* api_key);
char* virustotal_get_behaviour_report(const char* id, const char* api_key);
char* virustotal_get_mitre_report(const char* id, const char* api_key);
char* virustotal_post_URL(const char* url, const char* api_key);
char* virustotal_get_url_analysis_report(const char* url, const char* api_key);
char* virustotal_post_url_rescan(const char* url, const char* api_key);

#endif // VIRUSTOTAL_H