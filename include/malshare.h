#ifndef MALSHARE_H
#define MALSHARE_H

#include <stdio.h>
#include <Windows.h>


char* malshare_search(char* api_key, char* sample_hash);
BOOL malshare_download_file(char* api_key, char* sample_hash);
char* malshare_get_rate_limit(char* api_key);
char* malshare_sample_test(char* api_key, char* sample_hash);
BOOL malshare_validate_hash(char* api_key, char* sample_hash);

#endif // MALSHARE_H