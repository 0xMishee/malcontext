#pragma once


#ifndef MALSHARE_H
#define MALSHARE_H

#include <stdio.h>
#include <Windows.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>


char* malshare_sample_availability(char* api_key, char* sample_hash);
char* malshare_download_file(char* api_key, char* sample_hash);
char* malshare_get_rate_limit(char* api_key);


#endif // MALSHARE_H