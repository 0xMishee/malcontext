#pragma once


#ifndef MALPEDIA_H
#define MALPEDIA_H

#include <stdio.h>

char* malpedia_check_api_key(char* api_key);
char* malpedia_search_malware(char* api_key, char* sample_hash);
char* malpedia_download_malware(char* api_key, char* sample_hash);
#endif // MALPEDIA_H