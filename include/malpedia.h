#ifndef MALPEDIA_H
#define MALPEDIA_H

#include <stdio.h>
#include <windows.h>

char* malpedia_check_api_key(char* api_key);
char* malpedia_search_malware(char* api_key, char* sample_hash);
char* malpedia_download_malware(char* api_key, char* sample_hash);
BOOL malpedia_validate_key_hash(char* api_key, char* sample_hash);
char* malpedia_search_actor(char* api_key, char* actor_name);
char* malpedia_search_family(char* api_key, char* family_name);
char* malpedia_search_actor_meta(char* api_key, char* actor_id);


#endif // MALPEDIA_H