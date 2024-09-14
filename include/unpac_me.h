#ifndef UNPAC_ME_H
#define UNPAC_ME_H

#include <stdio.h>
#include <windows.h>

char* unpac_me_search(char* api_key, char* sample_hash);
char* unpac_me_get_batch_id(char* api_key, char* sample_hash);
char* unpac_me_get_url_batch_job(char* token, char* api_key);
BOOL unpac_me_validate_hash(char* api_key, char* sample_hash);



#endif // UNPAC_ME_H