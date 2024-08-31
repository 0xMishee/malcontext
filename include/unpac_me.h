#pragma once


#ifndef UNPAC_ME_H
#define UNPAC_ME_H

#include <stdio.h>

char* unpac_me_sample_availability(char* api_key, char* sample_hash);
char* unpac_me_get_batch_id(char* api_key, char* sample_hash);
char* unpac_me_get_url_batch_job(char* token, char* api_key);




#endif // UNPAC_ME_H