#pragma once


#ifndef MALSHARE_H
#define MALSHARE_H

#include <stdio.h>
#include <Windows.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>


char* malshare_sample_availability(char* api_key, char* sample_hash);


#endif // MALSHARE_H