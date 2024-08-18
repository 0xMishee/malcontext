#pragma once

#ifndef CONF_H
#define CONF_H

#include <stdio.h>
#include <Windows.h>

#define MAX_SIZE 100

typedef struct _configuration {
    char provider[MAX_SIZE];
    char guid[37];
    char api_key[MAX_SIZE];
} configuration;

typedef struct _conf_default {
    char provider[MAX_SIZE];
    char guid;
} conf_default;

typedef struct _malshare_api {
    char api_key[MAX_SIZE];
} malshare_api;

typedef struct _virustotal_api {
    char api_key[MAX_SIZE];
} virustotal_api;

typedef struct _unpac_me_api {
    char api_key[MAX_SIZE];
} unpac_me_api;

typedef struct _ETWProvider {
    char name[MAX_SIZE];
    char guid[37];
} ETWProvider;


enum Option {
    add_option,
    replace_option,
    remove_option
};

BOOL configuration_print();
BOOL configuration_check();
BOOL configuration_initialize();
    

#endif // CONF_DEFAULT_H
