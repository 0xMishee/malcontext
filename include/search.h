#pragma once

#ifndef SEARCH_H
#define SEARCH_H

#include <stdio.h>
#include <Windows.h>

// Structure to hold the loading animation flags.
typedef struct {
    BOOL loading_animation_virustotal;
    BOOL loading_animation_unpac_me;
    BOOL loading_animation_malshare;
} LoadingAnimationFlags;

// Structure to hold the search API response.
typedef struct {
    BOOL search_virustotal_found;
    BOOL search_unpac_me_found;
    BOOL search_malshare_found;
} SearchAPIResponse;

// Structure to hold the mutex handle and sample_hash n stuff, oh god it's growing!. Might move to mischeallaneous.h later.
typedef struct {
    HANDLE hMutex;
    char* sample_hash;
    LoadingAnimationFlags* loading_animation_flags;
    SearchAPIResponse* search_api_response;
} ThreadData;

void search_sample_available(char* sample_hash);


#endif // SEARCH_H