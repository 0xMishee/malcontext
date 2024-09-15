#ifndef SEARCH_H
#define SEARCH_H

#include <stdio.h>
#include <Windows.h>

// Structure to hold the loading animation flags.
typedef struct {
    BOOL loading_animation_virustotal;
    BOOL loading_animation_unpac_me;
    BOOL loading_animation_malshare;
    BOOL loading_animation_malpedia;
    BOOL loading_animation_malwarebazaar;
} LoadingAnimationFlags;

// Structure to hold the search API response.
typedef struct {
    BOOL search_virustotal_found;
    BOOL search_unpac_me_found;
    BOOL search_malshare_found;
    BOOL search_malpedia_found;
    BOOL search_malwarebazaar_found;
} SearchAPIResponse;

typedef struct {
    char* vt_first_date;
    char* um_first_date;
    char* mb_first_date;
} SampleSubmissionDates;


// Structure to hold the mutex handle and sample_hash n stuff, oh god it's growing!. Might move to mischeallaneous.h later.
typedef struct {
    HANDLE hMutex;
    char* sample_hash;
    LoadingAnimationFlags* loading_animation_flags;
    SearchAPIResponse* search_api_response;
    SampleSubmissionDates* sample_submission_dates;
} ThreadSearchData;



void search_sample_available(char* sample_hash);


#endif // SEARCH_H