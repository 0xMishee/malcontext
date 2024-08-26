#pragma once

#ifndef SEARCH_H
#define SEARCH_H

#include <stdio.h>
#include <Windows.h>


// Structure to hold the mutex handle and sample_hash. Might move to mischeallaneous.h later.
typedef struct {
    HANDLE hMutex;
    char* sample_hash;
} ThreadData;

void search_sample_available(char* sample_hash);


#endif // SEARCH_H