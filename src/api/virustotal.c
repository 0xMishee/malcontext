#include <stdio.h>
#include "virustotal.h"
#include "curl/curl.h"



bool virustotal_get(){
    printf("WTF!\n");
    CURL *hnd = curl_easy_init();

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/ip_addresses/10.10.10.10");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    headers = curl_slist_append(headers, "x-apikey: 0a5d21405a58422eec3732793323b666f2962d439b42bb9028ee71968b1a4339");
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);


    return true;
};
