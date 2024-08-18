#include <stdio.h>
#include <cjson/cJSON.h>
#include "ansi_colours.h"

#include "miscellaneous.h"

void context_virustotal_file_print(char* virustotal_json_string){

    cJSON* json = cJSON_Parse(virustotal_json_string);
    if (json == NULL) {
        printf(ANSI_RED "[!] Error parsing JSON\n" ANSI_RESET);
        return;
    }

    cJSON* data = cJSON_GetObjectItem(json, "data");

    if (cJSON_IsObject(data)) {

        int counter;

        // Hanz! This is where you get ze data!
        cJSON* id = cJSON_GetObjectItem(data, "id");
        cJSON* type = cJSON_GetObjectItem(data, "type");
        cJSON* attributes = cJSON_GetObjectItem(data, "attributes");
        cJSON* links = cJSON_GetObjectItem(data, "links");
        cJSON* self = cJSON_GetObjectItem(links, "self");

        //Printf galore!
        printf("\n\n\n");

        printf(ANSI_BOLD_BLUE"VirusTotal File Report\n"ANSI_RESET);
        printf(ANSI_BOLD_YELLOW"ID: %s\n\n" ANSI_RESET, id->valuestring);

        //Verdict
        cJSON* last_analysis_stats = cJSON_GetObjectItem(attributes, "last_analysis_stats");
        cJSON* malicious_score = cJSON_GetObjectItem(last_analysis_stats, "malicious");
        cJSON* suspicious_score = cJSON_GetObjectItem(last_analysis_stats, "suspicious");
        cJSON* undetected_score = cJSON_GetObjectItem(last_analysis_stats, "undetected");

        printf(ANSI_BOLD_GREEN"Verdict\n" ANSI_RESET);
        printf(ANSI_BOLD_YELLOW"Malicious: %d\n" ANSI_RESET,malicious_score->valueint);
        printf(ANSI_BOLD_YELLOW"Suspicious: %d\n" ANSI_RESET,suspicious_score->valueint);
        printf(ANSI_BOLD_YELLOW"Undetected: %d\n\n" ANSI_RESET,undetected_score->valueint);

        // Detected engines
        cJSON* last_analysis_results = cJSON_GetObjectItem(attributes, "last_analysis_results");
        cJSON* microsoft = cJSON_GetObjectItem(last_analysis_results, "Microsoft");
        cJSON* bitdefender = cJSON_GetObjectItem(last_analysis_results, "BitDefender");
        cJSON* crowdstrike = cJSON_GetObjectItem(last_analysis_results, "CrowdStrike");
        cJSON* fsecure = cJSON_GetObjectItem(last_analysis_results, "F-Secure"); 
        cJSON* sentinel_one = cJSON_GetObjectItem(last_analysis_results, "SentinelOne");
        cJSON* cyberreason = cJSON_GetObjectItem(last_analysis_results, "Cybereason");
        printf(ANSI_BOLD_GREEN"Detected engines\n" ANSI_RESET);
        printf(ANSI_BOLD_YELLOW"Microsoft:   %s\n" ANSI_RESET, cJSON_GetObjectItem(microsoft, "category")->valuestring);
        printf(ANSI_BOLD_YELLOW"BitDefender: %s\n" ANSI_RESET, cJSON_GetObjectItem(bitdefender, "category")->valuestring);
        printf(ANSI_BOLD_YELLOW"CrowdStrike: %s\n" ANSI_RESET, cJSON_GetObjectItem(crowdstrike, "category")->valuestring);
        printf(ANSI_BOLD_YELLOW"SentinelOne: %s\n" ANSI_RESET, cJSON_GetObjectItem(sentinel_one, "category")->valuestring);
        printf(ANSI_BOLD_YELLOW"Cybereason:  %s\n" ANSI_RESET, cJSON_GetObjectItem(cyberreason, "category")->valuestring);
        printf(ANSI_BOLD_YELLOW"F-Secure:    %s\n\n" ANSI_RESET, cJSON_GetObjectItem(fsecure, "category")->valuestring);

        // Timestamps
        cJSON *last_analysis_date = cJSON_GetObjectItem(attributes, "last_analysis_date");
        cJSON *first_submission_date = cJSON_GetObjectItem(attributes, "first_submission_date");
        cJSON *last_submission_date = cJSON_GetObjectItem(attributes, "last_submission_date");
        cJSON *creation_date = cJSON_GetObjectItem(attributes, "creation_date");
        printf(ANSI_BOLD_GREEN"Timestamps\n" ANSI_RESET);
        printf(ANSI_BOLD_YELLOW"Creation date:         %s\n" ANSI_RESET, convert_time(creation_date->valueint));
        printf(ANSI_BOLD_YELLOW"First submission date: %s\n" ANSI_RESET, convert_time(first_submission_date->valueint));
        printf(ANSI_BOLD_YELLOW"Last submission date:  %s\n" ANSI_RESET, convert_time(last_submission_date->valueint));
        printf(ANSI_BOLD_YELLOW"Last analysis date:    %s\n\n" ANSI_RESET, convert_time(last_analysis_date->valueint));

        // File information
        printf(ANSI_BOLD_GREEN"Hashes\n" ANSI_RESET);
        cJSON* md5 = cJSON_GetObjectItem(attributes, "md5");
        cJSON* sha256 = cJSON_GetObjectItem(attributes, "sha256");
        cJSON* sha1 = cJSON_GetObjectItem(attributes, "sha1");
        printf(ANSI_BOLD_YELLOW "MD5:      %s\n" ANSI_RESET, md5->valuestring);
        printf(ANSI_BOLD_YELLOW "SHA1:     %s\n" ANSI_RESET, sha1->valuestring);
        printf(ANSI_BOLD_YELLOW "SHA256:   %s\n\n" ANSI_RESET, sha256->valuestring);

        printf(ANSI_BOLD_GREEN"File aliases\n"ANSI_RESET);
        cJSON* names = cJSON_GetObjectItem(attributes, "names");
        counter = 1;
        for (int i = 0; i < cJSON_GetArraySize(names); i++) {
            cJSON* name = cJSON_GetArrayItem(names, i);
            printf(ANSI_BOLD_YELLOW "[%d]:      %s\n" ANSI_RESET, counter++, name->valuestring);
            if(i == cJSON_GetArraySize(names) - 1) {
                printf("\n");
            };
        };    

        printf(ANSI_BOLD_GREEN"Tags\n" ANSI_RESET);
        cJSON* tags = cJSON_GetObjectItem(attributes, "tags");
        counter = 1;
        for (int i = 0; i < cJSON_GetArraySize(tags); i+=2) {
            cJSON* tag_one = cJSON_GetArrayItem(tags, i);
            cJSON* tag_two = cJSON_GetArrayItem(tags, i+1);
            if (!cJSON_IsString(tag_two)) {
                printf(ANSI_BOLD_YELLOW "[%d]:      %s\n" ANSI_RESET, counter++, tag_one->valuestring);
                break;
            };
            printf(ANSI_BOLD_YELLOW "[%d]:      %s,%s\n" ANSI_RESET, counter++, tag_one->valuestring, tag_two->valuestring);
            if(i == cJSON_GetArraySize(tags) - 2) {
                printf("\n");
            };
        }; 

        cJSON* detect_it_easy = cJSON_GetObjectItem(attributes, "detectiteasy");
        if (detect_it_easy != NULL) {
            cJSON* filetype = cJSON_GetObjectItem(detect_it_easy, "filetype");
            cJSON* values = cJSON_GetObjectItem(detect_it_easy, "values");
            printf(ANSI_BOLD_GREEN"Detect it easy!\n"ANSI_RESET);
            printf(ANSI_BOLD_YELLOW"Filetype: %s\n"ANSI_RESET, filetype->valuestring);
            for (int i = 0; i < cJSON_GetArraySize(values); i++) {
                for (int j = 0; j < cJSON_GetArraySize(cJSON_GetArrayItem(values, i)); j++) {
                    cJSON* item = cJSON_GetArrayItem(cJSON_GetArrayItem(values, i), j);
                    printf(ANSI_BOLD_YELLOW"%s: %s\n"ANSI_RESET, item->string, item->valuestring);
                };
                printf("\n");
            };
        }
        
        cJSON* pe_info = cJSON_GetObjectItem(attributes, "pe_info");
        if (pe_info != NULL){
            cJSON* import_list = cJSON_GetObjectItem(pe_info, "import_list");
            if (import_list != NULL){
                for(int i = 0; i < cJSON_GetArraySize(import_list); i++){
                    cJSON* dll = cJSON_GetArrayItem(import_list, i);
                    
                }
            }

        };

        printf("\n\n\n");
    };



    // Cleanup
    cJSON_Delete(json);
    free(virustotal_json_string);
    return;
};