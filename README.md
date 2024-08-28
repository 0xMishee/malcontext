## About 
There's just too many tools for malware analysis, so I decided to pollute the waters and add another one written in C. The tool is heavil inspired by [Malwoverview](https://github.com/alexandreborges/malwoverview) written by Alexandre Borges.

This tool aims to:
1. Easy to chew information for initial triage of malware.
2. Option to query APIs from selected plattforms.
3. Search for availability of malware.
4. Download malware through the APIs. 


## Current Version
Version 0.0.1.x:
```
This version: 
- No stable way of using it; but it won't crash (ง •_•)ง Testing out how I want things to work.
```

## Installation
It's using cmake and vcpkg , so you do you (～￣▽￣)～ Still very, very early in development so it's barebones; which means we're on a "works on my PC" level.
The release version will built in the "bin" directory. 
```
mkdir build
cd build
cmake ..
cmake --build . --config Release
```
Open the conf.json in the bin folder and populate the APIs you will use. 

```
{
    "apiKeys": {
      "virustotal": "",
      "malshare": "",
      "unpacme": "",
      "hybridanalysis": "",
      "malpedia": "",
      "triage": ""
    }
}
```

## Contributors

Me, myself and I. 

