## About 
There's just too many tools for malware analysis, so I decided to pollute the waters and add another one written in C. The tool is heavil inspired by [Maloverview](https://github.com/alexandreborges/malwoverview) written by Alexandre Borges.

This tool aims to:

    1. Incorporate APIs from services that I commonly use (VT,Unpacme, Malshare etc).
    2. Summarize data and functionality from these platforms.
    3. Have a "monkey have hash||IP||domain, monkey want data" sort of approach to how complex the tool is to use.
    4. Add YARA-X and AOB Scanner.
    5. Incorporate windows event tracing events for targeted processes.
    6. Downloading malware (for research purposes (っ °Д °;)っ).


## Current Version
Version 0.0.1.x:
```
This version: 
- No stable way of using it; but it won't crash (ง •_•)ง Testing out how I want things to work.
```

## Installation
It's using cmake and vcpkg , so you do you (～￣▽￣)～ Still very, very early in development so it's barebones; which means we're on a "works on my PC" level.
```
mkdir build
cd build
cmake ..
cmake --build .

Add to PATH: 
$env:PATH += ";Your tools folder"

```

## Roadmap
    1. Add Virustotal API functionality.
    2. Add UnpacME API functionality. 
    3. Add Malshare API functionality.
    4. Add Hash search functionality.
    5. Add Yara-X functionality.
    6. ...more stuff. 
    7. Refactor into assembly (●'◡'●)

## Authors

Me, myself and I. 

