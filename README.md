# VT_Checker

Virus Total URL checker to search for malicious or suspicious URL's.

## Terminal Output

The BASH script will tell you if the URL is malicious or suspicious followed by the number of how many vendors flagged it as such.

## How to Use

Add URL as argument
```bash
./checkURL.sh http://ronnietucker.co.uk
```
Or read it in 
```bash
./checkURL.sh
```

### Install Requirements

Remember you will need an x-api key from VirusTotal for integration and access.
If jq is not installed, do:
```bash
sudo apt-get install jq
```

### Links

[VirusTotal API reference](https://docs.virustotal.com/reference/scan-url

