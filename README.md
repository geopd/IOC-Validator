# IoC-Validator

A simple script to validate IoCs (URLs, Domains, IP Addresses and Hashes) with virustotal/AbuseIPDB API
and get output in a .csv file.

## Usage

**Add APIKEY, IoC file name and malicious threshold in script**

```
bash ioc_validator.sh -s <SERVICE_TYPE>
```
SERVICE_TYPE includes 'virustotal' and 'abuseipdb'.
Default IoC filename is ioc.txt.


**For custom APIKEY, IoC/IP file name and threshold**
```
bash ioc_validator.sh -s virustotal -v <VIRUS_APIKEY> -f <ioc_filename> -t <malicious_threshold>
```
```
bash ioc_validator.sh -s abuseipdb -v <ABUSE_APIKEY> -f <ioc_filename> -t <abuseConfidenceScore>
```



