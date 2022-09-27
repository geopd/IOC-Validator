# IoC-Validator

A simple script to validate IoCs (URLs, Domains, IP Addresses and Hashes) with virustotal API
and get output in a .csv file in defanged format.

## Usage

**Add APIKEY, IoC file name and malicious threshold in script**

```
bash ioc_validator.sh
```
Default IoC filename is ioc.txt.


**For custom APIKEY, IoC file name and Malicious threshold**
```
bash ioc_validator.sh -v <VIRUS_APIKEY> -f <ioc_filename> -t <malicious_threshold>
```



