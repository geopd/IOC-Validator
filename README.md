# IoC-Validator

A simple script to validate IoCs (URLs, Domains, IP Addresses and Hashes) with virustotal API
and get output in a .csv file in defanged format.

## Usage

**Add APIKEY and IoC file name in script**

```
bash ioc_validator.sh
```
Default IoC filename is ioc.txt.


**For custom APIKEY and IoC file name**
```
bash ioc_validator.sh -k <APIKEY> -f <ioc_filename>
```



