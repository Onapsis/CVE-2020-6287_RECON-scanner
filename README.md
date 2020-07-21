# Vulnerability Assessment and Indicator of Compromise (IoC) Scanner for CVE-2020-6287 (RECON) 

RECON (Remotely Exploitable Code On NetWeaver) is a critical (CVSSv3 10) vulnerability affecting a number of SAP business and technical applications running on top of the SAP NetWeaver Java stack. This vulnerability was discovered by the Onapsis Research Labs, which collaborated closely with SAP to develop and release a patch on July 14, 2020. Given the criticality of this issue, the U.S. DHS CISA, BSI CERT-Bund and several other government agencies released alerts urging SAP customers to protect vulnerable applications, prioritizing internet-facing ones.

After observing significant malicious activity targeting RECON in the wild, and considering the number of vulnerable internet-facing SAP applications and the sensitivity of the data and processes typically supported by these systems, Onapsis decided to develop and release this open-source tool as quickly as possible. The goal is to help the information security and administration teams at all SAP customers protect their mission-critical applications by enabling them to assess their exposure and evaluate whether their SAP systems could have been compromised. We plan to further iterate this tool as new threat intelligence and forensic data is captured by our products, research team and the broader community.  

This tool can:
1. Perform a best-effort, black-box scan of your SAP application(s) to quickly assess if they may be vulnerable to RECON. 
2. Perform a *basic* analysis for Indicators of Compromise (IoCs) leveraging the RECON vulnerability by analyzing SAP application logs.

This tool cannot:
1. Guarantee with 100% accuracy whether your SAP applications are vulnerable or not.
2. Find all evidence of compromise of an SAP application, all IoCs related to RECON or post-exploitation activities.  

There are, however, several known limitations of this tool and its usage should not be considered a guarantee that SAP applications are either not exposed to RECON (and other vulnerabilities) or that the applications have not been compromised. Several conditions can affect the state of the assessed applications and/or log files, resulting in false positives and/or false negatives. 

## Tool Output

- For vulnerability scanning, the tool returns whether RECON was detected on the scanned URLs.
- For IoC scanning, the tool returns all the events that were identified in the logs that could indicate misuse of LM CTC Configuration Management, and which could require additional forensic investigation.

If IoCs are identified, it is strongly recommended that you perform an in-depth forensic examination of the evaluated systems (and inter-connected ones), to determine the scope and extent of a potential compromise. 

This tool is offered “as is” and without warranty.

**Alternate Online Version**

In order to assist SAP customers with a rapid assessment against RECON for internet-facing systems, we have also developed a free online version that supports both use cases. If preferred, you can use this service at [https://recon.onapsis.com](https://recon.onapsis.com). 


## Installation and Prerequisites

The scripts are developed in Python 3 and require you to install the following dependencies:

```
#  python3 -m venv .venv
#  . .venv/bin/activate
#  pip install -r requirements.txt
```


## Usage
Once you install the dependencies, you can use Python to run both scripts and get the Help from the command line. 

### Vulnerability Scanning

For vulnerability detection, execute the following script:

```
# python3 RECON_CVE-2020-6287_vuln_scanner.py -h
```
You must execute the script on a system that has a network connection with the target SAP Application being analyzed. The HTTP(s) port of the SAP NetWeaver JAVA Application server should be reachable (that is, for an instance 00, it will be 50000 for HTTP, but it could be exposed through a proxy/load balancer and/or be accessible through other TCP ports such as 80 or 443).

You should use the -u parameter to include a valid URL as a parameter for testing the RECON vulnerability:

```
# python3 RECON_CVE-2020-6287_vuln_scanner.py -u http://myinternalportal.mycompany.com:50000/
```
You can also use the -f parameter to assess multiple URLs by providing a file containing all the URLs to be analyzed:

```
# python3 RECON_CVE-2020-6287_vuln_scanner.py -f file_with_urls 
```
The output of the assessment is sent to stdout. It is possible to dump it into a file in the following way:

```
# python3 RECON_CVE-2020-6287_vuln_scanner.py -f file_with_urls >> results
```

### Indicators of Compromise Scanning
For detecting indicators of compromise, execute the following script: 

```
python3 RECON_CVE-2020-6287_ioc_scanner.py -h
```
The script receives a filename and parses the filename to look for IoCs based on usage of the LM CTC application. The following types of files are accepted: 

- applications_xx.y.log 
The required files are located in the following folder: <br/>
Linux: `/usr/sap/<SID>/<INSTANCE>/j2ee/cluster/server<X>/log/` <br/>
Windows: `\usr\sap\<SID>\<INSTANCE>\j2ee\cluster\server<X>\log\`

- responses_xx.y.trc
Using the default format configuration. If changes were made to the standard log format configuration, the parsing could fail. In that case, the internal regex should be manually adjusted to reflect the new format. The required files are located in the following folder: <br/>
Linux: `/usr/sap/<SID>/<INSTANCE>/j2ee/cluster/server<X>/log/system/httpaccess/` <br/>
Windows: `\usr\sap\<SID>\<INSTANCE>\j2ee\cluster\server<X>\log\system\httpaccess\`

You can execute the script to analyze specific files with the -f parameter:

```
python3 RECON_CVE-2020-6287_ioc_scanner.py -f path_to_logfile
```
You can use a bash script to run the script against multiple files at the same time. For example, if the directory containing multiple logs is present in /tmp/sap_RECON_logs/, the execution would look like:

```
path_to_log_folder="/tmp/sap_RECON_logs/";for log_file in `ls $path_to_log_folder`; do python RECON_CVE-2020-6287_ioc_scanner.py -f $path_to_log_folder/$log_file -o csv; done
```
## Additional Resources 
- For additional information about the RECON vulnerability, the potential business impact, the affected versions and other data points, please review the RECON Threat Report and information available here: [Onapsis / SAP RECON Cybersecurity Vulnerability](https://www.onapsis.com/recon-sap-cyber-security-vulnerability).
- The US-CERT in coordination with other international CERTs, released an alert (AA20-195A) to warn organizations about the criticality of this vulnerability. You can read the full alert here: [Critical Vulnerability in SAP NetWeaver AS Java | CISA](https://us-cert.cisa.gov/ncas/alerts/aa20-195a).
- The following SAP Notes provide additional information around patch and mitigations to the RECON vulnerability:
  - [2948106 FAQ - for SAP Note 2934135](https://launchpad.support.sap.com/#/notes/2948106)
  - [2947895 - RECON - SAP Vulnerability](https://launchpad.support.sap.com/#/notes/2947895)
  - [2934135 - [CVE-2020-6287] Multiple Vulnerabilities in SAP NetWeaver AS JAVA (LM Configuration Wizard)](https://launchpad.support.sap.com/#/notes/2934135)
  - [2939665 - Disable/Enable LM Configuration Wizard | Critical API's in LM Configuration Wizard](https://launchpad.support.sap.com/#/notes/2939665)

The Onapsis team of cybersecurity experts are available to answer any follow-up questions or to further assist you with getting visibility around the identified indicators. You can contact Onapsis at openrecon@onapsis.com.

