# Security Assessment
This is a report on security assessment of http://www.itsecgames.com domain including vulnerability assessment, mitigation methods and SSL/TLS analysis.

---

# Tools Used For Analysis
 * **Wappalyzer** - *(fingerprinting websites technologies)*
 * **Nmap**  - *(port scanning and enumeration of services)*
 * **Gobuster**  - *(fuzzing directories and virtual hosts)*
 * **Nikto**  - *(vulnerability scanning tool for web servers)*
 * **OWASP ZAP**  - *(web application security scanner)*
 * **OpenVAS**  - *(vulnerability scanner)*
 * **MX Toolbox**  - *(enumerates DNS,DMARC and SPF records)*
 * **Hacker Target** - *(Reverse IP lookup for domains in IP)*
 * **SecurityHeaders.com** - *(Checks for vulnerable and missing headers)*
 * **SSL Labs** - *(provides website SSL/TLS certificate status and information)*

---

# Findings
 **Wappalyzer** 
 * Found the website uses Apache HTTP Server and Microsoft for Emails

 **Nmap**

 * The scan revealed open ports 22 (ssh), 80 (http) and 443 (https)
 * Port 22 is running OpenSSH 6.7p1 which outdated and has vulnerabilities like CVE-2016-0777 and CVE-2018-1547
 * Found 36 of exposed directories through robots.txt including CHANGELOG.txt and intallation files exposing technologies and versions
 * Drupal version 7.69 exposed which is deprecated has muliple vulnerabilities found in https:\\mmesec.com domain hosted on same IP 
 * Found expired TLS certificate

 **Gobuster**

 * Found Directories images, downloads, js and javascrip with resticted access

 **Nikto**
