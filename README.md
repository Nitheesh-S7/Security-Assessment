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
 * **MX Toolbox**  - *(enumerates DNS, DMARC and SPF records)*
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
 * Found 36 exposed directories through robots.txt for https://mmesec.com domain hosted on same IP including CHANGELOG.txt and intallation files exposing technologies and versions 
 * Drupal version 7.69 exposed which is deprecated and has muliple critical vulnerabilities found in https://mmesec.com domain.
 * Found TLS certificate expired on 22-5-2025

 **Gobuster**

 * Found Directories called images, downloads, js and javascrip with resticted access

 **Nikto**
 
 * X-Content-Type-Options header missing which can make it vulnerable to content sniffing attacks incorrectly assessing MIME type of files
 * Referrer-Policy header missing which can leak sensitive information from url to other sites when clicking links.
 * Content-Security-Policy header not found which prevents attacks by verifiying only whitelisted data are being loaded in the website
 * Drupal version 7 was indentified through x-generator header, Drupal 7 is outdated and has multiple vulnerabilities
 * Apache default files /icons/README was found which can leak information on server and version
 * HTTP OPTIONS method is allowed which can be used to gain information of webserver and its users if Cross-Orgin-Resource-Sharing (CORS) is incorrectly configured.
 * Strict-Transport-Security_Header (HSTS) not set which allows downgrade attacks from HTTTPS to HTTP
 * No TLS/SSL Support found

 **OWASP ZAP**
 
 * Strict-Transport-Security_Header (HSTS) not set which allows downgrade attacks
 * Content-Security-Policy header not found on website which makes it more vulnerable to attacks

 **OpenVAS**
 
 * Weak Host Key Algorithm found for SSH which uses ssh-dss (Digital signature algorithm) which is depricated
 * Depricated TLS version 1.0 and 1.1 protocols found on certificate which is vulnerable to multiple CVE's 
 * Weak MAC algorithm umac-64-etm@openssh supported on SSH

 **MX Toolbox**

 * No DMARC record published 
 * DMARC(Domain-based Message Authentication) policy is not enabled which makes it vulnerable to email spoofing with the lack of email verification
 * TLS/SSL Certificate name mismatch in domain pointhing to a different domain
 * A null DNS lookup was found for include (mme-srv-dc1.mme.local) which can cause problem in email delivery
 * SOA (Start of Authority) Expire Value out of recommended range which may cause downtime if primary DNS server fails, secondary server may stop responding to DNS querries sooner than reccomended

 **Hacker Target**

 *Found Multiple hosts names on the ip 31.3.96.40
    * mmebv.be
    * www.mmebv.be
    * mmesec.be
    * www.mmesec.be
    * itsecgames.com
    * mmesec.com
    * www.mmesec.com
    * mmebv.com
    * www.mmebv.com
    * mmebvba.com
    * www.mmebvba.com

 
