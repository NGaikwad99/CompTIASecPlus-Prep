## Security Operations
### Common security techniques to computing resources

#### Secure baselines
Covered in [Configuration enforcement] (#configuration-enforcement).

#### Hardening targets 
* **Mobile devices**
    * Benchmarks available via Center for Internet Security (CIS).
    * Update and patch the operating system.
    * Enable remote wipe functionality.
    * Set passcodes and automated screen locks.
    * Configure the device to automatically wipe after a set number of unsuccessful logins.
    * Turn off unused connectivity options such as Bluetooth.
* **Workstations and servers**
    * Close unused or unnecessary ports and services.
    * Remove unnecessary software.
    * Set strong passwords.
    * Disable storage of passwords.
    * Place all servers in a secure data center.
    * Ensure implementation of principle of least privilege especially in the case of servers.
    * Ensure the OS is up to date with latest patches.
* **Switches and Routers**
    * Benchmarks available via Center for Internet Security (CIS).
    * Protect the management console by putting the management ports onto an isolated VLAN that can only be accessed through a jump server or VPN.
    * Restrict physical access to the devices by placing them in network closets that are secure and, in some cases, monitored to ensure tracking of who accesses the area.
    * Disable unused interfaces, ports, and services.
    * Ensure the devices contain latest updates and patches.
    * Enable port security
    * Change SSID and configure username and strong passwords.
* **Cloud infrastructure**
    * Cloud access security brokers (CASBs) are software tools that serve as intermediaries between cloud service users and cloud service providers. Inline CASBs are placed in the connection while API-based CASBs interact with the cloud provider through the provider's API.
    * Resource policies can be used by customers to restrict the actions that users can take.
    * Hardware security modules (HSMs) can be used to securely store and manage sensitive information such as encryption keys.
* **ICS/SCADA**
    * Ensure latest patches and updates are installed.
    * Secure connections using firewalls and intrusion detection/prevention systems.
    * Implement customized industrial communication protocols and proprietary interfaces.
    * In some cases, isolate the systems from trusted networks.
* **Embedded systems and RTOS**
    * Encrypt command and control channels for drones and autonomous vehicles.
    * Protect VoIP systems using segmentation and regular updates as well as applying baseline security standards.
    * Protect access to printers including multifunction printers as they are a significant data leakage risk.
    * Install surveillance systems to secure physical access to the systems.
    * Change default configurations.
* **IoT devices**
    * Change default settings.
    * Encrypt communication.
    * Ensure thorough and reliable vetting of the vendor.

#### Wireless devices
* **Site surveys**
    * Moving throughout a facility to gather information about existing networks.
    * Helps set up a network.
    * Find options for placing access points.
* **Heat maps**
    * Moving around a building to map the strength of the network.
    * Also provides information on which channel(s) each access point is on.
    * Helps improve network strength after it is setup.

#### Mobile solutions
* **Mobile device management (MDM)**
    * Centralized solution for monitoring and managing a wide range of mobile devices such as company owned mobile phones.
    * Application management features provide remote access to install/uninstall applications and ensure no unnecessary or insecure apps are present on the device.
    * Content management protects the data on mobile devices by locking it within a controlled space and managing access.
    * Remote wiping capabilities that in case of compromise of the device ensure confidentiality of data stored on the device. Either full device wipe or removing only organizational data. Will not work if device is placed airplane mode or using an RF-blocking bag.
    * Geolocation and geofencing capabilities enabling access control based on location or being able to find the device if lost.
    * Screen locks, passwords and PINs can be set remotely.
    * Biometrics such as fingerprints and facial recognition enabled remotely allowing ease of use.
    * Context-aware authentication provides access based on behavioral elements such as location and hours of use.
    * Containerization and storage segmentation separates professional and personal use contexts by storing and running organizational data and processes in a secure container.
    * Full-device encryption protects confidentiality of data in case device is lost or stolen.
    * Push notifications allow sending alerts or warnings to users or a thief from a central location.
* **Deployment models** 
    * Bring your own device (BYOD)
        * Employees use their personal devices for work purposes.
        * More freedom for users and lower cost for organization.
        * Higher risk to the organization.
    * Choose your own device (CYOD)
        * Employees pick the device they would use for work. 
        * Device is owned and controlled by the organization.
    * Corporate-owned personally enabled (COPE)
        * Organization provides the employee with a device.
        * Employee can use this device for reasonable personal uses.
        * Device is owned and controlled by the organization. 
* **Wireless connection methods** 
    * Cellular
        * Subscriber identity module (SIM) uniquely identifies devices on a cellular network.
        * Geographic areas are divided into cells with tower coverage.
        * Cellular network technologies include LTE, 4G and 5G.
        * Provided by cellular carriers so traffic goes through third-party network (external network).
    * Bluetooth
        * Operates in 2.4 GHz range.
        * Low-power, short-range connections.
        * Point-to-point model.
        * Easy to attack.
    * Wi-Fi
        * Wireless protocols for wireless networking.
        * Primarily relies on 2.4 GHz and 5 GHz radio bands.
        * Signals cannot be contained or controlled when traveling.
        * Service set identifiers (SSIDs) uniquely identify Wi-Fi networks.
        * Secured by WPA2 or WPA3 protocols.
        * Devices can be deployed in either ad-hoc (direct communication) or infrastructure mode (traffic sent via base station).

#### Wireless security settings
* **Wi-Fi Protected Access 2 (WPA2) **   
    * *WPA2-Personal* uses pre-shared key (PSK) for authentication.
    * *WPA2-Enterprise* leverages RADIUS authentication server.
    * Counter mode cipher block chaining message authentication code protocol (CCMP) uses AES for confidentiality.
* **Wi-Fi Protected Access 3 (WPA3) **
    * Replacement for WPA2.
    * *WPA3-Personal*
        * Uses Simultaneous Authentication of Equals (SAE) for authentication.
        * Both client and servers must interact for validation thereby protecting from brute-force attacks.
        * Implements perfect forward secrecy (constantly changing encryption key) to ensure confidentiality of data in transit.
    * *WPA3-Enterprise*
        * Continues to use RADIUS but with improved encryption and key management features.
        * Optional 192-bit security mode.
        * Additional controls for stronger security.
* **Remote Authentication Dial-In User Service (RADIUS)**
    * One of the most common AAA systems.
    * Operates in client-server model via TCP or UDP.
    * Transmitted passwords are obfuscated by shared secret and MD5 hash.
    * Traffic is usually encrypted using IPSec tunnels.
* **Cryptographic protocols**
    * *Secure Sockets Layer/Transport Layer Security (SSL/TLS) * is used for securing web communications. TLS is an updated and more secure version of SSL.
    * *Secure Shell (SSH)* is used for secure remote access and file transfers.
    * *Internet Protocol Security (IPsec)* provides security at the IP layer for virtual private networks (VPNs)
* **Authentication protocols**
    * *Extensible authentication protocol (EAP)*
        * Protected EAP (PEAP)
            * Uses certificate.
            * Wraps EAP using TLS.
            * Does not require installation of any additional software.
            * Devices use encryption keys that are replaced using Temporal Key Integrity Protocol (TKIP).
        * EAP-Flexible Authentication via Secure Tunneling (EAP-FAST)
            * Secure version of LEAP
            * Provides faster reauthentication using shared secret (symmetric) key while devices are roaming.
            * Uses either PSK or dynamic keys established using asymmetric cryptography.
        * EAP-Transport Layer Security (EAP-TLS)
            * Certificate-based authentication and mutual authentication.
            * Used less frequently due to certification management challenges.
        * EAP-Tunneled Transport Layer Security (EAP-TTLS)
            * Extends EAP-TLS.
            * May require additional software to be installed.
            * Provides similar functionality to PEAP.

#### Application security
* **Input validation**
    * Allow or deny listing to control user input.
    * Prevent code injection attacks such as SQLi or XSS.
    * Parameter pollution may be used to bypass this control as an attacker gives two values to one variable wherein the first value is subject to input validation but the second is not.
* **Secure cookies**
    * Cookies marked with the SECURE attribute to protect against session replay attacks.
    * Cookies are files or small pieces of data stored on the user's browser.
    * Sent to and from the server with each request.
    * Contain information about the user making it easier to maintain state.
* **Static code analysis**
    * Reviewing the code for an application either using automated tools or manually.
    * If done manually, best practice is the reviewer should be someone apart from the original developer(s) of the code.
    * Type of known environment testing as reviewers have all the related background.
* **Dynamic code analysis**
    * Analysing code through execution.
    * Provides input for testing.
    * Fuzzing sends random data to evaluate the application and identify simple problems such as input validation issues, logic issues, memory leaks and error handling.
* **Code signing**
    * Developers confirm the authenticity of their code.
    * Developers sign their code using their private key and then browsers use their public key for verification to ensure that the code is legitimate and was not subject to unauthorized changes.
    * Ensures authentication and integrity and protects from malicious updates.

#### Sandboxing 
* Running an application in a controlled or isolated environment.
* Application has limited access to other networks and resources.
* Useful when testing new untrusted software or software updates before deployment in production.

#### Monitoring
* Keeping track of the activities performed in relation to systems, applications, and networks.
* Logs are essential for future reference in the case of a security issue.
* Typically results in a lot of data that needs to be securely stored to avoid unauthorized modification.

### Security implications of proper hardware, software, and data asset management
#### Acquisition/procurement process
* Obtaining an asset.
* Perform due diligence to ensure the vendor of the asset have appropriate controls and practices.
* Each asset is assigned an owner and subject to classification based on sensitivity.

#### Assignment/accounting
* Ownership provides each asset with a point of contact responsible for management and monitoring.
* Classification of an asset is done based on its sensitivity and significance to the organization.
    * Public
    * Private
    * Sensitive
    * Confidential
    * Secret
    * Top secret
    * Critical
    * Restricted
    * Each organization has their own classification policy.

#### Monitoring/asset tracking
* **Inventory**
    * List of all assets (devices, systems, software, and data) belonging to the organization.
    * Mentions the owners or managers for each asset.
    * Allows tracking of all assets.
    * Helps identify any lost or stolen assets or flag unauthorized assets.
* **Enumeration**
    * Scanning the inventory to identify assets.
    * Some organizations use port and vulnerability scans to find systems that have not been added to their inventory.

#### Disposal/decommissioning
* Process followed when a product reaches its end of useful life cycle.
* Involves removing a device or system from service, removing it from inventory, and ensuring that no sensitive data remains on the device before it is discarded.
* **Sanitization** includes either wiping the data or destroying the device
    * Degaussing exposes magnetic media such as tapes to extraordinarily strong electromagnetic fields. This cannot be applied to SSDs, optical media and drives or flash drives.
    * Data can be wiped from hard drives or other magnetic media by performing a series of writes to every storage location of the device. However, this may leave data remnants as it may skip some sections of the drive such as in SSD. 
    * Tools using built-in secure Erase command ensure that no data is left behind.
    * Using FDE on the drive and then discarding the decryption key.
    * Shredding, pulverizing or incinerating drives will ensure that data cannot be retrieved from them.
* **Certification of destruction** is an important part of the process to verify that the asset has been destroyed completely by the third-party vendor.
* **Data retention** may be essential for legal purposes as determined by law. 
* Organizations should be aware of retention policies, procedures, and categorization.

### Vulnerability management
#### Identification methods
* **Vulnerability scans**
    * Detect weaknesses in a system or device and then implement remediations based on priority scores.
    * Determine scan coverage based on the following factors:
        * Classification level of the data stored, transmitted or processes by the system.
        * Whether the system has access to untrusted networks.
        * Services offered by the system.
        * Environment in which the system is placed, such as production, test, or development.
    * Determine scan frequency based on the following factors:
        * *Risk appetite* is the organization's willingness to tolerate risk within the environment.
        * Regulatory requirements included in rules and guidelines such as PCI DCSS or FISMA.
        * Technical constraints may limit the number of scans that can be performed. 
        * Business constraints refer to peak hours of operation when scans should not be conducted.
        * Licensing limitations may restrict the bandwidth that can be consumed by the scans.
* **Application security**
    * *Static analysis*: covered in previous section.
    * *Dynamic analysis*: covered in previous section.
    * *Package monitoring*
        * Keeping track of all third-party libraries or packages used in an organization.
        * Regularly updating dependencies.
        * Automated tools to notify users when an update is pending.
        * Understand trustworthiness and reputation of the source/vendor.
* **Threat feed**
    * *Threat intelligence* refers to information related to known threats or the process of gathering, processing, and analysing that data to better understand threats. It keeps security professionals aware of the changes in the threat environment.
    * Threat intelligence can be used for predictive analysis to identify potential risks in the organization.
    * *Open-source intelligence (OSINT)* refers to publicly available threat data.
    * *Proprietary/third-party sources* perform their research to gather, curate, and maintain their threat feeds.
    * *Information sharing organizations* exchange threat data to help protect each other.
    * *Dark web* is used as a communication platform by hackers to share gather information, or stolen data. Organizations can search for sensitive data on marketplaces of the dark web and if found, they identify a breach.
* **Penetration testing** uses offensive security to help identify weaknesses in the organization.
* **Responsible disclosure program** 
    * Allows security researchers to securely share vulnerabilities found in a product with the vendor. This ensures timely identification, reporting, and remediation of the vulnerabilities.
    * Bug bounty program incentivizes responsible disclosure submissions by offering monetary awards to testers or researchers who discover vulnerabilities.
* **Security assessments** 
    * Informal and thorough reviews of the security of a system, application, or other environments.
    * Performed regularly by teams within the organization.
* **System/process audits**
    * Formal examinations performed by independent auditors to highlight the effectiveness of controls to a third party. 
    * Includes an *attestation* (formal statement) by the auditor verifying that the organization has met its objectives and controls are working as expected.
    * *Internal audits* are meant for internal use and performed by internal audit staff, for reassurance.
    * *External audits* are performed by outside auditing firm who serves as an independent third party.
    * *Third-party audits* are conducted by or on behalf od another organization. The organization initiating the audit usually selects the auditors and designs the scope.

#### Analysis
* **Confirmation** that the vulnerability exists.
* **False positive** is when the flagged vulnerability does not exist. 
* **False negative** is when an existing vulnerability is not flagged.
* **Prioritize** identified vulnerabilities using CVSS and CVE to determine the order of remediation.
* **Common vulnerability scoring system (CVSS)** provides a vulnerability with a score from 0 to 10 that indicates its severity. 
* **Common vulnerability enumeration (CVE)** is a database of known vulnerabilities in software and hardware, including CVEID, description and references for each vulnerability.
* **Vulnerability classification** is done based on the calculated CVSS.
* Vulnerability analysis reports also include organization-specific information such as exposure factor, environmental variables, impact, and risk tolerance.
* **Exposure factor** is the percentage of loss in case of the compromise of an asset.
* **Environmental variables** are those that contribute to or are associated with the vulnerability.
* **Industry/organizational impact** is the effect of the vulnerability being exploited.
* **Risk tolerance** is the ability of an organization to withstand risks and continue operations without any significant impact.

#### Vulnerability response and remediation
* **Patching** to correct the vulnerability.
* **Insurance** to transfer the financial risk of the vulnerability being exploited. 
* **Segmentation** to isolate the affected system thereby reducing the impact of the breach.
* **Compensating controls** to temporarily deal with the vulnerability until it can be fixed completely.
* **Exceptions and exemptions** given to the system as part of formal risk acceptance strategy.

#### Validation of remediation
* **Rescanning** to ensure that the vulnerability is no longer present.
* **Audit** is performed in case of more serious vulnerabilities to obtain assurance/attestation that the weakness is remediated.
* **Verification** that the vulnerability has been removed and there is no additional impact of this change.

#### Reporting

### Security alerting and monitoring concepts and tools
#### Monitoring computing resources
<span style="color: blue">explained in 'Mitigation techniques used to secure the enterprise'</span>
* Systems
* Applications
* Infrastructure

#### Activities
* **Log aggregation** 
    * Gathering all data points into a centralized software tool for correlation and analysis.
    * Done using tools such as SIEM, syslog-ng and syslog.
* **Alerting**
    * Generate alarms or alerts based on a defined rule. 
    * Poorly constructed rules may cause issues leading to false positives or false negatives.
    * Rules need to be carefully built and evaluated.
    * Most SIEM devices have pre-defined set of rules that can be adjusted based on organization-specific needs.
* **Scanning** is done as regularly as possible to ensure all assets are in check.
* **Reporting** of identified vulnerabilities or issues from logs must be done immediately and in a secure fashion to ensure the organization has enough time to patch the impacted asset(s).
* **Archiving logs** is part of the full lifespan of log data wherein the logs are retained but not in active use. Typically done to maintain logs in case needed for future investigation. 
* **Alert response and remediation/validation**
    * *Quarantine* or isolation of suspected files places them in a restricted location with no access to or from trusted networks.
    * *Alert tuning* is adjusting the sensitivity of the analysis tool to reduce the number of false positives while ensuring minimal or no impact in the false negative rate.

#### Tools
* **Security content automation protocol** is a standardized set of roles use for the exchange of information regarding security. This includes Common Configuration Enumeration (CCE), Common Platform Enumeration (CPE), Common Vulnerabilities and Exposures (CVE), Common Vulnerability Scoring System (CVSS), Extensible Configuration Checklist Description Format (XCCDF) and Open Vulnerability and Assessment Language (OVAL).
* **Benchmarks** typically specify required logging sources. A well-constructed benchmark might require central logging, configuring log and alerting levels, and that endpoints or servers log critical and major events.
* **Agents/agentless sources for logging**
    * Agents involve the special-purpose software deployed to systems and devices that send logs to a centralized system.
    * Agentless sources do not require any installments and send the logs via standardized log interfaces like syslog.
* **Security information and event management (SIEM)**
    * Central security monitoring tool.
    * Input includes log data and packet capture.
    * Collect and aggregate log data from a wide range of sources and perform correlation and analysis.
    * May include ability to review and alert on user behavior or to perform sentiment analysis.
    * Alerting, reporting, and response.
    * Dashboards provide a high-level visual view of the gathered data and findings.
* **Antivirus**
    * Tool to detect malicious software and applications.
    * Signature-based detection: Uses hash or pattern to identify known malware in files or components.
    * Heuristic- or behavior-based detection: Compares current state or behaviors to a normal baseline to identify any unusual activity. Can identify new malware based on what it is doing.
    * Artificial intelligence and machine learning systems can be trained to identify known and unknown malware based on seen patterns or signatures.
    * Sandboxing allows antivirus vendors to run sample malicious code within a protected environment. The experiment and results are then documented and reported.
    * Typically installed on endpoints such as desktops, laptops, and mobile devices.
* **Data loss prevention (DLP)**
    * Deployed to endpoints or can have network and server-resident components.
    * Ability to classify data.
    * Data labeling or tagging.
    * Policy management and enforcement.
    * Monitoring and reporting.
    * Data encryption or obfuscation during transmission.
* **Simple network management (SNMP) traps**
    * SNMP is a protocol used for network monitoring and management.
    * SNMP is an alert generated when a device configured to use SNMP encounters and error.
    * Sent to SNMP manager from SNMP agents.
* **NetFlow** is Cisco's proprietary protocol for monitoring network flow and volume and gathering IP traffic information.
* **Vulnerability scanners**
    * *Network vulnerability scanners* 
        * Enable’s Nessus: one of the earliest scanners launched.
        * Qualys: offers software-as-a-service (SaaS) management console.
        * Rapid7's Nexpose: offers features like those of Nessus and Qualys.
        * OpenVAS: free alternative to the commercial scanners mentioned above.
    * *Web application scanners*
        * Nikto: open-source scanner, uses a command-line interface and is difficult to use.
        * Arachni: open-source tool, package scanner.
        * Acunetix: another dedicated web app scanning tool.
        * However, many organizations use traditional network scanners such as Nessus, Qualys and Nexpose.

### Enterprise capabilities to enhance security
#### Firewall
* Deployed as network appliances or on individual devices.
* **Stateless firewalls**
    * First generation firewalls and called packet filters.
    * Most basic type of firewall filtering every packet based on source and destination IP, port, protocol, etc.
* **Stateful firewalls**
    * Also known as dynamic packet filters.
    * Connection information is tracked in a state table thereby reducing the number of packets that need to be reviewed.
* **Next-generation firewalls (NGFWs)**
    * All in one security devices.
    * Range of features including deep packet inspection, ID/PS functionality, and antivirus and antimalware.
    * Usually faster than UTMs as they are more focused.
    * Require more configuration and expertise than UTMs.
* **Unified threat management devices (UTMs)**
    * Combine the capabilities of firewalls, IDS/IPS, antimalware, DLP, VPN, URL and email filtering, and security monitoring and analytics.
    * Easier and quicker to configure and use. 
    * Usually deployed at network boundaries.
* **Web application firewalls (WAFs)**
    * Intercept, analyse and apply rules to web traffic.
    * Block or modify traffic in real-time.
    * Works like a firewall combined with an IPS.
* **Rules** define the action to be taken on the current packet based on certain attributes such as port, protocol, and IP address.
* **Access lists** are rules that permit or deny actions based on source and destination IP address, protocol, port, time, etc. 
* **Ports/protocols** help identify insecure packets that should be dropped or further investigated. 
* **Screened subnets** use three interfaces on a firewall to connect to the Internet or an untrusted network, trusted network or secure area and public area or DMZ.

#### IDS/IPS
* Tools used to detect threats and in the case of IPS, blocking them as well.
* Signatures or hashes are used to detect known attacks.
* Anomaly-based detection identifies threats based on unusual behavior by comparing the activities to a baseline.
* IPS should be deployed inline to be able to block potentially malicious traffic.
* IDS can be deployed in passive or tap mode such that it receives copies of the traffic entering or exiting the network.

#### Web filter
* Centralized proxy devices or agent-based tools that allow or block traffic based on content rules.
    * Sometimes called content filters.
    * Agent-based tools are installed on the devices.
    * Traffic is routed through the device.
* Universal resource locator (URL) scanning enables blocking specific URLs based on configured access/deny lists.
* Content categorization is used for URL filtering, with common categories including adult material, business, and child-friendly material.
* Block rules stop systems from visiting sites that are in an undesired category or that have been blocked due to reputation or threat.
* Reputation of a site determines the trust one has on that site and those resources with poor reputation or known mishaps are typically added to deny lists.

#### Operating system security
* **Group policy** 
    * Feature in Windows that enables controlling the settings and access using Group Policy Objects (GPOs).
    * GPOs are rules such as password requirements or software restrictions, which can be applied locally or via Active Directory for centralized management.
* **SELinux**
    * Linux kernel-based security module built on top of existing Linux distributions.
    * SELinux implements various security measures such as Mandatory Access Control (MAC).
    * Also implemented in Android.

#### Implementation of secure protocols
* Ensure communication and services are secure.
* **Protocol selection** typically defaults to using the secure protocol if it exists and is supported. 
* Insecure protocols being used are noted as a risk and compensating controls are implemented until a replacement is found.
* **Port selection** goes hand in hand with protocol selection. Many protocols have default ports that are preselected.
* **Transport method** including protocol versions is important when selecting secure protocols to avoid downgrade attacks or using vulnerable versions.

#### DNS filtering
* Block malicious domains using a list of prohibited domains, subdomains, and hosts that, when accessed, redirect the user to an internal website that displays a message accordingly.
* Prompt response to phishing campaigns.
* Sites are added to block lists based on threat, reputation, and block list feeds.

#### Email security
* **Domain keys identified mail (DKIM)** signs both the body of the message and elements of the header to verify the sender organization by checking the DKIM-Signature header against the organization's public key. 
* **Sender policy framework (SPF)** is an email authentication technique that allows organizations to publish a list of their authorized email servers. SPF records are limited to 255 characters. 
* **Domain-based message authentication reporting and conformance (DMARC)** uses SPF and DKIM to determine whether an email message is authentic.
* **Email security gateways** are used for additional security to filter both inbound and outbound emails.

#### File integrity monitoring (FIM)
* Detect unauthorized file changes and either report them or correct them.
* Tripwire is a popular file integrity monitor that monitors files and filesystems using their signature or fingerprint.
* Can be noisy and require time and effort to set up and maintain.

#### DLP
Already covered.

#### Network access control (NAC)
* Determines whether a device or system should be allowed to join a network based on its security status.
* Can be agent-based (requiring installation) or agentless (runs from the browser and provides less detail).
* Check can occur before a device is allowed on the network (preadmission) or after it has connected (postadmission).
* 802.1x is commonly used for port-based authentication or port security, so if devices want to connect to a LAN, they need to have an 802.1X supplicant to complete the authentication process.

#### Endpoint detection and response (EDR) and Extended detection and response (XDR)
* EDR tools are focused on monitoring endpoint devices and systems using client or software agents.
* EDR systems look for anomalies and indicators of compromise in the collected data using automated rules and detection engines.
* XDR has a broader perspective considering the organization's whole technology stack and use artificial intelligence and machine learning for detection.

#### User behavior analytics
* Tracking, collecting, and assessing user activities using tools such as artificial intelligence and machine learning.
* Help detect insider threats.
* Analyse authentication logs, actions performed and other historical data to identify any suspicious behavior.

### Identity and access management
#### Provisioning/de-provisioning user accounts
* Provisioning refers to creation.
    * May include *identity proofing* (using government issued IDs and personal information) to verify the user the account is being created for.
    * Includes *permission assignment* based on the user role and following principle of least privilege.
    * Commonly done during employee onboarding.
    * *Privilege creep* occurs when the permissions of an employee from previous roles have not been revoked.
* Deprovisioning refers to deletion, disabling or termination.
    * Helps ensure that dormant accounts cannot be compromised.
    * Removes all related files, permissions and data associated with the user.
    * Limited in the case of role change within the same organization.
    * Deletion is preferred over disabling.

#### Federation

#### Single sign-on (SSO)
* Lightweight directory access protocol (LDAP)
* Open authorization (OAuth)
* Security assertions markup language (SAML)

#### Interoperability 

#### Attestation

#### Access control schemes
* **Mandatory access control (MAC)** is configured by a security policy administrator and then automatically enforced by the operating system. MAC is a highly secure access control scheme as it is managed centrally and does not allow any user to make changes to the settings configured centrally. MAC used to be implemented in only government and military but is now also found in SELinux and Windows. 
* **Discretionary access control (DAC)** is managed solely by the owner of the resource who determines which users have access to the resources and the actions that they can perform. Linux file permissions is an example of this.
* **Role-based access control (RBAC)** grants/denies permissions based on the role of the subject. RBAC uses role assignment (subject's role should match the role having the requested permissions), role authorization (subject's current role should be verified) and permission authorization (access to resources based on only current role).
* **Rule-based access control (RuBAC)** helps differentiate from RBAC as it is based on access control lists. Firewall rules is an example of RuBAC.
* **Attribute-based access control (ABAC)** grants/denies permissions based on comparatively complex rulesets that are created using a combination of attributes that may vary depending on the way and the role that users interact with the system.
* **Time-of-day restrictions** limit when the activities such as system login can occur.
* **Principle of least privilege** provides employees and users access to only those resources that they need. 

#### Multifactor authentication
* **Implementations** 
    * *Biometrics*: patterns that are unique to everyone such as facial structure or fingerprint
    * *Hard/soft authentication tokens*
        * Typically used for multi-factor authentication
        * Hard tokens include hardware devices such as USB sticks, key fobs, smart cards, and security keys that generate a one-time passcode or use a unique radio signal for identification. 
        * Soft tokens are one-time passwords sent via SMS or email as a part of multi-factor authentication.
    * *Security keys*: hardware devices such as USB sticks that are plugged into the system for authentication. User will need to enter a PIN or show their fingerprint for unlocking the key for login.
* **Factors**
    * *Something you have*: keys, smart cards, magnetic strip card, USB drives, one-time password applications, and token devices.
    * *Something you know*: personal identification number (PIN), password, and answer to security question.
    * *Something you are*: biometric identification including fingerprints, facial recognition, retina scan, voice, and iris pattern.
    * *Somewhere you are*: location determined using GPS, IP address, etc.

#### Password concepts
* **Best practices** 
    * Length: set minimum number of characters for password.
    * Complexity: enforce use of multiple character classes including lower case and upper-case letters, numbers, and special characters.
    * Reuse: password history should be maintained to ensure user is not setting passwords that have already been used recently.
    * Expiration: maximum number of days after which a password should be changed.
    * Age: minimum number of days after which a password can be changed.
* **Password managers**: software used to securely store passwords as well as generate strong passwords encouraging users to set complex passwords as they just need to remember the password for the password manager. 
* **Passwordless**: relies on something you have or something that you are a security key provides elevated level of protection; reduce risk associated with passwords.

#### Privileged access management tools
* **Just-in-time permissions** are granted only when needed and then revoked when the task is complete. Helps prevent privilege creep.
* **Password vaulting** allows users to access privileged accounts during emergencies or outages without needing to know the password.
* **Ephemeral credentials** are temporarily accounts created for guests or for specific purposes. The account should be deprovisioned in a timely manner.

### Automation and orchestration related to secure operations

#### Use cases of automation and scripting
* **User provisioning**: Create, modify, or revoke user access.
* **Resource provisioning**: Allocating and deallocating system resources.
* **Guard rails**: Enforce policy controls and prevent violations of security protocols.
* **Security groups**: Manage user permissions using security group memberships.
* **Ticket creation**: Immediate creation and routing of issues to the corresponding teams.
* **Escalation**: Alerting key personnel quickly.
* **Enabling/disabling services and access**: Turn services on or off based on conditions or triggers.
* **Continuous integration and testing**: Speeding up the build and test process.
* **Integrations and Application programming interfaces (APIs)**: Data exchange between different software applications to enhance interoperability.

#### Benefits
* **Efficient time saving**: Reduces manual tasks allowing users to focus on higher-level tasks.
* **Enforcing baselines**: Maintain consistent security baselines across the organization.
* **Standard infrastructure configurations**: Ensuring uniformity and reducing errors in system configuration.
* **Scaling in a secure manner**: Rapid scaling of infrastructure while maintaining security controls.
* **Employee retention**: Increase job satisfaction by assisting with mundane tasks.
* **Reaction time**: Reduce time to react by generating quick alerts and triggering alarms when needed.
* **Workforce multiplier**: Increases capacity and productivity by helping with repetitive tasks.

#### Other considerations
* **Complexity**: Development and management of scripts can require high level of skill.
* **Cost**: Additional expenses as automation might require tools, training, and domain experts.
* **Single point of failure**: Over-reliance can lead to a single point of failure where one malfunctioning script can disrupt business operations.
* **Technical debt**: Outdated or inefficient scripts pile up over time.
* **Ongoing supportability**: Scripts should be maintained consistently and timely updated.

### Incident response 
#### Process
* **Preparation**: Putting together a team, training the team, conducting exercises, documenting the procedure to be followed, and acquiring, configuring, and operating security tools and incident response capabilities.
* **Detection**: Reviewing events or logs to identify incidents by paying attention to indicators of compromise and having a comprehensive awareness and reporting program for employees.
* **Analysis**: Identifying any other related events and their target or impact.
* **Containment**: Isolating or removing affected systems or network zones to prevent further issues or damage.
* **Eradication**: Removing artifacts associated with the incident that may involve rebuilding the systems from backups as it is essential to ensure complete eradication.
* **Recovery**: Restoration to normal operations that involves bringing systems back online and implementing necessary fixes to ensure the event does not happen again.
* **Lessons learned**: Taking actions such as patching systems or mandating additional employee training modules based on the realizations derived from to the incident.

#### Training
IR teams typically include the following:
* *Member of management and organizational leadership* who makes decisions and acts as a liaison between the team and senior management.
* *Information security staff* members make up the core, specializing in IR and analysis.
* *Technical experts* such as systems administrators and developers decided depending on the nature of the incident.
* *Communications and public relations staff* to help manage internal and external communications.
* *Legal and human resources staff* might be needed in some cases if legal advice is needed or the incident involves an insider.
* *Law enforcement* might also be added if needed.

#### Testing
* **Tabletop exercises** are used to talk through processes. Team members think through a scenario and document improvements.
* **Simulations** include rehearsals of individual functions or elements of the plan ensuring that all participants are aware. Can also be done at full scale.

#### Root cause analysis
* Process conducted after mitigating issues to identify the underlying cause for an issue or compromise.
* Common techniques used include five whys, event analysis and diagramming cause and effect.
* Fishbone diagrams are commonly used.
* Part of the recovery phase and feeds the preparation phase of the incident response process.

#### Threat hunting
Covered in Indicators subsection.

#### Digital forensics
* Digital forensics investigate and reconstructs cybersecurity incidents by collecting, analyzing, and preserving digital evidence.
* **Legal hold or litigation hold**
    * Notice that obligates an organization to preserve data and records including backups, paper documents and electronic files.
    * Often the first part of e-discovery process.
* **Chain of custody** documentation should be maintained to show the transfer, access permissions and ownership of evidence.
* **Acquisition** is gathering the data in the form of drives, files, copies of live memory, etc., for further analysis.
* **Reporting** all related evidence and any potential tampering is essential.
* **Preservation** of the information or evidence covered by a legal hold ensures that it is not modified or deleted.
* **E-discovery** allows each side of a legal case to obtain electronic or digital evidence from each other and other parties.
* **Electronic Discovery Reference Model (EDRM)** is useful framework that includes nine stages to describe the discovery process.
* **Order of volatility** documents data from most to least likely to be lost. 
    * CPU cache and registers
    * Routing table, ARP cache, process table, kernel statistics
    * System memory - RAM
    * Temporary files and swap space
    * Data on the hard disk
    * Remote logs
    * Backups
* **Admissibility** requires that data be relevant, reliable, intact, and unaltered and have provably remained unaltered before and during forensic process.

### Data sources to support an investigation
#### Log data
* **Firewall logs** provide information about blocked/allowed traffic. More advanced protocols like NGFW and UTM, users can also obtain application layer details.
* **Application logs** include installer information, errors generated, license checks and requests to web servers. Help identify web app attacks like SQLi.
* **Endpoint logs** include application installation details, system, and service logs.
* **OS-specific security logs** comprise of endpoint specific information such failed and successful logins.
* **IPS/IDS logs** include information about all the traffic that travelled in the network.
* **Network logs** store events related to routers and switches such as configuration changes, traffic information, network flows and data captured by packet analysers.
* **Metadata** is data or information about other data. For instance, file metadata includes file size.

#### Data sources
* **Vulnerability scans** help identify weaknesses in the system that should be fixed.
* **Automated reports** allow efficient generation of information derived from gathered data for further analysis and investigation.
* **Dashboards** provide a high-level, visual representation of the information they contain including statistics and findings.
* **Packet captures** allow analysing raw packet data from network traffic. This data can be correlated with IDS and IPS events, firewall and WAF logs.
