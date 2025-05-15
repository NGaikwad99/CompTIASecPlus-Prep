## Threats, Vulnerabilities, and Mitigations
### Common threat actors and motivations
#### Threat actors 
* **Nation-state attackers** 
    * Highly skilled advanced persistent threat (APT) actors with significant resources
    * Hired and sponsored by the nation for political or economic motives such as spying on targets or rivals. 
* **Unskilled attackers** 
    * Also known as script kiddies.
    * Amateurs who want to have some fun and/or prove their skill. 
    * Leverage publicly available tools or scripts and have limited skills and low access to resources.
* **Hacktivists** 
    * Believe they are motivated by the greater good and have strong philosophical or political beliefs. 
    * Level of capability varies widely as well as the access to resources. 
    * Might perform attacks like defacing a website or targeting a network due to a political issue. 
    * Anonymous is a hacktivist group that has targeted various generous sized companies like PayPal and Visa and Mastercard as well as government agencies.
* **Insider threats** 
    * Are or used to be employed within the target organization. 
    * Sophistication of attacks may vary but they have an upper hand given their knowledge of the organization. 
    * Limited financial resources and time. 
    * Challenging to detect. 
    * Motives may include revenge or causing disruption by disclosing confidential information or targeting the day-to-day operations. 
    * Behavioral assessments are an effective tool for identifying insider threats.
* **Organized crime** 
    * Typically motivated by financial gain. 
    * Includes cyber-dependent crime (ransomware, data compromise, DDoS, etc.), child sexual abuse, online fraud, dark web activity, and cross-cutting crime factors. 
    * Extremely high resources including time and money and their skills range from moderate to high.
* **Shadow IT** 
    * Purchase and use of devices that do not conform to the organization's policy and requirements. 
    * May intentionally or unintentionally place sensitive information in the hands of the vendor. 
    * For instance, following the release of Dropbox, many employees began uploading sensitive files to synchronize their personal and work devices. 

|Threat actor | Location | Resources | Sophistication | Motivation |
|-------------|-------------|-------------|-------------|-------------|
| Nation-state | External | High | High | Geopolitical reasons, Data exfiltration, Espionage, War |
| Unskilled attacker | External | Low | Low | Disruption/chaos |
| Hacktivist | External | Medium to High | Low to high | Philosophical/political beliefs, Disruption/chaos, Revenge |
| Insider threat | Internal | High | Low to High | Revenge, Financial gain |
| Organized crime | External | High | Moderate to High | Financial gain |
| Shadow IT | Internal | High | Low | Philosophical beliefs, Revenge |

#### Attributes of actors
* **Internal/external**: Internal actors are already part of the organization and thus have an advantage in achieving their goals. External actors, on the other hand, operate from outside the organization and typically have no prior knowledge about the target.
* **Resources/funding**: Hackers vary based on financial resources and time. While actors like nation-state and organized crime are provided with a lot of funding, unskilled attackers or insider threats may have limited time and finances to achieve their goal. 
* **Sophistication/capability**: Hackers also greatly vary based on their knowledge and skill. Nation state and organized crime are among the very highly skilled attackers; hacktivists range from moderately to highly skilled and script kiddies are newbies who want to have some fun during their free time.
* **Intent/motivation**: There are a diverse set of reasons that encourage hackers to target an entity or an individual. Some hackers do it for fun while some have other motives such as data exfiltration, espionage or revenge. 

#### Motivations
* **Data exfiltration** involves stealing sensitive data or proprietary information such as intellectual property or customer data from computer systems or mobile phones. 
* **Espionage** refers to spying on the target to gather sensitive information typically in nation-state or corporate rivalry.
* **Service disruption** seeks to impact availability as it takes down or interrupts critical systems or networks such as those of healthcare, national security, or banking.
* **Blackmail** involves making a demand in exchange of protection of sensitive data. This is typically related to ransomware attacks wherein the attacker demands money to release all the encrypted files on the user's device. The attacker may also threaten to publish the stolen information on the internet.
* **Financial gain** attacks such as organized crime are motivated by the desire to make money from stolen data. 
* **Philosophical/political beliefs** encourage attackers like hacktivists to use cybercrime to promote their ideologies.
* **Ethical** attacks performed by white-hat hackers such as security researchers are aimed to identify vulnerabilities and warn organizations.
* **Revenge** attacks are conducted to defame an entity or embarrass them in public. These may be waged by an insider threat who is not happy with their job or their workplace.
* **Disruption/chaos** attacks are motivated by a desire to cause havoc and interfere with normal operations.
* **War** may be motivation for nation-state attackers who seek to disrupt or gain more information on military operations especially during an ongoing conflict. 

### Common threat vectors and attack surfaces
#### Message-based
* Attacker may send a malicious link and compel the user to click on it by creating a sense of fear or urgency. Once clicked, the attacker may get access to the device and/or the network or may be able to have a worm or virus injected into the target. 
* Media: _Email_ (most common), _Short Message Service (SMS)_ and _Instant Messaging (IM)_.

#### Image-based
* Linking images to illicit sites. 
* For instance, the image on a website can be linked to a fake login page for another site or clicking on it might trigger a malicious script to be run in the background. 

#### File-based
* Delivery of malicious scripts via remote logins or backdoors. 
* Attacker with unauthorized access to load a file into the system and trigger it to run in the background. 
* Malicious code can also be embedded into another file on the system to make it more difficult to detect.

#### Voice call
Social engineering attacks conducted over a voice call are called vishing. These are discussed further in the document.

#### Removable device
* Removal devices such as USB drives are commonly used as a medium to transport malicious scripts into target devices. 
* An attacker might intentionally leave USB sticks lying around in parking lot, on a staircase, on a table in an airport or other public areas. 
* Out of curiosity, the finder plugs in the USB into their device and the USB runs a malicious script such as installing and starting spyware.

#### Vulnerable software
* Client-based vulnerable software requires human intervention to be downloaded locally on the target device.
* Agentless software, on the other hand, does not require any installation and runs via the browser or cloud. 

#### Unsupported systems and applications
* Software vendors eventually discontinue support (software or security updates and customer support) for their products including applications and/or devices. 
* Organizations using these products should find a replacement. 
* Use of unsupported systems and applications poses as a significant security risk as security flaws are no longer being investigated and/or patched. 
* In some cases, organizations may need to continue using the product for business continuity. This results in the need for implementing a compensating control such as isolating the system or application to ensure that if compromised, the impact is contained.

#### Unsecure networks
* Wireless networks ae inherently vulnerable to a wide range of attacks given the mode of data transmission. An attacker can compromise these networks remotely by sitting in the organization's parking lot. 
* Wired networks can only be accessed on-premises. Thus, the attacker would need to find a way to enter the organization's facilities. Attackers may leverage various methods to do so such as tailgating that is following an employee into the organization or pretexting that is creating a fake scenario that convinces the employee to give them access into the organization. Once the attacker gains physical access into the organization facilities, they might be able to find an insecure system or network device that they can use to intrude the network. 
* Bluetooth-enabled devices can be used to ensure that unauthorized individuals are not permitted into the network. 

#### Open service ports
* Ensure that only necessary and secure ports are always open. 
* Insecure ports may provide attackers with the opportunity to remotely access the systems and/or load malicious files into them. Port is a 16-bit number ranging from 0 to 65535 that is used for communication at the Transport layer. The port number used for the communication depends on the associated application or protocol.
* **Well-known ports**: 0-1023
* **Registered ports**: 1024-49151 
* **Dynamic ports**: 49152-65535

| Protocol | Port Number | TCP/UDP | Description |
| ------ | ------ | ------ | ------ |
| FTP | 20 (data) <br> 21 (control) | TCP | File Transfer Protocol |
| SSH/SFTP | 22 | TCP/UDP | Secure Shell / SSH File Transfer Protocol | 
| Telnet | 23 | TCP | insecure remote access |
| SMTP | 25 | TCP | Simple Mail Transfer Protocol |
| DNS | 53 | TCP/UDP | Domain Name System |
| DHCP | 67/68 | UDP | Dynamic Host Configuration Protocol |
| TFTP | 69 | UDP | Trivial File Transfer Protocol |
| HTTP | 80 | TCP | Hypertext Transfer Protocol |
| Kerberos | 88 | UDP | authentication |
| POP3 | 110 | TCP | Post Office Protocol |
| NNTP | 119 | TCP | Network News Transfer Protocol |
| NTP | 123 | UDP | Network Time Protocol |
| IMAP | 143 | TCP | Internet Message Access Protocol |
| SNMP | 161,162 | TCP/UDP | Simple Network Management Protocol |
| LDAP | 389 | TCP/UDP | Lightweight Directory Access Protocol |
| HTTPS | 443 | TCP/UDP | Hypertext Transfer Protocol Secure |
| RDP | 3389 | TCP | Remote Desktop Protocol |
| IRC | 6667 | TCP | Internet Relay Chat |

#### Default credentials 
Many services or products are manufactured with default credentials that should be changed during set up. If not modified, these credentials can be of significant risk to the security as they are easily available online and attackers simply need to check for negligence to compromise the device or service.

#### Supply chain
* Network of individuals and entities involved in the company operations from the creation to the selling of a product. 
* Begins with the sourcing of raw materials and includes the manufacturing, transportation, third-party vendors, suppliers, and resellers that participate in delivering the product to the customer.
* **Managed service providers (MSPs)** are organizations that provide information technology as a service. They either handle all the IT related needs of their customers or provide specific services such as network design and implementation. While MSPs are not necessarily cloud service providers, a service organization can be both an MSP and CSP. MSPs that also provide security services such as vulnerability management, incident response and firewall management are called Managed security service providers (MSSPs). If an attacker gains access to the MSP, they can compromise the entire technological infrastructure of the consumer organization.
* **Vendors** are organizations that provide hardware or software products to another organization for certain purpose. For instance, a bank might adopt a software for banking created by a company X for their day-to-day operations including creating and managing account and performing money transfers. 
* **Suppliers** are entities that provide products to the third-party vendors. 
* Vendors and suppliers are an indirect mechanism of compromising an organization's security. For instance, a flaw in a hardware device that is acquired from another entity can lead to compromise of the organization's operations. It is thus essential to ensure consideration and minimization of risks associated with third-party vendors and suppliers by assessing interdependencies, conducting periodic risk assessments of the vendors, setting clear terms and conditions, and signing appropriate agreements. 

#### Human vectors/social engineering
Manipulate people into making a mistake. 
An attacker typically creates scenarios wherein targets are compelled to reveal sensitive information or fulfil the demands of the attacker. 
Social engineering techniques involve taking advantage of human's weaknesses by utilizing one or more of the following principles:

* **Authority** is when the attacker impersonates someone at a higher level such as the target's manager or the CEO of a company or a government official. This creates a sense of fear in the target and the obligation to obey orders. 
* **Intimidation** is used to scare or bully the target into performing an action. For instance, an attacker may create a scenario wherein the target's bank account has been locked and ask for their credentials claiming they can fix the problem. 
* **Trust and familiarity** are similar concepts wherein an attacker impersonates someone closely related to the target individual. For instance, an attacker might pose as a close friend or family member to obtain sensitive information from the target. 
* **Consensus-based** social engineering exploits a human's tendency to "follow the herd" wherein attackers try to convince the target that the desired action (such as clicking a malicious link or signing up for a fake service) has already been performed by many of their colleagues or other people and they have gained something out of it.
* **Urgency** is used by many attackers by creating a sense of care or fear of losing something or someone if they do not act fast. For instance, a scammer might pose as someone who really needs help as their family friend is in a serious medical situation and thus try to extract funds from the target. 

One of the most common defenses against social engineering attacks is **awareness**. It is utterly crucial for everyone to be known to the possibility of being scammed and to question any situation that seems suspicious or fake. Such attempts can also be caught by technological solutions that leverage pattern matching, machine or deep learning or filtering based on keywords. 

* **Phishing** attacks manipulate the target into revealing sensitive typically over email. In these attacks, the attacks use a spoofed or compromised email address to contact the target. The email may include a malicious link, file attachment and/or simply just compelling text that forces the target to make a mistake. Phishing can also be conducted using other media such as SMS (smishing) or voice call (vishing). Phishing also differs based on the target of the attack. Spear phishing is when the attacker focuses on specific employees or groups in the organization. Whale phishing or whaling occurs when the target is someone of a higher authority in an organization such as an executive or governing official. 

* **Vishing** is performing a phishing attack using voice call. This typically involves creating a sense of urgency or intimidation while posing as a close friend or relative of the target. It may involve healthcare situation or bank related scenarios that attempt to convince the target to send funds or provide their bank details. Some attackers may also use AI tools to generate audio files that mimic the voice of someone known to the target.

* **Smishing** is phishing via SMS. It typically involves clicking a malicious link by creating a pretext (fake scenario) such as bank account lockout or too many funds being seen in the bank and a link to a fake login page. 

* **Misinformation/disinformation** are typically a result of influence campaigns that aim to turn people's opinions and spread false information. Misinformation refers to incorrect information that is implied from facts whereas disinformation is intentionally false information that is publicised with illicit objectives. Various methods can be used to conduct these campaigns with social media being the most common. It is necessary for organizations to monitor and deal with cases of misinformation or disinformation with high priority. 

* **Impersonation** is pretending to be someone else. This is a commonly used tool to gain trust and create a sense of urgency to convince the target to reveal sensitive information such as username and password or SIN number. Identity theft or identity fraud involves using someone else's identity to perform actions. For instance, an attacker using their target's badge to gain access into an organization's facility. 

* **Business email compromise (BEC)** occurs when an attacker typically uses a compromised email address to make a demand by impersonating someone else in the organization. For instance, an attacker might pose as the Dean of the university who is stuck in an important meeting and contact other professors to urgently send him a gift card.

* **Pretexting** is creating a fake scenario to convince the target to make a mistake. This concept is usually used along with impersonation to instill trust in the target and a sense of urgency or intimidation. A target should ask questions to verify the attacker's identity before considering revealing any confidential data. 

* **Watering hole attacks** involve compromising a website that is visited by a group of people. For instance, embedding malicious code into an internal website that is frequently accessed by the employees of an organization.

* **Brand impersonation** typically occurs through emails wherein the attacker uses various components like themes, logos, or signatures to make the email look legitimate and convince the attacker to click on the provided link or download the attachment. Attackers usually use this technique to extract credentials by compelling targets to click on links that would take them to a fake bank login page. 

* **Typo squatting** exploits human tendency to make typos. When a user is searching for a website by directly entering the site name in the URL box, they may make a tiny mistake that goes unnoticed. Attackers link such incorrect URLs to fake sites where the user unknowingly enters their credentials and/or provides other sensitive information. Such attacks can be avoided by organizations by publishing even those domains that include minor errors. For example, amazon.com has also purchased the domain amaz0n.com that redirects the user to the legitimate amazon site. 

* **Pharming** is like typo squatting but relies on changes in the host files of DNS servers instead of URLs. Host files are those that are checked to resolve a domain name and direct a user to the site. In this case, even if the user enters the domain name correctly, they might be directed to a malicious site as modified in the DNS server. 

### Types of vulnerabilities
#### Application
* **Memory injection** occurs when an attacker corrupts the system memory by inserting malicious information.
* **Buffer overflow** is a memory injection attack wherein an attacker overwrites system memory by making a program use more memory than allocated to it. This may be used to get access to the data stored in another memory location or embed malicious instructed that will be executed by another program. 
* **Race conditions** occur when the security of a code segment depends on the order of execution of related instructions. These attacks are caused when multiple operations occur in a location at a time. 
    * *Time-of-check (TOC)* is when the system verified the access to be granted to the subject.
    * *Time-of-use (TOU)* refers to when the authorization is provided to the user based on assigned permissions.
    * *Race window* is the period between TOC and TOU
    * *Target of evaluation (TOE)* is the subject that is requesting for access such as user or device.
    * *Time-of-check-to-time-of-use (TOCTOU)* is a race condition attack wherein the permissions are checked significantly before the moment the subject uses the resource. For instance, if an operating system caches the user permissions to check them throughout the session, any changes such as revocation of access will not be applied until the next login and the user will have to do to maintain access is stay logged in. Another example of a race condition is limit overrun wherein an attacker will try to use a voucher or coupon more than once by applying it multiple times within the period between the verification of the voucher and the moment it is marked as "used".
* **Malicious update** may be an attacker's attempt to convince a user or system to install malicious code by mistaking it to be a legitimate patch. Code signing that is the process of digitally signing code allows developers to confirm the authenticity of the code. As a result, devices are configured to install only trusted patches and updates that were not created or modified with implicit intents. The updates that are not trusted by the system are rejected. 

#### Operating system (OS)-based

#### Web-based
Code injection attacks typically exploit the absence of input validation, allowing an attacker to run code in the web servers from the browser via the component of a website such as a form field. Such attacks succeed due to absence of input validation and direct concatenation of the input within the code base that causes the server to run it as part of the search instruction. 

##### Structured Query Language Injection (SQLi)
* Attacker injects malicious SQL code into an input field to manipulate a program into executing unintended database queries. 
* Unauthorized access to sensitive data, such as user credentials or personal records. 
* **Classic SQLi**: application executes SQL query, and expected results are displayed on the screen.
* **Blind SQLi**: application executes the malicious SQL query, but the results are not directly visible to the attacker due to the page's formatting or security measures.
    * *Content-based Blind SQLi*: The attacker modifies the query to return no records and if the site behaves as expected then it is vulnerable to SQLi. 
    * *Timing-based Blind SQLi*: The attacker injects SQL code that introduces a delay in the database response. If the application takes noticeably longer to display results, the site is vulnerable. 
* Mitigation techniques include prepared statements, input validation, and proper database access controls.

##### Cross-site scripting (XSS)
* Cross-site scripting is the injection of HTML code using a form field. 
* **Reflected XSS**: attacker can enter data into an input field along with a sophisticated script that is executed once in the browser after clicking Submit. 
* **Stored/Persistent XSS**: malicious script is stored in the server to be executed even when the attacker is not waging the attack. For instance, say a social media web application allows users to use HTML code to create posts. In the absence of secure input validation, an attacker can include a script in the post that is executed in all the browsers where it is viewed. 

#### Hardware
* **Firmware** is embedded software code that facilitates operation of hardware devices, allowing them to smoothly communicate with other devices and software. Firmware attacks can occur through any path that provides access to the firmware such as using executable updates or via the network. Firmware validation is the key to mitigating firmware attacks including various methods such as secure boot, measured boot, and trusted boot. Secure boot verifies the components of the boot process to ensure all of them are trusted by the original equipment manufacturer. Measured boot on the other hand, records the measurement of each component and stores it into the trusted platform module (TPM) for remote validation. Windows uses the trusted boot process that ensures integrity of the components involved in the boot process.
* **End-of-life** of a product occurs when the equipment or device is no longer sold but vendors still provide temporary support for the units in use until they are replaced by up-to-date products. After a certain period, the products reach end-of-support when the vendor stops providing support. 
* **Legacy hardware, software, or devices** are those that are no longer supported and should ideally be replaced within organizations.

#### Virtualization
* **Virtual machine (VM) escape attack** occurs when an attack successfully forces the operating system within a virtual machine to start communicating directly with the hypervisor thereby allowing the attacker to access resources allocated to other VMs on the host. This usually occurs in infrastructure as a service environment.
* **Resource reuse** occurs when attackers reassign a resource such as memory location reserved to be used by one customer to be used by another customer instead. 

#### Cloud-specific
Cloud applications heavily rely on the use of Application programming interfaces (APIs) to facilitate communication and interoperability. In addition to analysing code for potential vulnerabilities or insecure coding practices, web application firewalls are configured to ensure security of APIs through inspection mechanisms. Secure web gateways are also used as an additional layer of security to review web requests and block potentially malicious attempts.

#### Supply chain
* Provider can be an individual, business or company that outsource products such as hardware devices or software applications or services like consulting, legal, marketing, or real estate. 
* **Service provider**: Attacker may infiltrate a service provider with a malicious intent against the organization. For instance, attackers may pose as a set of advocates hired to fight a lawsuit filed against the company and intentionally lose the case causing high rate of loss to the organization.
* **Hardware provider**: An attacker may tamper with a hardware device being outsourced to other companies. They may insert backdoors that give them control of the device the moment the customer configures the hardware. 
* **Software provider**: An attacker may target the software being provisioned to organizations by external companies and inserting malicious code before it is released or manipulating it into downloading malicious scripts through fake patches or updates.

#### Cryptographic
Cryptographic vulnerabilities refer to the weaknesses in the design and/or implementation of cryptographic algorithms or protocols. These may include low key sizes, use of outdated cryptographic protocols and insecure storage and/or communication of cryptographic keys.

#### Misconfiguration
A misconfiguration vulnerability occurs when there is a security issue in the device that allows the attacker to gain access to the device and control it. This may occur intentionally or unintentionally that is due to human error. For instance, an employee might have forgotten to update a system with a security patch.

#### Mobile device
* **Side loading** involves the installation of applications or transferring of files into a mobile device that are not from the official source.
* **Jailbreaking** occurs when an attacker conducts privilege escalation to gain administrator access and perform tasks such as installing applications that would otherwise be untrusted, changing settings or options or installing custom elements of the operating system.

#### Zero-day
Zero-day attacks are associated with vulnerabilities that are unknown to the vendors and hence, cannot be patched in time. The term "Zero-day" is derived from the fact that developers do not have any time to patch the vulnerability after it is known as it has already been exploited by an attacker.

### Indicators of malicious activity
#### Malware attacks
* **Ransomware** 
    * Takes over a device and demands ransom. 
    * For instance, crypto malware encrypts all the data on a system and demands a ransom for the decryption key. 
    * Other ransomware methods involve threatening to report the target to law enforcement due to pirated software that was injected into their device or to publicise sensitive information on their system. Ransomware is typically delivered through phishing campaigns but can also use direct attack mechanisms like remote desktop protocol that if compromised, allows the attacker to themselves install the ransomware on to the target system. Indicators of compromise for ransomware include command and control traffic, use of legitimate tools in abnormal or suspicious ways, lateral movement processes, encryption of files, notices demanding ransom and data exfiltration behaviors. Having a secure backup of all the data is an effective counter to ransomware attacks.
* **Trojan** is a type of malware that disguises itself as legitimate software but is intended for malicious tasks running in the background. Indicators of compromise for trojans include signatures, command and control and folders or files created on target devices. Remote access trojans (RATs) provide attackers with remote control to target systems. These might be challenging to detect.
* **Worm** is a program that self-installs, replicates itself and spreads across a network of systems. Stuxnet and Raspberry Robin are popular examples. Indicators of compromise include known malicious files, downloads of additional components from remote systems, command and control, malicious behaviors, and hands-on-keyboard attacker activity. Firewalls, IPSs, network segmentation, patching and configuring services help prevent worm-based attacks. In the case of successful infection, tools such as EDR and antimalware help respond to the attacks. 
* **Spyware** is software that is used to keep an eye on the target's actions. For instance, a use one's laptop camera to stalk their actions and day-to-day activities for illicit purposes. The use of spyware can be linked to various motives such as credential stealing, identity theft and fraud and illicitly monitor a partner in a relationship. Antimalware tools and user awareness help prevent or mitigate these attacks. Indicators of compromise include remote-access and remote-control-related indicators, known software file fingerprints, malicious processes, and injection attacks.
* **Bloatware** refers to unnecessary and unwanted applications installed on a device. While bloatware is typically not intentionally malicious, it adds an attack surface to otherwise secure devices as it may contain vulnerabilities. It should thus be removed to prevent potential issues. 
* **Virus**, in contrast to a worm, is a program that requires human intervention by copying to a USB or network share for example, to be installed and spread across a network. Viruses have two components: trigger and payload. Trigger refers to the conditions that cause the virus to execute and payload is the actions performed by the virus when triggered. Indicators of compromise for viruses are noted in threat feeds such as Virus Total that are made public for reference. These threat feeds include information such as behaviors and analyses associated with known viruses.
* **Keyloggers** are programs that keep track of a user's keyboard input to be analysed and used by an attacker. These tools can also capture user's mouse movements, touchscreen inputs, or credit card swipes. Many keyloggers are used to acquire user credentials or identity information that they can use to their advantage. Use of multifactor authentication can help mitigate the impact of a keylogger as passwords would not be enough to be able to log into your accounts. Indicators of compromise include file hashes and signatures, data exfiltration, process names and known reference URLs. 
* **Logic bomb** is a function or piece of code that executes as soon as a condition is met. Logic bombs are rare and difficult to detect as they are embedded in code and can be located by analysing the source code or logic in the application.
* **Rootkits** are programs that provide attackers with remote system access. These are challenging to detect and remove. Indicators of compromise used for detection include file hashes and signatures, command and control, behavior-based identification and opening ports or reverse proxy tunnels. Once a system is infected with the rootkit, the best way to ensure removal is to rebuild the system or restore it from a reliable backup. 

#### Physical attacks
* **Brute force attacks** involve barging into an organizations facility such as by breaking down a door or cutting off a lock.
* **Radio frequency identification (RFID) cloning** is commonly used to duplicate access cards and gain unauthorized access into an organization's premises. These attacks can be challenging to detect as they involve the creation of a legitimate looking access card providing the attacker with the ability to remain unsuspected. 
* **Environmental attacks** include those wherein an attacker targets the heating or cooling system of an organization to cause overheating in a data center or intentionally activates the water sprinklers to cause harm to systems. 

#### Network attacks
* **Distributed denial of service (DDoS) attacks** occur when attackers use multiple compromised devices or systems to overwhelm a target with large amounts of traffic that causes the target to crash thereby affecting availability to legitimate users.
    * Amplified DDoS takes advantage of a small request resulting in a large response. In this attack, the attacker's systems send multiple requests to a server such as a DNS server causing amplified responses for each request to be directed to the target system. 
    * Reflected DDoS allows the attacker to spoof the victim's IP address thereby making the original source of the packets more challenging to detect and directing all traffic to the target system.
* **Domain name system (DNS) attacks**
    * Domain hijacking occurs when an attacker gains access to the registration of a domain and can alter configurations in a way that gives them the ability to intercept communication or send/receive emails. This attack may be challenging to detect on the client-side, but domain owners can leverage security tools to help prevent or identify such attacks.
    * DNS poisoning attacks involve corrupting the DNS cache system by adding a malicious DNS entry that directs the user to a fraudulent site when they try to access a legitimate domain. This attack can also be carried out using on-path attacks wherein the attacker impersonates a DNS server replying to DNS requests sent by the target.
    * Domain Name System Security Extensions (DNSSEC) is a security feature that is used for authenticating messages sent by the DNS servers thereby preventing DNS poisoning attacks.
    * URL redirection is conducted altering the host file that is the file which is checked first when accessing a site via DNS. The attacker updates the file to associate a legitimate URL to a fraudulent site that can be used to obtain credentials of the user or other malicious intents.
* Wireless
* **On-path attacks** also known as man-in-the-middle attacks occur when an attacker intercepts communication between two systems. The attacker may do this to just eavesdrop on the communication or modify the data in transit. 
    * SSL stripping attack occurs when the client sends an HTTP request to a site. The attacker intercepts this request and modifies the request to have all response traffic redirected to their system instead of sending it to the client. 
    * HTTP strict transport security (HSTS) helps prevent SSL stripping attacks by enforcing only HTTPS connections using TLS. However, this feature only works after the client has visited the site at least once.
    * Browser plug-ins also protect against such attacks.
    * Browser-based on-path attacks formerly known as Man in the browser attack is conducted using a Trojan installed into the client browser that allows the attacker to gain access to the information sent and received by the browser.
* **Credential replay** is reusing the user credentials to gain access to their account. This attack can be conducted by resending authentication hashes. The use of session IDs and encryption help prevent such attacks.
* **Malicious code** such as worms, viruses, trojans and ransomware can spread across a network to affect multiple systems until it is detected and removed. Indicators of compromise include signatures that IDS and IPS systems can detect.

#### Application attacks
* Injection 
* Buffer overflow
* Replay
* Privilege escalation
* Forgery
* Directory traversal attacks occur when attackers can navigate through the directory paths on web servers accessing sensitive files such as system configuration files or password files. 

#### Cryptography attacks
* **Downgrade attack** is an attempt to manipulate the target into using a less secure cryptographic scheme that compromises the confidentiality and integrity of the data being transmitted or stored. 
* **Collision attack** occurs when a hashing algorithm gives the same output for two different inputs. 
* **Birthday attack** is based on the birthday theorem that asks for the probability of two people among a group of people sharing the same birthday. This is related to the probability of a collision which need not be 100% but should be high enough to reduce the number of brute-force attempts needed.

#### Password attacks
* **Spraying attack** is a type of brute-force attack wherein an attacker tries a set of passwords on multiple accounts to find a match. This is to prevent account lockout that might notify the system administrators of potential attack attempts.
* **Brute force attacks** occur when attackers try a diverse set of generated passwords to login to a user account. Once they find a match, they obtain the credentials of the target. 

#### Indicators
* Threat hunters are responsible for identifying and analysing cyberattacks. 
* To achieve this objective, threat hunters use behaviors called indicators of compromise which are associated with malicious attempts to compromise a system or user. 
* **Account lockout** occurs after a certain number of unsuccessful logins attempts to protect the user account from brute-force attacks.
* **Concurrent session usage** when the user's account is logged in from multiple devices that are not in the same location, or the application is not commonly used on two devices at once. 
* **Blocked content** is that which is filtered out by an ID/PS or DLP system that indicates malicious attempts to insert malicious code or exfiltrate data.
* **Impossible travel** based on the timestamps of login into an account from multiple locations that a user cannot travel to within the period between the connection attempts. 
* **Resource consumption** exceeding the norm indicates filling of a disk or high use of bandwidth that needs to be further investigated to ensure it does not indicate an attack like DDoS.
* **Resource inaccessibility** to legitimate users can hint to something unexpected such as a denial-of-service attack or another malicious attempt.
* **Out-of-cycle logging** is when an event occurs at an unexpected or unusual time. For example, an employee logging in at 2am when they usually login between 9-5.
* **Published/documented content** that is confidential to the organization but now available for public access. Indicates potential data exfiltration and insider threat or unauthorized access to sensitive information.
* **Missing logs** indicate an attacker trying to cover up their tracks by erasing any hints. These should be investigated further to make a conclusion. 

### Mitigation techniques used to secure the enterprise
#### Segmentation
Segmentation is using security, network, and physical boundaries to separate critical or infected systems into different zones or segments to reduce impact of a security incident. This can also be done in cloud or virtual environments.

#### Access control
* Access control list (ACL) is a set of rules that denies or allows actions based on the source IP address, service, time, etc. 
* For network devices, ACL rules are like firewall rules. 
* Permissions are assigned to each user based on various attributes such as their role and current location. 

#### Application allow list
Also referred to as whitelisting specifies the applications, software and other system components that can be installed on a system.

#### Isolation
Isolation is the process of moving systems or applications to a secure space or network where it is protected from the impact of a security incident. It may involve taking a system off the primary network, using security rules in case of cloud environments or separating a VLAN.

#### Patching
Patches, in the context of security, refer to fixes that are deployed when a vulnerability or weakness is found in a product such as an application, operating system or hardware device. The process of applying these fixes to the product is called patching.

#### Encryption
Encryption ensures data confidentiality in the case of a successful security breach. If the attacker gains access to sensitive data, encryption ensures that they are not able to read the data and hence, misuse it. Encryption should be implemented in all three states: data at rest (stored data), data in motion (data being transmitted) and data in use (data being processed). 

#### Monitoring
* **System monitoring** is done using system logs and central management systems to keep track of system health and performance.
* **Application monitoring** includes application logs, application management interfaces and performance monitoring tools. It varies for each application depending on its purpose.
* **Infrastructure monitoring** uses Simple network management protocol (SNMP) and syslog to keep track of infrastructure components like communication networks and data centers.

#### Least privilege
* Ensures that subjects are given access to only those resources that they need to perform their activities or job functions. 
* *Privilege creep* occurs when an employee moves from one position to another and is granted new permissions accordingly, but the access granted based on the previous role are not revoked.

#### Configuration enforcement
* Process of monitoring and modifying the security settings on systems across the organization to prevent security breaches or cyberattacks.
* Done by security professionals and system administrators 
* Using configuration management tools such as JamfPro for macOS, Configuration Manager for Windows or CFEngine
* Consists of three phases 
    * *Establishing a baseline* using existing industry standards like CIS benchmarks that are modified based on organization specific goals and requirements.
    * *Deploying the baseline* using central management tools.
    * *Maintaining the baseline* using central management tools and performing regular assessments to ensure configuration enforcement as well as adjusting where needed.

#### Decommissioning
* Process followed when a product reaches its end of useful life cycle.
* Involves removing a device or system from service, removing it from inventory, and ensuring that no sensitive data remains on the device before it is discarded.
* Protects the data from dumpster diving attempts wherein attackers seek sensitive information from discarded physical or digital materials.
* Explained in further detail in the next chapter.

#### Hardening techniques
* **Encryption** ensures confidentiality of the data in the case of a successful security incident as it renders the data unreadable to an attacker unless they have the decryption key.
* **Installation of endpoint protection** to detect the presence of malware or alert in case of any potentially malicious behavior. 
* **Host-based firewall** is a software works on a singular system to examine incoming and outgoing traffic. It alerts and/or blocks any suspicious communication such as malware or communications that may indicate an attack attempt.
* **Host-based intrusion prevention system (HIPS)** is also a system-specific solution and is aimed at blocking intrusion attempts. 
* **Disabling ports/protocols** that are not in use also reduces the attack surface as well as monitoring requirements. It also ensures that no insecure services are enabled on the system allowing an attacker easy access.
* **Default password changes** should be one of the first steps when configuring a new product as default passwords are published on the internet and can be easily accessed by attackers. Vulnerability scanners typically flag the use of default passwords.
* **Removal of unnecessary software** reduces the attack surface by ensuring that only required products are kept on the systems. Organizations usually build their own system images that are installed on new systems to exclude all unnecessary software.
