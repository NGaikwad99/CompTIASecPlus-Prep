# CompTIA Security+ Exam Notes SY0-701
This document is formatted based on the Exam Objectives provided by CompTIA. The content is written by referring to CompTIA Security+ Study Guide as well as various other sources. The document should be used as a reference for preparing for the Security+ exam. Please make sure to use additional sources.

## General Security Concepts
### Security controls
#### Categories 
* **Technical** controls are those implemented by the system. Examples include Firewalls, intrusion prevention/detection systems, jump servers, multi-factor authentication, backups, encryption, and anti-virus software.
* **Managerial** controls are policies and procedures used to manage the systems. Examples include risk assessments, security planning exercises, disaster recovery plans, incident response schemes, and contingency planning.
* **Operational** controls include the processes conducted by people periodically or regularly to manage the technology put in place. Examples include user accounting, log monitoring, awareness training, asset classification and vulnerability management.
* **Physical** controls are those that are focused on protecting the infrastructure and physical assets of the organization. Examples include security guards, bollards, and lighting.

#### Control Types
* **Preventive** controls reduce the possibility of a security issue or attack. Examples include firewalls, intrusion prevention systems and anti-virus software.
* **Deterrent** controls discourage attackers from attempting a security breach. Examples include warning signs, barbed wire fences and video surveillance.
* **Compensating** controls serve as an alternative in case a primary control cannot be implemented, typically in the case of an exception from a security policy. For instance, isolating a system that contains an outdated application, or operating system is required to run the business. This system should soon be replaced, but compensating controls serves as a temporary workaround.
* **Detective** controls seek to identify evidence of potential security breaches or issues. Examples include intrusion detection systems and reviewing log files.
* **Corrective** controls aim to restore operations after a security event or disaster has occurred. For instance, launching backup systems in case of a ransomware attack.
* **Directive** controls provide information for employees and organizations to help achieve their security goals. Examples include policies and procedures, laws and regulations, guidelines, and training seminars.

### Fundamental security concepts
#### CIA Triad and non-repudiation
* **Confidentiality** focuses on ensuring only authorized access to sensitive information. Various controls, such as encryption, hashing, and data obfuscation, can be used to implement confidentiality.
* **Integrity** focuses on ensuring authorized modifications to sensitive files, configurations, etc. Hashing is commonly used to check whether data has been tampered with or corrupted.
* **Availability** focuses on ensuring that systems are accessible to users and employees when needed. Fault tolerance mechanisms, DDoS protection, backups, business continuity plans, etc., are examples of controls used to enhance the availability of systems.
* **Non-repudiation** ensures that a certain action cannot be denied. Digital signatures (hashing + public key cryptography) are used to achieve non-repudiation. Although this is not part of the CIA Triad, it is one of the fundamental security principles that should be taken into consideration when implementing controls.

#### DAD Triad
* **Denial** is the violation of availability wherein legitimate users cannot access an application or system. For instance, employees cannot access their systems due to a denial-of-service attack.
* **Alteration** is the violation of integrity wherein data is subject to unauthorized changes.
* **Disclosure** is the violation of confidentiality because of which an unauthorized user gains access to sensitive information such as user credentials. 

#### AAA framework
* **Authentication** identifies the user based on their credentials typically username and password. Might also include other factors such as biometrics or OTPs that are used to implement multi-factor authentication (MFA).
* **Authorization** provides the user with access based on their roles and responsibilities. This follows the principle of least privilege to ensure that individuals are given access to only those resources that are essential for them to perform their day-to-day activities.
* **Accounting** keeps track of user activities such as logins and data modifications. These logs are monitored by automated systems and may be subject to further investigation in case of a flagged security incident. Administrators may also check the logs manually to ensure all is well.

#### Gap analysis
* Assessing difference between the current security posture of an organization and its desired security objective. 
* Gap occurs when the implemented control does not meet the control objectives. 
* Gaps must be treated as risks and remediated when possible based on the availability of resources and its severity. 

#### Zero Trust
* **Control plane**
    * *Adaptive identity*, also known as Adaptive authentication, relies on identifying the user using context-based authentication that is based on various attributes such as location, device being used and whether it meets security requirements.
    * *Threat scope reduction*, sometimes referred to as limiting blast radius, is used to manage the possibility of security mishaps by providing only the necessary access to users. This is done using the principle of least privilege and identity-based network segmentation.
    * *Policy Engine* facilitates policy-driven access control by allowing or denying access based on certain policies. 
    * *Policy Administrator* executes the decisions made by the policy engine.
    * *Policy Decision Point* comprises the Policy Engine and Policy Administrator.
* **Data plane**
    * *Policy Enforcement Point* delegates user information to the policy decision point to ensure policy-drive access control.
    * *Subject/system* is the device or individual requesting access to a resource.
    * *Implicit trust zones* are areas wherein a user can freely move after being authenticated by zero trust policy engine.

#### Physical security
* **Bollards** prevent vehicles from ramming into doors or buildings or entering restricted areas.
* **Fencing** surrounds restricted areas to discourage trespassers from entering.
* **Lighting** helps keep a building illuminated and hence visible from the outside which discourages attempts of breaching the property.
* **Sensors** usually serve as detective measures to trigger an alarm if needed.
    * Infrared
    * Ultrasonic
    * Pressure
    * Microwave
* **Video surveillance** records all events in the surrounding for investigation in the future in case an incident occurs. Generates a large amount of data which must be stored securely and easily accessible when needed.
* **Access control vestibule** is a pair of doors that help prevent tailgating. Both doors can be opened one after the other only by authorized individuals. 
* **Access badges** use magnetic strip and radio frequency ID (RFID) technology to secure access into restricted areas. These badges may also highlight information about the individual such as name and role, which allows others to identify whether the subject is an employee or guest. The badges are typically used with proximity readers that allow users to gain access by tapping the card instead of inserting or swiping it.
* **Security guards** provide human intervention and are strategically placed in communal areas such as near entrances to be able to make decisions and detect and respond to any incidents.

#### Deception and disruption technology
* Intentionally placed to attract attackers and observe their movement.
* Typically contain false sensitive information and are highly monitored to ensure that all the activities of an attacker in relation to these components is tracked and noted.
* **Honeypots** are systems that are intentionally configured to appear vulnerable thereby tempting the attacker to attempt an intrusion. 
* **Honeynets** are networks that encourage attackers to attempt network intrusions. 
* **Honey files** contain false sensitive information such as credentials that will attract an attacker. The contents of these files are constantly searched for on the internet and when found, administrators know that someone fell for the trap.
* **Honeytokens** are sensitive data intentionally included in a database, file, directory, or other data assets to provoke attackers. Intrusion detection and prevention system as well as data loss prevention systems are configured to look for this information and trigger an alarm when found in transit. 

### Importance and impact of change management processes
#### Business processes impacting security operation
* **Approval process** ensures that every change is subject to additional review and security impact analysis to assess the risks associated with the change. Peer review and review from stakeholders as well as in some cases, members of the board ensures that all changes are documented, and everyone is aware of the modifications and/or advancements taking place in the organization. The approval process consists of six steps:
    * *Request the change*: Once the requirements are identified, a change request is submitted using the internal systems available for this purpose. It might be through a website to be able to track the change throughout the process. 
    * *Review the change*: The change is then subject to impact analysis with the owners and stakeholders. Stakeholders may take the decision some cases while in other cases, the change advisory board may be responsible for formal change review. Board members review the change request.
    * *Accept/reject the change*: The change is then subject to approval based on the review that is clearly documented and submitted. In some cases, the board may require the creation of a backout plan that will be followed in case the change does not go as planned and systems need to revert to prior state.
    * *Evaluate the change*: Once approved, the change is then evaluated first on a non-production server to ensure it is working as expected and will not disrupt any of the current operations. 
    * *Schedule and implement the change*: Provided the test is successful, the change is deployed to production servers typically during maintenance window or non-peak hours to minimize impact in case the change causes disruption or downtime. If the change results in problem, the backout plan formulated during prior stages of this process are adapted to restore operations.
    * *Document the change*: Information about the change and its deployment is clearly documented for future reference. This involves editing the configuration management documentation that is used in case the system needs to be rebuilt. 
* **Ownership** is essential for accountability and to provide a first point of contact in case a change results in unforeseen situations or for additional information in the future.
* **Stakeholders** include individuals that hold interest (mostly, financial) in the organization. They can be divided into five groups - employees, investors, suppliers and vendors, customers, and communities.
* **Impact analysis** helps assess the effect of the change on the ongoing operations in terms of security, customer satisfaction and working. This involves discussions with multiple individuals across the organization including owners, stakeholders, and board members.
* **Test results** are reviewed to ensure that the change is working as expected in non-production environments before being deployed. This helps reduce the risk of any unforeseen errors or disruptions resulting from the change. 
* **Backout plan** is essential for every change to ensure that there is a procedure that can be followed in case the system needs to be reverted to the state it was at before the change was deployed. The backout plan should allow smooth and timely restoration of business operations.
* **Maintenance window** is the period during which most changes are deployed. This is set to non-peak hours to reduce impact on customers as well as the business in case the change results in downtime. There is typically an announcement placed on websites or systems to inform customers of the ongoing deployments to ensure there are no surprises.
* **Standard operating procedure** provides instructions for day-to-day functions serving as a reference document for employees across the organization.
* **Emergency change** may be required in some cases. During this time, the deployment of change may occur prior to receiving all the approval. Review and documentation, however, must be conducted as needed to ensure that there is a set of information to be reference in case the change needs to be reverted in the future or systems need to be rebuilt. For instance, a system administrator may need to make changes to the firewall configurations in case of an attack, or a critical vulnerability needs to be patched as soon as possible.

#### Technical implications
* **Allow lists** specify the applications, software, and other system components that users are permitted access to within the network.
* **Deny lists** also known as block lists include the applications, software and other system components that cannot be run or installed within the network. An allow list will provide greater security than a block list as a block list will allow the access to any new applications until they are known and blocked if needed.
* **Restricted activities** ensure the adherence to principle of least privilege. Employees may not be permitted to perform certain activities such as changing system settings, running scripts or sending sensitive data outside the organization. 
* **Downtime** occurs when the system operations are adversely impacted by a change, attack or natural disaster and users can no longer access the resources or a certain feature. It is essential to ensure minimal downtime by having tested procedures put in place to be followed in this case. 
* **Service or application restart** may be required in case of a change to ensure successful deployment. 
* **Legacy applications** include those that are outdated or obsolete and lack vendor support. It is essential to ensure that the change does not involve modifications to any such applications. 
* **Dependencies** must be identified and documented to ensure all information is available for future reference. 

#### Documentation
* Essential to collate information regarding all implemented changes for future reference. 
* Includes the current configuration of systems and is essential when there is a need to revert a change or rebuild a system. 
* Provides details such as the purpose of the change, its owner and an explanation of the modifications applied. 
* Paper documents now replaced with formal and digitized configuration management system. 
* Ensure all documentation is timely updated including diagrams, guidelines, policies, and procedures. 

#### Version control
* Allows tracking of changes and makes rollback a quicker process. 
* Developers and users can access latest versions of software and manage changes throughout the release process. 
* A labelling or numbering system helps differentiate software sets, versions, and configurations. 

### Cryptographic solutions
#### Public key infrastructure (PKI)
Public key infrastructure facilitates communication between two arbitrary systems using asymmetric cryptography, symmetric cryptography, hashing and digital certificates. 
* **Public key** is typically used for encryption of a message. In the case of digital signatures, it is used for decryption of the encrypted hashed message.
* **Private key** is typically used for decryption of a message and thus, need to be stored in a secure location. In the case of digital signatures, it is used for encryption of the hashed message.
* **Key escrow** systems serve as backup for private keys in case a private key is lost, or an employee leaves the organization. These are accessed in the case of an emergency based on a formal key recovery policy that highlights situations in which users are permitted to retrieve keys from the system without the owner's knowledge.

#### Encryption
* Level
    * *Full-disk encryption (FDE)* involves encoding all the data on a hard drive. This only requires initial set up after which it is performed automatically when the system is powered off. If the drive is stolen, the data is unreadable and hence confidentiality is maintained. However, the drive is vulnerable to access when in use currently the data is in plaintext form. 
    * *Partition encryption* focuses on encrypting certain parts of the drive as opposed to all the stored information. This allows flexibility based on data sensitivity and is useful for dual-boot systems.
    * *File encryption* focuses on specific files. This may not be secure but provides great amount of flexibility.
    * *Volume encryption* involves encryption of a certain set of files or folders within a disk or partition. 
    * *Database encryption* focuses on the data contained in a database to protect any sensitive information such as user credentials or healthcare data. Transparent data encryption and column-level encryption are two forms of database encryption that focus on the entire database and specific columns, respectively.
    * *Record-level encryption* allows encoding of specific records or rows in a database.
* **Transport/communication** of information in a secure manner ensures privacy and protection of sensitive data. 
    * Even in the case an attacker gets access to the information being transmitted, encryption ensures that the data is not readable unless they have the decryption key. 
* **Ciphers** are algorithms that are used to encode or decode message. 
* Substitution, transposition, and polyalphabetic ciphers are historical, non-mathematical ciphers that simply scrambled letters to make a secret message unreadable. 
* Based on the amount of data encrypted at a time:
    * Block ciphers such as blowfish, two fish, AES, IDEA and DES operate on chunks of data at a time. 
    * Stream ciphers like Rivest Cipher 4 (RC4) operate on a single character at a time. 
* **Symmetric encryption** involves the use of a single shared key to encrypt messages. Examples include Data encryption standard (DES), Advanced encryption standard (AES), blowfish, two fish, 3DES, and International Data Encryption Algorithm (IDEA). While symmetric key encryption is fast, it can get difficult to implemented as every pair of users would require one shared key for communication using this method. 
* **Asymmetric encryption** solves the primary drawback of symmetric encryption by using a pair of keys called public key and private key wherein the public key is used for encryption whereas the private key is used for decryption. In this case, a user only needs to share the public key with another user to facilitate secure communication. Examples of asymmetric encryption include RSA and Elliptic curve cryptography. However, while more secure in comparison to symmetric key encryption, asymmetric encryption involves a lot more overhead.
* **Key exchange** when sharing secret keys must be done in a very secure manner especially in the case of symmetric key encryption in which encryption and decryption are both done using the same key. One solution given the drawbacks of asymmetric and symmetric encryption is to combine them by using asymmetric encryption for key sharing followed by symmetric encryption with the shared key. 

| Algorithm | Key length (in bits) | Block or Stream | Symmetric or Asymmetric |
|-------------|-------------|-------------|-------------|
| DES | 56 | Block | Symmetric |
| 3DES | 168 | Block | Symmetric |
| AES | 128, 192, or 256 | Block | Symmetric |
| RC4 | 8 to 2048 | Stream | Symmetric |
| RC5 | 0 to 2040 | Block | Symmetric |
| RC6 | 128, 192, 256 up to 2040 | Block | Symmetric |
| Blowfish | 32 to 448 | Block | Symmetric |
| Two fish | 128, 192 or 256 | Block | Symmetric |
| IDEA | 128 | Block | Symmetric |
| RSA | 2,048 to 4,096 | Block | Asymmetric |
| ECC | 256 | n/a | Asymmetric |

#### Tools
* **Trusted platform module (TPM)** is a specialized chip that resides on a PC's motherboard. It is designed to store cryptographic keys used for volume encryption and for facilitating a secure boot process. TPM is primarily used for securing data on a specific computer or device.
* **Hardware security module (HSM)** is a removable hardware unit that much like TPMs is designed to create, store and manage digital keys for digital signatures, authentication, and other cryptographic functions. HSM is used for securing data on a network or system-level.
* **Key management systems** offer centralized storage and management of keys and certificates while enforcing policies. many cloud providers provide KMS as a service for their environments.
* **Secure enclave** helps separate secret information such as cryptographic keys from the main CPU throughout their life cycle. Vendors include Apple, SGX, Google's Titan M and Samsung's Trust Zone and Knox. 

#### Obfuscation
* **Steganography** is the process of embedding sensitive information or secret messages in other media such as images, videos, audio files, etc. 
    * Can be used to hide messages in plain sight as the embedding results in negligible changes to the files. 
    * Has some legitimate uses as well. For instance, steganography can be used for adding digital watermarks to artwork that help identify any duplicates. 
    * Opens Tego is a popular free tool used for steganography. 
* **Tokenization** is used to substitute sensitive information with a randomly picked unique identifier that is stored in a lookup table. The lookup table must be placed in a secure location. 
* **Data masking** replaces a part of sensitive information with symbols. For instance, the first twelve digits of credit card number are replaced with an * on a receipt. 

#### Hashing
* One-way encoding process wherein a hash algorithm is used to convert a message into a fixed-size message digest using a set of mathematical operations. 
* Once hashed, the plaintext cannot be retrieved from its corresponding hash value. 
* Commonly used for storing and validating passwords. 
* Hash algorithm should be collision free that is, two different strings will not generate the same hash value. 
* Examples: Message Digest 5 (MD5) and Secure Hashing Algorithm (SHA) 1 and 2. 
* MD5 is vulnerable to collision attacks and hence, not in use today.

#### Salting
* Adds a randomly generated string to the password prior to hashing. 
* Salting aims to prevent rainbow table attacks on user credentials. 
* In rainbow table attacks, an attacker generates the message digests for commonly used passwords and then tries to find a match in a (stolen) file of hashed passwords. 

#### Digital signatures
* Leverage combination of hashing and public key cryptography to ensure authentication, integrity, and non-repudiation. 
* Suppose Alice wants to send a digitally signed message to Bob. The communication would occur as follows:
    1. Alice obtains the message digest of the message that she wants to send to Bob.
    2. Alice encrypts the message digest with her private key to obtain the digital signature.
    3. Alice attaches this signature to the message and sends it to Bob. At this stage, Alice can encrypt the message with Bob's public key to ensure confidentiality or privacy.
    4. On receiving the message, Bob decrypts the message with his private key to obtain the original message and Alice's digital signature.
    5. Bob decrypts the digital signature using Alice's public key to obtain the message digest.
    6. Bob generates the message digest of the plaintext message.
    7. Bob compares the hash values obtained in steps 5 and 6. If they are a match, Bob knows that the message was not tampered with in transit.
* Commonly used by software vendors to authenticate their products available for download on the internet.

#### Key stretching
* Generate robust keys from passwords by using multiple iterations of salting and hashing.
* Example: Password bases key derivation function v2 (PBKDF2).

#### Blockchain
* Distributed and immutable _open public ledger_ that serves as a resilient solution to tracking of records in a way that they cannot be tampered with or destroyed. 
* Copies of the ledger are distributed among multiple systems to ensure that in case a record is tampered with on one system, an inconsistency will help detect this corruption. 
* With each legitimate transaction, all the copies are updated. 
* Popular application: Cryptocurrency to keep track of Bitcoin transactions among all participants. 
* Also has other use cases such as property ownership records and to track supply chains. 

#### Digital certificates
* Endorsed copy of a public key that is signed by a trusted certificate authority (CA) to ensure authenticity of a server, device, email address, developer, or user. 
    * Version of the X.509 standard
    * Serial number
    * Signature algorithm identifier that is used by the CA to digitally sign the certificate
    * Issuer name that is the name of the CA that verified the certificate
    * Validity period 
    * Subject's common name (CN) that describes the certificate owner
    * Subject alternative names (SANs) [optional] that highlight additional items (domain names, IP addresses) protected by the certificate
    * Wildcard [optional] denoted by an * in the certificate name denotes that the certificate is valid for only one level of subdomains as well.
* **Certificate authority (CA)** 
    * Neutral organization responsible for signing digital certificates after they have verified the identity of the subject. 
    * Major CAs include IdenTrust, Amazon Web Services, GoDaddy, DigiCert Group, GlobalSign, Section/Comodo, and Let Us Encrypt. 
    * Protect their private keys using an offline root CA that safeguards the root certificate called the _root of trust_ used to create a number of *intermediary CAs*. 
    * Intermediary CAs are kept online to verify and sign digital certificates in a process called *certificate chaining*. 
    * Some organizations create internal CAs to create _self-signed certificates_, trusted only within the organization.
* **Certification revocation lists (CRLs)** 
    * Contain all the invalid certificates. 
    * Ensure validity of a certificate by checking if the certificate is included in the list. 
    * Time-consuming process as the list is long and must be downloaded periodically. 
* **Online certificate status protocol (OCSP)**
    * More optimal solution for checking certificate validity. 
    * Servers operated by CAs are contacted by the browser to verify the status of a certificate. 
    * The server responds with good, revoked, or unknown which is used by the browser to determine if the certificate is valid.
* **Certificate stapling** 
    * Another method of verifying the validity of a certificate. 
    * Extension to OSCP that reduces the load on OCSP servers. 
    * Instead of a browser contacting the OCSP server, the web server of the site contacts the OCSP server and attaches the signed and timestamped response to the certificate. When a browser requests to access the site, the certificate is sent along with the stapled OCSP response to check validity. 
    * Stapled certificates commonly have a validity of 24 hours after which the web server must contact the OCSP server again.
* <span style="color: blue">Third-party</span>
* **Certificate signing request (CSR)** 
    * Occurs after the CA has verified the identity of the subject as part of the enrollment process. 
    * The subject provides the CA with their public key in the form of a CSR. 
    * The CA uses this to create a certificate following the X.509 standard. 
    * Two types of certificates depending on the level of identity verification performed by the CA. 
        * *Domain Validation (DV)* certificates are the most common certificates that indicates that the subject has control of the domain name. 
        * *Extended Verification (EV)* certificates involve further assurance that the certificate owner is a legitimate business.

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

## Security Architecture

### Explain the security implications and differences of different architecture models 

#### Monolithic Architecture
* A single-tiered application.
* Vulnerability in one part can compromise the entire system.
* Hard to apply the perfect security.
* Patching one part means affecting the entire system.

#### Microservices Architecture
* Application is broken into independently deployable services.
* Each service may have its own security posture.
* Larger attack surface requires robust API security.
* Isolation between services can reduce impact of a breach.

#### Serverless Architecture
* Code runs in cloud-managed environments
* Developers focus on logic, not infrastructure.
* Less control over the runtime.
* Requires strong IAM policies and API gateways.
* Misconfigurations can expose sensitive data or allow unauthorized access.

#### Service-Oriented Architecture (SOA)
* Uses message-based communication between services.
* Often uses XML/SOAP.
* Requires secure messaging protocols.
* Ensures access control and confidentiality of inter-service communication.


### Secure Processing and Compute Considerations

#### Trusted Execution Environment (TEE)
* Isolated execution environment inside the main processor.
* Protects code and data from external access.

#### Secure Enclave
* System or CPU-level secure zone to isolate sensitive processes.
* Used in mobile (Apple Secure Enclave) and cloud environments.

#### Hardware Security Module (HSM)
* Dedicated physical device for secure key storage.
* Performs cryptographic operations.

#### Edge & Fog Computing
* Data processed closer to source (edge) or intermediate (fog).
* Improves latency but increases physical security risk.
* Devices must be hardened and monitored.

#### Homomorphic Encryption
* Allows computation on encrypted data.
* Data never needs to be decrypted.
* Enables secure data processing in cloud environments.

#### Cryptographic Agility
* Ability to quickly swap out cryptographic algorithms.
* Important for post-quantum transition.
* Use abstraction layers in cryptographic design.

### Embedded and Specialized Systems

#### Embedded Systems
* Purpose-built for specific functions.
* Limited updates and compute capacity.
* Secure coding and physical protection critical.

#### Industrial Control Systems (ICS) / Supervisory Control and Data Acquisition (SCADA)
* Used in industrial automation and critical infrastructure.
* Vulnerable due to legacy protocols.
* Should be segmented and monitored.

#### Internet of Things (IoT) Devices
* Includes sensors, smart cameras, wearables, etc.
* Typically lack robust security.
* Must enforce firmware updates, strong auth, and network segmentation.

#### Medical Devices
* Must protect health data (HIPAA).
* Enforce data integrity and access controls.

#### Vehicles and Drones
* Use real-time embedded systems.
* Must be protected from remote takeover and firmware attacks.

#### Smart Appliances
* Often internet-connected (smart fridges, TVs).
* Can leak data or serve as entry points to home networks.

#### OT/IT Convergence
* OT (Operational Technology) merging with IT increases attack surface.
* Requirement of unified monitoring, patch management, and access control.


### Firmware Security
* Firmware is foundational to hardware operation.
* Should be cryptographically signed.
* Secure boot enforces only trusted firmware is executed.
* Firmware updates must be validated and protected from tampering.

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


## Security Program Management and Oversight

### Explain the importance of policies, procedures, and frameworks

#### Policies
Policies define strategic direction and security expectations. 
Examples:
* **Acceptable Use Policy (AUP)**: Acceptable use of organizational assets
* **Security Policy**: Security expectations across the organization
* **Password Policy**: Password creation and management rules
* **Remote Access Policy**: Secure use of remote connectivity
* **Data Classification Policy**: Categorizing and handling data based on sensitivity

#### Procedures
Tactical, step-by-step instructions for executing policies. Examples:
* User onboarding
* Backup processes
* Incident response workflows

#### Standards and Guidelines
* **Standards**: Mandatory rules (e.g., use AES-256 encryption)
* **Guidelines**: Best practices (recommended but not enforced)


### Describe risk management processes

#### Risk Assessment
1. Identify assets
2. Identify threats/vulnerabilities
3. Assess likelihood and impact
4. Determine overall risk (e.g., Risk = Likelihood x Impact)

#### Risk Responses
* **Avoidance**: Eliminate risk by changing plans
* **Transference**: Use third parties (e.g., insurance)
* **Mitigation**: Reduce likelihood/impact
* **Acceptance**: Acknowledge and tolerate the risk

#### Risk Register
Track identified risks, severity, and controls.


### Security Awareness and Training
* **Phishing simulations**: Train against email scams
* **Role-based training**: Job-specific security content
* **Policy reviews**: Ensure policy comprehension
* **Ongoing education**: Address evolving threats


### Auditing and Monitoring
* **Auditing**: Periodic checks for policy compliance (internal/external)
* **Monitoring**: Continuous log and alert surveillance for threats


### Compliance Requirements
* **Regulations**: Mandatory (e.g., GDPR, HIPAA)
* **Standards**: Voluntary best practices (e.g., ISO 27001, NIST)
* **Audits**: Validate compliance controls and enforcement


### Benchmarks and Frameworks
* **CIS Controls**: Prioritized security actions
* **NIST CSF**: Identify, Protect, Detect, Respond, Recover
* **ISO/IEC 27001**: ISMS framework
* **COBIT**: IT governance and management


### Business Continuity and Disaster Recovery

#### BCP (Business Continuity Plan)
* Keep operations running during disruption

#### DRP (Disaster Recovery Plan)
* Restore IT systems after an outage

#### Metrics
* **RTO (Recovery Time Objective) **: Max acceptable downtime
* **RPO (Recovery Point Objective) **: Max acceptable data loss

#### Testing Methods
* **Tabletop exercise**: Scenario discussion
* **Simulation**: Test response mechanisms
* **Full-interruption test**: Complete shutdown (rare)
