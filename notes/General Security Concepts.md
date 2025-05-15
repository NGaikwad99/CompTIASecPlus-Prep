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
        