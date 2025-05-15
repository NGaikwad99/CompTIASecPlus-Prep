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
