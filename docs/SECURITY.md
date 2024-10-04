# Security considerations

### Description

Bonfire is a secure service that allows automated command line inspection
as well as prevention of various kinds of attacks commited through the
command line. This is achieved using SoTA LLM queries whereby the LLM decides
about the harmfulness of the user based on factors such as the command and the
expectations.

### Requirement analysis

> Server

* Compatibility with API standards
* gRPC for secure communication
* Disable gRPC reflection for improved security
* E2E TLS encryption between server and client
* Defense against injection attacks
* Configurability
* Logging for non-repudiation
* Origin authentication

> Client

* gRPC for secure communication
* E2E TLS encryption between client and server
* Compile time configurability to avoid spoofing addresses
* Embedded shell environment to restrict spoofing of executable
* Origin authentication
* Implement Fail Open / Fail Closed strategy

### Acceptance testing

* Solves the problem of command line attacks
* Has issues due to limitations in LLMs
* Costs time and efficiency
* Slow, but works

### System design

* Using rust for memory safety
* Using tonic for grpc connection with reflection disabled
* Using serde_json for configurability
* Using tracing for logging
* using tokio for asynchronous task execution
* Using llamafile for increased portability, swappability and grammar based constraints

### System testing

* The rust ecosystem is well known for its security making it a good choice for a security related project

### Architecture design

* Simple client-server grpc connection
* Stateless completions from the LLM http server
* The core logic is in the server
* Modular architecture

### Architecture testing

* Parameters can be altered or spoofed if a malicious actor authenticates successfully
* DOS attack possible using a different username
* Username collisions can happen

### Module design

* gRPC server & client module
* Github API module
* LLamafile module
*

---
Spoofing uuid -> DDOS
