# Certificate Authority System Implementation

This code implements a Certificate Authority (CA) system for issuing and managing digital certificates, including secure key management, certificate signing, validation, and revocation. It also demonstrates a basic secure message exchange using hybrid encryption.

## Key Features

* **Certificate Management:**
    * Issuance of new certificates for entities.
    * Validation of certificates against the CA's root certificate.
    * Revocation of certificates with timestamps and reasons.
    * Secure storage of certificates and keys.
* **Key Management:**
    * Generation of RSA and ECC key pairs.
    * Secure storage of private keys with optional password protection.
    * Handling of key usage restrictions (e.g., digital signature, key encipherment).
* **Secure Message Exchange:**
    * Hybrid encryption using asymmetric (for session key) and symmetric (for message) encryption.
    * Secure message exchange between entities using their certificates.
* **CRL (Certificate Revocation List) Management:**
    * Maintenance of a list of revoked certificates.
    * Efficient revocation checks during certificate validation.

## Code Structure

* **Configuration:**
    * Logging setup for recording events.
    * Definition of constants (directories, key sizes, supported algorithms).
    * Creation of directories with appropriate permissions.
* **Data Structures:**
    * `Certificate` class: Represents a digital certificate with attributes like serial number, subject, public key, issuer, expiration date, signature, and extensions.
    * `CRL` class: Represents the Certificate Revocation List with methods for revocation, checking revocation status, and loading/saving the CRL.
    * `CertificateAuthority` class: Encapsulates CA functionalities, including key generation, certificate signing, verification, issuance, and revocation.
* **Flask Server Implementation:**
    * Creation of a Flask application instance.
    * Implementation of API endpoints for certificate issuance, validation, and revocation.
    * Rate limiting to prevent abuse of the API.
* **Secure Message Exchange:**
    * `SecureMessageExchange` class for handling secure message encryption and decryption using hybrid encryption.

## Demonstration

The code includes a `main()` function that demonstrates the following:

1. **Issuance of certificates for Alice and Bob.**
2. **Validation of issued certificates.**
3. **Secure message exchange between Alice and Bob.**
4. **Revocation of Alice's certificate.**
5. **Validation of the revoked certificate.**
