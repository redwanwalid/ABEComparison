# SPARQL Performance Evaluation for Health Recording Systems with Attribute-Based Encryption

## Overview

This repository hosts the source code for evaluating the SPARQL performance of electronic health recording systems. The systems are implemented with three distinct Attribute-Based Encryption (ABE) schemes: Ciphertext Policy ABE (CP-ABE), Key Policy ABE (KP-ABE), and Multi Authority ABE (MA-ABE).

## Dataset

The evaluation leverages the MIMIC-III dataset, a comprehensive collection of health records, to generate synthetic data with varying record sizes. This diverse dataset facilitates a thorough examination of the system's performance under different scenarios.

## Encryption Schemes

### Ciphertext Policy ABE (CP-ABE)

This scheme grants access based on policies defined over attributes associated with users and data.

### Key Policy ABE (KP-ABE)

Access in KP-ABE is determined by a user's attributes matching the access policy embedded in the encrypted data.

### Multi Authority ABE (MA-ABE)

MA-ABE extends ABE to support multiple authorities, enabling more flexible access control in a distributed environment.

### Contribution Matters
Feel free to contribute, report issues, or provide feedback. We welcome collaboration to enhance and extend the capabilities of health recording systems with secure attribute-based encryption.
