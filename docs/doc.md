# Adaptive MFA Login

## Introduction

Multi-Factor Authentication (MFA) is a widely adopted security mechanism for protecting web applications and user identities. It adds an additional layer of verification to prevent unauthorized access—even in cases where attackers have obtained valid credentials. However, traditional MFA can introduce unnecessary friction for legitimate users.

This repository provides a self-contained implementation of an **Adaptive Multi-Factor Authentication (MFA)** system, which intelligently assesses login risk and dynamically determines whether additional verification is necessary.

By analyzing contextual signals such as:

- IP address  
- Device fingerprint  
- User-agent  

the system evaluates the risk level associated with each login attempt.

Based on this assessment, users may be prompted for secondary authentication via configurable methods, including:

- **OTP via Email or SMS**
- **TOTP** using authenticator apps such as **Google Authenticator** or **Authy**

The goal is to maintain a strong security posture while minimizing disruption to trusted users.

---

## C4 Diagram

![Adaptive MFA System Diagram](https://github.com/user-attachments/assets/4013a95b-6bae-4437-b2fe-0e1b992936a0)

### System Modules

- **Adaptive MFA System**  
  Acts as the entry point for user requests and coordinates the login flow.

- **Authentication Module**  
  Validates user credentials and interfaces with the Risk Assessment Module to determine whether MFA is required.

- **Risk Assessment Module**  
  Calculates a risk score based on contextual data and determines the need for MFA enforcement.

- **MFA Module**  
  Handles the generation, delivery, and verification of MFA codes (via email, SMS, or TOTP).

- **Database**  
  Stores user profiles, login history, and MFA configuration data.
