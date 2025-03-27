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

---

## Sequence Diagram
- **Login and Login with MFA flows**
![image](https://github.com/user-attachments/assets/2429d394-e296-4a6e-8cf2-99a04d3afed3)
- **Disavow login request flow**
![image](https://github.com/user-attachments/assets/10060165-f59b-43d1-b9c7-692050767ed6)

## Database schema
![image](https://github.com/user-attachments/assets/edeae327-0a77-4fde-bc66-8de480d06b8a)

## Solutions:
- **API Service**:
  - We have 5 main groups API:
    - Login (1): **/auth/login**, we can login with basic auth (username/password). Or system will request you login with MFA, then system returns reference_id to help system identify you in the next requests.
    - Send Verification Code (2): **/auth/send-login-email-code**, **/auth/send-login-phone-code**, If you are requested MFA Login, you must call these apis (with **reference_id**) to get **verification_code**
    - Verify code (3): When you receive code from SMS/Email, you must call one of apis **/auth/verify-login-email-code**, **/auth/verify-login-email-code** (with **reference_id**) to verify code. After verify successfully, system returns a **private key**
    - Login with MFA (4): When you receive **private_key**, you must call api **/auth/login-with-mfa** (with **reference_id** and **private_key**), system will verify and generate token.
    - Diasow (5): When you receive message from **/hacked/disavow** from (2), you also receive a link to let you report to us if the login attempt was not initiated by yours. 
- **Risk Assessment**
  - System gets analysis from table user_login_logs to calculate risk score. 
  - Improvement: Apply AI to caculate risk score.

## Technologies:
- **Golang**: Main programming language for this project
- **Docker**: Build contianer of project
- **Postgres**: Save/Get data
- **Prometheus**: Display metrics
- **Libraries**:
  - bcrypt: create hashed pasword
  - prometheus: send metrics
  - redis: interact with redis
  - database/sql: interact with database

## Contributions:
- **MFA System**: A system to handle user login with MFA (rely on risk assesstment module)
- **Custom HTTP Server**: Custom HTTP Server that reduce boilerplate code likes (covert request body to struct, handle response error, write response header, write response body). Now engineer only need declare request, response structs and focus handle business code.
- **Log tracking**: A log mechaism to help trace logs over services/ layers with **request_id** when user get an error.


