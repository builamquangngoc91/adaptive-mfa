# Adaptive MFA Login

## Introduction

Multi-Factor Authentication (MFA) is a widely adopted security mechanism for protecting web applications and user identities. It adds an extra layer of verification to prevent unauthorized access—even in cases where attackers have obtained valid credentials. However, traditional MFA can introduce unnecessary friction for legitimate users.

This repository presents a self-contained implementation of an **Adaptive Multi-Factor Authentication (MFA)** system, which intelligently assesses login risks and dynamically applies secondary authentication when necessary.

By analyzing contextual signals such as:

- IP address  
- Device fingerprint  
- User-agent  

the system evaluates the risk level of each login attempt. Based on this evaluation, users may be prompted for additional verification using configurable MFA methods:

- **OTP via Email or SMS**
- **TOTP** using authenticator apps such as **Google Authenticator** or **Authy**

This design ensures strong security while maintaining a smooth experience for trusted users.

---

## C4 Diagram

![Adaptive MFA System Diagram](https://github.com/user-attachments/assets/4013a95b-6bae-4437-b2fe-0e1b992936a0)

### System Modules

- **Adaptive MFA System**  
  Entry point for user requests, coordinating the authentication flow.

- **Authentication Module**  
  Validates user credentials and interacts with the Risk Assessment Module to determine MFA necessity.

- **Risk Assessment Module**  
  Calculates risk scores based on contextual and historical login data.

- **MFA Module**  
  Generates, sends, and verifies OTP codes via email, SMS, or authenticator apps.

- **Database**  
  Stores user data, login logs, and MFA configurations.

- **Redis**  
  Temporarily stores verification codes and session-related data for fast access.

- **Prometheus**  
  Collects system performance and behavior metrics for observability.

---

## Sequence Diagrams

### Login & MFA Flow

![Login & MFA Flow](https://github.com/user-attachments/assets/2429d394-e296-4a6e-8cf2-99a04d3afed3)

### Disavow Login Request Flow

![Disavow Flow](https://github.com/user-attachments/assets/10060165-f59b-43d1-b9c7-692050767ed6)

---

## Database Schema

![Database Schema](https://github.com/user-attachments/assets/edeae327-0a77-4fde-bc66-8de480d06b8a)

---

## Solution Overview

### API Service

The system exposes five main groups of APIs:

1. **Login**  
   - `POST /auth/login`  
     Users authenticate with basic credentials. If MFA is required, the system responds with a `reference_id` to proceed with verification.

2. **Send Verification Code**  
   - `POST /auth/send-login-email-code`  
   - `POST /auth/send-login-phone-code`  
     Trigger the delivery of a verification code via email or SMS using the `reference_id`.

3. **Verify Code**  
   - `POST /auth/verify-login-email-code`  
   - `POST /auth/verify-login-phone-code`  
     Submit the received OTP along with the `reference_id`. If successful, the system returns a temporary `private_key`.

4. **Login with MFA**  
   - `POST /auth/login-with-mfa`  
     Complete login using the `reference_id` and `private_key`. Upon success, the system issues an access token.

5. **Disavow Login**  
   - `GET /hacked/disavow`  
     Users can report unauthorized login attempts via a link sent in the MFA message, allowing the system to update risk models.

---

### Risk Assessment

- Evaluates user login behavior using data from the `user_login_logs` table.
- Supports extensibility for integrating AI models to improve risk scoring.

---

## Technologies

- **Golang** – Core language for system implementation  
- **Docker** – Containerization for deployment  
- **PostgreSQL** – Persistent data storage  
- **Redis** – Fast in-memory storage for verification codes and session data  
- **Prometheus** – Monitoring and metrics collection

--- 

### Key Libraries

- `bcrypt` – Secure password hashing  
- `prometheus/client_golang` – Exporting performance metrics  
- `go-redis/redis` – Redis client for storing temporary MFA/session data  
- `database/sql` – Standard SQL interface for PostgreSQL interaction

---

## APIs

- **Login**
  ```
  curl --location 'localhost:8082/v1/auth/login' \
      --header 'Content-Type: application/json' \
      --data '{
          "username": "<username>",
          "password": "<password>"
      }'
  ```
- **Login with MFA**
```
curl --location 'localhost:8082/v1/auth/login-with-mfa' \
    --header 'Content-Type: application/json' \
    --data '{"reference_id":"<reference_id>","private_key":"<private_key>"}
    '
```
- **Send login email code**
```
curl --location 'localhost:8082/v1/auth/send-login-email-code' \
    --header 'Authorization: <token>' \
    --header 'Content-Type: application/json' \
    --data '{
        "reference_id": "<reference_id>"
    }'
```
- **Send login phone code**
```
curl --location 'localhost:8082/v1/auth/send-login-phone-code' \
    --header 'Authorization: <token>' \
    --header 'Content-Type: application/json' \
    --data '{
        "reference_id": "<reference_id>"
    }'
```
- **Verify login email code**
```
curl --location 'localhost:8082/v1/auth/verify-login-email-code' \
    --header 'Authorization: <token>' \
    --header 'Content-Type: application/json' \
    --data '{
        "reference_id": "<reference_id>",
        "code": "<code>"
    }'
```

- **Verify login phone code**
```
curl --location 'localhost:8082/v1/auth/verify-login-phone-code' \
    --header 'Authorization: <token>' \
    --header 'Content-Type: application/json' \
    --data '{
        "reference_id": "<reference_id>",
        "code": "<code>"
    }'
```

-- **Disavow**
```
curl --location --request GET 'localhost:8082/v1/hacked/disavow?ref=<ref_id>' \
    --header 'Content-Type: application/json' \
    --data '{}'
```

---

## Contributions & Architecture Highlights

- **MFA System**  
  Centralized logic to support risk-based MFA enforcement across login flows.

- **Custom HTTP Server**  
  Lightweight framework that minimizes boilerplate by automatically handling request decoding, error responses, and header formatting—allowing developers to focus solely on business logic.

- **Structured Logging with Request ID**  
  End-to-end request tracking across services and layers using `request_id`, making it easy to trace errors and debug complex flows.
