# ADAPTIVE MFA LOGIN
## Introduction
Multi-factor Authentication (MFA) is a well-known verification method for securing web applications and users' identities. It prevents bad actors from accessing an account even if they've acquired the username and password. However, it will also add friction for real users.
This repository presents a self-contained implementation of an Adaptive Multi-Factor Authentication (MFA) system designed to intelligently assess login risks and dynamically apply secondary authentication challenges. The solution is tailored to balance security with usability by leveraging contextual data—such as IP address, device fingerprint, and user-agent—to evaluate the risk level of each login attempt. Based on this assessment, the system conditionally prompts users for additional verification via configurable MFA methods, including OTP via email/SMS or TOTP through authenticator applications (e.g., Google Authenticator, Authy).

## C4 Diagram
