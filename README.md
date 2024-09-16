# GoAuth - Role-Based Token Management System

**GoAuth** is a Redis client-based token management system that generates a token for each auth ID and unique key:
- Short-lived **JWT tokens**
- AES-encrypted **Refresh tokens**

## Components

### 1. JWT Token (JSON Web Token):
- **Features**:
    - Short-lived token
    - Contains user claims ID in the payload which gets verified with database lookup to return actual auth ID.
    - Signed to ensure integrity

### 2. AES-Encrypted Refresh Token:
- **Purpose**: Used to obtain new JWT after it expires
- **Features**:
    - Long-lived token
    - Stored securely in Redis
    - Encrypted using **AES** (Advanced Encryption Standard) for added security

## Token Flow:

1. **Login**:
    - User authenticates, and the system generates both a **JWT** and an **encrypted refresh token**.
2. **Accessing Resources**:
    - User presents the **JWT** to access protected resources until the token expires.
3. **Token Refresh**:
    - Once the **JWT** expires, the user can use the **refresh token** to obtain a new JWT without re-authenticating.
4. **Invalidation**:
    - Tokens can be invalidated (e.g., when a user logs out) through Redis to ensure they can no longer be used.

## Benefits:
- **Efficiency**: Redis ensures fast, in-memory storage of tokens.
- **Security**: AES encryption secures the refresh token, and JWT ensures quick, stateless verification backed by a session key stored in redis
