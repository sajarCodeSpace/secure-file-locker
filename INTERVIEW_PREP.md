# Secure File Locker — Interview Defense & Resume Guide

A master guide for showcasing the **Secure File Locker** project during technical screens, system design interviews, and resume reviews.

---

## 1. Resume Bullet Points (Ready to Copy & Paste)

### Option A: Full-Stack / Backend Software Engineer Focus
> - **Engineered a Zero-Knowledge File Vault REST API** in Java 21 & Spring Boot 3.5, utilizing **AES-256-GCM authenticated encryption** and **PBKDF2WithHmacSHA256 (120k iterations)** to ensure zero file password persistence on server or database.
> - **Eliminated critical vulnerabilities (OWASP Top 10)** by introducing atomic database-scoped ownership queries (`findByIdAndUserId`) to prevent IDOR attacks and implemented an in-memory **Token Bucket rate limiter** to defend against PBKDF2 CPU-starvation DoS and brute-force attacks.
> - **Decoupled file storage architecture** via a swappable `StorageService` interface, containerized the multi-tier application using a multi-stage Docker build running as an unprivileged user, and configured automated GitHub Actions CI with 100% test coverage across unit and MockMvc integration tests.

### Option B: Security & Systems-Oriented Focus
> - **Architected a zero-trust cryptographic file locker** migrating legacy desktop cryptography (AES/ECB, unsalted SHA-256) into a hardened Spring Security service with stateless JWT authentication and BCrypt (cost 12) hashing.
> - **Designed authenticated encryption pipelines** leveraging AES-GCM with per-file cryptographically secure random 16-byte salts and 12-byte IVs, leveraging the 128-bit authentication tag for tamper detection and password verification with zero secret storage.
> - **Containerized and secured production deployments** using Docker & Docker Compose with unprivileged non-root execution, hardened HTTP headers, path-traversal/CRLF sanitized file uploads, and integrated Spring Actuator health monitoring.

---

## 2. The 30-Second Elevator Pitch

> *"I built Secure File Locker, a zero-knowledge file encryption REST service using Java 21 and Spring Boot 3.5. Unlike standard cloud storage services that either store file passwords or rely on unauthenticated encryption, this project uses AES-256-GCM where each file is encrypted with a unique salt, IV, and a key derived via PBKDF2 with 120,000 iterations. The server never stores the file password or its hash—the GCM authentication tag itself proves password correctness. I hardened the service with in-memory Token Bucket rate limiting to stop CPU starvation, decoupled the storage layer, and backed the entire lifecycle with comprehensive MockMvc and IDOR integration tests."*

---

## 3. STAR Story: Refactoring Legacy Cryptography to Production-Ready Microservice

- **Situation:** A legacy desktop application used insecure `AES/ECB` encryption with a hardcoded key string, stored file passwords in plaintext in MySQL, and hashed user credentials with unsalted SHA-256.
- **Task:** Rebuild the application from scratch into an enterprise-grade, stateless Spring Boot REST API that adheres to zero-trust cryptographic standards, eliminates OWASP Top 10 vulnerabilities, and is fully automated for CI/CD.
- **Action:**
  1. Replaced ECB mode with **AES-256-GCM**, embedding per-file random salt and IV headers.
  2. Adopted **zero-knowledge password verification**: eliminated file password hashes from the database entirely, relying on GCM's 128-bit authentication tag to verify decryption integrity.
  3. Implemented **Token Bucket rate limiting** to prevent attackers from executing CPU-exhaustion DoS attacks against PBKDF2 (120k iterations).
  4. Secured all file queries with user-scoped predicates (`findByIdAndUserId`) to prevent IDOR attacks.
  5. Implemented comprehensive unit tests and MockMvc integration tests covering happy paths, wrong passwords, corrupted ciphertexts, and multi-user isolation.
- **Result:** Delivered a hardened, containerized microservice with zero password storage, zero-friction local execution (auto-fallback to H2 file DB), full OpenAPI documentation with interactive Swagger UI, and complete CI verification.

---

## 4. Top 15 Deep-Dive Technical Interview Questions & Staff-Level Answers

### Q1: How does your zero-knowledge file password verification work without storing any hash?
**Answer:**
> In traditional systems, a server hashes a password and checks `hash(input) == stored_hash`. That stored hash is an attack surface: if the DB leaks, attackers can run offline dictionary attacks with Hashcat.
> In our design, the file is encrypted using **AES-256-GCM**. The user's password is fed into PBKDF2 along with a 16-byte random salt to derive a 256-bit AES key. GCM generates a 128-bit authentication tag over the ciphertext. When a user requests a download, we attempt decryption with the derived key. If the password is wrong or even a single bit of ciphertext was tampered with, the GCM tag verification fails and the cryptographic engine throws an `AEADBadTagException`. We map this directly to an HTTP 401 Unauthorized. The tag verification *is* the password check—there is zero reason to persist a separate hash.

---

### Q2: Why did you choose AES-256-GCM over AES-CBC or AES-ECB?
**Answer:**
> - **AES-ECB (Electronic Codebook)** was used in the legacy code. It encrypts identical 16-byte blocks into identical ciphertext blocks, leaking structural data (the famous "ECB Penguin" issue) and is vulnerable to replay and block-shuffling attacks.
> - **AES-CBC (Cipher Block Chaining)** requires a separate MAC (e.g., HMAC-SHA256) following the *Encrypt-then-MAC* paradigm to guarantee integrity. If implemented naively without constant-time MAC checks or if CBC padding errors are leaked, CBC is notoriously vulnerable to **Padding Oracle Attacks** (like BEAST, POODLE, Lucky Thirteen).
> - **AES-GCM (Galois/Counter Mode)** provides **Authenticated Encryption with Associated Data (AEAD)**. It guarantees both confidentiality and ciphertext integrity in a single pass with hardware-accelerated Galois field multiplication (CLMUL instructions on modern x86/ARM CPUs), eliminating padding oracle vulnerabilities entirely.

---

### Q3: What is the purpose of PBKDF2, and why 120,000 iterations instead of simple SHA-256?
**Answer:**
> Fast cryptographic hashes like SHA-256 or MD5 are designed to be computed rapidly—a modern consumer GPU can compute over 10 billion SHA-256 hashes per second, making brute-force cracking trivial.
> **PBKDF2 (Password-Based Key Derivation Function 2)** is a key-stretching algorithm. By configuring `PBKDF2WithHmacSHA256` with 120,000 iterations and a 16-byte unique salt, we force an attacker to execute 120,000 HMAC rounds for every single password candidate per file. This raises the computational barrier for attackers by orders of magnitude while introducing negligible delay (~30-50ms) for legitimate single-file operations.

---

### Q4: If PBKDF2 is computationally heavy, couldn't an attacker exploit it to launch a Denial of Service (DoS) attack? How do you prevent it?
**Answer:**
> Yes, asymmetric resource consumption is a real threat: a client sends a lightweight HTTP POST request, but forces the server CPU to execute 120,000 HMAC iterations.
> We mitigated this threat by implementing an in-memory **Token Bucket Rate Limiter** filter in front of the API.
> - `/api/files/{id}/download` is throttled per client IP/user to a burst capacity of 30 and sustained rate of 30 requests per minute.
> - `/api/auth/login` is throttled to 20 requests per minute.
> When limits are exceeded, requests are immediately dropped with HTTP 429 Too Many Requests before any PBKDF2 key derivation or database querying occurs.

---

### Q5: Why do you generate a fresh random salt and IV for every single file?
**Answer:**
> - **Salt (16 bytes):** Prevents pre-computation attacks (rainbow tables) and ensures that two users using the identical password produce completely different derived AES keys.
> - **IV (Initialization Vector - 12 bytes):** In GCM mode, counter reuse under the same key is catastrophic. If the same key and IV are ever reused across two files, an attacker can XOR the ciphertexts to reveal the XOR of the plaintexts and reconstruct the internal authentication key ($H$), destroying both confidentiality and integrity. Using 12-byte cryptographically secure random IVs ensures semantic security (IND-CPA).

---

### Q6: How do you prevent Insecure Direct Object References (IDOR)?
**Answer:**
> An IDOR vulnerability occurs when an API accepts a resource ID (e.g. `/api/files/42/download`) and accesses the database by ID alone without verifying ownership.
> In our implementation:
> 1. The client's identity is authenticated via signed JWT and injected as `@AuthenticationPrincipal AuthenticatedUser user`.
> 2. Every repository lookup strictly binds the user's ID: `storedFileRepository.findByIdAndUserId(fileId, userId)`.
> 3. If User B tries to download or delete User A's file ID, the database returns `Optional.empty()`, resulting in an immediate `ResourceNotFoundException` (HTTP 404), preventing resource enumeration or unauthorized access.

---

### Q7: Why is the file password sent in the HTTP request body rather than query parameters or headers?
**Answer:**
> 1. **Query parameters** (`?password=...`) are routinely written to web server access logs (Nginx, Apache), proxy logs, browser histories, and Cloudflare/CDN traces.
> 2. **HTTP Headers** are often logged by API gateways or APM tools (e.g., Datadog, New Relic) unless explicitly masked.
> 3. Placing the password in an encrypted HTTPS **Request Body** ensures the secret is protected in transit by TLS and is not captured in default HTTP access logging infrastructure.

---

### Q8: What are the streaming decryption trade-offs with AES-GCM?
**Answer:**
> In AES-GCM, the 128-bit authentication tag is located at the very end of the ciphertext stream.
> If you stream decrypted bytes directly to the HTTP response before the stream finishes:
> - If an invalid password was used or the file was tampered with, the client would already have received partially decrypted (or garbage) bytes before the server detects the tag mismatch at EOF.
> - To preserve zero-trust integrity, the ciphertext must be fully processed and the tag verified before sending or trusting the decrypted output, or decrypted into a bounded buffer. In our design, we decrypt into memory buffers sized safely for max allowed file payloads (25MB).

---

### Q9: Why did you choose BCrypt (work factor 12) for user logins, rather than using PBKDF2 for everything?
**Answer:**
> **BCrypt** is purpose-built for user authentication passwords. It uses an adaptive, memory-hard Blowfish-based key schedule that resists FPGA and GPU-accelerated parallel cracking much better than standard PBKDF2 (which is compute-bound rather than memory-bound).
> Work factor 12 requires $2^{12} = 4096$ rounds of Blowfish expansion, tuning login latency to ~250ms on modern CPUs, which is the industry standard benchmark for preventing offline hash cracking.

---

### Q10: How did you design the storage layer, and how would you migrate to AWS S3 or MinIO?
**Answer:**
> We applied the **Dependency Inversion Principle (DIP)**. The core service `FileVaultService` does not depend on `java.nio.file.Path` or local disk APIs; instead, it depends on a `StorageService` interface declaring `store()`, `load()`, `delete()`, and `exists()`.
> The current default implementation is `LocalStorageService`. To migrate to AWS S3 or MinIO:
> 1. Create an `S3StorageService implements StorageService` using the AWS SDK v2 `S3Client`.
> 2. Use Spring's `@ConditionalOnProperty(name = "app.storage.type", havingValue = "s3")` to conditionally instantiate the bean.
> 3. Zero business logic inside `FileVaultService` or controllers needs to change.

---

### Q11: How do you handle transactional consistency between the database and the storage backend on deletion or upload?
**Answer:**
> Local storage and relational databases do not share a two-phase commit (XA) distributed transaction coordinator.
> - **During Upload:** We encrypt and store the file blob first; only if storage succeeds do we insert the database record. If the database save fails, the transaction rolls back, and an orphan cleanup scheduled job deletes unreferenced blobs.
> - **During Deletion:** We delete the storage blob and remove the DB record inside `@Transactional`. If disk deletion fails, an exception is thrown, rolling back the DB transaction so the database never references a missing file.

---

### Q12: Why did you configure a multi-stage Docker build running as an unprivileged user?
**Answer:**
> 1. **Multi-stage build:** Keeps the final runtime image minimal and secure. The build stage contains Maven, JDK compilers, and source files. The runtime stage only contains the stripped Eclipse Temurin JRE 21 and the compiled `.jar`, shrinking the image from ~800MB to ~250MB and eliminating build tooling attack surfaces.
> 2. **Unprivileged user (`appuser`):** By default, Docker containers run as `root`. If a container breakout or remote code execution vulnerability occurs, running as `root` grants full host-level access. Switching to `USER appuser` adheres to the Principle of Least Privilege.

---

### Q13: How does your JWT authentication filter handle expired or malformed tokens?
**Answer:**
> `JwtAuthFilter` intercepts incoming requests and extracts the `Bearer ` token. When parsing with JJWT's `JwtParser`:
> - If the token is expired, has an invalid signature, or is malformed, `JwtException` or `IllegalArgumentException` is caught.
> - Rather than crashing or leaking stack traces, the filter silently logs a debug event and allows the request to continue without setting an `Authentication` in the `SecurityContextHolder`.
> - Spring Security's `SecurityFilterChain` subsequently evaluates `.anyRequest().authenticated()`, cleanly returning HTTP 401 Unauthorized to the client.

---

### Q14: What database optimizations did you implement for high-scale file lookups?
**Answer:**
> In the `files` table, users frequently execute `findByUserId(userId)` (listing files) and `findByIdAndUserId(fileId, userId)` (validating ownership).
> Without an index, querying files by `userId` requires a full table scan ($O(N)$). We declared `@Table(name = "files", indexes = {@Index(name = "idx_files_user_id", columnList = "userId")})`, ensuring $O(\log N)$ B-Tree index lookups, which maintains sub-millisecond response times even with millions of records.

---

### Q15: How would you horizontally scale this application to handle 10,000 requests/sec across multiple regions?
**Answer:**
> 1. **Stateless App Tier:** Spring Boot instances are already 100% stateless (JWT authentication, no HTTP sessions). They can be scaled horizontally behind an AWS ALB or Kubernetes Ingress controller.
> 2. **Shared Storage:** Replace `LocalStorageService` with an object store like AWS S3 or Google Cloud Storage, with bucket replication across regions.
> 3. **Distributed Rate Limiter:** Replace in-memory Token Bucket with Redis-backed rate limiting (using Redis Lua scripts or Bucket4j Redis integration) to share quota across all microservice pods.
> 4. **Database Tier:** Use Aurora MySQL with read replicas. Writes (uploads/deletions) go to the primary writer instance, while read queries (`listFiles`) are routed to read replicas.
