# GuideMate Backend

GuideMateBackend is the Spring Boot API and business-rule layer of the GuideMate platform, which connects travelers with local guides. Authentication, tour lifecycle, reservations, capacity, payments, refunds, wallets, earnings, messaging, notifications, and media security are managed centrally by the backend.

Android repository: [GuideMate](https://github.com/Ahmetkaragunlu/GuideMate)

## Core Capabilities

- Email/password and Google authentication
- Email verification, password recovery, and role selection
- JWT access/refresh tokens with secure token rotation
- Tour creation, admin review, and publishing lifecycle
- Tour session, capacity, reservation, cancellation, and refund management
- iyzico Checkout Form, saved-card metadata, and multiple charge currencies
- Tourist wallet, guide earnings, bank account, and withdrawal flows
- Real-time WebSocket/STOMP messaging
- Firebase Cloud Messaging notifications and device registration
- Profile/tour image upload, validation, and controlled access
- Guide ratings, reviews, levels, and ranking

## Architecture

The codebase follows a feature-first package structure:

```text
guidematebackend/
├── auth/
├── chat/
├── media/
├── notification/
├── payment/
├── profile/
├── reservation/
├── review/
├── tour/
├── user/
├── wallet/
└── common/
```

Each feature owns the controllers, DTOs, services, repositories, domain models, mappers, configuration, and provider adapters it needs. Controllers define HTTP contracts, services coordinate application workflows, domain models protect state transitions, and repositories handle persistence. Shared security, error, configuration, and infrastructure behavior lives under `common`.

## Technical Decisions

### Authentication and Security

- Short-lived JWT access tokens and rotated refresh tokens are used.
- Refresh tokens are stored as hashes instead of plaintext values.
- Issuer, audience, token version, and account status are validated.
- Login, registration, and public authentication operations are rate-limited.
- Sensitive values such as provider tokens and IBANs are encrypted with AES/GCM, with separate fingerprints for matching.
- Stable feature-based error codes form the contract between Android and the API.

### Transactions and Concurrency

PostgreSQL transaction boundaries, optimistic/pessimistic locking, and idempotency keys are used together. This protects concurrent tour purchases, capacity limits, wallet double-spending, and repeated payment/refund requests at the database level.

### Payments and Refunds

Card data is processed by iyzico Checkout Form without reaching GuideMate systems. The backend handles payment initialization, callbacks, `X-IYZ-SIGNATURE-V3` signed webhooks, and provider retrieve verification. Incomplete payments and refunds are revisited by scheduler-based recovery mechanisms. USD is the canonical pricing currency, while short-lived FX quotes can be generated for supported charge currencies.

### Messaging and Notifications

WebSocket/STOMP connections are authenticated with JWT and use user-specific queues. Notifications are delivered through FCM with Firebase Admin SDK. Firebase Installation IDs are linked to user accounts, while retries, duplicate prevention, and inactive-device cleanup are handled by the backend.

### Media

Uploaded images are validated by size, content type, pixel limits, and actual image decoding. Files are re-encoded, ownership rules are enforced, and only permitted media resources are publicly served.

### Database

The PostgreSQL schema is versioned through Flyway migrations. Hibernate only validates the schema (`ddl-auto=validate`) and never creates tables at application startup. Flyway clean is disabled.

## Tech Stack

- Java 17 and Spring Boot 3.5
- Spring Security, Spring Data JPA, and Hibernate
- PostgreSQL and Flyway
- JWT, OAuth 2.0, and Google Identity
- WebSocket and STOMP
- Firebase Admin SDK and FCM
- iyzico Java SDK
- Spring Mail and SMTP
- OpenAPI and Swagger UI
- JUnit 5, Mockito, MockMvc, and Testcontainers

## Requirements

- JDK 17 or newer
- PostgreSQL
- Docker-compatible container runtime for integration tests
- Google Web OAuth Client ID
- SMTP account
- iyzico Sandbox credentials
- Firebase service account when FCM is enabled
- Public HTTPS address for payment callback/webhook testing

## Local Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/Ahmetkaragunlu/GuideMateBackend.git
   cd GuideMateBackend
   ```

2. Create the local PostgreSQL database:

   ```sql
   CREATE DATABASE guidemate_db;
   ```

3. Copy the local secret template:

   ```bash
   cp config/application-local-secrets.example.properties \
      config/application-local-secrets.properties
   ```

4. Replace the placeholders in `config/application-local-secrets.properties` with your local values.

5. Start the application with the local profile:

   ```bash
   ./mvnw spring-boot:run -Dspring-boot.run.profiles=local
   ```

The default local connection uses `jdbc:postgresql://localhost:5432/guidemate_db` and the operating-system user. Override it with `DB_URL`, `DB_USERNAME`, and `DB_PASSWORD` when needed.

## Configuration

Core local secret keys:

```properties
JWT_SECRET=base64-encoded-secret
GOOGLE_CLIENT_ID=your-google-web-client-id
MAIL_USERNAME=your-mail-username
MAIL_PASSWORD=your-mail-password
PUBLIC_BASE_URL=http://your-host:8080
MEDIA_STORAGE_ROOT=/absolute/path/to/media
IYZICO_API_KEY=your-sandbox-api-key
IYZICO_SECRET_KEY=your-sandbox-secret-key
FINANCIAL_DATA_ENCRYPTION_KEY=base64-encoded-32-byte-key
PAYMENT_CALLBACK_BASE_URL=https://your-public-callback-host
FCM_ENABLED=false
FCM_CREDENTIALS_PATH=./config/firebase-service-account.json
```

Real secret files and Firebase service-account credentials are excluded from Git. Production deployments should provide these values through environment variables or a secret manager.

## API Documentation

When the local profile is running:

- Swagger UI: `http://localhost:8080/swagger-ui/index.html`
- OpenAPI JSON: `http://localhost:8080/v3/api-docs`

Swagger and API docs are disabled by default in the production profile.

## Tests

```bash
./mvnw test
```

The test suite includes unit, controller/security, repository, migration, contract, concurrency, and real PostgreSQL integration tests. Integration tests use PostgreSQL 18 through Testcontainers and require a Docker-compatible runtime.

## Sandbox Status

- Card collection and refund flows use iyzico Sandbox.
- Guide payout runs in `SIMULATED` mode by default.
- FCM can be enabled with valid Firebase service-account credentials.
- Local callback/webhook verification requires a publicly reachable HTTPS address. A temporary Cloudflare Quick Tunnel can be used for local testing; `PAYMENT_CALLBACK_BASE_URL` must be updated whenever the tunnel address changes.

## Security Note

Secrets, private keys, real user data, and local credential files must never be committed. This README only documents required variable names and safe placeholder values.
