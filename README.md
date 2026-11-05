# Spring Security: JWT Authentication and Authorization

A Spring Boot demo of **stateless JWT authentication** backed by a **MySQL** user database. A client logs in with `POST /login`, receives a signed JWT, and sends it as `Authorization: Bearer <token>` on later requests. Access is controlled by URL rules, method-level annotations, and roles stored in the database.

The project is a learning demo. It has hard-coded secrets and default passwords, and is not meant for production. See [Known limitations](#known-limitations).

---

## Table of contents

- [Features](#features)
- [Project structure](#project-structure)
- [Tech stack](#tech-stack)
- [Data model and seed data](#data-model-and-seed-data)
- [Authentication flow](#authentication-flow)
- [Endpoints and access rules](#endpoints-and-access-rules)
- [Configuration](#configuration)
- [Running locally](#running-locally)
- [Running the tests](#running-the-tests)
- [Trying it out](#trying-it-out)
- [Build notes](#build-notes)
- [Known limitations](#known-limitations)

---

## Features

- Stateless authentication with **JWT** (HS256, `jjwt` 0.13.0). Sessions are not created.
- **Login endpoint** that checks credentials against the database and returns a token.
- **BCrypt** password hashing.
- A `JwtTokenFilter` that runs before the username/password filter. It validates the token and loads the user from the database on each request.
- JSON `401` responses from a custom entry point, and role checks that return `403`.
- URL-based rules (`/public/**`, `/private/**`, `/restricted/**`) plus method-level security with `@PreAuthorize`, `@Secured` and JSR-250, all enabled.
- Two seeded users, `user` (`ROLE_USER`) and `admin` (`ROLE_ADMIN`), created at startup.
- A `/csrf-token` endpoint, but CSRF protection is disabled. See [Known limitations](#known-limitations).

---

## Project structure

```
spring-security-jwt-auth-csrf-demo/
├── pom.xml                                        # Spring Boot 3.5.7 parent, Java 27 / release 25
└── src/main/
    ├── java/com/security/demo/
    │   ├── SpringSecurityJwtAuthCsrfDemoApplication.java
    │   ├── config/
    │   │   └── SecurityConfiguration.java         # filter chain, seed data, BCrypt, AuthenticationManager
    │   ├── controller/
    │   │   ├── AuthenticationController.java      # POST /login
    │   │   ├── CsrfController.java                # GET /csrf-token
    │   │   └── SpringSecurityTestController.java  # demo endpoints with different access rules
    │   ├── model/
    │   │   ├── RoleEntity.java, RoleEnum.java     # roles table, ROLE_USER / ROLE_ADMIN
    │   │   ├── UserEntity.java                    # users table
    │   │   └── http/                              # LoginRequest, LoginResponse
    │   ├── repository/                            # RoleRepository, UserRepository
    │   ├── security/
    │   │   ├── JwtManagerComponent.java           # create, read and validate JWTs
    │   │   ├── filter/JwtTokenFilter.java         # reads the Bearer token on each request
    │   │   ├── model/AuthorizedUserDetails.java   # UserDetails built from UserEntity
    │   │   └── service/
    │   │       ├── AuthenticationService.java
    │   │       └── impl/ (AuthenticationServiceImpl, UserDetailsServiceImpl,
    │   │                  JwtAuthenticationEntryPoint)
    │   └── service/ (UserDetailsServiceSecure, impl/)  # @Secured method example
    └── resources/
        └── application.properties                 # MySQL, JPA, JWT settings
```

---

## Tech stack

- Java 27 (`java.version`), compiled with `maven.compiler.release` **25**
- Spring Boot 3.5.7 (parent POM): Web, Security, Data JPA, Validation
- JJWT 0.13.0 (`jjwt-api`, `jjwt-impl`, `jjwt-jackson`)
- MySQL Connector/J 8.0.33 and MySQL 8 as the database
- Lombok 1.18.48
- JUnit 6.1.3 and Mockito 5.24.0 for unit tests (pinned in `pom.xml`)
- Maven

---

## Data model and seed data

Hibernate creates the tables with `ddl-auto=update`.

| Table | Columns |
|---|---|
| `roles` | `role_id` (PK, identity), `role_name` (enum string: `ROLE_USER`, `ROLE_ADMIN`) |
| `users` | `user_id` (PK, identity), `username` (unique), `email` (unique), `password` (BCrypt, never serialised to JSON), `account_non_locked`, `account_non_expired`, `credentials_non_expired`, `enabled`, `credentials_expiry_date`, `account_expiry_date`, `two_factor_secret`, `is_two_factor_enabled`, `sign_up_method`, `role_id` (FK to `roles`), `created_date`, `updated_date` |

**Seed data** (`SecurityConfiguration.initData`, runs once at startup if the rows are missing)

| Username | Password | Email | Role |
|---|---|---|---|
| `user` | `user` | `user@mail.com` | `ROLE_USER` |
| `admin` | `admin` | `admin@mail.com` | `ROLE_ADMIN` |

The passwords are stored as BCrypt hashes. The `user` account is created with `accountNonLocked = false`. The application does not check that flag, though (see [Known limitations](#known-limitations)).

---

## Authentication flow

1. **Login.** The client sends `POST /login` with a JSON body containing `username` and `password`. `AuthenticationServiceImpl` passes them to Spring's `AuthenticationManager`, which loads the user with `UserDetailsServiceImpl` and checks the BCrypt hash.
2. **Token.** On success, `JwtManagerComponent` signs a token with the HMAC-SHA key from `spring.app.jwt.secret`. The subject is the username, and the token expires after `spring.app.jwt.expiration-ms` (one hour by default). The token does not contain roles.
3. **Each request.** `JwtTokenFilter` reads `Authorization: Bearer <token>`, validates the signature and expiry, loads the user from the database, and puts an authenticated principal in the `SecurityContext`. Roles therefore come from the database on every request.
4. **Failure.** A missing, invalid or expired token leaves the request unauthenticated. Protected endpoints return a JSON `401` from `JwtAuthenticationEntryPoint`. Authenticated users without the required role get `403`.

---

## Endpoints and access rules

The server listens on the default port **8080**.

| Method | Path | Access | Notes |
|---|---|---|---|
| `POST` | `/login` | Anyone | Returns a JWT on success |
| `GET` | `/public/information` | Anyone | `permitAll` |
| `GET` | `/private/information` | Any authenticated user | |
| `GET` | `/restricted/information` | Nobody | `denyAll` |
| `GET` | `/user/details` | `ROLE_USER` | `@PreAuthorize("hasRole('USER')")` |
| `PUT` | `/user/details` | `ROLE_USER` | `@PreAuthorize("hasRole('USER')")` |
| `GET` | `/user/details/method` | `ROLE_USER` | `@Secured("ROLE_USER")` on the service method |
| `GET` | `/admin/details` | `ROLE_ADMIN` | `@PreAuthorize("hasRole('ADMIN')")` |
| `PUT` | `/admin/details` | `ROLE_ADMIN` | `@PreAuthorize("hasRole('ADMIN')")` |
| `GET` | `/user-admin/details` | `ROLE_USER` or `ROLE_ADMIN` | Returns the current username |
| `GET` | `/csrf-token` | Any authenticated user | Returns `null` in practice (see limitations) |

Other paths, such as `/csrf-token`, fall under `anyRequest().authenticated()` and need a valid token.

---

## Configuration

`src/main/resources/application.properties`

| Property | Value | Purpose |
|---|---|---|
| `spring.datasource.url` | `jdbc:mysql://localhost:3306/spring_security_demo?useSSL=false&serverTimezone=UTC` | MySQL database. The database must already exist |
| `spring.datasource.username` / `password` | `root` / `root` | Database credentials |
| `spring.datasource.driver-class-name` | `com.mysql.cj.jdbc.Driver` | JDBC driver |
| `spring.jpa.properties.hibernate.dialect` | `org.hibernate.dialect.MySQL8Dialect` | Hibernate dialect |
| `spring.jpa.hibernate.ddl-auto` | `update` | Create and update tables on startup |
| `spring.app.jwt.secret` | Base64 HMAC key | Signs the JWTs. Must decode to at least 256 bits for HS256 |
| `spring.app.jwt.expiration-ms` | `3600000` | Token lifetime (1 hour) |
| `logging.level.org.springframework.security` | `DEBUG` | Logs each security decision |

---

## Running locally

### Prerequisites

- **JDK 27** (or 25 or later, see [Build notes](#build-notes))
- **Maven 3.6.3+**
- **MySQL 8** on `localhost:3306` with user `root` and password `root`, and an empty database called `spring_security_demo`:

  ```sql
  CREATE DATABASE spring_security_demo;
  ```

### Build and run

```bash
mvn clean install
mvn spring-boot:run
```

The application starts on http://localhost:8080. Tables and seed users are created on first startup.

---

## Running the tests

```bash
mvn test
```

The 24 unit tests live in `src/test/java`. They need no MySQL database and no running server. They cover:

- `JwtManagerComponent`: reading the Bearer header, creating and parsing tokens, and rejecting malformed, empty and expired tokens.
- `JwtTokenFilter`: setting the security context for a valid token, and continuing the chain for missing, invalid or failing tokens.
- `AuthenticationServiceImpl`, `UserDetailsServiceImpl`, `JwtAuthenticationEntryPoint` and `AuthenticationController`.
- The seed-data runner in `SecurityConfiguration`.

The tests do not check the HTTP access rules in the endpoint table, and they do not touch MySQL. Those need `MockMvc` or `@SpringBootTest` tests, which the project does not have yet.

---

## Trying it out

1. **Log in** as the `user` account:

   ```bash
   curl -s -X POST http://localhost:8080/login \
     -H 'Content-Type: application/json' \
     -d '{"username": "user", "password": "user"}'
   ```

   ```json
   {"success":true,"message":"Login successful","jwtToken":"eyJhbGciOiJIUzI1NiJ9...","username":"user","roles":["ROLE_USER"]}
   ```

   A wrong password returns HTTP `200` with `"success": false` and `"message": "Bad credentials"`.

2. **Call a protected endpoint** with the token:

   ```bash
   TOKEN=$(curl -s -X POST http://localhost:8080/login \
     -H 'Content-Type: application/json' \
     -d '{"username": "user", "password": "user"}' | sed -E 's/.*"jwtToken":"([^"]+)".*/\1/')

   curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/user/details      # User details endpoint
   curl -X PUT -H "Authorization: Bearer $TOKEN" http://localhost:8080/user/details  # Update User details endpoint
   ```

3. **Check the role rules:**

   ```bash
   curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/admin/details   # 403, user is not ADMIN
   curl -i http://localhost:8080/private/information                               # 401, no token
   curl -i http://localhost:8080/public/information                                # 200, no token needed
   ```

4. **Log in as `admin`** (`admin` / `admin`) to call `/admin/details`, `PUT /admin/details`, and `/user-admin/details`.

---

## Build notes

- `java.version` is 27. The compiler targets `maven.compiler.release` **25**. Spring Boot's repackage plugin cannot read Java 27 class files (major version 71), so the build must target 25.
- Lombok is pinned to **1.18.48** with the `lombok.version` property. Earlier versions fail on JDK 26/27 with a `TypeTag :: UNKNOWN` error.
- Sources follow google-java-format style.
- Unit tests (`mvn test`) use JUnit 6 and Mockito 5, pinned in `pom.xml`. `byte-buddy.version` is pinned to 1.18.17 so that Mockito can mock interfaces on Java 27.
- `spring-security-test` is on the test classpath but not used yet.

---

## Known limitations

This is a demo. The following are known gaps.

**Secrets and credentials**

- The JWT signing key is in `application.properties`, committed to the repository. Anyone with the repository can forge tokens. Load it from an environment variable or a secrets manager instead.
- Database credentials are `root` / `root`.
- The seed users have passwords equal to their usernames.

**Logging**

- `JwtManagerComponent.getJwtFromHeader` logs the full `Authorization` header at `INFO`, which exposes live tokens in the logs.
- `JwtTokenFilter` logs the authentication object at `INFO`.
- `JwtManagerComponent.validateJwtToken` contains a leftover `System.out.println("Validate")`.

**CSRF**

- The project is named for CSRF, but `http.csrf(AbstractHttpConfigurer::disable)` turns CSRF protection off. The comments that mention `X-XSRF-TOKEN` do not match the behaviour.
- With CSRF disabled, Spring does not set the `CsrfToken` request attribute, so `GET /csrf-token` returns no token.
- The protection is not needed for this design (the client sends a Bearer token, not a cookie), but the README and comments should not suggest that CSRF is active.

**Account state**

- The `user` seed account is created with `accountNonLocked = false`, but `AuthorizedUserDetails` does not carry the account flags from `UserEntity`. A locked, disabled or expired account can still log in.
- `credentialsExpiryDate` and `accountExpiryDate` are stored but never checked.

**Tokens**

- There is no token revocation, refresh token or logout. A token stays valid until it expires, one hour after issue by default.
- `validateJwtToken` does not catch `SignatureException`, so a token signed with another key makes the method throw instead of returning `false`. `JwtTokenFilter` catches the exception, logs it as an error and continues, so the request is treated as anonymous. The unit test `JwtManagerComponentTest` documents this behaviour.
- The token contains no roles. Roles are read from the database on each request, which keeps role changes immediate but adds a database query per request.

**Other**

- `POST /login` returns HTTP `200` for bad credentials, with `success: false`. A `401` would be more conventional.
- `AuthenticationServiceImpl` writes the authentication into `SecurityContextHolder`, which has no effect in a stateless application.
- The `mysql-connector-java` coordinate is the legacy name. The current artifact is `com.mysql:mysql-connector-j`.
- Only unit tests exist. No test covers the HTTP access rules, the MySQL persistence, or the full login-and-call flow.
