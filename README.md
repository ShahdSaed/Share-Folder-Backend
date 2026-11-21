# Company File Hub - Backend

Enterprise-grade backend API for Company File Hub built with Node.js, Express 5, Prisma 7, and MySQL / MariaDB. Designed for secure, reliable integration with an Angular frontend.

---

## 1. Technology Stack & Architecture

- **Runtime:** Node.js (CommonJS)
- **Framework:** Express 5
- **ORM & Database:** Prisma 7 with MySQL / MariaDB adapter
- **Authentication:** Dual-Token System:
  - **Access Token:** Short-lived JWT (15 minutes default) with strict `type: "access"` validation.
  - **Refresh Token:** Cryptographically secure random opaque token (7 days default), hashed with SHA-256 in the database, delivered via `HttpOnly`, `Secure`, `SameSite=Lax` cookies with atomic rotation.
  - **File Unlock Token:** Dedicated short-lived JWT (15 minutes) with strict `type: "file_unlock"` bound to `userId` and `fileId`.
- **Password Hashing:** Argon2id with cryptographically sound parameters.
- **Security:** Helmet, CORS with strict explicit origin allowlist, CSRF origin verification on cookie endpoints, path traversal guards, magic bytes / file signature validation, express-rate-limit.

### Architecture Flow
```
Client (Angular)
       │
       ▼
Routes (/api/v1/*)
       │
       ▼
Middlewares (Helmet, CORS, CookieParser, RateLimiters, CSRF, Auth, Roles)
       │
       ▼
Controllers (Thin HTTP request/response handlers)
       │
       ▼
Services (Business logic, token issuance, password verification, audit logging)
       │
       ▼
Repositories (Prisma ORM queries, data projections, transaction handling)
       │
       ▼
Database (MySQL / MariaDB) & Secure Disk Storage
```

---

## 2. Environment Variables & Setup

Copy `.env.example` to `.env` and fill in your values:

```env
PORT=3000
NODE_ENV=development

# Database connection URL
DATABASE_URL="mysql://filehub_user:secure_password@localhost:3306/filehub_db"

# JWT Secret (minimum 32 characters in production)
JWT_SECRET="replace_with_a_secure_random_secret_at_least_32_chars"
JWT_EXPIRES_IN="15m"

# Refresh Token configuration
REFRESH_TOKEN_EXPIRES_IN="7d"
COOKIE_SAMESITE="lax"

# CORS Allowed Origins (comma-separated, no trailing slashes)
CORS_ORIGINS="http://localhost:4200,http://127.0.0.1:4200"

# Rate Limiting
LOGIN_RATE_LIMIT_MAX=5
LOGIN_RATE_LIMIT_WINDOW_MS=900000
FILE_PASSWORD_RATE_LIMIT_MAX=5
FILE_PASSWORD_RATE_LIMIT_WINDOW_MS=900000
REFRESH_RATE_LIMIT_MAX=30
REFRESH_RATE_LIMIT_WINDOW_MS=900000
```

### Installation & Prisma Generation
```bash
# Install dependencies
npm install

# Generate Prisma Client (uses prisma7.config.ts)
npm run db:generate

# Format Prisma schema
npm run db:format
```

### Running the Application
```bash
# Start development server with nodemon
npm run dev

# Start production server
npm start
```

### Running Tests
```bash
# Run all unit tests (115 passing tests across 34 suites)
npm test

# Explicit unit tests
npm run test:unit

# Run integration tests (requires live test database configured in DATABASE_URL)
npm run test:integration

# Run all tests (unit + integration)
npm run test:all
```

---

## 3. API Contract & Response Format

The canonical API prefix is `/api/v1`. (Legacy `/api` endpoints are maintained for backward compatibility).

### Standard Success Response
```json
{
  "status": "success",
  "message": "Optional human-readable message",
  "data": {}
}
```

### Standard Error Response
```json
{
  "status": "error",
  "code": "ERROR_CODE",
  "message": "Human-readable error description"
}
```

Standard Error Codes:
- `BAD_REQUEST` (400)
- `UNAUTHORIZED` (401)
- `FORBIDDEN` (403)
- `NOT_FOUND` (404)
- `CONFLICT` (409)
- `TOO_MANY_REQUESTS` (429)
- `INTERNAL_SERVER_ERROR` (500)

---

## 4. Authentication & Token Lifecycle

### 1. Dual-Token Architecture
- **Access Token:**
  - Sent in response body on login and refresh.
  - Formatted as `Authorization: Bearer <ACCESS_TOKEN>`.
  - Type: `"access"`. Normal endpoints accept **only** tokens with `type === "access"`.
  - Normal authentication reloads the user from the database and immediately rejects inactive users.
- **Refresh Token:**
  - Cryptographically secure random 256-bit hex token.
  - Stored in the database **only as a SHA-256 hash**.
  - Delivered to the browser as an `HttpOnly`, `Secure` (in production), `SameSite=Lax` cookie named `refresh_token` scoped to `/api/v1/auth` (and `/api/auth`).
  - **Rotation:** Every call to `/api/v1/auth/refresh` revokes the old refresh token and issues a brand-new refresh token.
  - **Reuse Detection:** If an already-invalidated/replayed refresh token is presented, the affected session is revoked immediately.
- **File Unlock Token:**
  - Separate short-lived JWT (15 minutes).
  - Explicit type: `"file_unlock"`.
  - Explicitly bound to `{ sub: userId, fileId: fileId }`.
  - **Cannot be used to authenticate to any normal protected endpoint** (strictly rejected by `authenticate` middleware).
  - Sent via the `X-File-Unlock-Token` HTTP header when streaming file content.

### 2. Session Revocation Rules
- Calling `POST /api/v1/auth/logout` revokes the current session and clears the cookie.
- Calling `POST /api/v1/auth/logout-all` revokes all active sessions for the current user.
- Changing password (`PATCH /api/v1/auth/change-password`) revokes all active sessions.
- An administrator deactivating a user immediately revokes all of that user's active sessions.
- An administrator resetting another user's password immediately revokes all of that user's active sessions.

---

## 5. Endpoints Reference

### Authentication (`/api/v1/auth`)
| Method | Endpoint | Auth | Role | Description |
|---|---|---|---|---|
| `POST` | `/api/v1/auth/login` | None | Public | Email + password login. Returns Access Token; sets Refresh Token cookie. |
| `POST` | `/api/v1/auth/refresh` | Cookie | Public | Refreshes Access Token and rotates Refresh Token cookie. |
| `POST` | `/api/v1/auth/logout` | Cookie | Public | Revokes current session and clears cookie. |
| `POST` | `/api/v1/auth/logout-all`| Bearer | All | Revokes all active sessions for the user. |
| `PATCH`| `/api/v1/auth/change-password` | Bearer | All | Verifies old password, updates password, revokes sessions. |
| `GET`  | `/api/v1/auth/me` | Bearer | All | Returns current user profile (never leaks password hashes). |

### User Management (`/api/v1/users`)
| Method | Endpoint | Auth | Role | Description |
|---|---|---|---|---|
| `GET`  | `/api/v1/users` | Bearer | ADMIN | Paginated list of users (`page`, `limit`). |
| `POST` | `/api/v1/users` | Bearer | ADMIN | Create user (`name`, `email`, `password`, `role`). |
| `GET`  | `/api/v1/users/:id` | Bearer | ADMIN or Self | Get user profile. |
| `PATCH`| `/api/v1/users/:id` | Bearer | ADMIN | Update user (name, email, role, isActive). Blocks self-demotion/deactivation. |
| `PATCH`| `/api/v1/users/:id/password` | Bearer | ADMIN | Reset user password and revoke their sessions. |

### Files Management (`/api/v1/files`)
| Method | Endpoint | Auth | Role | Description |
|---|---|---|---|---|
| `GET`  | `/api/v1/files` | Bearer | All | List files. ADMIN sees all; VIEWER sees only assigned files. |
| `POST` | `/api/v1/files` | Bearer | ADMIN | Multipart upload (`file`, `password`, optional `name`). |
| `GET`  | `/api/v1/files/:id` | Bearer | All | Metadata of a file. |
| `PATCH`| `/api/v1/files/:id` | Bearer | ADMIN | Rename file display name. |
| `DELETE`| `/api/v1/files/:id` | Bearer | ADMIN | Deletes file from database and deletes disk storage. |
| `PUT`  | `/api/v1/files/:id/password` | Bearer | ADMIN | Updates file password. |
| `POST` | `/api/v1/files/:id/verify-password` | Bearer | All | Verifies file password and returns short-lived `unlockToken`. |
| `GET`  | `/api/v1/files/:id/content` | Bearer + Unlock Token | All | Streams file content. VIEWER must provide `X-File-Unlock-Token`. |
| `GET`  | `/api/v1/files/:id/access` | Bearer | ADMIN | List grants for file with optional `status=active|expired|all`. |
| `POST` | `/api/v1/files/:id/access` | Bearer | ADMIN | Grant/update access (`userId`, `expiresInDays` 1-365). |
| `DELETE`| `/api/v1/files/:id/access/:userId` | Bearer | ADMIN | Revoke access grant for user. |

### Audit Logs (`/api/v1/admin/audit-logs`)
| Method | Endpoint | Auth | Role | Description |
|---|---|---|---|---|
| `GET`  | `/api/v1/admin/audit-logs` | Bearer | ADMIN | Paginated audit logs with filters: `action`, `result`, `userId`, `targetType`, `fromDate`, `toDate`. |

---

## 6. End-to-End User Flows

### VIEWER User Flow
1. **Login:**
   `POST /api/v1/auth/login` with email and password.
   Store `accessToken` in memory. Browser automatically receives `refresh_token` HttpOnly cookie.
2. **List Assigned Files:**
   `GET /api/v1/files` with `Authorization: Bearer <ACCESS_TOKEN>`.
   Response contains files the user has active grants for.
3. **Unlock File:**
   User enters file password.
   Call `POST /api/v1/files/<fileId>/verify-password` with `{ "password": "<filePassword>" }`.
   Response returns:
   ```json
   {
     "status": "success",
     "data": {
       "unlockToken": "<FILE_UNLOCK_TOKEN>",
       "expiresInSeconds": 900
     }
   }
   ```
4. **Download or View File:**
   Call `GET /api/v1/files/<fileId>/content` (add `?inline=true` for in-browser PDF preview).
   Send headers:
   ```http
   Authorization: Bearer <ACCESS_TOKEN>
   X-File-Unlock-Token: <FILE_UNLOCK_TOKEN>
   ```
5. **Handle Expirations:**
   - If Access Token expires (HTTP 401): Call `/api/v1/auth/refresh` (with `withCredentials: true`), get new access token, and retry the request once.
   - If Unlock Token expires (HTTP 403 `FILE_ACCESS_DENIED`): Re-prompt user to verify file password.
   - If Grant expires (HTTP 403 `FILE_ACCESS_DENIED`): Inform user that their access grant has expired and contact an administrator.

---

### ADMIN User Flow
1. **Login:** `POST /api/v1/auth/login`.
2. **Manage Users:**
   - Create viewer: `POST /api/v1/users`
   - List users: `GET /api/v1/users`
   - Reset password: `PATCH /api/v1/users/:id/password`
3. **Upload Files:**
   - `POST /api/v1/files` with `multipart/form-data`:
     - `file`: binary document (PDF, DOCX, XLSX, etc.)
     - `password`: unlock password
     - `name`: optional custom name
4. **Grant Access to Viewers:**
   - `POST /api/v1/files/:id/access` with `{ "userId": "...", "expiresInDays": 30 }`.
5. **Monitor System Security:**
   - `GET /api/v1/admin/audit-logs?action=LOGIN_FAILED&result=FAILURE` to inspect failed attempts.
6. **Revoke Access:**
   - `DELETE /api/v1/files/:id/access/:userId`. This immediately terminates access.

---

## 7. Angular Integration Guide

### Angular HTTP Interceptor Setup (Access Token & Auto-Refresh)
In Angular 15+ / 17+ with standalone HTTP interceptor:

```typescript
// auth.interceptor.ts
import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from './auth.service';
import { catchError, switchMap, throwError } from 'rxjs';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const token = authService.getAccessToken();

  let authReq = req;
  // Attach Bearer Access Token if present
  if (token) {
    authReq = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  // Always enable credentials for auth endpoints so the refresh cookie is sent
  if (req.url.includes('/api/v1/auth/')) {
    authReq = authReq.clone({ withCredentials: true });
  }

  return next(authReq).pipe(
    catchError((error: HttpErrorResponse) => {
      // If 401 Unauthorized and not already refreshing or logging in
      if (error.status === 401 && !req.url.includes('/auth/login') && !req.url.includes('/auth/refresh')) {
        return authService.refreshToken().pipe(
          switchMap((newToken: string) => {
            const retriedReq = req.clone({
              setHeaders: {
                Authorization: `Bearer ${newToken}`
              }
            });
            return next(retriedReq);
          }),
          catchError((refreshErr) => {
            authService.logoutLocal();
            return throwError(() => refreshErr);
          })
        );
      }
      return throwError(() => error);
    })
  );
};
```

### Angular File Content Streaming
```typescript
// file.service.ts
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class FileService {
  private baseUrl = 'http://localhost:3000/api/v1/files';

  constructor(private http: HttpClient) {}

  downloadFileContent(fileId: string, unlockToken?: string, inline = false): Observable<Blob> {
    let headers = new HttpHeaders();
    if (unlockToken) {
      headers = headers.set('X-File-Unlock-Token', unlockToken);
    }

    return this.http.get(`${this.baseUrl}/${fileId}/content?inline=${inline}`, {
      headers,
      responseType: 'blob'
    });
  }
}
```

---

## 8. Database Migrations Status

1. `20261025180430_create_core_tables`: Applied in initial database setup.
2. `20261025181127_change_ids_to_uuid`: Applied in initial database setup.
3. `20261102150000_file_access_grant_user_file_unique`: **Applied**. Creates `file_access_grants_user_id_file_id_key` unique index and drops redundant composite index while preserving foreign key support.
4. `20261103120000_refresh_sessions`: **Applied**. Creates `refresh_sessions` table with indexes on `token_hash`, `user_id`, and `expires_at`.


