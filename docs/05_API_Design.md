# API Design

## API Style

The API is built with FastAPI and follows a versioned route structure under /api/v1. The service exposes a modern REST-style interface with JSON responses and typed schemas.

## Base URL

- /api/v1

## Authentication Endpoints

### POST /api/v1/auth/register

Creates a new user account.

### POST /api/v1/auth/login

Authenticates a user and returns a token payload.

## User Endpoints

### GET /api/v1/users/me

Returns the authenticated user's profile information.

### POST /api/v1/users/change-password

Updates the current user's password after validation.

## Scan Endpoints

### POST /api/v1/scans

Creates a new scan for the authenticated user.

### GET /api/v1/scans

Lists the current user's scans in reverse chronological order.

### GET /api/v1/scans/{scan_id}

Retrieves one scan by ID and enforces user ownership checks.

### GET /api/v1/scans/{scan_id}/findings

Returns all findings attached to a selected scan.

### GET /api/v1/scans/findings/all

Returns all findings for the current user across scans.

### DELETE /api/v1/scans/{scan_id}

Deletes a scan and its related data.

## Response Conventions

- Standard JSON payloads
- Pydantic response models for deterministic contracts
- HTTP error responses for validation and authorization failures
- User ownership checks for protected scan resources

## Security Model

- authentication required for profile and scan operations
- JWT token-based access
- protected endpoints enforce the current authenticated user context
- additional validation is performed at the service layer before mutating data

## Future API Expansion

Planned expansion includes:

- richer report generation endpoints
- scheduled scanning operations
- AI-assistant query routes
- filtering and sorting for scan history
- export and download endpoints for reports
