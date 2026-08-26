# Project Requirements

## Functional Requirements

### User Management

- Users must be able to create an account.
- Users must be able to log in securely.
- Users must be able to update their password.
- Users must be able to view their profile information.
- Email verification should support secure account validation flows.

### Scanning Workflow

- Authenticated users must be able to submit a target URL for scanning.
- A scan should be created with a status such as pending or completed.
- The system should record scan metadata, including target URL and creation time.
- Users must be able to list, view, and delete their scans.
- Findings should be associated with the corresponding scan.

### Security Analysis

- The system should inspect SSL and certificate-related properties.
- Security headers should be examined for missing or weak configuration.
- Cookie attributes should be reviewed for issues such as missing flags.
- DNS and technology detection should be available as part of passive checks.
- Risk scoring should summarize the overall posture of the scanned target.

### Reporting

- Results should be returned in structured API responses.
- The backend should permit future PDF or report generation workflows.
- Findings should support severity and explanation context.

## Non-Functional Requirements

- The backend should be performant and maintainable.
- The API should be structured around versioned routes.
- Sensitive values such as secrets should be stored as environment variables.
- Data access should be restricted to authenticated users.
- The system should be suitable for local development and later production deployment.

## Technology Constraints

- Preferred backend language: Python.
- Preferred API framework: FastAPI.
- Preferred ORM: SQLAlchemy.
- Preferred frontend framework: React with Vite.
- Preferred persistence layer: PostgreSQL.

## Assumptions

- The initial version focuses on passive security checks rather than full active exploitation testing.
- Findings are derived from scan artifacts and metadata rather than browser automation.
- Authentication is required for user-owned scans and relevant API actions.
- The project will expand iteratively via plug-in architecture.
