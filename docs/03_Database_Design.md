# Database Design

## Design Overview

The database is modeled around a user-centric scanning workflow. Each authenticated user can create multiple scans, and each scan can produce multiple findings and report records.

## Core Tables

### users

Stores account information for authenticated users.

Fields include:

- id
- username
- email
- hashed_password
- full_name
- role
- is_active
- is_verified
- created_at
- updated_at

### scans

Stores submitted target scan requests for each user.

Fields include:

- id
- user_id
- target_url
- status
- risk_score
- created_at
- completed_at

### findings

Stores security issues discovered during a scan.

A typical finding captures:

- id
- scan_id
- category
- severity
- title
- description
- evidence
- remediation

### reports

Stores report metadata or generated report artifacts associated with a given scan.

### email_verifications

Stores verification-related records for email validation and OTP-based flows.

## Relationships

- One user has many scans.
- One scan belongs to one user.
- One scan has many findings.
- One scan has many reports.
- One user has many email verification records.

## Constraints and Principles

- Foreign keys enforce user ownership and scan association.
- Cascading deletes are used where associated data should be removed with parent records.
- Timestamps track creation and update activity.
- Enum values are used for user roles and scan states.

## Future Database Growth

As the system expands, the schema can support:

- scheduled scan jobs
- user organizations or teams
- history snapshots for results comparison
- richer report metadata
- event logs and audit trails
