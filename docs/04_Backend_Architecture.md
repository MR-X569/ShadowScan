# Backend Architecture

## Overview

The backend follows a layered FastAPI architecture built to separate API endpoints, business logic, database access, and scanner functionality.

## Layered Structure

### API Layer

The API layer defines versioned routes for authentication, user actions, and scan operations. It is responsible for request validation, route metadata, and error handling.

Current API modules include:

- auth routes
- user routes
- scan routes

### Service Layer

The service layer contains the business logic that coordinates data access and scanner behavior. This is where operations such as user registration, scan creation, and result orchestration are managed.

### Schema Layer

Pydantic schemas validate request and response models and define the contract between the API and clients. They help maintain consistency for authentication tokens, users, scans, and findings.

### Model Layer

SQLAlchemy models map the data model to the database. The project currently includes models for:

- User
- Scan
- Finding
- Report
- EmailVerification

### Scanner Layer

The scanner engine is designed around a plugin architecture. Each plugin can run a specific check type, such as:

- header validation
- technology detection
- sitemap or robots discovery
- SSL evaluation

The scanner manager coordinates plugin execution and consolidates findings into scan results.

## Core Design Principles

- keep routes thin and focused
- isolate database access behind service logic
- prefer modular scanning plugins over monolithic logic
- maintain stateless configuration via environment variables
- support future extensibility without rewriting the API surface

## Execution Flow

1. User submits a URL through the API.
2. Auth and validation checks are performed.
3. A scan record is created for the authenticated user.
4. The scanner manager schedules plugin execution.
5. Findings are collected and associated with the scan.
6. Results are exposed via API endpoints for retrieval and reporting.

## Security Considerations

- environment-based secret management
- JWT-based access control
- database-level ownership checks for user resources
- CORS configuration for front-end access in development
- optional OAuth integration for login extensibility
