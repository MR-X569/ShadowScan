# ShadowScan

ShadowScan is an AI-assisted website security scanner designed to help users evaluate a target domain for common web security risks, identify misconfigurations, and generate structured reports with actionable findings.

## Overview

The platform combines a FastAPI backend, a modern frontend shell, and a modular scanner engine to perform passive security checks across a target URL. The system supports user authentication, scan history, findings summaries, and future expansion into deeper automated testing workflows.

## Core Capabilities

- SSL and certificate inspection
- Security header validation
- Cookie and session-related checks
- DNS reconnaissance and domain metadata review
- Technology stack detection
- Risk scoring and findings aggregation
- User-specific scan history and reporting
- Authentication and profile management
- PDF-ready reporting foundation for downstream export

## Repository Structure

- backend/ — FastAPI API, service layer, DB models, scanner engine, and schemas
- frontend/ — user-facing application shell
- docs/ — project planning, architecture, and design documentation
- frontend-demo/ — demo-only prototype content, not the production application
- temp1/ — ignored experimental or reference assets

## Current Architecture

### Backend

The backend is built with FastAPI and organized into:

- API routes under backend/app/api/v1/
- core configuration and dependency management
- SQLAlchemy models for users, scans, findings, and reports
- scanner engine modules under backend/app/scanner/
- service and schema layers for business logic and validation

The active API surface currently includes:

- Auth routes for registration and login
- User routes for profile access and password changes
- Scan routes for creating, listing, retrieving, and deleting scans
- Findings routes for per-scan and aggregated review

### Database

The data model currently centers on:

- users
- scans
- findings
- reports
- email verification records

### Frontend

The frontend is separated from the backend and is designed to consume the API for login, scans, and reporting workflows.

## Tech Stack

- Frontend: React, Vite, TypeScript, Tailwind CSS
- Backend: Python, FastAPI, SQLAlchemy, Pydantic
- Database: PostgreSQL
- Authentication: JWT and OAuth-ready integration
- Security scanning: Python-based modular plugins
- Testing: Pytest
- Packaging: pip / requirements-driven backend setup

## Documentation

The main project documentation is located in the docs folder:

- [docs/00_Project_Vision.md](docs/00_Project_Vision.md)
- [docs/01_Project_Requirements.md](docs/01_Project_Requirements.md)
- [docs/02_UI_UX_Design.md](docs/02_UI_UX_Design.md)
- [docs/03_Database_Design.md](docs/03_Database_Design.md)
- [docs/04_Backend_Architecture.md](docs/04_Backend_Architecture.md)
- [docs/05_API_Design.md](docs/05_API_Design.md)
- [docs/06_Project_Roadmap.md](docs/06_Project_Roadmap.md)
- [docs/07_Tech_Stack.md](docs/07_Tech_Stack.md)
- [docs/08_Meeting_Notes.md](docs/08_Meeting_Notes.md)
- [docs/09_References.md](docs/09_References.md)

## Local Setup

### Backend

1. Navigate to the backend directory.
2. Create and activate a virtual environment.
3. Install dependencies from backend/requirements.txt.
4. Configure environment variables such as database credentials, JWT secret, and SMTP settings.
5. Run the FastAPI app with Uvicorn or equivalent local tooling.

### Frontend

1. Navigate to the frontend directory.
2. Install dependencies using the project package manager.
3. Run the Vite app for local UI development.

## Current Status

This repository is in active documentation and architecture refinement. The backend has a working API skeleton, modular scanner patterns, and authentication flow, while the documentation is now aligned to those real project components.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
