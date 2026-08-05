# ShadowScan - Backend Foundation Notes

## 1. What is a `.env` file?

A `.env` (Environment Variables) file stores sensitive configuration values separately from the source code.

### Why do we use it?

- Keeps passwords and secret keys out of the code.
- Different environments (Development, Testing, Production) can use different configurations.
- Prevents accidental exposure of credentials on GitHub.

### Example

```env
DATABASE_URL=postgresql://postgres:password@localhost:5432/shadowscan

SECRET_KEY=your_super_secret_key

ALGORITHM=HS256

ACCESS_TOKEN_EXPIRE_MINUTES=30

PROJECT_NAME=ShadowScan

API_V1_PREFIX=/api/v1
```

Never upload the `.env` file to GitHub.

Instead upload:

```
.env.example
```

---

# 2. Python Packages Used

## fastapi

Purpose:
Main backend framework.

Used for:

- Creating REST APIs
- Routing
- Request handling
- Response handling

Example:

```python
@app.get("/")
def home():
    return {"message": "Hello"}
```

---

## uvicorn

Purpose:

ASGI Server used to run FastAPI.

Command:

```bash
uvicorn app.main:app --reload
```

---

## sqlalchemy

Purpose:

ORM (Object Relational Mapper)

Used for:

- Connecting Python with PostgreSQL
- Creating Models
- Querying Database

Instead of writing SQL manually:

```sql
SELECT * FROM users;
```

we can write:

```python
db.query(User).all()
```

---

## psycopg2-binary

Purpose:

PostgreSQL Driver.

Used for connecting Python with PostgreSQL.

Without this package Python cannot communicate with PostgreSQL.

---

## alembic

Purpose:

Database Migration Tool.

Used for:

- Creating tables
- Updating tables
- Version controlling the database

Example:

Today:

Users Table

Tomorrow:

Add Role Column

Alembic updates the database safely.

---

## python-jose

Purpose:

JWT Authentication.

Used for:

- Creating Tokens
- Verifying Tokens

Example:

```
eyJhbGc......
```

Generated after login.

---

## passlib[bcrypt]

Purpose:

Password Hashing.

Instead of storing:

```
vivek123
```

Database stores:

```
$2b$12$....
```

This keeps passwords secure.

---

## python-multipart

Purpose:

Processes Form Data.

Used for:

- Login Forms
- Register Forms
- File Uploads

---

## pydantic-settings

Purpose:

Reads values from `.env`.

Example:

```python
settings.SECRET_KEY
settings.DATABASE_URL
```

---

## email-validator

Purpose:

Checks whether an email is valid.

Example:

```
vivek@gmail.com
```

---

## httpx

Purpose:

Modern HTTP Client.

Used for sending HTTP requests.

Will be useful in the Scanner Engine.

---

## requests

Purpose:

Classic HTTP Client.

Used for:

- Fetching websites
- Reading HTTP headers
- Getting HTML pages

---

## dnspython

Purpose:

Reads DNS Records.

Examples:

- A Record
- MX Record
- TXT Record
- SPF
- DMARC

Useful for DNS Scanner.

---

## beautifulsoup4

Purpose:

HTML Parser.

Used for:

- Reading HTML
- Finding Forms
- Extracting Meta Tags
- Parsing Website Content

Useful in Technology Detection and Scanner Modules.

---

## python-dotenv

Purpose:

Loads `.env` variables into Python.

---

# Development Packages

## black

Purpose:

Automatically formats Python code.

---

## isort

Purpose:

Automatically sorts Python imports.

---

## flake8

Purpose:

Checks code quality.

Detects:

- Unused Imports
- Long Lines
- Syntax Style Issues

---

## pytest

Purpose:

Testing Framework.

Used for writing automated tests.

---

# 3. What is `pip freeze`?

Command:

```bash
pip freeze
```

Shows all installed Python packages along with their versions.

Example:

```
fastapi==0.116.1
uvicorn==0.35.0
sqlalchemy==2.0.43
```

---

Command:

```bash
pip freeze > requirements.txt
```

Creates a `requirements.txt` file containing all installed packages.

---

Why is it important?

If someone clones the project, they only need to run:

```bash
pip install -r requirements.txt
```

and they will get the exact same development environment.

---

# Summary

| Package | Purpose |
|----------|---------|
| FastAPI | Backend Framework |
| Uvicorn | Runs FastAPI |
| SQLAlchemy | ORM for Database |
| psycopg2 | PostgreSQL Driver |
| Alembic | Database Migration |
| python-jose | JWT Authentication |
| passlib+bcrypt | Password Hashing |
| python-multipart | Form Handling |
| pydantic-settings | Read `.env` |
| email-validator | Email Validation |
| requests | HTTP Requests |
| httpx | Modern HTTP Client |
| dnspython | DNS Analysis |
| BeautifulSoup | HTML Parsing |
| python-dotenv | Load `.env` |
| black | Code Formatter |
| isort | Import Sorter |
| flake8 | Code Quality Checker |
| pytest | Testing Framework |

---

# Jarvis Notes

Always ask yourself:

1. Why am I installing this package?
2. What problem does it solve?
3. Where will it be used in ShadowScan?

If you know these three answers, you truly understand the project instead of just copying code.