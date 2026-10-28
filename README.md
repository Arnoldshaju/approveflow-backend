# ApproveFlow Backend

A robust RESTful API backend for **ApproveFlow** — an enterprise purchase request and multi-tier approval workflow management system built with Django and Django REST Framework.

---

## 🚀 Tech Stack

- **Framework:** Python 3.12+, Django 5.2, Django REST Framework
- **Authentication:** JWT (djangorestframework-simplejwt)
- **Database:** PostgreSQL (production / Docker) / SQLite (local development)
- **Containerization:** Docker & Docker Compose
- **Testing:** Django Test Runner (comprehensive unit & integration suite)

---

## ✨ Key Features

- **Role-Based Access Control (RBAC):** `EMPLOYEE`, `MANAGER`, `FINANCE`, `ADMIN`.
- **Purchase Request Lifecycle:** Create, edit, submit, cancel, and review purchase requests.
- **Dynamic Multi-Level Approval Engine:**
  - Configurable amount threshold (requests exceeding threshold require secondary Finance approval).
  - Sequential approval step tracking (`PENDING`, `APPROVED`, `REJECTED`).
- **Audit Logging:** Full history and audit trail for compliance and status transitions.
- **Dashboard Metrics:** Role-tailored metrics and pending approval queues.

---

## 🛠️ Quick Start

### 1. Local Development Setup

```bash
# 1. Clone repository & enter backend directory
cd approveflow-backend

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env

# 5. Run database migrations
python manage.py migrate

# 6. (Optional) Run tests
python manage.py test

# 7. Start the development server
python manage.py runserver 8000
```

### 2. Docker Setup

```bash
# Build and run containers in detached mode
docker compose up -d --build

# Run migrations inside the web container
docker compose exec web python manage.py migrate
```

Backend will be available at `http://localhost:8001` (or your configured `HOST_PORT`).

---

## 📡 API Endpoints Overview

All endpoints are versioned under `/api/v1/`:

| Method | Endpoint | Description | Access |
|---|---|---|---|
| `GET` | `/api/v1/health/` | Service health status | Public |
| `POST` | `/api/v1/login/` | User login & obtain JWT pair | Public |
| `POST` | `/api/v1/token/refresh/` | Refresh JWT access token | Public |
| `GET` | `/api/v1/me/` | Current user profile & role | Authenticated |
| `GET` | `/api/v1/dashboard/stats/` | Role-specific dashboard statistics | Authenticated |
| `GET`, `POST` | `/api/v1/purchase-requests/` | List or create purchase requests | Authenticated |
| `GET`, `PUT`, `DELETE` | `/api/v1/purchase-requests/<id>/` | View or update purchase request | Owner / Authorized |
| `POST` | `/api/v1/purchase-requests/<id>/submit/` | Submit request into approval workflow | Owner |
| `POST` | `/api/v1/purchase-requests/<id>/cancel/` | Cancel submitted request | Owner |
| `GET` | `/api/v1/purchase-requests/<id>/history/` | View request audit history | Authorized |
| `GET` | `/api/v1/approvals/pending/` | Get pending approval steps for user | Manager / Finance |
| `POST` | `/api/v1/approvals/steps/<id>/approve/` | Approve step with comments | Assigned Approver |
| `POST` | `/api/v1/approvals/steps/<id>/reject/` | Reject step with comments | Assigned Approver |
| `GET`, `POST` | `/api/v1/admin/users/` | List and create user accounts | Admin |
| `GET`, `PUT`, `DELETE` | `/api/v1/admin/users/<id>/` | Manage specific user & role | Admin |
| `GET`, `PUT` | `/api/v1/admin/threshold/` | View or update approval threshold | Admin |

---

## 🧪 Testing

Run the test suite:

```bash
python manage.py test
```
