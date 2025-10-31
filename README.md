# GTFS Public Transit Data API

A secure, production-ready REST API built with Python, Flask-RESTX, and SQLite. This backend service provides a robust interface for querying GTFS (General Transit Feed Specification) data, managing user favourites, and performing advanced data export and visualization tasks.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Flask-RESTX](https://img.shields.io/badge/Flask-RESTX-blue.svg)](https://flask-restx.readthedocs.io/en/latest/)
[![JWT](https://img.shields.io/badge/Security-JWT-green.svg)](https://jwt.io/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-blue.svg)](https://www.sqlite.org/index.html)
[![Pandas](https://img.shields.io/badge/Data-Pandas-blue.svg)](https://pandas.pydata.org/)
[![Matplotlib](https://img.shields.io/badge/Data-Matplotlib-blue.svg)](https://matplotlib.org/)

---

## 🌟 Core Features

This API is more than a simple data service. It includes critical features required for a production-grade application:

### 1. Security & Authentication

* **JWT Authentication:** All sensitive endpoints are secured using **JSON Web Tokens (JWT)** for stateless session management.
* **Role-Based Access Control (RBAC):** Implements a robust authorization layer distinguishing between three user roles:
    * `Commuter`: Can read public data and manage their own favourites.
    * `Planner`: Can access advanced features like data export.
    * `Admin`: Has full control over the system, including user management.
* **Secure Password Hashing:** User passwords are never stored in plaintext. They are securely hashed using the industry-standard **PBKDF2-SHA256** algorithm with a unique salt for every user.
* **Environment-Safe Keys:** API and JWT secret keys are loaded from environment variables (`.env` file), following best practices for key management.

### 2. API Functionality

* **GTFS Data Querying:** Provides endpoints for querying stops, routes, trips, and stop times.
* **Fuzzy Search:** Features a high-performance fuzzy search endpoint (`/gtfs/search/stops`) using the `rapidfuzz` library for a user-friendly stop search experience.
* **User Favourites:** A full CRUD (`POST`, `GET`, `DELETE`) system for users to manage their favourite routes. The database uses `UNIQUE` constraints to prevent duplicate entries.
* **Automated API Docs:** Generates a **Swagger UI** automatically at the root (`/`) for interactive API documentation and testing.

### 3. Advanced Data Handling & Visualization

* **Dynamic CSV Export:** An endpoint for `Planner` roles (`/gtfs/export/routes/<agency_id>`) that uses **Pandas** to generate and serve a CSV file on-the-fly.
* **Dynamic Map Generation:** An endpoint (`/gtfs/visualize/favourites`) that uses **Matplotlib** to dynamically generate a map of a user's favourite routes, sending it directly to the browser as a `image/png` byte stream.


---

## 📖 API Usage & Example Walkthrough

The best way to explore the API is to run it locally and open the interactive **Swagger UI** documentation at `http://127.0.0.1:5000/`.

However, here is a quick walkthrough of the core authentication flow and key features.

### 1. Default Users

The database is initialized with three default users (if they don't already exist). **You must log in as one of these users to get a JWT token.**

| Username | Password | Role |
| :--- | :--- | :--- |
| `admin` | `admin` | `Admin` |
| `planner` | `planner` | `Planner` |
| `commuter` | `commuter` | `Commuter` |

### 2. How to Get an Authentication Token

You cannot access protected routes until you get a `Bearer Token`.

**Request:** `POST /auth/login`

**Body:**
```json
{
  "username": "commuter",
  "password": "commuter"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ..."
}
```

### 3. How to Use the Token (Example)

You must now copy this `access_token` and provide it in the **Authorization** header for all protected routes.

In the Swagger UI, click the "Authorize" 🔒 button at the top right and paste your token in this format: `Bearer <your_token>`.

**Example: Add a Favourite Route**

**Request:** `POST /favourites`
**Header:** `Authorization: Bearer <your_token>`
**Body:**
```json
{
  "route_id": "RTEST_123"
}
```

### 4. Key Endpoints to Test

* **`GET /gtfs/search/stops?q=circular`**: Test the fuzzy search functionality.
* **`POST /favourites`**: Add a favourite route (as a `Commuter`).
* **`GET /gtfs/visualize/favourites`**: The **"wow" feature**. See the map of your favourites (as a `Commuter`).
* **`GET /gtfs/export/routes/{agency_id}`**: Test the CSV export (as a `Planner`).

---

## 🚀 How to Run Locally

### 1. Prerequisites

* Python 3.10 or higher
* `pip` (Python package manager)

### 2. Installation

1.  Clone this repository:
    ```bash
    git clone [https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git](https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git)
    cd YOUR_REPOSITORY
    ```

2.  Create and activate a virtual environment (recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use: venv\Scripts\activate
    ```

3.  Install all required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### 3. Configuration

1.  Copy the example environment file. (The file you will use is `transport_api.key.env`, which should be in your `.gitignore`).
    ```bash
    cp transport_api.key.env.example transport_api.key.env
    ```

2.  Edit your new `transport_api.key.env` file with your credentials:
    * Get your `TRANSPORT_API_KEY` by registering at the [NSW Transport Open Data portal](https://opendata.transport.nsw.gov.au/).
    * Create your own long, random, and secure string for the `JWT_SECRET_KEY`.

### 4. Running the Application

1.  **Initialize the Database:**
    The application is designed to create all necessary tables (`users`, `favourites`, etc.) on its first run.

2.  **Import GTFS Data (If required):**
    *(You need to add the command for your data import script here, for example:)*
    ```bash
    # Run the import script to download GTFS data and populate the database
    python your_import_script.py
    ```

3.  **Start the API Server:**
    ```bash
    python your_api_file.api.py
    ```

4.  **Access the API:**
    Once the server is running, open your browser and go to **`http://127.0.0.1:5000/`**.

    You will see the live, interactive **Swagger UI** documentation, where you can test every endpoint.

---

## 🛠️ Tech Stack

* **Framework:** Flask, Flask-RESTX
* **Database:** SQLite 3
* **Security:** PyJWT, hashlib
* **Data Handling:** Pandas, Matplotlib, RapidFuzz
* **Testing:** Pytest (via Flask client)
* **Environment:** python-dotenv

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).
