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

### 3. How to Import Data (Critical Step)

After logging in as a `Planner` or `Admin`, you must import the data.

1.  In the Swagger UI, click the "Authorize" 🔒 button at the top right and paste your token in this format: `Bearer <your_token>`.
2.  Find the `gtfs` section and the endpoint: `POST /gtfs/import/{agency_id}`.
3.  Click "Try it out".
4.  In the `agency_id` field, type a valid ID (e.g., **`GSBC001`**).
5.  Click **Execute**. This will download the data and populate your database.


### 4. How to Use Other Endpoints

After the import is successful, you can test other features.

* **`GET /gtfs/search/stops?q=circular`**: Test the fuzzy search.
* **`POST /favourites`**: (Requires a `Commuter` token) Add a favourite route.
* **`GET /gtfs/visualize/favourites`**: (Requires a `Commuter` token) See the map.

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

1.  **Create Your Local Environment File**
    This project requires a file named `transport_api.key.env` to store your secret API keys. This file is **not** included in the repository (it is listed in `.gitignore` for security).

    You must create your own local copy by **copying the template file** (`.example`) that *is* included:

    ```bash
    # This command copies the template to a new file
    cp transport_api.key.env.example transport_api.key.env
    ```

2.  **Edit Your New Local File**
    Now, open the **newly created `transport_api.key.env` file** (the one *without* the `.example` extension) in your code editor.

    Fill in the placeholder values with your own keys:

    * Get your `TRANSPORT_API_KEY` by registering at the [NSW Transport Open Data portal](https://opendata.transport.nsw.gov.au/).
    * Create your own long, random, and secure string for the `JWT_SECRET_KEY`.

---

### 4. Running the Application 

1.  **Start the API Server:**
    This command starts the server. The first time it runs, it will also create all the **empty** database tables (`users`, `favourites`, `routes`, `stops`, etc.).

    *(**Note:** Replace `Transport.api.py` with the **actual name** of your API file.)*
    ```bash
    python [actual name].api.py
    ```

2.  **Access the API & Import Data:**
    * Once the server is running, open your browser and go to **`http://127.0.0.1:5000/`**.
    * Follow the instructions in the **"📖 API Usage & Example Walkthrough"** section above to log in and **run the `POST /gtfs/import/{agency_id}` endpoint**.

3.  **Ready to Use:**
    * After the import is successful, your database will be populated with data, and all API endpoints will be fully functional.

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
