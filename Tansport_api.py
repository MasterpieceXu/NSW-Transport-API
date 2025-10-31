#-------------------------------------------------------
# PART 1: Imports, Configuration, and Security Utilities
#-------------------------------------------------------
import jwt
import pandas
import datetime
import hashlib
import binascii
import requests
import zipfile
import os
import io
import sqlite3
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from functools import wraps
from flask import request, jsonify, Flask, send_file
from flask_restx import Api, Resource, fields
from http import HTTPStatus
from rapidfuzz import fuzz,process
from dotenv import load_dotenv
#-----------------------------------------------
# 2. Initialize Constants and Configuration
#-----------------------------------------------
# Create the database
DateBase_NAME="z5707025.sqlite"

# JWT/Authentication Configuration (Load from environment variables to protect keys)
JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY", "A_SECURE_JWT_SECRET_HERE")
authorizations = {
    'Bearer Auth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "JWT Authorization header using the Bearer scheme. Example: 'Bearer {token}'"
    }
    }
TOKEN_EXPIRATION_DAYS=7
ALL_USERS = ['Admin', 'Planner', 'Commuter']

# Set up Base_URL
API_KEY = os.environ.get("NSW_TRANSPORT_API_KEY")
GTFS_BASE_URL = "https://api.transport.nsw.gov.au/v1/gtfs/schedule"
# For task 2
GTFS_BUSWAYS_R1_PATH = "/buses/GSBC001" 
# For task 2  efficient prefixe
VALID_AGENCY_PREFIXES = ('GSBC', 'SBSC')
DEFAULT_PAGE_SIZE = 50 # Task 3 Pagination
MAX_PAGE_SIZE = 500    # Task 3 Maximum Page Size
MAX_FAVOURITES = 20     # Task 5 Maximum Favorites Limit


#----------------------------------------------------------------------------------
# 3. Password Handling Utility Functions (Using the PBKDF2-SHA256 Standard Library)
#----------------------------------------------------------------------------------
HASH_ITERATIONS = 100000

def hash_password(password):
    """use PBKDF2-SHA256 for hash_password。"""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, HASH_ITERATIONS)
    salt_hex = binascii.hexlify(salt).decode('utf-8')
    key_hex = binascii.hexlify(key).decode('utf-8')
    return f'{HASH_ITERATIONS}${salt_hex}${key_hex}'

def check_password(password, hashed_password):
    """Verify the plaintext password against the stored hash"""
    try:
        iterations, salt_hex, key_hex = hashed_password.split('$')
        salt = binascii.unhexlify(salt_hex)
        iterations = int(iterations)
        
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        
        return binascii.hexlify(new_key).decode('utf-8') == key_hex
    except Exception:
        return False

#-------------------------------------------------------------------
# 4.  Database helper
#-------------------------------------------------------------------
def get_db_connection():
    return sqlite3.connect(DateBase_NAME,isolation_level=None)

#--------------------------------------------------------------------
# Paer2 : Database Initialization and Default User Creation (Task 1):
#--------------------------------------------------------------------

DEFAULT_USERS = [
    ("admin", "admin", "Admin"),
    ("commuter", "commuter", "Commuter"),
    ("planner", "planner", "Planner"),
]

def setup_database_schema(conn):
    """create users, stops, favourites datebase items"""
    cursor = conn.cursor()

# Task 1: Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            is_active INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
 # Task 5: Favourite Routes 
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS favourites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            route_id TEXT NOT NULL,
            UNIQUE(user_id, route_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS stops (
            stop_id TEXT PRIMARY KEY,
            stop_code TEXT,
            stop_name TEXT NOT NULL,
            stop_lat REAL,
            stop_lon REAL
        )
    """)
    cursor.execute("CREATE TABLE IF NOT EXISTS routes (route_id TEXT PRIMARY KEY, agency_id TEXT, route_short_name TEXT, route_long_name TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS trips (trip_id TEXT PRIMARY KEY, route_id TEXT, trip_headsign TEXT, direction_id INTEGER, shape_id TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS stop_times (trip_id TEXT, arrival_time TEXT, departure_time TEXT, stop_id TEXT, stop_sequence INTEGER)")
    cursor.execute("CREATE TABLE IF NOT EXISTS shapes (shape_id TEXT, shape_pt_lat REAL, shape_pt_lon REAL, shape_pt_sequence INTEGER)")
    
    conn.commit()

def initialize_default_users(conn):
    """Automatically create default users on the first run"""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        print("--- Creating USERS ---")
        users_to_insert = []
        for username, plain_password, role in DEFAULT_USERS:
            hashed_pw = hash_password(plain_password)
            users_to_insert.append((username, hashed_pw, role, 1))
        
        cursor.executemany("INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, ?, ?)", users_to_insert)
        conn.commit()
        print(f"--- Create {len(DEFAULT_USERS)} default USERS successfully. ---")
    else:
        print("--- Default users were not created because user accounts already exist in the database. ---")

def ensure_app_is_ready():
    """Main Initialization Process."""
    conn = get_db_connection()
    setup_database_schema(conn)
    initialize_default_users(conn)
    conn.close()
    
# Run initialization at startup
ensure_app_is_ready() 


#-------------------------------------------------
# Part 3: JWT Authentication and Login (Task 1)
#-------------------------------------------------
def token_required(allowed_roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                try:
                    token = request.headers['Authorization'].split(' ')[1]
                except:
                    return {'message': 'Invalid Token format'}, HTTPStatus.UNAUTHORIZED
            if not token:
                return {'message': 'Valid Token required.'}, HTTPStatus.UNAUTHORIZED

            try:
                data = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
                current_user_id = data['user_id']
                current_user_role = data['role']
                
                
                role_for_check = current_user_role.lower()

                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT is_active FROM users WHERE id=?", (current_user_id,))
                user_status = cursor.fetchone()
                conn.close()

            except jwt.ExpiredSignatureError:
                return {'message': 'Token is expired'}, HTTPStatus.UNAUTHORIZED
            except jwt.InvalidTokenError:
                return {'message': 'Invalid Token'}, HTTPStatus.UNAUTHORIZED
            except Exception as e: 
                 
                 print(f"DEBUG: Token decode error or KeyError: {e}")
                 return {'message': 'Invalid Token payload'}, HTTPStatus.UNAUTHORIZED


            
            if user_status is None or user_status[0] == 0:
                return {'message': 'Account is disabled or does not exist'}, HTTPStatus.FORBIDDEN
            
            
            if allowed_roles:
                
                allowed_roles_lower = [r.lower() for r in allowed_roles]
                
                if role_for_check not in allowed_roles_lower:
                    return {'message': 'Insufficient permissions'}, HTTPStatus.FORBIDDEN
                
            
            
            request.current_user = {'id': current_user_id, 'role': current_user_role}

            return f(current_user_id, *args, **kwargs)
        return decorated
    return decorator

# 3.2. Flask-RESTX Initialization and Login Endpoint (/auth/login)
app = Flask(__name__)
api = Api(app, 
          version='1.0', 
          title='NSW Bus Network GTFS API',
          description='RESTful API for Admin, Planners, and Commuters.',
          authorizations=authorizations, 
          security='Bearer Auth')

auth_ns = api.namespace('auth', description='Authentication')

login_input_model = api.model('Login', {
    'username': fields.String(required=True, description='User_name'),
    'password': fields.String(required=True, description='User_password', min_length=1)
})

@auth_ns.route('/login')
class UserLogin(Resource):
    @auth_ns.doc('user_login')
    @auth_ns.expect(login_input_model)
    def post(self):
        """User login in and get JWT Token"""
        data = request.json
        username = data.get('username')
        password = data.get('password')

        conn = None 
        user_data = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash, role, is_active FROM users WHERE username=?", (username,))
            user_data = cursor.fetchone()
        except Exception as e:
        
            raise 
        finally:
            if conn:
                conn.close()
        if user_data is None:
        
            return {'message': 'Incorrect username or password'}, HTTPStatus.UNAUTHORIZED

        user_id, hashed_pw, role, is_active = user_data
        
        if not check_password(password, hashed_pw):
            return {'message': 'Incorrect username or password'}, HTTPStatus.UNAUTHORIZED
            
        if not is_active:
            return {'message': 'Account is deactivated'}, HTTPStatus.FORBIDDEN
            
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=TOKEN_EXPIRATION_DAYS)
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
        
        return {'token': token, 'role': role}, HTTPStatus.OK


# ----------------------------------------------------
# PART 4: Admin User Management Endpoint (Task 1)
# ----------------------------------------------------
admin_ns = api.namespace('admin', description='Admin User Management operations (Admin Only)')

user_output_model = api.model('UserOutput', {
    'id': fields.Integer(readOnly=True),
    'username': fields.String(),
    'role': fields.String(enum=ALL_USERS),
    'is_active': fields.Boolean(),
    'created_at': fields.String(description='users create time')
})

new_user_input_model = api.model('NewUser', {
    'username': fields.String(required=True),
    'password': fields.String(required=True, min_length=1),
    'role': fields.String(required=True, enum=['Planner', 'Commuter'])
})

@admin_ns.route('/users')
class UserList(Resource):
    @admin_ns.doc('list_users', security='Bearer Auth', description='Admin can scan all users and their details.')
    @token_required(allowed_roles=['Admin'])
    @admin_ns.marshal_list_with(user_output_model)
    def get(self, current_user_id):
        """scan all users table and their details (Admin Only)"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, is_active, created_at FROM users.")
        users = [{'id': row[0], 'username': row[1], 'role': row[2], 'is_active': bool(row[3]), 'created_at': row[4]} for row in cursor.fetchall()]
        conn.close()
        return users, HTTPStatus.OK

    @admin_ns.doc('create_user', security='Bearer Auth', description='Admin can create new Planner or Commuter accounts')
    @token_required(allowed_roles=['Admin'])
    @admin_ns.expect(new_user_input_model, validate=True)
    def post(self, current_user_id):
        """Create Planner or Commuter (Admin Only)"""
        data = request.json
        username = data['username']
        role = data['role']
        plain_password = data['password']
        hashed_pw = hash_password(plain_password)
        conn = None 
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
            "INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, ?, 1)", 
                (username, hashed_pw, role)
            )
            user_id = cursor.lastrowid
            conn.commit()
        
            return {'message': f'User {username} ({role}) created successfully', 'id': user_id}, HTTPStatus.CREATED
        
        except sqlite3.IntegrityError:
            if conn: conn.rollback() 
            return {'message': f'Username {username} already exists'}, HTTPStatus.CONFLICT
        
        except Exception as error:
            if conn: conn.rollback()
            raise 
        finally:
            if conn:
                conn.close()


@admin_ns.route('/users/<int:user_id>') 
@admin_ns.param('user_id', 'The user identifier')
class UserDetail(Resource):
    @admin_ns.doc('delete_user', security='Bearer Auth', description='Admin can delete Planner or Commuter accounts but can not delete him self')
    @token_required(allowed_roles=['Admin'])
    @admin_ns.response(204, 'Delete successfully')
    def delete(self, current_user_id, user_id):
        """Delete Planner or Commuter (Admin Only)"""
        if current_user_id == user_id:
            return {'message': 'Current logged-in Admin account cannot be deleted'}, HTTPStatus.FORBIDDEN
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM users WHERE id=?", (user_id,))
            user_info = cursor.fetchone()
            if not user_info:
                return {'message': 'User not found'}, HTTPStatus.NOT_FOUND
        
            if user_info[0] == 'Admin':
            
                return {'message': 'Current logged-in Admin account cannot be deleted'}, HTTPStatus.FORBIDDEN
            
            cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.commit()
            return '', HTTPStatus.NO_CONTENT
        
        except Exception as error:
            if conn: conn.rollback()
            raise 
        finally:
            if conn:
                conn.close()


@admin_ns.route('/users/<int:user_id>/status')
@admin_ns.param('user_id', 'The user identifier')
@admin_ns.route('/users/<int:user_id>/status')
@admin_ns.param('user_id', 'The user identifier')
class UserActivation(Resource):
    status_input = api.model('StatusUpdate', {
        'action': fields.String(required=True, enum=['activate', 'deactivate'], description='Operation: activate or deactivate')
    })

    @admin_ns.doc('set_user_status', security='Bearer Auth', description='Admin can active or deactive Planner or Commuter account')
    @token_required(allowed_roles=['Admin'])
    @admin_ns.expect(status_input, validate=True)
    def put(self, current_user_id, user_id):
        """Toggle active status for a Planner or Commuter account (Admin Only)""" 
        action = request.json.get('action')
    
    
        if current_user_id == user_id:
            return {'message': 'Current logged-in Admin account cannot be modified'}, HTTPStatus.FORBIDDEN 

        new_status = 1 if action == 'activate' else 0
        conn = None 
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
        
            cursor.execute("SELECT role FROM users WHERE id=?", (user_id,))
            user_info = cursor.fetchone()
        
            if not user_info:
                return {'message': 'User not found'}, HTTPStatus.NOT_FOUND
            
    
            if user_info[0] == 'Admin':
            
                return {'message': 'Current logged-in Admin account cannot be modified'}, HTTPStatus.FORBIDDEN
            
            cursor.execute("UPDATE users SET is_active=? WHERE id=?", (new_status, user_id))
            conn.commit()
            return {'message': f'User status successfully updated to {action}d'}, HTTPStatus.OK

        except Exception as error:
            if conn: conn.rollback()
            raise 
        
        finally:
            if conn:
                conn.close()

# -------------------------------------------------------------
# Part 5: GTFS Data Import and Management (Task 2)
# -------------------------------------------------------------
gtfs_ns = api.namespace('gtfs', description='GTFS Data Import, Query and Visualization')

def download_and_store_gtfs_data(agency_id: str):
    """"Download the GTFS data for a specific agency_id and store it in SQLite using pandas"""
    if not API_KEY:
        return ValueError("The NSW_TRANSPORT_API_KEY environment variable is not set")
    
    full_url=f"{GTFS_BASE_URL}/buses/{agency_id}"
    headers={"Authorization": f"apikey {API_KEY}", "Accept": "application/zip"}
    
    print(f"--- Downloading GTFS data: {agency_id} ---")

    try:
        response=requests.get(full_url,headers=headers, stream=True, timeout=60)
        response.raise_for_status()
        print('Dowanload successfully.')

        data_frames={}
        count=0

        zip_content = io.BytesIO(response.content)

        GTFS_FILES_MAP = {
            'stops.txt': 'stops',
            'routes.txt': 'routes',
            'trips.txt': 'trips',
            'stop_times.txt': 'stop_times',
            'shapes.txt': 'shapes',
        }
        
        with zipfile.ZipFile(zip_content,'r') as zf:
            for gtfs_name,table_name in GTFS_FILES_MAP.items():
                if gtfs_name in zf.namelist():
                    print(f'  -> preparing  {gtfs_name} ')
                    with zf.open(gtfs_name) as file:
                        df = pandas.read_csv(file, low_memory=False)
                        if table_name in ['routes']:
                            df['agency_id'] = agency_id
                            
                        data_frames[table_name] = df 
                        count += len(df)
        

        if count==0:
            print("The downloaded ZIP file does not contain any importable GTFS files.")
        return data_frames,count
    except requests.exceptions.HTTPError as error1:
        error_msg = f"HTTP error {error1.response.status_code}: Unable to download GTFS data. Please check the Agency ID or API Key."
        raise Exception(error_msg)
    except Exception as error2:
        raise Exception(f"An error occurred while processing the GTFS data: {error2}")

@gtfs_ns.route('/import/<string:agency_id>')
@gtfs_ns.param('agency_id', 'The GTFS agency ID (e.g., GSBC001)')
class GTFSImport(Resource):
    @gtfs_ns.doc('import_agency_data', security='Bearer Auth', 
                 description="Admin or Planner imports GTFS data for the specified agency, and the data will replace existing data in the local database.")
    @token_required(allowed_roles=["Admin","planner"])
    
    def post(self,current_id, agency_id):
        if not agency_id.startswith(VALID_AGENCY_PREFIXES):
            return{'message': f"Invalid message. Message must start {','.join(VALID_AGENCY_PREFIXES)}."}, HTTPStatus.BAD_REQUEST
        
        conn = None 
        try:
            
            data_frames, total_rows = download_and_store_gtfs_data(agency_id)
            conn = get_db_connection()
            cursor = conn.cursor()
            print(f"--- Deleting existing data for Agency ID: {agency_id} ---")

            cursor.execute("""
                DELETE FROM stop_times 
                WHERE trip_id IN (
                    SELECT trip_id FROM trips WHERE route_id IN (
                        SELECT route_id FROM routes WHERE agency_id=?
                    )
                )
            """, (agency_id,))
            
            
            cursor.execute("DELETE FROM trips WHERE route_id IN (SELECT route_id FROM routes WHERE agency_id=?)", (agency_id,))

            cursor.execute("DELETE FROM routes WHERE agency_id=?", (agency_id,))
            
            
            
            print("--- Importing new data ---")
            for table_name, df in data_frames.items():
                
                df.to_sql(table_name, conn, if_exists='append', index=False)
                
            conn.commit() 
            
            return {
                'message': F'Import agency id= {agency_id} successfully. Existing data was replaced. A total of {total_rows} records were imported.',
                'agency_id': agency_id
                }, HTTPStatus.OK
        except Exception as error:
            if conn:
                conn.rollback()
            return {'message': str(error)}, HTTPStatus.INTERNAL_SERVER_ERROR
        finally:
            if conn:
                conn.close()


# ----------------------------------------------------
# PART 6: Search GTFS data (Task 3)
# ----------------------------------------------------
route_model = api.model('Route', {
    'route_id': fields.String, 'agency_id': fields.String,
    'route_short_name': fields.String, 'route_long_name': fields.String,
})
trip_model = api.model('Trip', {
    'trip_id': fields.String, 'route_id': fields.String,
    'trip_headsign': fields.String, 'direction_id': fields.Integer,
})
stop_model = api.model('Stop', {
    'stop_id': fields.String, 'stop_code': fields.String,
    'stop_name': fields.String, 'stop_lat': fields.Float, 'stop_lon': fields.Float,
})
stop_times_model = api.model('StopTime', {
    'trip_id': fields.String, 'arrival_time': fields.String,
    'departure_time': fields.String, 'stop_id': fields.String, 'stop_sequence': fields.Integer,
})


def get_pagination_params():
    """Parse page and page_size from request parameters and apply security limits."""
    try:
        page = max(1, request.args.get('page', 1, type=int))
        page_size = min(MAX_PAGE_SIZE, max(1, request.args.get('page_size', DEFAULT_PAGE_SIZE, type=int)))
        offset = (page - 1) * page_size
        return page, page_size, offset
    except ValueError:
        gtfs_ns.abort(HTTPStatus.BAD_REQUEST, "Page or page_size must be positive integers.")

@gtfs_ns.route('/routes/<string:route_id>')
@gtfs_ns.param('route_id', 'The ID of the route')
class RouteResource(Resource):
    @gtfs_ns.doc('get_route_by_id', description='All users can retrieve information for a specific Route.')
    @gtfs_ns.marshal_with(route_model)
    def get(self, route_id):
        """Search specific Route information"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT route_id, agency_id, route_short_name, route_long_name FROM routes WHERE route_id=?", (route_id,))
        route = cursor.fetchone()
        conn.close()
        
        if not route:
            gtfs_ns.abort(HTTPStatus.NOT_FOUND, f"Route ID {route_id} not found. Ensure agency data is imported.")
            
        return dict(zip(['route_id', 'agency_id', 'route_short_name', 'route_long_name'], route)), HTTPStatus.OK



@gtfs_ns.route('/trips/<string:trip_id>')
@gtfs_ns.param('trip_id', 'The ID of the trip')
class TripResource(Resource):
    @gtfs_ns.doc('get_trip_by_id', description='All users can retrieve information for a specific Trip.')
    @token_required(allowed_roles=ALL_USERS) 
    @gtfs_ns.marshal_with(trip_model)
   
    @gtfs_ns.response(404, 'Trip ID not found. Ensure agency data is imported.')
    
    def get(self, trip_id):
        """Retrieve information for a specific Trip (All Users)""" 
        conn = None 
        trip = None
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT trip_id, route_id, trip_headsign, direction_id FROM trips WHERE trip_id=?", (trip_id,))
            trip = cursor.fetchone()

        except Exception as error:
            gtfs_ns.abort(HTTPStatus.INTERNAL_SERVER_ERROR, f"Database query failed: {str(error)}")
        finally:
            if conn:
                conn.close()
        if not trip:
            gtfs_ns.abort(HTTPStatus.NOT_FOUND, f"Trip ID {trip_id} not found. Ensure agency data is imported.")
            
        return dict(zip(['trip_id', 'route_id', 'trip_headsign', 'direction_id'], trip)), HTTPStatus.OK

@gtfs_ns.route('/stops/<string:stop_id>') 
@gtfs_ns.param('stop_id', 'The ID of the stop')
class StopResource(Resource):
    @gtfs_ns.doc('get_stop_by_id', description='All users can retrieve information for a specific Stop.')
    @token_required(allowed_roles=ALL_USERS) 
    
    @gtfs_ns.response(404, 'Stop ID not found. Ensure agency data is imported.')
    
    def get(self, stop_id):
        """Retrieve information for a specific Stop (All Users)""" 
        conn = None 
        stop = None
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT stop_id,stop_code,stop_name, stop_lat, stop_lon FROM stops WHERE stop_id=?", (stop_id,))
            stop = cursor.fetchone()
            
        except Exception as error:
            gtfs_ns.abort(HTTPStatus.INTERNAL_SERVER_ERROR, f"Database query failed: {str(error)}")
        finally:
            if conn:
                conn.close()
        if not stop:
            gtfs_ns.abort(HTTPStatus.NOT_FOUND, f"Stop ID {stop_id} not found. Ensure agency data is imported.")
        return dict(zip(['stop_id', 'stop_code','stop_name', 'stop_lat','stop_lon'], stop)), HTTPStatus.OK


pagination_headers = {
    'X-Total-Count': fields.String(description='Total number of records matching the query'),
    'X-Page': fields.String(description='Current page number'),
    'X-Page-Size': fields.String(description='Number of items per page'),
}
@gtfs_ns.route('/agency/<string:agency_id>/routes')
@gtfs_ns.param('agency_id', 'The ID of the agency')
class AgencyRoutesList(Resource):
    @gtfs_ns.doc('get_routes_by_agency',  
                 description='All users can retrieve all Routes for a specific Agency, with pagination support.')
    @gtfs_ns.param('page', 'Page number for pagination', type=int)
    @gtfs_ns.param('page_size', f'Items per page (Max {MAX_PAGE_SIZE})', type=int)
    @token_required(allowed_roles=ALL_USERS)
    @gtfs_ns.marshal_list_with(route_model)

    @gtfs_ns.marshal_list_with(trip_model)
    @gtfs_ns.response(200, 'Success', headers=pagination_headers) 
    @gtfs_ns.response(404, 'No Trips found for the specified Route ID.') 
    
    def get(self, route_id):
        """Search all paginated Trips associated with a specific Route ID (All Users)""" 
        page, page_size, offset = get_pagination_params() 
        conn = None 
        total_count = 0
        result_list = []
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM trips WHERE route_id=?", (route_id,))
            total_count = cursor.fetchone()[0]
            
            SQL = """
            SELECT trip_id, route_id, trip_headsign, direction_id 
            FROM trips 
            WHERE route_id=?
            ORDER BY trip_id
            LIMIT ? OFFSET ?
            """
            cursor.execute(SQL, (route_id, page_size, offset))
            trips_data = cursor.fetchall() 
            keys = ['trip_id', 'route_id', 'trip_headsign', 'direction_id']
            result_list = [dict(zip(keys, row)) for row in trips_data]
            
        except Exception as error:
            gtfs_ns.abort(HTTPStatus.INTERNAL_SERVER_ERROR, f"Database query failed: {str(error)}")
            
        finally:
            if conn:
                conn.close()
        if total_count == 0:
             gtfs_ns.abort(HTTPStatus.NOT_FOUND, f"No Trips found for Route ID {route_id}.")
        response_headers = {
            'X-Total-Count': str(total_count), 'X-Page': str(page), 'X-Page-Size': str(page_size),
        }
        return result_list, HTTPStatus.OK, response_headers



pagination_headers = {
    'X-Total-Count': fields.String(description='Total number of records matching the query'),
    'X-Page': fields.String(description='Current page number'),
    'X-Page-Size': fields.String(description='Number of items per page'),
}
@gtfs_ns.route('/routes/<string:route_id>/trips')
@gtfs_ns.param('route_id', 'The ID of the route to retrieve trips for')
class RouteTripsResource(Resource): 
    @gtfs_ns.doc('get_trips_for_route', 
                 description='All users can retrieve a paginated list of Trips for a specific Route.')
    @gtfs_ns.param('page', 'Page number for pagination (default: 1)', type=int)
    @gtfs_ns.param('page_size', f'Number of trips per page (Max {MAX_PAGE_SIZE})', type=int)
    @token_required(allowed_roles=ALL_USERS)
    
    @gtfs_ns.marshal_list_with(trip_model) 
    @gtfs_ns.response(200, 'Success', headers=pagination_headers)
    @gtfs_ns.response(404, 'No Trips found for the specified Route ID.')
    
    def get(self, route_id):
        """Retrieve all paginated Trips associated with a specific Route ID (All Users)""" 
        page, page_size, offset = get_pagination_params() 
        conn = None
        total_count = 0
        result_list = []
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM trips WHERE route_id=?", (route_id,))
            total_count = cursor.fetchone()[0]
            
            SQL = """
            SELECT trip_id, route_id, trip_headsign, direction_id 
            FROM trips 
            WHERE route_id=?
            ORDER BY trip_id
            LIMIT ? OFFSET ?
            """
            cursor.execute(SQL, (route_id, page_size, offset))
            trips_data = cursor.fetchall() 
            keys = ['trip_id', 'route_id', 'trip_headsign', 'direction_id']
            result_list = [dict(zip(keys, row)) for row in trips_data]
        except Exception as error:
            gtfs_ns.abort(HTTPStatus.INTERNAL_SERVER_ERROR, f"Database query failed: {str(error)}")
        finally:
            if conn:
                conn.close()
        if total_count == 0:
             gtfs_ns.abort(HTTPStatus.NOT_FOUND, f"No Trips found for Route ID {route_id}.")
            
        response_headers = {
            'X-Total-Count': str(total_count), 'X-Page': str(page), 'X-Page-Size': str(page_size),
        }
        return result_list, HTTPStatus.OK, response_headers


pagination_headers = {
    'X-Total-Count': fields.String(description='Total number of records matching the query'),
    'X-Page': fields.String(description='Current page number'),
    'X-Page-Size': fields.String(description='Number of items per page'),
}
@gtfs_ns.route('/trips/<string:trip_id>/stop_times')
@gtfs_ns.param('trip_id', 'The ID of the trip to retrieve all stop times for')
class TripStopTimesResource(Resource): 
    @gtfs_ns.doc('get_all_stop_times_for_trip', 
                  description='All users can retrieve a paginated list of Stop Times for a specific Trip.')
    @gtfs_ns.param('page', 'Page number (for pagination)', type=int) 
    @gtfs_ns.param('page_size', f'Number of items per page (Max {MAX_PAGE_SIZE})', type=int) 
    @token_required(allowed_roles=ALL_USERS) 
    
    
    @gtfs_ns.marshal_list_with(stop_times_model) 
    @gtfs_ns.response(200, 'Success', headers=pagination_headers) 
    
    @gtfs_ns.response(404, 'No Stop Times found for the specified Trip ID.')
    
    def get(self, trip_id):
        """Retrieve all paginated Stop Times for a specific Trip ID (All Users)""" 
        page, page_size, offset = get_pagination_params() 
        conn = None 
        total_count = 0
        result_list = []

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM stop_times WHERE trip_id=?", (trip_id,))
            total_count = cursor.fetchone()[0]
            
            SQL_QUERY = """
            SELECT trip_id, arrival_time, departure_time, stop_id, stop_sequence 
            FROM stop_times 
            WHERE trip_id=? 
            ORDER BY stop_sequence
            LIMIT ? OFFSET ? 
            """
            cursor.execute(SQL_QUERY, (trip_id, page_size, offset)) 
            stop_times_data = cursor.fetchall()
            
            keys = ['trip_id', 'arrival_time', 'departure_time', 'stop_id', 'stop_sequence']
            result_list = [dict(zip(keys, row)) for row in stop_times_data]
            
        except Exception as error:
            gtfs_ns.abort(HTTPStatus.INTERNAL_SERVER_ERROR, f"Database query failed: {str(error)}")
        finally:
            if conn:
                conn.close()
        
        if total_count == 0:
            gtfs_ns.abort(HTTPStatus.NOT_FOUND, f"No Stop Times found for Trip ID {trip_id}.") 
            
        response_headers = {
            'X-Total-Count': str(total_count), 'X-Page': str(page), 'X-Page-Size': str(page_size),
        }
        return result_list, HTTPStatus.OK, response_headers


#--------------------------------------------------------------
# Part 7 Tsak 4 Search by name
#--------------------------------------------------------------
associated_route_model = api.model('AssociatedRoute', {
    'route_id': fields.String, 'route_name': fields.String(attribute='route_long_name'),
    'trip_id': fields.String, 'trip_headsign': fields.String,
})

search_stops_model = api.model('StopSearchResult', {
    'stop_id': fields.String, 'stop_name': fields.String,
    'score': fields.Float(description='RapidFuzz Match Score (0-100)'),
    'associated_services': fields.List(fields.Nested(associated_route_model)),
})
@gtfs_ns.route('/search/stops')
class StopSearchResource(Resource):
    @gtfs_ns.doc('search_stops', 
                  description='All users can fuzzily search for Stops by name and retrieve the associated Routes and Trips. Use RapidFuzz.')
    @gtfs_ns.param('q', 'The stop name query (e.g., Kingswood Station)', required=True)
    @gtfs_ns.param('threshold', 'Minimum RapidFuzz score threshold (e.g., 80)', type=int)
    @gtfs_ns.marshal_list_with(search_stops_model)
    
    @gtfs_ns.response(400, "Search query 'q' cannot be empty and must contain at least 3 characters.")
    @gtfs_ns.response(404, "No matching stops found.")
    def get(self):
        """Fuzzy Stop Search (Task 4, All Users)""" 
        query = request.args.get('q')
        threshold = request.args.get('threshold', 80, type=int) 
        
        if not query or len(query.strip()) < 3:
            gtfs_ns.abort(HTTPStatus.BAD_REQUEST, "Search query 'q' cannot be empty and must contain at least 3 characters.")
            
        conn = None 
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT stop_id, stop_name FROM stops")
            all_stops_data = cursor.fetchall()
            stop_names = [data[1] for data in all_stops_data]
            stop_map = {data[1]: data[0] for data in all_stops_data} 
            
            matches = process.extract(
                query, stop_names, scorer=fuzz.WRatio, limit=50, score_cutoff=threshold
            )
            
            final_results = []
            for name_match, score, index in matches:
                stop_id = stop_map.get(name_match)
                if not stop_id: continue
                
                cursor.execute(
                    """
                    SELECT DISTINCT
                        t.trip_id, t.trip_headsign, r.route_id, r.route_long_name
                    FROM stop_times st
                    JOIN trips t ON st.trip_id = t.trip_id
                    JOIN routes r ON t.route_id = r.route_id
                    WHERE st.stop_id = ?
                    LIMIT 100
                    """,
                    (stop_id,)
                )
                associated_services = [
                    dict(zip(['trip_id', 'trip_headsign', 'route_id', 'route_long_name'], row))
                    for row in cursor.fetchall()
                ]
                
                final_results.append({
                    'stop_id': stop_id, 'stop_name': name_match, 'score': round(score, 2),
                    'associated_services': associated_services
                })
        
        except Exception as error:
            gtfs_ns.abort(HTTPStatus.INTERNAL_SERVER_ERROR, f"Search failed due to internal error: {str(error)}")
            
        finally:
            if conn:
                conn.close()
        if not final_results:
             gtfs_ns.abort(HTTPStatus.NOT_FOUND, 'No matching stops found.')
        return final_results, HTTPStatus.OK

#-----------------------------------------------------------------
# Part 8 Task 5 Favourite list
#-----------------------------------------------------------------
favourite_input_model = api.model('FavouriteRouteInput', {'route_id': fields.String(required=True, description='favourite route ID')})
favourite_output_model = api.model('FavouriteRouteOutput', {
    'id': fields.Integer(readOnly=True), 'route_id': fields.String,
    'route_short_name': fields.String, 'route_long_name': fields.String
})
favourites_ns = api.namespace('favourites', description='Favourite Routes Management (All Users)')

@favourites_ns.route('')
class FavouriteList(Resource):
    @favourites_ns.doc('list_favourites', security='Bearer Auth', description='All users can scan their favourite list.')
    @token_required(allowed_roles=ALL_USERS)
    @favourites_ns.marshal_list_with(favourite_output_model)
    def get(self, user_id):
        """Retrieve the Current User's List of Favourite Routes (Task 5)"""
        conn = None 
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT f.id, f.route_id, r.route_short_name, r.route_long_name 
                FROM favourites f LEFT JOIN routes r ON f.route_id = r.route_id
                WHERE f.user_id = ?
                """, (user_id,)
            )
            favourites = [
                dict(zip(['id', 'route_id', 'route_short_name', 'route_long_name'], row)) 
                for row in cursor.fetchall()
            ]
            
            return favourites, HTTPStatus.OK
            
        except Exception as error:
            raise 
            
        finally:
            if conn:
                conn.close()
   
    def post(self, user_id):
        """Create a new favourite route entry (Task 5)"""
        route_id = request.json.get('route_id')
        conn = None 
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM favourites WHERE user_id = ?", (user_id,))
            current_count = cursor.fetchone()[0]
            
            if current_count >= MAX_FAVOURITES:
                return {'message': f'You have reached the limit  ({MAX_FAVOURITES}for saved routes ).'}, HTTPStatus.FORBIDDEN
            
            
            cursor.execute("SELECT route_id FROM routes WHERE route_id = ?", (route_id,))
            if cursor.fetchone() is None:
                return {'message': f'Route ID {route_id} does not exist in the imported GTFS data.'}, HTTPStatus.NOT_FOUND
                
            
            cursor.execute("INSERT INTO favourites (user_id, route_id) VALUES (?, ?)", (user_id, route_id))
            new_fav_id = cursor.lastrowid
            conn.commit()
            return {'message': f'Route {route_id} saved successfully.', 'id': new_fav_id}, HTTPStatus.CREATED
            
        except sqlite3.IntegrityError:
            if conn: conn.rollback()
            return {'message': f'Route {route_id} has been saved'}, HTTPStatus.CONFLICT
        
        except Exception as error:
            if conn: conn.rollback()
            raise 
        finally:
            if conn:
                conn.close()

@favourites_ns.route('/<int:fav_id>')
@favourites_ns.param('fav_id', 'The ID of the favourite record')
class FavouriteResource(Resource):
    @favourites_ns.doc('delete_favourite', security='Bearer Auth', description='All Users can delete their favoureta list.')
    @token_required(allowed_roles=ALL_USERS)
    def delete(self, user_id, fav_id):
        """Delete one favourite item"""
        conn = None 
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM favourites WHERE id = ? AND user_id = ?", (fav_id, user_id))
        
            if cursor.rowcount == 0:
                return {'message': 'Favourite record not found or you are not authorized to delete it'}, HTTPStatus.NOT_FOUND
            conn.commit()
            return '', HTTPStatus.NO_CONTENT
            
        except Exception as error:
            if conn:
                conn.rollback()
            raise 
            
        finally:
            if conn:
                conn.close()

# ----------------------------------------------------
# PART 9: Visualization and Data Export (Task 6)
# ----------------------------------------------------
@gtfs_ns.route('/export/routes/<string:agency_id>')
@gtfs_ns.param('agency_id', 'The ID of the agency to export routes for')
class RouteExport(Resource):
    @gtfs_ns.doc('export_routes_csv', security='Bearer Auth', 
                 description='The Planner can export all Route data for a specific Agency to a CSV file')
    @token_required(allowed_roles=['Planner'])
    def get(self, agency_id): 
        """Export Routes Data for a Specific Agency as CSV (Planner Only)"""
        conn = None 
        try:
            conn = get_db_connection()
            sql_query = "SELECT * FROM routes WHERE agency_id=?"
            routes_df = pandas.read_sql_query(sql_query, conn, params=(agency_id,))
            
        except Exception as error:
            gtfs_ns.abort(HTTPStatus.INTERNAL_SERVER_ERROR, f"Database query or export failed: {str(error)}")
            
        finally:
            if conn:
                conn.close()

        if routes_df.empty:
            gtfs_ns.abort(HTTPStatus.NOT_FOUND, f"No Routes data found for Agency ID {agency_id}.")

        output = io.StringIO()
        routes_df.to_csv(output, index=False)
        output.seek(0)
        
        buffer = io.BytesIO(output.getvalue().encode('utf-8'))

        return send_file(
            buffer,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'routes_{agency_id}_{datetime.datetime.now().strftime("%Y%m%d%H%M%S")}.csv'
        )


@gtfs_ns.route('/visualize/favourites')
class FavouriteVisualization(Resource):
    @gtfs_ns.doc('visualize_favourites', security='Bearer Auth', 
                 description='All users can generate a map visualizing the shape of their favourite routes, returning a PNG byte stream.')
    @token_required(allowed_roles=ALL_USERS) 
    def get(self, user_id): 
        """Generate Favourite Routes Map Visualization (All Users)"""
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT route_id FROM favourites WHERE user_id = ?", (user_id,))
            route_ids = [row[0] for row in cursor.fetchall()]

            if not route_ids:
                return {'message': 'User has no favourite routes; map generation failed.'}, HTTPStatus.NOT_FOUND

            route_placeholders = ','.join('?' * len(route_ids))
            cursor.execute(
                f"SELECT DISTINCT t.shape_id FROM trips t WHERE t.route_id IN ({route_placeholders}) AND t.shape_id IS NOT NULL", 
                route_ids
            )
            shape_ids = [row[0] for row in cursor.fetchall()]
            
            if not shape_ids:
                return {'message': 'Shape data missing for the favourited routes.'}, HTTPStatus.NOT_FOUND

            
            shape_placeholders = ','.join('?' * len(shape_ids))
            
            cursor.execute(
                f"""
                SELECT 
                    s.shape_pt_lat, s.shape_pt_lon, r.route_short_name
                FROM shapes s
                JOIN trips t ON s.shape_id = t.shape_id
                JOIN routes r ON t.route_id = r.route_id
                WHERE s.shape_id IN ({shape_placeholders})
                ORDER BY s.shape_id, s.shape_pt_sequence
                """,
                shape_ids
            )
            full_shape_data = cursor.fetchall()
            
            routes_to_plot = {}
            for lat, lon, name in full_shape_data:
                if name not in routes_to_plot:
                    routes_to_plot[name] = {'lats': [], 'lons': []}
                routes_to_plot[name]['lats'].append(lat)
                routes_to_plot[name]['lons'].append(lon)

            plt.switch_backend('Agg') 
            fig, ax = plt.subplots(figsize=(10, 10))
            colors = list(mcolors.TABLEAU_COLORS.keys()) 
            
            for i, (name, data) in enumerate(routes_to_plot.items()):
                color = mcolors.TABLEAU_COLORS[colors[i % len(colors)]]
                ax.plot(data['lons'], data['lats'], marker='', linestyle='-', linewidth=2, alpha=0.7,
                         color=color, label=f'Route {name}')

            ax.set_title(f"User {user_id}'s Favourite Routes Visualization")
            ax.legend(loc='best', fontsize='small')
            ax.set_aspect('equal', adjustable='box') 
            
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png', bbox_inches='tight')
            plt.close(fig)
            img_buffer.seek(0)

            return send_file(
                img_buffer,
                mimetype='image/png',
                as_attachment=False
            )
            
        except Exception as error:
            gtfs_ns.abort(HTTPStatus.INTERNAL_SERVER_ERROR, f"Fail to create a map: {str(error)}")
        finally:
            if conn:
                conn.close()


if __name__ == '__main__':
    app.run(debug=True)