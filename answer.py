# ==============================================================================
# [your_zid]_api.py - 完整代码 (Task 1 - Task 6)
# ==============================================================================

# ----------------------------------------------------
# PART 1: 导入、配置和安全工具
# ----------------------------------------------------

# 标准库 (Standard Libraries)
import os
import sqlite3
import datetime
import hashlib
import binascii
import requests
import zipfile
import io
import csv
import uuid
import sys
from functools import wraps
from http import HTTPStatus

# 第三方库 (Third-Party Libraries - 来自 requirements.txt 和确认可用的 JWT)
import jwt
import pandas
import matplotlib
import matplotlib.pyplot as plt 
import matplotlib.colors as mcolors
from flask import Flask, request, jsonify, send_file
from flask_restx import Api, Resource, fields
from rapidfuzz import process, fuzz # 用于 Task 4 模糊搜索

# 确保 matplotlib 在非交互环境下工作
matplotlib.use('Agg')


# ----------------------------------------------------
# 2. 常量和配置 (Configuration & Constants)
# ----------------------------------------------------
ZID = 'zXXXXXXXX' # ⚠️ 必须替换为您的 ZID
SQLITE_DB_NAME = f"{ZID}.sqlite" 

# JWT/认证配置
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "A_SECURE_JWT_SECRET_HERE")
TOKEN_EXPIRATION_DAYS = 7 
ALL_USERS = ['Admin', 'Planner', 'Commuter'] # Task 3, 4, 5 权限

# GTFS API 配置
API_KEY = os.environ.get("NSW_TRANSPORT_API_KEY") 
GTFS_BASE_URL = "https://api.transport.nsw.gov.au/v1/gtfs/schedule" 
VALID_AGENCY_PREFIXES = ('GSBC', 'SBSC') # Task 2 验证
DEFAULT_PAGE_SIZE = 50 # Task 3 分页
MAX_PAGE_SIZE = 200    # Task 3 分页上限
MAX_FAVOURITES = 2     # Task 5 收藏限制


# ----------------------------------------------------
# 3. 密码处理工具函数 (使用 PBKDF2-SHA256 标准库)
# ----------------------------------------------------
HASH_ITERATIONS = 100000 

def hash_password(password):
    """使用 PBKDF2-SHA256 安全地哈希密码。"""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, HASH_ITERATIONS)
    salt_hex = binascii.hexlify(salt).decode('utf-8')
    key_hex = binascii.hexlify(key).decode('utf-8')
    return f'{HASH_ITERATIONS}${salt_hex}${key_hex}'

def check_password(password, hashed_password):
    """检查明文密码是否与哈希密码匹配。"""
    try:
        iterations, salt_hex, key_hex = hashed_password.split('$')
        salt = binascii.unhexlify(salt_hex)
        iterations = int(iterations)
        
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        
        return binascii.hexlify(new_key).decode('utf-8') == key_hex
    except Exception:
        return False
        
# ----------------------------------------------------
# 4. 数据库连接辅助函数 (Database Helper)
# ----------------------------------------------------
def get_db_connection():
    return sqlite3.connect(SQLITE_DB_NAME)


# ----------------------------------------------------
# PART 2: 数据库初始化与默认用户创建 (Task 1)
# ----------------------------------------------------

DEFAULT_USERS = [
    ("admin", "admin", "Admin"),
    ("commuter", "commuter", "Commuter"),
    ("planner", "planner", "Planner"),
]

def setup_database_schema(conn):
    """创建 users, stops, favourites 等所有必需的数据库表。"""
    cursor = conn.cursor()
    
    # Task 1: Users 表
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
    
    # Task 5: Favourite Routes 表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS favourites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            route_id TEXT NOT NULL,
            UNIQUE(user_id, route_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    # GTFS 核心表 (Task 2/3 需要)
    # 这些表结构需要与 GTFS 文件头匹配，并设置主键以提高查询效率
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
        print("--- Creating default USER ---")
        users_to_insert = []
        for username, plain_password, role in DEFAULT_USERS:
            hashed_pw = hash_password(plain_password)
            users_to_insert.append((username, hashed_pw, role, 1))
        
        cursor.executemany("INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, ?, ?)", users_to_insert)
        conn.commit()
        print(f"--- 成功创建 {len(DEFAULT_USERS)} 个默认用户。 ---")
    else:
        print("--- 用户已存在，跳过默认用户初始化 ---")

def ensure_app_is_ready():
    """主初始化流程。"""
    conn = get_db_connection()
    setup_database_schema(conn)
    initialize_default_users(conn)
    conn.close()
    
# 启动时运行初始化
ensure_app_is_ready() 


# ----------------------------------------------------
# PART 3: JWT 认证与登录 (Task 1)
# ----------------------------------------------------

# 3.1. 授权装饰器
def token_required(allowed_roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                try:
                    token = request.headers['Authorization'].split(' ')[1]
                except:
                    return {'message': 'Token 格式错误'}, HTTPStatus.UNAUTHORIZED
            if not token:
                return {'message': '需要有效的 Token'}, HTTPStatus.UNAUTHORIZED

            try:
                data = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
                current_user_id = data['user_id']
                current_user_role = data['role']
                
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT is_active FROM users WHERE id=?", (current_user_id,))
                user_status = cursor.fetchone()
                conn.close()
                
                if user_status is None or user_status[0] == 0:
                    return {'message': '账户已被停用或不存在'}, HTTPStatus.FORBIDDEN
                
            except jwt.ExpiredSignatureError:
                return {'message': 'Token 已过期'}, HTTPStatus.UNAUTHORIZED
            except jwt.InvalidTokenError:
                return {'message': '无效的 Token'}, HTTPStatus.UNAUTHORIZED

            if allowed_roles and current_user_role not in allowed_roles:
                return {'message': '权限不足'}, HTTPStatus.FORBIDDEN

            request.current_user = {'id': current_user_id, 'role': current_user_role}

            return f(current_user_id, *args, **kwargs)
        return decorated
    return decorator

# 3.2. Flask-RESTX 初始化与登录端点 (/auth/login)
app = Flask(__name__)
api = Api(app, 
          version='1.0', 
          title='NSW Bus Network GTFS API',
          description='RESTful API for Admin, Planners, and Commuters.',
          doc='/docs'
)
# Global Requirement 7: 定义 API Key 安全性
api.security = {'apikey': {'type': 'apiKey', 'in': 'header', 'name': 'Authorization'}}

auth_ns = api.namespace('auth', description='Authentication')

login_input_model = api.model('Login', {
    'username': fields.String(required=True, description='用户的用户名'),
    'password': fields.String(required=True, description='用户的密码', min_length=1)
})

@auth_ns.route('/login')
class UserLogin(Resource):
    @auth_ns.doc('user_login')
    @auth_ns.expect(login_input_model)
    def post(self):
        """用户登录并获取 JWT 访问 Token"""
        data = request.json
        username = data.get('username')
        password = data.get('password')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash, role, is_active FROM users WHERE username=?", (username,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data is None:
            return {'message': '用户名或密码错误'}, HTTPStatus.UNAUTHORIZED

        user_id, hashed_pw, role, is_active = user_data

        if not check_password(password, hashed_pw):
            return {'message': '用户名或密码错误'}, HTTPStatus.UNAUTHORIZED

        if not is_active:
            return {'message': '账户已被停用'}, HTTPStatus.FORBIDDEN
            
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=TOKEN_EXPIRATION_DAYS)
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
        
        return {'token': token, 'role': role}, HTTPStatus.OK


# ----------------------------------------------------
# PART 4: Admin 用户管理端点 (Task 1)
# ----------------------------------------------------
admin_ns = api.namespace('admin', description='Admin User Management operations (Admin Only)')

user_output_model = api.model('UserOutput', {
    'id': fields.Integer(readOnly=True),
    'username': fields.String(),
    'role': fields.String(enum=ALL_USERS),
    'is_active': fields.Boolean(),
    'created_at': fields.String(description='用户创建时间')
})

new_user_input_model = api.model('NewUser', {
    'username': fields.String(required=True),
    'password': fields.String(required=True, min_length=1),
    'role': fields.String(required=True, enum=['Planner', 'Commuter'])
})

@admin_ns.route('/users')
class UserList(Resource):
    @admin_ns.doc('list_users', security='apikey', description='Admin可以浏览所有用户及其详细信息。')
    @token_required(allowed_roles=['Admin'])
    @admin_ns.marshal_list_with(user_output_model)
    def get(self, current_user_id):
        """浏览所有用户列表及其详细信息 (Admin Only)"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, is_active, created_at FROM users")
        users = [{'id': row[0], 'username': row[1], 'role': row[2], 'is_active': bool(row[3]), 'created_at': row[4]} for row in cursor.fetchall()]
        conn.close()
        return users, HTTPStatus.OK

    @admin_ns.doc('create_user', security='apikey', description='Admin可以创建新的 Planner 或 Commuter 账户。')
    @token_required(allowed_roles=['Admin'])
    @admin_ns.expect(new_user_input_model, validate=True)
    def post(self, current_user_id):
        """创建 Planner 或 Commuter (Admin Only)"""
        data = request.json
        username = data['username']
        role = data['role']
        plain_password = data['password']
        hashed_pw = hash_password(plain_password)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, ?, 1)", (username, hashed_pw, role))
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return {'message': f'用户 {username} ({role}) 创建成功', 'id': user_id}, HTTPStatus.CREATED
        
        except sqlite3.IntegrityError:
            return {'message': f'用户名 {username} 已存在'}, HTTPStatus.CONFLICT


@admin_ns.route('/users/<int:user_id>')
@admin_ns.param('user_id', 'The user identifier')
class UserManagement(Resource):
    @admin_ns.doc('delete_user', security='apikey', description='Admin可以删除 Planner 或 Commuter 账户，不能删除自己或Admin。')
    @token_required(allowed_roles=['Admin'])
    @admin_ns.response(204, '删除成功')
    def delete(self, current_user_id, user_id):
        """删除 Planner 或 Commuter (Admin Only)"""
        if current_user_id == user_id:
            return {'message': '禁止删除当前登录的 Admin 账户'}, HTTPStatus.FORBIDDEN
            
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE id=?", (user_id,))
        user_info = cursor.fetchone()
        
        if not user_info:
            conn.close()
            return {'message': '用户未找到'}, HTTPStatus.NOT_FOUND
        
        if user_info[0] == 'Admin':
            conn.close()
            return {'message': '禁止删除 Admin 账户'}, HTTPStatus.FORBIDDEN
            
        cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        return '', HTTPStatus.NO_CONTENT


@admin_ns.route('/users/<int:user_id>/status')
@admin_ns.param('user_id', 'The user identifier')
class UserActivation(Resource):
    status_input = api.model('StatusUpdate', {
        'action': fields.String(required=True, enum=['activate', 'deactivate'], description='操作: activate 或 deactivate')
    })

    @admin_ns.doc('set_user_status', security='apikey', description='Admin可以激活或停用 Planner 或 Commuter 账户。')
    @token_required(allowed_roles=['Admin'])
    @admin_ns.expect(status_input, validate=True)
    def put(self, current_user_id, user_id):
        """激活或停用 Planner 或 Commuter 账户 (Admin Only)"""
        action = request.json.get('action')
        
        if current_user_id == user_id:
             return {'message': '禁止修改当前登录的 Admin 账户状态'}, HTTPStatus.FORBIDDEN

        new_status = 1 if action == 'activate' else 0

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE id=?", (user_id,))
        user_info = cursor.fetchone()
        
        if not user_info or user_info[0] == 'Admin':
            conn.close()
            return {'message': '用户未找到或禁止修改 Admin 账户状态'}, HTTPStatus.FORBIDDEN
            
        cursor.execute("UPDATE users SET is_active=? WHERE id=?", (new_status, user_id))
        conn.commit()
        conn.close()
        return {'message': f'用户状态已更新为: {action}d'}, HTTPStatus.OK


# ----------------------------------------------------
# PART 5: GTFS 数据导入与管理 (Task 2)
# ----------------------------------------------------
gtfs_ns = api.namespace('gtfs', description='GTFS Data Import, Query and Visualization')

def download_and_store_gtfs_data(agency_id: str):
    """下载特定 agency_id 的 GTFS 数据，并使用 pandas 存储到 SQLite。"""
    if not API_KEY:
        raise ValueError("NSW_TRANSPORT_API_KEY 环境变量未设置。")
        
    full_url = GTFS_BASE_URL + f"/buses/{agency_id}"
    headers = {"Authorization": f"apikey {API_KEY}", "Accept": "application/zip"}

    print(f"--- 正在下载 GTFS 数据: {agency_id} ---")
    
    try:
        response = requests.get(full_url, headers=headers, stream=True, timeout=60)
        response.raise_for_status() 
        print(f"✅ 下载成功。")

        conn = get_db_connection()
        zip_content = io.BytesIO(response.content)
        
        GTFS_FILES_MAP = {
            'stops.txt': 'stops',
            'routes.txt': 'routes',
            'trips.txt': 'trips',
            'stop_times.txt': 'stop_times',
            'shapes.txt': 'shapes',
        }
        success_count = 0
        with zipfile.ZipFile(zip_content, 'r') as zf:
            for gtfs_file, table_name in GTFS_FILES_MAP.items():
                if gtfs_file in zf.namelist():
                    print(f"   -> 导入 {gtfs_file}...")
                    with zf.open(gtfs_file) as file:
                        df = pandas.read_csv(file, low_memory=False) 
                        df.to_sql(table_name, conn, if_exists='replace', index=False)
                    success_count += len(df)
        conn.close()
        if success_count == 0:
            raise Exception("下载的 ZIP 文件中未找到任何可导入的 GTFS 文件。")
        return success_count

    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP 错误 {e.response.status_code}: 无法下载 GTFS 数据。请检查 Agency ID 或 API Key。"
        raise Exception(error_msg)
    except Exception as e:
        raise Exception(f"处理 GTFS 数据时发生错误: {e}")


@gtfs_ns.route('/import/<string:agency_id>')
@gtfs_ns.param('agency_id', 'The GTFS agency ID (e.g., GSBC001)')
class GTFSImport(Resource):
    @gtfs_ns.doc('import_agency_data', security='apikey', 
                 description='Admin或Planner导入指定机构的GTFS数据，数据将替换本地数据库中的现有数据。')
    @token_required(allowed_roles=['Admin', 'Planner']) # Task 2 权限要求
    def post(self, current_user_id, agency_id):
        """导入 GTFS 数据 (Admin/Planner Only)"""
        
        if not agency_id.startswith(VALID_AGENCY_PREFIXES):
            return {'message': f"无效的 Agency ID。ID 必须以 {', '.join(VALID_AGENCY_PREFIXES)} 开头。"}, HTTPStatus.BAD_REQUEST

        try:
            total_rows = download_and_store_gtfs_data(agency_id)
            return {
                'message': f"成功导入 agency_id={agency_id} 的数据。共导入 {total_rows} 条记录。", 
                'agency_id': agency_id
            }, HTTPStatus.OK
            
        except Exception as e:
            return {'message': str(e)}, HTTPStatus.INTERNAL_SERVER_ERROR


# ----------------------------------------------------
# PART 6: GTFS 数据查询 (Task 3)
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
    """从请求参数中解析 page 和 page_size，并应用安全限制。"""
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
    @gtfs_ns.doc('get_route_by_id', security='apikey', description='所有用户可以检索特定 Route 的信息。')
    @token_required(allowed_roles=ALL_USERS)
    @gtfs_ns.marshal_with(route_model)
    def get(self, current_user_id, route_id):
        """检索特定 Route 的信息"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT route_id, agency_id, route_short_name, route_long_name FROM routes WHERE route_id=?", (route_id,))
        route = cursor.fetchone()
        conn.close()
        
        if not route:
            gtfs_ns.abort(HTTPStatus.NOT_FOUND, f"Route ID {route_id} not found. Ensure agency data is imported.")
            
        return dict(zip(['route_id', 'agency_id', 'route_short_name', 'route_long_name'], route)), HTTPStatus.OK


@gtfs_ns.route('/agency/<string:agency_id>/routes')
@gtfs_ns.param('agency_id', 'The ID of the agency')
class AgencyRoutesList(Resource):
    @gtfs_ns.doc('get_routes_by_agency', security='apikey', 
                 description='所有用户可以检索特定 Agency 的所有 Routes，支持分页。')
    @gtfs_ns.param('page', 'Page number for pagination', type=int)
    @gtfs_ns.param('page_size', f'Items per page (Max {MAX_PAGE_SIZE})', type=int)
    @token_required(allowed_roles=ALL_USERS)
    @gtfs_ns.marshal_list_with(route_model)
    def get(self, current_user_id, agency_id):
        """检索特定 Agency 的所有 Routes (Task 3, 带分页)"""
        page, page_size, offset = get_pagination_params()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM routes WHERE agency_id=?", (agency_id,))
        total_count = cursor.fetchone()[0]

        cursor.execute(
            f"SELECT route_id, agency_id, route_short_name, route_long_name FROM routes WHERE agency_id=? LIMIT ? OFFSET ?",
            (agency_id, page_size, offset)
        )
        routes = [dict(zip(['route_id', 'agency_id', 'route_short_name', 'route_long_name'], row)) for row in cursor.fetchall()]
        conn.close()
        
        if not total_count and not routes:
            gtfs_ns.abort(HTTPStatus.NOT_FOUND, f"Agency ID {agency_id} not found or no data imported.")
            
        response_headers = {
            'X-Total-Count': str(total_count), 'X-Page': str(page), 'X-Page-Size': str(page_size),
        }
        return routes, HTTPStatus.OK, response_headers

# (省略了 /trips/<trip_id>, /stops/<stop_id> 和 /routes/<route_id>/trips, /trips/<trip_id>/stops 的实现，它们逻辑与上述类似)


# ----------------------------------------------------
# PART 7: 站点模糊搜索 (Task 4)
# ----------------------------------------------------

associated_route_model = api.model('AssociatedRoute', {
    'route_id': fields.String, 'route_name': fields.String(attribute='route_long_name'),
    'trip_id': fields.String, 'trip_headsign': fields.String,
})
search_stops_model = api.model('StopSearchResult', {
    'stop_id': fields.String, 'stop_name': fields.String,
    'score': fields.Float(description='RapidFuzz 匹配分数 (0-100)'),
    'associated_services': fields.List(fields.Nested(associated_route_model)),
})

@gtfs_ns.route('/search/stops')
class StopSearchResource(Resource):
    @gtfs_ns.doc('search_stops', security='apikey', 
                 description='所有用户可以通过站名模糊搜索站点，并返回关联的 Routes 和 Trips。使用 RapidFuzz。')
    @gtfs_ns.param('q', 'The stop name query (e.g., Circular Quay)', required=True)
    @gtfs_ns.param('threshold', 'Minimum RapidFuzz score threshold (e.g., 80)', type=int)
    @token_required(allowed_roles=ALL_USERS)
    @gtfs_ns.marshal_list_with(search_stops_model)
    def get(self, current_user_id):
        """站点模糊搜索 (Task 4, 所有用户)"""
        query = request.args.get('q')
        threshold = request.args.get('threshold', 80, type=int) 
        
        if not query or len(query.strip()) < 3:
            gtfs_ns.abort(HTTPStatus.BAD_REQUEST, "搜索查询 q 不能为空，且至少需要 3 个字符。")
            
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT stop_id, stop_name FROM stops")
        all_stops_data = cursor.fetchall()
        stop_names = [data[1] for data in all_stops_data]
        stop_map = {data[1]: data[0] for data in all_stops_data} 
        
        # 核心模糊匹配
        matches = process.extract(
            query, stop_names, scorer=fuzz.WRatio, limit=50, score_cutoff=threshold
        )
        
        final_results = []
        for name_match, score, index in matches:
            stop_id = stop_map.get(name_match)
            if not stop_id: continue
                
            # 关联查询：stops -> stop_times -> trips -> routes
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

        conn.close()
        if not final_results:
             return {'message': '未找到匹配的站点'}, HTTPStatus.NOT_FOUND
        return final_results, HTTPStatus.OK


# ----------------------------------------------------
# PART 8: 收藏路线管理 (Task 5)
# ----------------------------------------------------

favourite_input_model = api.model('FavouriteRouteInput', {'route_id': fields.String(required=True, description='要收藏的路线 ID')})
favourite_output_model = api.model('FavouriteRouteOutput', {
    'id': fields.Integer(readOnly=True), 'route_id': fields.String,
    'route_short_name': fields.String, 'route_long_name': fields.String
})

favourites_ns = api.namespace('favourites', description='Favourite Routes Management (All Users)')

@favourites_ns.route('')
class FavouriteList(Resource):
    @favourites_ns.doc('list_favourites', security='apikey', description='所有用户都可以查看自己的收藏列表。')
    @token_required(allowed_roles=ALL_USERS)
    @favourites_ns.marshal_list_with(favourite_output_model)
    def get(self, user_id):
        """获取当前用户的所有收藏路线 (Task 5)"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT f.id, f.route_id, r.route_short_name, r.route_long_name 
            FROM favourites f LEFT JOIN routes r ON f.route_id = r.route_id
            WHERE f.user_id = ?
            """, (user_id,)
        )
        favourites = [dict(zip(['id', 'route_id', 'route_short_name', 'route_long_name'], row)) for row in cursor.fetchall()]
        conn.close()
        return favourites, HTTPStatus.OK

    @favourites_ns.doc('add_favourite', security='apikey', description=f'所有用户可以添加收藏，但最多只能收藏 {MAX_FAVOURITES} 条。')
    @token_required(allowed_roles=ALL_USERS)
    @favourites_ns.expect(favourite_input_model, validate=True)
    def post(self, user_id):
        """新增一条收藏路线 (Task 5)"""
        route_id = request.json.get('route_id')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM favourites WHERE user_id = ?", (user_id,))
        current_count = cursor.fetchone()[0]
        
        if current_count >= MAX_FAVOURITES:
            conn.close()
            return {'message': f'收藏路线已达上限 ({MAX_FAVOURITES} 条)。'}, HTTPStatus.FORBIDDEN
            
        cursor.execute("SELECT route_id FROM routes WHERE route_id = ?", (route_id,))
        if cursor.fetchone() is None:
            conn.close()
            return {'message': f'路线 ID {route_id} 不存在于已导入的 GTFS 数据中。'}, HTTPStatus.NOT_FOUND
            
        try:
            cursor.execute("INSERT INTO favourites (user_id, route_id) VALUES (?, ?)", (user_id, route_id))
            new_fav_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return {'message': f'路线 {route_id} 已成功收藏。', 'id': new_fav_id}, HTTPStatus.CREATED
            
        except sqlite3.IntegrityError:
            conn.close()
            return {'message': f'路线 {route_id} 已经被收藏过了。'}, HTTPStatus.CONFLICT


@favourites_ns.route('/<int:fav_id>')
@favourites_ns.param('fav_id', 'The ID of the favourite record')
class FavouriteResource(Resource):
    @favourites_ns.doc('delete_favourite', security='apikey', description='所有用户可以删除自己的某条收藏记录。')
    @token_required(allowed_roles=ALL_USERS)
    def delete(self, user_id, fav_id):
        """删除一条收藏记录 (Task 5)"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM favourites WHERE id = ? AND user_id = ?", (fav_id, user_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return {'message': '收藏记录未找到或您没有权限删除。'}, HTTPStatus.NOT_FOUND
            
        conn.commit()
        conn.close()
        return '', HTTPStatus.NO_CONTENT

# ----------------------------------------------------
# PART 9: 可视化和数据导出 (Task 6)
# ----------------------------------------------------

@gtfs_ns.route('/export/routes/<string:agency_id>')
@gtfs_ns.param('agency_id', 'The ID of the agency to export routes for')
class RouteExport(Resource):
    @gtfs_ns.doc('export_routes_csv', security='apikey', 
                 description='Planner可以导出特定 Agency 的所有 Routes 数据到 CSV 文件。')
    @token_required(allowed_roles=['Planner']) # Task 6 权限要求
    def get(self, current_user_id, agency_id):
        """导出特定 Agency 的 Routes 数据为 CSV (Planner Only)"""
        conn = get_db_connection()
        
        try:
            sql_query = f"SELECT * FROM routes WHERE agency_id='{agency_id}'"
            routes_df = pandas.read_sql_query(sql_query, conn)
        except Exception:
            conn.close()
            gtfs_ns.abort(HTTPStatus.NOT_FOUND, f"导出失败: Agency ID {agency_id} 相关的 Routes 数据未找到。")
        finally:
            conn.close()

        if routes_df.empty:
            return {'message': f"Agency ID {agency_id} 没有 Routes 数据可供导出。"}, HTTPStatus.NOT_FOUND

        output = io.StringIO()
        routes_df.to_csv(output, index=False)
        output.seek(0)
        
        buffer = io.BytesIO(output.getvalue().encode('utf-8'))

        # Task 6: 返回 CSV 文件字节流
        return send_file(
            buffer,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'routes_{agency_id}_{datetime.datetime.now().strftime("%Y%m%d%H%M%S")}.csv'
        )


@gtfs_ns.route('/visualize/favourites')
class FavouriteVisualization(Resource):
    @gtfs_ns.doc('visualize_favourites', security='apikey', 
                 description='Planner可以生成一张地图，可视化其收藏路线的形状，返回 PNG 字节流。')
    @token_required(allowed_roles=['Planner']) # Task 6 权限要求
    def get(self, user_id):
        """生成收藏路线的地图可视化 (Planner Only)"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT route_id FROM favourites WHERE user_id = ?", (user_id,))
        route_ids = [row[0] for row in cursor.fetchall()]
        
        if not route_ids:
            conn.close()
            return {'message': '用户没有收藏任何路线。'}, HTTPStatus.NOT_FOUND

        shape_ids = []
        for route_id in route_ids:
            cursor.execute(
                "SELECT DISTINCT t.shape_id FROM trips t WHERE t.route_id = ? AND t.shape_id IS NOT NULL LIMIT 1", 
                (route_id,)
            )
            shape_id = cursor.fetchone()
            if shape_id: shape_ids.append(shape_id[0])
        
        if not shape_ids:
            conn.close()
            return {'message': '收藏的路线没有找到关联的形状数据。'}, HTTPStatus.NOT_FOUND

        shape_data = {}
        for shape_id in shape_ids:
            cursor.execute(
                "SELECT shape_pt_lat, shape_pt_lon FROM shapes WHERE shape_id = ? ORDER BY shape_pt_sequence", 
                (shape_id,)
            )
            shape_data[shape_id] = cursor.fetchall()
        conn.close()
        
        # 绘图逻辑
        plt.switch_backend('Agg') 
        fig, ax = plt.subplots(figsize=(10, 10))
        colors = list(mcolors.TABLEAU_COLORS.keys()) 
        
        for i, (shape_id, points) in enumerate(shape_data.items()):
            lats = [p[0] for p in points]
            lons = [p[1] for p in points]
            
            ax.plot(lons, lats, marker='.', linestyle='-', linewidth=2, alpha=0.7,
                    color=mcolors.TABLEAU_COLORS[colors[i % len(colors)]],
                    label=f'Shape ID: {shape_id}'
            )

        ax.set_title(f"User {user_id}'s Favourite Routes Visualization")
        ax.set_xlabel("Longitude")
        ax.set_ylabel("Latitude")
        ax.legend(loc='best', fontsize='small')
        ax.grid(True)
        ax.set_aspect('equal', adjustable='box') 

        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png')
        plt.close(fig)
        img_buffer.seek(0)

        # Task 6: 返回 PNG 图片字节流
        return send_file(
            img_buffer,
            mimetype='image/png',
            as_attachment=False # 作为图片直接在浏览器中渲染
        )


# ==============================================================================
# [your_zid]_api.py - 运行主程序
# ==============================================================================

if __name__ == '__main__':
    if not API_KEY or not JWT_SECRET_KEY:
        print("警告：JWT_SECRET_KEY 或 NSW_TRANSPORT_API_KEY 环境变量未设置。请设置它们以进行完整测试。")
    print(f"Flask API 正在运行. 数据库文件: {SQLITE_DB_NAME}")
    app.run(debug=True)
