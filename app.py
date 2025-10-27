from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flasgger import Swagger
import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv

# DB 파일 연결
from dataBase import (
    db,
    User,
    init_app,
    init_database,
    create_user,
    get_user_by_email,
    get_user_by_id,
    check_user_exists_by_email,
)
# 환경변수 설정
load_dotenv()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# dataBase의 db를 현재 앱에 연결
db = init_app(app)
CORS(app)  # CORS 설정으로 프론트엔드와의 통신 허용

# 데이터베이스
with app.app_context():
    init_database() # 데이터베이스 초기화 및 테이블 생성
    print("데이터베이스 테이블이 생성되었습니다.")
    print("데이터베이스 파일: database.db")


# JWT 설정
# 보안을 위해 반드시 환경변수에 JWT_SECRET_KEY를 설정해야 합니다.
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-default-secret')
JWT_ALGORITHM = os.environ.get('JWT_ALGORITHM', 'HS256')
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRE_MINUTES', 30))

# 간단한 메모리 데이터베이스 (실제 프로덕션에서는 실제 DB 사용)
# key: username, value: user dict (email also included)
users_db = {}

# JWT 유틸리티 함수들
def hash_password(password):
    """비밀번호 해시화"""
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_bytes.decode('utf-8')

def verify_password(password, hashed):
    """비밀번호 검증"""
    if isinstance(hashed, str):
        hashed = hashed.encode('utf-8')
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def generate_token(user_id):
    """JWT 토큰 생성"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_token(token):
    """JWT 토큰 검증"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """JWT 토큰 검증 데코레이터"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({'message': '토큰 형식이 올바르지 않습니다.'}), 401
        
        if not token:
            return jsonify({'message': '토큰이 필요합니다.'}), 401
        
        payload = verify_token(token)
        if payload is None:
            return jsonify({'message': '유효하지 않은 토큰입니다.'}), 401
        
        return f(payload['user_id'], *args, **kwargs)
    return decorated

# Swagger 설정
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs",
    "swagger_ui_config": {
        "deepLinking": True,
        "displayRequestDuration": True,
        "docExpansion": "none",
        "filter": True,
        "operationsSorter": "alpha",
        "showRequestHeaders": True,
        "tagsSorter": "alpha"
    }
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Dinuri Flask API",
        "description": "Dinuri Flask API 문서",
        "version": "1.0.0"
    },
    "host": "localhost:5000",
    "basePath": "/",
    "schemes": ["http", "https"],
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT 토큰을 'Bearer <token>' 형식으로 입력하세요"
        }
    }
}

# Swagger 초기화 (에러 핸들링 포함)
try:
    swagger = Swagger(app, config=swagger_config, template=swagger_template)
    print("Swagger 문서화가 성공적으로 초기화되었습니다.")
except Exception as e:
    print(f"Swagger 초기화 중 오류 발생: {str(e)}")
    print("Swagger 없이 서버를 계속 실행합니다.")
    swagger = None

###### Api 엔드포인트 목록 ######
@app.route('/')
def home():
    """
    홈페이지 엔드포인트
    ---
    tags:
      - 기본
    responses:
      200:
        description: 성공적인 응답
        schema:
          type: object
          properties:
            message:
              type: string
              example: "Dinuri Flask API에 오신 것을 환영합니다!"
            status:
              type: string
              example: "success"
            version:
              type: string
              example: "1.0.0"
    """
    return jsonify({
        'message': 'Dinuri Flask API에 오신 것을 환영합니다!',
        'status': 'success',
        'version': '1.0.0'
    })

@app.route('/api/health')
def health_check():
    """
    서버 상태 확인
    ---
    tags:
      - 기본
    responses:
      200:
        description: 서버가 정상적으로 작동 중
        schema:
          type: object
          properties:
            status:
              type: string
              example: "healthy"
            message:
              type: string
              example: "서버가 정상적으로 작동 중입니다."
    """
    return jsonify({
        'status': 'healthy',
        'message': '서버가 정상적으로 작동 중입니다.'
    })

# Flask 테스트용 엔드포인트
@app.route('/api/test', methods=['GET', 'POST'])
def test_endpoint():
    """
    테스트 엔드포인트
    ---
    tags:
      - 테스트
    parameters:
      - name: body
        in: body
        description: POST 요청 시 전송할 데이터
        required: false
        schema:
          type: object
          properties:
            test_data:
              type: string
              example: "테스트 데이터"
    responses:
      200:
        description: 성공적인 응답
        schema:
          type: object
          properties:
            method:
              type: string
              enum: [GET, POST]
              example: "GET"
            message:
              type: string
              example: "요청이 성공적으로 처리되었습니다."
            data:
              type: object
              properties:
                timestamp:
                  type: string
                  example: "2025-01-27"
                server:
                  type: string
                  example: "dinuri-flask"
            received_data:
              type: object
              description: POST 요청 시에만 포함
            response:
              type: string
              example: "데이터를 성공적으로 받았습니다."
    """
    if request.method == 'GET':
        return jsonify({
            'method': 'GET',
            'message': 'GET 요청이 성공적으로 처리되었습니다.',
            'data': {
                'timestamp': '2025-01-27',
                'server': 'dinuri-flask'
            }
        })
    elif request.method == 'POST':
        data = request.get_json()
        return jsonify({
            'method': 'POST',
            'message': 'POST 요청이 성공적으로 처리되었습니다.',
            'received_data': data,
            'response': '데이터를 성공적으로 받았습니다.'
        })

@app.errorhandler(404)
def not_found(error):
    """
    404 에러 핸들러
    ---
    tags:
      - 에러
    responses:
      404:
        description: 리소스를 찾을 수 없음
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Not Found"
            message:
              type: string
              example: "요청한 리소스를 찾을 수 없습니다."
            status_code:
              type: integer
              example: 404
    """
    return jsonify({
        'error': 'Not Found',
        'message': '요청한 리소스를 찾을 수 없습니다.',
        'status_code': 404
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """
    500 에러 핸들러
    ---
    tags:
      - 에러
    responses:
      500:
        description: 서버 내부 오류
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Internal Server Error"
            message:
              type: string
              example: "서버 내부 오류가 발생했습니다."
            status_code:
              type: integer
              example: 500
    """
    return jsonify({
        'error': 'Internal Server Error',
        'message': '서버 내부 오류가 발생했습니다.',
        'status_code': 500
    }), 500

# 인증 관련 API들
# 새로운 사용자 계정 생성하기(DB에 저장)
@app.route('/api/auth/register', methods=['POST'])
def register():
    """
    사용자 회원가입
    ---
    tags:
      - 인증
    parameters:
      - name: body
        in: body
        description: 회원가입 정보
        required: true
        schema:
          type: object
          required:
            - username
            - password
            - email
          properties:
            username:
              type: string
              description: 사용자명
              example: "testuser"
            password:
              type: string
              description: 비밀번호
              example: "password123"
            email:
              type: string
              description: 이메일 주소
              example: "test@example.com"
    responses:
      201:
        description: 회원가입 성공
        schema:
          type: object
          properties:
            message:
              type: string
              example: "사용자가 성공적으로 등록되었습니다."
      400:
        description: 잘못된 요청
        schema:
          type: object
          properties:
            error:
              type: string
              example: "사용자명, 비밀번호, 이메일이 모두 필요합니다."
      500:
        description: 서버 오류
        schema:
          type: object
          properties:
            error:
              type: string
              example: "사용자 등록에 실패했습니다."
    """
    data = request.get_json() # 사용자 정보 담긴 json 데이터 받기

    if not data or not all(k in data for k in ('username', 'password', 'email')):
        return jsonify({'error': '사용자명, 비밀번호, 이메일이 모두 필요합니다.'}), 400
    
    username = data['username']
    password = data['password']
    email = data['email']

    # # 이메일 중복 확인
    if check_user_exists_by_email(email=email) is True:
        return jsonify({'error': '이메일이 이미 존재합니다.'}), 400

    # 비밀번호 해시화
    hashed_password = hash_password(password)
    user = create_user(username,hashed_password,email)

    if user is not None:
        return jsonify({'message': '사용자가 성공적으로 등록되었습니다.'}), 201
    else:
        return jsonify({'error': '사용자 등록에 실패했습니다.'}), 500


# 로그인 기능 구현
@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    사용자 로그인
    ---
    tags:
      - 인증
    parameters:
      - name: body
        in: body
        description: 로그인 정보
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
              description: 이메일 주소
              example: "test@example.com"
            password:
              type: string
              description: 비밀번호
              example: "password123"
    responses:
      200:
        description: 로그인 성공
        schema:
          type: object
          properties:
            message:
              type: string
              example: "로그인에 성공했습니다."
            access_token:
              type: string
              description: JWT 액세스 토큰
              example: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
            token_type:
              type: string
              example: "bearer"
            expires_in:
              type: integer
              description: 토큰 만료 시간(초)
              example: 1800
      400:
        description: 잘못된 요청
        schema:
          type: object
          properties:
            error:
              type: string
              example: "이메일과 비밀번호가 필요합니다."
      401:
        description: 인증 실패
        schema:
          type: object
          properties:
            error:
              type: string
              example: "잘못된 이메일 또는 비밀번호입니다."
    """
    data = request.get_json() # 사용자가 입력한 데이터 가져오기
    
    if not data or not all(k in data for k in ('email', 'password')):
        return jsonify({
        'message': '이메일과 비밀번호가 필요합니다.',
        'access_token': None,
        'token_type': None,
        'expires_in': None
    }), 400
    
    email = data['email']
    password = data['password']
    
    # 이메일로 사용자 찾기
    user = get_user_by_email(email)
    
    if not user:
       return jsonify({
        'message': '로그인에 실패했습니다.',
        'access_token': None,
        'token_type': None,
        'expires_in': None
    }), 401
    
    # 비밀번호 검증
    if not verify_password(password, user.password):
        return jsonify({
        'message': '잘못된 이메일 또는 비밀번호입니다.',
        'access_token': None,
        'token_type': None,
        'expires_in': None
    }), 401
    
    # JWT 토큰 생성
    token = generate_token(user.id)
    
    return jsonify({
        'message': '로그인에 성공했습니다.',
        'access_token': token,
        'token_type': 'bearer',
        'expires_in': JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    })

# 사용자 프로필 반환
@app.route('/api/auth/profile', methods=['GET']) 
@token_required
def get_profile(user_id):
    """
    사용자 프로필 조회
    ---
    tags:
      - 인증
    security:
      - Bearer: []
    parameters:
      - name: Authorization
        in: header
        description: JWT 토큰 (Bearer 토큰)
        required: true
        type: string
        example: "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
    responses:
      200:
        description: 프로필 조회 성공
        schema:
          type: object
          properties:
            id:
              type: integer
              description: 사용자 ID
              example: 1
            username:
              type: string
              description: 사용자명
              example: "testuser"
            email:
              type: string
              description: 이메일 주소
              example: "test@example.com"
      401:
        description: 인증 실패
        schema:
          type: object
          properties:
            message:
              type: string
              example: "토큰이 필요합니다."
      404:
        description: 사용자를 찾을 수 없음
        schema:
          type: object
          properties:
            error:
              type: string
              example: "사용자를 찾을 수 없습니다."
    """
    user = get_user_by_id(user_id)
    if user is not None:
        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email
        }), 200
    else:
        return jsonify({
            'message': '사용자를 찾을 수 없습니다.',
            'id': None,
            'username': None,
            'email': None
        }), 404


if __name__ == '__main__':
    # 환경변수에서 포트 설정, 기본값은 5000
    port = int(os.environ.get('PORT', 5000))
    # 디버그 모드 설정 (개발 환경에서만 True)
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"Dinuri Flask 서버가 포트 {port}에서 시작됩니다...")
    print(f"API 엔드포인트: http://localhost:{port}")
    print(f"헬스 체크: http://localhost:{port}/api/health")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
