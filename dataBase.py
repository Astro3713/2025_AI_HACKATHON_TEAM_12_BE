from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.orm.interfaces import NotExtension

# Flask 앱 없이 SQLAlchemy만 생성
db = SQLAlchemy()

# DB 초기화
def init_app(app):
    """앱에 데이터베이스 연결"""
    db.init_app(app)
    return db

# User Table 생성
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return f"<User {self.username}>"
    
    def to_dict(self):
        """사용자 정보를 딕셔너리로 변환"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email
        }

# OCR Data 게시물 Table 생성
class OCRData(db.Model):
    post_id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 게시물 ID(PK)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 사용자 ID(FK)
    post_content = db.Column(db.Text, nullable=False)  # 장문의 게시물 내용 저장 (Text 타입 사용)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # 생성일시

    def __repr__(self):
        return f"<OCRData {self.post_id}>"

    def to_dict(self): # 게시물 정보 딕셔너리로 변환
        return {
            'post_id': self.post_id,
            'user_id': self.user_id,
            'post_content': self.post_content,
            'created_at': self.created_at
        }

######################## 사용자(User) 관련 API #########################################################
# 새로운 사용자 생성하기
def create_user(username, password, email):
    """새 사용자 생성"""
    try:
        # 중복 확인
        if User.query.filter_by(email=email).first():
            print(f"이메일 '{email}'이 이미 존재합니다.")
            return None
        
        user = User(username=username, password=password, email=email)
        db.session.add(user)
        db.session.commit()
        print(f"사용자 '{username}' 생성 완료")
        return user

    except Exception as e:
        db.session.rollback()
        print(f"사용자 생성 실패: {str(e)}")
        return None

# 사용자 이름으로 사용자 조회(키값으로 조회)
def get_user_by_username(username):
    """사용자명으로 사용자 조회"""
    return User.query.filter_by(username=username).first()

# ID값(key value)로 사용자 조회
def get_user_by_id(user_id):
    """ID로 사용자 조회"""
    return User.query.get(user_id)

# 이메일로 사용자(유저) 조회
def get_user_by_email(email):
    """이메일로 사용자(개체) 조회"""
    return User.query.filter_by(email=email).first()

# 모든 사용자 조회
def get_all_users():
    """모든 사용자 조회"""
    return User.query.all()

# 사용자 정보 업데이트
def update_user(user_id, **kwargs):
    """사용자 정보 업데이트"""
    try:
        user = User.query.get(user_id)
        if user:
            for key, value in kwargs.items():
                if hasattr(user, key) and key != 'id':
                    setattr(user, key, value)
            db.session.commit()
            print(f"사용자 ID {user_id} 정보 업데이트 완료")
            return True
        print(f"사용자 ID {user_id}를 찾을 수 없습니다.")
        return False
    except Exception as e:
        db.session.rollback()
        print(f"사용자 업데이트 실패: {str(e)}")
        return False

# 사용자 정보 삭제
def delete_user(user_id):
    """사용자 삭제"""
    try:
        user = User.query.get(user_id)
        if user:
            username = user.username
            db.session.delete(user)
            db.session.commit()
            print(f"사용자 '{username}' 삭제 완료")
            return True
        print(f"사용자 ID {user_id}를 찾을 수 없습니다.")
        return False
    except Exception as e:
        db.session.rollback()
        print(f"사용자 삭제 실패: {str(e)}")
        return False

def check_user_exists_by_email(email = None):
    if(User.query.filter_by(email=email).first() is not None):
        return True
    else:
        return False

def check_user_exists_by_username(username = None):
    if(User.query.filter_by(username=username).first() is not None):
        return True
    else:
        return False

# 전체 사용자 수 조회하기
def get_user_count():
    """전체 사용자 수 조회"""
    return User.query.count()

# 모든 사용자 목록 출력하기
def show_all_users():
    """모든 사용자 목록 출력"""
    users = get_all_users()
    print(f"\n등록된 사용자 목록 (총 {len(users)}명):")
    if users:
        for user in users:
            print(f"   ID: {user.id}, 사용자명: {user.username}, 이메일: {user.email}")
    else:
        print("등록된 사용자가 없습니다.")


######################## 데이터베이스 관련 API  #########################################################
def init_database():
    """데이터베이스 초기화 및 테이블 생성"""
    db.create_all()
    print("데이터베이스 테이블이 생성되었습니다.")
    print("데이터베이스 파일: database.db")

if __name__ == "__main__":
    print("Dinuri Flask SQLite 데이터베이스 관리")
    print("=" * 50)
    show_all_users()
    
    print("\n데이터베이스 설정이 완료되었습니다!")
