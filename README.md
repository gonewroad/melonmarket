# MelonMarket

WhiteHat School Secure Coding 과제 - 중고거래 플랫폼

## 기술 스택
- Python 3.9, Flask, Flask-SocketIO
- SQLite3 (raw SQL, parameterized query)

## 환경 설정

### 1. 저장소 클론
```bash
git clone <이 저장소 URL>
cd secure-coding
```

### 2. Miniconda 설치 (없는 경우)
https://docs.anaconda.com/free/miniconda/index.html 참고하여 설치

### 3. conda 가상환경 생성 및 활성화
```bash
conda env create -f enviroments.yaml
conda activate secure_coding
```

## 실행 방법

```bash
python app.py
```

브라우저에서 `http://127.0.0.1:5000` 접속

### 관리자 계정 만들기
회원가입 후, 아래 명령어로 특정 계정에 관리자 권한 부여:
```bash
python3 -c "
import sqlite3
db = sqlite3.connect('market.db')
db.execute(\"UPDATE user SET is_admin=1 WHERE username='본인아이디'\")
db.commit()
"
```

## 주요 기능
- 회원가입 / 로그인 / 로그아웃
- 마이페이지 (소개글, 비밀번호 변경)
- 사용자 조회 (전체 목록 + 프로필 조회)
- 상품 등록 / 조회 / 검색 / 수정 / 삭제
- 유저 간 송금
- 실시간 전체 채팅 + 1:1 채팅
- 신고 기능 (일정 횟수 이상 누적 시 상품 자동 차단 / 유저 자동 휴면)
- 관리자 대시보드 (유저/상품 상태 관리, 신고 내역 조회)

## 외부 접속 테스트 (선택)
```bash
ngrok http 5000
```
