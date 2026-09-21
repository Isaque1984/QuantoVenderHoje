import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import jwt
import requests
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

app = FastAPI(title="Quanto Vender Hoje PRO API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB = os.getenv("DATABASE_PATH", "qvh.db")
JWT_SECRET = os.getenv("JWT_SECRET", "")
MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN", "")
MP_PLAN_ID = os.getenv("MP_PLAN_ID", "")

APP_URL = os.getenv(
    "APP_URL",
    "https://quantovenderhoje.onrender.com"
)

JWT_EXPIRE_DAYS = 30


# =========================
# BANCO
# =========================

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            mp_subscription_id TEXT,
            pro_status TEXT DEFAULT 'inactive',
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()


# =========================
# SENHA
# =========================

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200000
    ).hex()

    return password_hash, salt


def check_password(password, password_hash, salt):
    calculated, _ = hash_password(password, salt)
    return secrets.compare_digest(calculated, password_hash)


# =========================
# JWT
# =========================

def create_token(user_id, email):
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET não configurado")

    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(
            (now + timedelta(days=JWT_EXPIRE_DAYS)).timestamp()
        )
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )


def get_user_from_token(authorization):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Token não informado"
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Token inválido"
        )

    token = authorization.replace("Bearer ", "", 1).strip()

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )

        user_id = int(payload["sub"])

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Sessão expirada"
        )

    conn = db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    conn.close()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Usuário não encontrado"
        )

    return user


# =========================
# MODELOS
# =========================

class RegisterData(BaseModel):
    email: EmailStr
    password: str


class LoginData(BaseModel):
    email: EmailStr
    password: str


# =========================
# TESTE
# =========================

@app.get("/")
def root():
    return {
        "app": "Quanto Vender Hoje PRO API",
        "status": "online"
    }


@app.get("/health")
def health():
    return {"ok": True}


# =========================
# CADASTRO
# =========================

@app.post("/cadastro")
def cadastro(data: RegisterData):

    email = data.email.strip().lower()
    password = data.password

    if len(password) < 6:
        raise HTTPException(
            status_code=400,
            detail="A senha precisa ter pelo menos 6 caracteres."
        )

    conn = db()

    existing = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if existing:
        conn.close()

        raise HTTPException(
            status_code=400,
            detail="Este e-mail já está cadastrado."
        )

    password_hash, salt = hash_password(password)

    cursor = conn.execute("""
        INSERT INTO users
        (email, password_hash, salt, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        email,
        password_hash,
        salt,
        datetime.now(timezone.utc).isoformat()
    ))

    conn.commit()

    user_id = cursor.lastrowid

    conn.close()

    token = create_token(user_id, email)

    return {
        "ok": True,
        "token": token,
        "email": email,
        "pro": False
    }


# =========================
# LOGIN
# =========================

@app.post("/login")
def login(data: LoginData):

    email = data.email.strip().lower()

    conn = db()

    user = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    conn.close()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="E-mail ou senha incorretos."
        )

    if not check_password(
        data.password,
        user["password_hash"],
        user["salt"]
    ):
        raise HTTPException(
            status_code=401,
            detail="E-mail ou senha incorretos."
        )

    token = create_token(
        user["id"],
        user["email"]
    )

    return {
        "ok": True,
        "token": token,
        "email": user["email"],
        "pro": user["pro_status"] == "active"
    }


# =========================
# USUÁRIO
# =========================

@app.get("/me")
def me(authorization: str = Header(None)):

    user = get_user_from_token(authorization)

    return {
        "ok": True,
        "email": user["email"],
        "pro": user["pro_status"] == "active",
        "status": user["pro_status"]
    }


# =========================
# VERIFICAR MERCADO PAGO
# =========================

def check_mercado_pago(subscription_id):

    if not MP_ACCESS_TOKEN:
        return None

    if not subscription_id:
        return None

    try:

        response = requests.get(
            f"https://api.mercadopago.com/preapproval/{subscription_id}",
            headers={
                "Authorization":
                    f"Bearer {MP_ACCESS_TOKEN}"
            },
            timeout=10
        )

        if response.status_code != 200:
            return None

        return response.json()

    except Exception:
        return None


# =========================
# VERIFICAÇÃO PRO
# =========================

@app.get("/verificar-pro")
def verificar_pro(
    authorization: str = Header(None)
):

    user = get_user_from_token(authorization)

    status = user["pro_status"]

    subscription_id = user["mp_subscription_id"]

    # Se já temos assinatura no Mercado Pago,
    # fazemos uma confirmação silenciosa.

    if subscription_id:

        mp = check_mercado_pago(subscription_id)

        if mp:

            mp_status = str(
                mp.get("status", "")
            ).lower()

            if mp_status == "authorized":

                status = "active"

            elif mp_status in [
                "cancelled",
                "canceled",
                "paused"
            ]:

                status = "inactive"

            conn = db()

            conn.execute(
                """
                UPDATE users
                SET pro_status = ?
                WHERE id = ?
                """,
                (status, user["id"])
            )

            conn.commit()
            conn.close()

    return {
        "ok": True,
        "pro": status == "active",
        "status": status,
        "email": user["email"]
    }


# =========================
# CRIAR ASSINATURA
# =========================

@app.post("/assinar")
def assinar(
    authorization: str = Header(None)
):

    user = get_user_from_token(authorization)

    if not MP_ACCESS_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="Mercado Pago ainda não configurado."
        )

    if not MP_PLAN_ID:
        raise HTTPException(
            status_code=500,
            detail="MP_PLAN_ID ainda não configurado."
        )

    payload = {
        "preapproval_plan_id": MP_PLAN_ID,
        "payer_email": user["email"],
        "external_reference": f"QVH_USER_{user['id']}"
    }

    try:

        response = requests.post(
            "https://api.mercadopago.com/preapproval",
            headers={
                "Authorization":
                    f"Bearer {MP_ACCESS_TOKEN}",
                "Content-Type":
                    "application/json"
            },
            json=payload,
            timeout=15
        )

    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Não foi possível conectar ao Mercado Pago."
        )

    if response.status_code not in [200, 201]:
        raise HTTPException(
            status_code=400,
            detail="Mercado Pago recusou a criação da assinatura."
        )

    data = response.json()

    subscription_id = data.get("id")

    init_point = data.get("init_point")

    conn = db()

    conn.execute(
        """
        UPDATE users
        SET mp_subscription_id = ?,
            pro_status = 'pending'
        WHERE id = ?
        """,
        (
            subscription_id,
            user["id"]
        )
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "subscription_id": subscription_id,
        "init_point": init_point
    }


# =========================
# WEBHOOK MERCADO PAGO
# =========================

@app.post("/webhook/mercadopago")
def mercadopago_webhook(payload: dict):

    subscription_id = None

    data = payload.get("data")

    if isinstance(data, dict):
        subscription_id = data.get("id")

    if not subscription_id:
        return {
            "ok": True
        }

    mp = check_mercado_pago(subscription_id)

    if not mp:
        return {
            "ok": True
        }

    status = str(
        mp.get("status", "")
    ).lower()

    if status == "authorized":
        new_status = "active"

    elif status in [
        "cancelled",
        "canceled",
        "paused"
    ]:
        new_status = "inactive"

    else:
        new_status = "pending"

    conn = db()

    conn.execute(
        """
        UPDATE users
        SET pro_status = ?
        WHERE mp_subscription_id = ?
        """,
        (
            new_status,
            str(subscription_id)
        )
    )

    conn.commit()
    conn.close()

    return {
        "ok": True
      }
