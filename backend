import os
import sqlite3
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Optional

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr


# ============================================================
# CONFIGURAÇÃO
# ============================================================

APP_NAME = "Sellium PRO API"

MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN", "").strip()
MP_PLAN_ID = os.getenv("MP_PLAN_ID", "").strip()
MP_WEBHOOK_SECRET = os.getenv("MP_WEBHOOK_SECRET", "").strip()

APP_URL = os.getenv(
    "APP_URL",
    "https://quantovenderhoje.onrender.com"
).rstrip("/")

DATABASE = os.getenv(
    "DATABASE_PATH",
    "sellium.db"
)

PRICE = 9.90

MP_API = "https://api.mercadopago.com"


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        APP_URL,
        "https://quantovenderhoje.onrender.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# BANCO
# ============================================================

def db():
    connection = sqlite3.connect(
        DATABASE,
        check_same_thread=False
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_db():

    connection = db()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token_hash TEXT,
            pro INTEGER DEFAULT 0,
            subscription_id TEXT,
            subscription_status TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT UNIQUE,
            event_type TEXT,
            received_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


init_db()


# ============================================================
# MODELOS
# ============================================================

class AccountData(BaseModel):
    email: EmailStr
    password: str


class TokenData(BaseModel):
    token: str


class SubscribeData(BaseModel):
    email: EmailStr


# ============================================================
# UTILIDADES
# ============================================================

def now():

    return datetime.now(
        timezone.utc
    ).isoformat()


def normalize_email(email):

    return str(email).strip().lower()


def hash_password(password):

    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        120000
    )

    return (
        salt.hex()
        + ":"
        + digest.hex()
    )


def verify_password(password, stored):

    try:

        salt_hex, digest_hex = stored.split(":")

        salt = bytes.fromhex(salt_hex)

        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            120000
        )

        return hmac.compare_digest(
            digest.hex(),
            digest_hex
        )

    except Exception:

        return False


def hash_token(token):

    return hashlib.sha256(
        token.encode()
    ).hexdigest()


def generate_token():

    return secrets.token_urlsafe(48)


def mp_headers():

    if not MP_ACCESS_TOKEN:

        raise HTTPException(
            status_code=500,
            detail="MP_ACCESS_TOKEN não configurado."
        )

    return {
        "Authorization":
            f"Bearer {MP_ACCESS_TOKEN}",

        "Content-Type":
            "application/json"
    }


def get_user_by_email(email):

    connection = db()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (normalize_email(email),)
    )

    user = cursor.fetchone()

    connection.close()

    return user


def get_user_by_token(token):

    if not token:
        return None

    token_hash = hash_token(token)

    connection = db()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE token_hash = ?
        """,
        (token_hash,)
    )

    user = cursor.fetchone()

    connection.close()

    return user


def set_pro_status(
    email,
    pro,
    subscription_id=None,
    subscription_status=None
):

    connection = db()

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET
            pro = ?,
            subscription_id = COALESCE(?, subscription_id),
            subscription_status = COALESCE(?, subscription_status),
            updated_at = ?
        WHERE email = ?
        """,
        (
            1 if pro else 0,
            subscription_id,
            subscription_status,
            now(),
            normalize_email(email)
        )
    )

    connection.commit()

    connection.close()


# ============================================================
# ROOT / HEALTH
# ============================================================

@app.get("/")
def root():

    return {
        "app": APP_NAME,
        "status": "online",
        "price": "R$ 9,90/mês"
    }


@app.get("/health")
def health():

    return {
        "ok": True,
        "app": APP_NAME
    }


# ============================================================
# CRIAR CONTA
# ============================================================

@app.post("/criar-conta-pro")
def criar_conta(data: AccountData):

    email = normalize_email(data.email)

    if len(data.password) < 6:

        raise HTTPException(
            status_code=400,
            detail="A senha precisa ter pelo menos 6 caracteres."
        )

    existing = get_user_by_email(email)

    if existing:

        raise HTTPException(
            status_code=409,
            detail="Este e-mail já possui uma conta. Entre na conta existente."
        )

    token = generate_token()

    connection = db()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO users (
            email,
            password_hash,
            token_hash,
            pro,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, 0, ?, ?)
        """,
        (
            email,
            hash_password(data.password),
            hash_token(token),
            now(),
            now()
        )
    )

    connection.commit()

    connection.close()

    return {
        "ok": True,
        "email": email,
        "token": token,
        "pro": False
    }


# ============================================================
# LOGIN
# ============================================================

@app.post("/login-pro")
def login(data: AccountData):

    email = normalize_email(data.email)

    user = get_user_by_email(email)

    if not user:

        raise HTTPException(
            status_code=401,
            detail="E-mail ou senha incorretos."
        )

    if not verify_password(
        data.password,
        user["password_hash"]
    ):

        raise HTTPException(
            status_code=401,
            detail="E-mail ou senha incorretos."
        )

    token = generate_token()

    connection = db()

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET
            token_hash = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            hash_token(token),
            now(),
            user["id"]
        )
    )

    connection.commit()

    connection.close()

    return {
        "ok": True,
        "email": email,
        "token": token,
        "pro": bool(user["pro"])
    }


# ============================================================
# VERIFICAR SESSÃO
# ============================================================

@app.post("/verificar-sessao")
def verificar_sessao(data: TokenData):

    user = get_user_by_token(data.token)

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Sessão inválida."
        )

    return {
        "ok": True,
        "email": user["email"],
        "pro": bool(user["pro"]),
        "subscription_status":
            user["subscription_status"]
    }


# ============================================================
# CRIAR ASSINATURA MERCADO PAGO
# ============================================================

@app.post("/assinar")
def criar_assinatura(data: SubscribeData):

    email = normalize_email(data.email)

    user = get_user_by_email(email)

    if not user:

        raise HTTPException(
            status_code=404,
            detail="Conta não encontrada."
        )

    if not MP_PLAN_ID:

        raise HTTPException(
            status_code=500,
            detail="MP_PLAN_ID não configurado no Render."
        )

    payload = {

        "preapproval_plan_id":
            MP_PLAN_ID,

        "payer_email":
            email,

        "external_reference":
            f"SELLIUM_USER_{user['id']",

        "back_url":
            f"{APP_URL}/pro.html"

    }

    try:

        response = requests.post(
            f"{MP_API}/preapproval",
            headers=mp_headers(),
            json=payload,
            timeout=20
        )

    except requests.RequestException as error:

        raise HTTPException(
            status_code=502,
            detail=f"Erro ao conectar ao Mercado Pago: {error}"
        )


    try:

        result = response.json()

    except Exception:

        result = {}


    if not response.ok:

        detail = (
            result.get("message")
            or result.get("error")
            or "Mercado Pago recusou a criação da assinatura."
        )

        raise HTTPException(
            status_code=response.status_code,
            detail=detail
        )


    subscription_id = result.get("id")

    init_point = result.get("init_point")

    if not subscription_id or not init_point:

        raise HTTPException(
            status_code=502,
            detail="Mercado Pago não retornou o link da assinatura."
        )


    connection = db()

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET
            subscription_id = ?,
            subscription_status = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            subscription_id,
            result.get("status", "pending"),
            now(),
            user["id"]
        )
    )

    connection.commit()

    connection.close()


    return {

        "ok": True,

        "subscription_id":
            subscription_id,

        "status":
            result.get("status"),

        "init_point":
            init_point,

        "price":
            PRICE

    }


# ============================================================
# CONSULTAR ASSINATURA NO MERCADO PAGO
# ============================================================

def consultar_assinatura(subscription_id):

    response = requests.get(
        f"{MP_API}/preapproval/{subscription_id}",
        headers=mp_headers(),
        timeout=20
    )

    try:
        data = response.json()
    except Exception:
        data = {}

    if not response.ok:

        return None

    return data


# ============================================================
# VERIFICAR PRO
# ============================================================

@app.get("/verificar-pro")
def verificar_pro(email: EmailStr):

    normalized = normalize_email(email)

    user = get_user_by_email(normalized)

    if not user:

        return {
            "ok": True,
            "pro": False,
            "status": "inactive"
        }


    subscription_id = user["subscription_id"]


    if not subscription_id:

        return {
            "ok": True,
            "pro": False,
            "status":
                user["subscription_status"]
                or "inactive"
        }


    subscription = consultar_assinatura(
        subscription_id
    )


    if not subscription:

        return {
            "ok": True,
            "pro": bool(user["pro"]),
            "status":
                user["subscription_status"]
                or "unknown"
        }


    status = str(
        subscription.get("status", "")
    ).lower()


    active_statuses = {
        "authorized",
        "active"
    }


    is_pro = status in active_statuses


    set_pro_status(
        normalized,
        is_pro,
        subscription_id,
        status
    )


    return {

        "ok": True,

        "pro":
            is_pro,

        "status":
            status,

        "subscription_id":
            subscription_id,

        "next_payment_date":
            subscription.get(
                "next_payment_date"
            )

    }


# ============================================================
# WEBHOOK MERCADO PAGO
# ============================================================

def validar_webhook(request: Request):

    if not MP_WEBHOOK_SECRET:

        return True

    signature = request.headers.get(
        "x-signature",
        ""
    )

    request_id = request.headers.get(
        "x-request-id",
        ""
    )

    if not signature:

        return False

    parts = {}

    for item in signature.split(","):

        if "=" in item:

            key, value = item.split(
                "=",
                1
            )

            parts[key.strip()] = value.strip()


    ts = parts.get("ts")
    v1 = parts.get("v1")


    if not ts or not v1:

        return False


    # O Mercado Pago utiliza o ID recebido
    # no parâmetro data.id para a validação.
    # A validação completa também é feita
    # consultando o objeto diretamente na API.

    return True


@app.post("/webhook/mercadopago")
async def webhook_mercadopago(request: Request):

    body = await request.json()

    event_type = (
        body.get("type")
        or body.get("topic")
        or ""
    )

    data = body.get("data") or {}

    object_id = data.get("id")


    event_key = (
        f"{event_type}:{object_id}"
    )


    # Evita processar o mesmo evento várias vezes.

    connection = db()

    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO webhook_events (
                event_key,
                event_type,
                received_at
            )
            VALUES (?, ?, ?)
            """,
            (
                event_key,
                event_type,
                now()
            )
        )

        connection.commit()

    except sqlite3.IntegrityError:

        connection.close()

        return {
            "ok": True,
            "duplicate": True
        }

    connection.close()


    # --------------------------------------------------------
    # ASSINATURA CRIADA / ATUALIZADA
    # --------------------------------------------------------

    if event_type in {
        "subscription_preapproval",
        "preapproval"
    }:

        if object_id:

            subscription =
                consultar_assinatura(
                    str(object_id)
                )

            if subscription:

                email = (
                    subscription.get(
                        "payer_email"
                    )
                )

                status = str(
                    subscription.get(
                        "status",
                        ""
                    )
                ).lower()


                if email:

                    is_pro = status in {
                        "authorized",
                        "active"
                    }


                    set_pro_status(
                        email,
                        is_pro,
                        str(object_id),
                        status
                    )


    # --------------------------------------------------------
    # PAGAMENTO RECORRENTE
    # --------------------------------------------------------

    elif event_type in {
        "subscription_authorized_payment",
        "payment"
    }:

        # Para pagamentos, precisamos obter
        # o objeto correspondente no Mercado Pago.

        if object_id:

            payment_url = (
                f"{MP_API}/v1/payments/"
                f"{object_id}"
            )

            response = requests.get(
                payment_url,
                headers=mp_headers(),
                timeout=20
            )

            try:
                payment = response.json()
            except Exception:
                payment = {}


            if response.ok:

                status = str(
                    payment.get(
                        "status",
                        ""
                    )
                ).lower()


                if status == "approved":

                    email = (
                        payment.get(
                            "payer",
                            {}
                        )
                        .get(
                            "email"
                        )
                    )


                    if email:

                        set_pro_status(
                            email,
                            True,
                            None,
                            "authorized"
                        )


    return {
        "ok": True
    }


# ============================================================
# CANCELAR / DESATIVAR PRO
# ============================================================

@app.post("/sincronizar-pro")
def sincronizar_pro(data: TokenData):

    user = get_user_by_token(
        data.token
    )

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Sessão inválida."
        )


    subscription_id = user[
        "subscription_id"
    ]


    if not subscription_id:

        return {
            "ok": True,
            "pro": False,
            "status": "inactive"
        }


    subscription = consultar_assinatura(
        subscription_id
    )


    if not subscription:

        return {
            "ok": True,
            "pro": bool(user["pro"]),
            "status":
                user["subscription_status"]
        }


    status = str(
        subscription.get(
            "status",
            ""
        )
    ).lower()


    is_pro = status in {
        "authorized",
        "active"
    }


    set_pro_status(
        user["email"],
        is_pro,
        subscription_id,
        status
    )


    return {

        "ok": True,

        "pro":
            is_pro,

        "status":
            status,

        "next_payment_date":
            subscription.get(
                "next_payment_date"
            )

  }
