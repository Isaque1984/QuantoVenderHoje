import os
import hmac
import hashlib
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Optional

import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr


# =========================================================
# SELLium PRO API
# =========================================================

APP_NAME = "Sellium PRO API"
APP_URL = os.getenv(
    "APP_URL",
    "https://quantovenderhoje.onrender.com"
)

MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN", "")
MP_PLAN_ID = os.getenv("MP_PLAN_ID", "")
MP_WEBHOOK_SECRET = os.getenv("MP_WEBHOOK_SECRET", "")

DATABASE_PATH = os.getenv(
    "DATABASE_PATH",
    "/var/data/sellium.db"
)

MP_API = "https://api.mercadopago.com"

PRO_PRICE = 9.90


# =========================================================
# APP
# =========================================================

app = FastAPI(
    title=APP_NAME,
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# DATABASE
# =========================================================

def get_db():
    folder = os.path.dirname(DATABASE_PATH)

    if folder:
        os.makedirs(folder, exist_ok=True)

    conn = sqlite3.connect(
        DATABASE_PATH,
        check_same_thread=False
    )

    conn.row_factory = sqlite3.Row

    return conn


def init_db():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            pro INTEGER DEFAULT 0,
            subscription_id TEXT,
            subscription_status TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS webhook_events (
            id TEXT PRIMARY KEY,
            type TEXT,
            received_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()


# =========================================================
# HELPERS
# =========================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_email(email: str):
    return email.strip().lower()


def hash_password(password: str):

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )

    return (
        salt.hex()
        + ":"
        + password_hash.hex()
    )


def verify_password(password: str, stored: str):

    try:
        salt_hex, hash_hex = stored.split(":", 1)

        salt = bytes.fromhex(salt_hex)

        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            200_000
        )

        return hmac.compare_digest(
            calculated.hex(),
            hash_hex
        )

    except Exception:
        return False


def create_session(user_id: int):

    token = secrets.token_urlsafe(48)

    conn = get_db()

    conn.execute(
        """
        INSERT INTO sessions
        (token, user_id, created_at)
        VALUES (?, ?, ?)
        """,
        (
            token,
            user_id,
            now_iso()
        )
    )

    conn.commit()
    conn.close()

    return token


def get_user_by_token(token: str):

    if not token:
        return None

    conn = get_db()

    row = conn.execute(
        """
        SELECT u.*
        FROM users u
        JOIN sessions s
          ON s.user_id = u.id
        WHERE s.token = ?
        """,
        (token,)
    ).fetchone()

    conn.close()

    return row


def update_user_pro(
    user_id: int,
    pro: bool,
    subscription_id: Optional[str] = None,
    subscription_status: Optional[str] = None
):

    conn = get_db()

    conn.execute(
        """
        UPDATE users
        SET
            pro = ?,
            subscription_id = COALESCE(?, subscription_id),
            subscription_status = COALESCE(
                ?,
                subscription_status
            ),
            updated_at = ?
        WHERE id = ?
        """,
        (
            1 if pro else 0,
            subscription_id,
            subscription_status,
            now_iso(),
            user_id
        )
    )

    conn.commit()
    conn.close()


# =========================================================
# MERCADO PAGO
# =========================================================

def mp_headers():

    if not MP_ACCESS_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="MP_ACCESS_TOKEN não configurado."
        )

    return {
        "Authorization": f"Bearer {MP_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }


def consultar_assinatura(subscription_id: str):

    response = requests.get(
        f"{MP_API}/preapproval/{subscription_id}",
        headers=mp_headers(),
        timeout=20
    )

    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail="Não foi possível consultar a assinatura no Mercado Pago."
        )

    return response.json()


def status_pro(status: str):

    return status.lower() in {
        "authorized",
        "active"
    }


# =========================================================
# WEBHOOK MERCADO PAGO
# =========================================================

def validar_webhook(request: Request):

    if not MP_WEBHOOK_SECRET:
        return True

    x_signature = request.headers.get(
        "x-signature"
    )

    x_request_id = request.headers.get(
        "x-request-id"
    )

    if not x_signature or not x_request_id:
        return False

    data_id = request.query_params.get(
        "data.id",
        ""
    ).lower()

    parts = x_signature.split(",")

    ts = None
    received_hash = None

    for part in parts:

        key_value = part.split(
            "=",
            1
        )

        if len(key_value) != 2:
            continue

        key = key_value[0].strip()
        value = key_value[1].strip()

        if key == "ts":
            ts = value

        elif key == "v1":
            received_hash = value

    if not ts or not received_hash:
        return False

    manifest_parts = []

    if data_id:
        manifest_parts.append(
            f"id:{data_id}"
        )

    if x_request_id:
        manifest_parts.append(
            f"request-id:{x_request_id}"
        )

    if ts:
        manifest_parts.append(
            f"ts:{ts}"
        )

    manifest = ";".join(
        manifest_parts
    ) + ";"

    calculated_hash = hmac.new(
        MP_WEBHOOK_SECRET.encode("utf-8"),
        manifest.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(
        calculated_hash,
        received_hash
    )


# =========================================================
# MODELS
# =========================================================

class CriarConta(BaseModel):
    email: EmailStr
    password: str


class Login(BaseModel):
    email: EmailStr
    password: str


class Assinar(BaseModel):
    token: str


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():

    return {
        "app": APP_NAME,
        "status": "online",
        "price": "R$ 9,90/mês"
    }


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():

    return {
        "ok": True,
        "app": APP_NAME
    }


# =========================================================
# CRIAR CONTA
# =========================================================

@app.post("/criar-conta-pro")
def criar_conta(data: CriarConta):

    email = normalize_email(
        data.email
    )

    if len(data.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="A senha deve ter pelo menos 6 caracteres."
        )

    conn = get_db()

    existing = conn.execute(
        """
        SELECT id
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    if existing:

        conn.close()

        raise HTTPException(
            status_code=409,
            detail="Este e-mail já possui uma conta."
        )

    password_hash = hash_password(
        data.password
    )

    cursor = conn.execute(
        """
        INSERT INTO users
        (
            email,
            password_hash,
            pro,
            created_at,
            updated_at
        )
        VALUES (?, ?, 0, ?, ?)
        """,
        (
            email,
            password_hash,
            now_iso(),
            now_iso()
        )
    )

    user_id = cursor.lastrowid

    conn.commit()
    conn.close()

    token = create_session(
        user_id
    )

    return {
        "ok": True,
        "token": token,
        "email": email,
        "pro": False
    }


# =========================================================
# LOGIN
# =========================================================

@app.post("/login-pro")
def login(data: Login):

    email = normalize_email(
        data.email
    )

    conn = get_db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    conn.close()

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

    token = create_session(
        user["id"]
    )

    return {
        "ok": True,
        "token": token,
        "email": user["email"],
        "pro": bool(user["pro"]),
        "subscription_status":
            user["subscription_status"]
    }


# =========================================================
# VERIFICAR SESSÃO
# =========================================================

@app.get("/verificar-sessao")
def verificar_sessao(
    token: str
):

    user = get_user_by_token(
        token
    )

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Sessão inválida."
        )

    return {
        "ok": True,
        "user_id": user["id"],
        "email": user["email"],
        "pro": bool(user["pro"]),
        "subscription_id":
            user["subscription_id"],
        "subscription_status":
            user["subscription_status"]
    }


# =========================================================
# CRIAR ASSINATURA
# =========================================================

@app.post("/assinar")
def assinar(data: Assinar):

    user = get_user_by_token(
        data.token
    )

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Sessão inválida."
        )

    if not MP_ACCESS_TOKEN:

        raise HTTPException(
            status_code=500,
            detail="Mercado Pago não configurado no servidor."
        )

    # Se já existe assinatura, consultar antes
    if user["subscription_id"]:

        try:

            subscription = consultar_assinatura(
                user["subscription_id"]
            )

            status = subscription.get(
                "status",
                ""
            )

            update_user_pro(
                user["id"],
                status_pro(status),
                user["subscription_id"],
                status
            )

            if status_pro(status):

                return {
                    "ok": True,
                    "already_pro": True,
                    "pro": True,
                    "subscription_id":
                        user["subscription_id"]
                }

        except Exception:
            pass

    external_reference = (
        f"SELLIUM_USER_{user['id']}"
    )

    payload = {
        "reason": "Sellium PRO",
        "external_reference":
            external_reference,
        "payer_email":
            user["email"],
        "auto_recurring": {
            "frequency": 1,
            "frequency_type": "months",
            "transaction_amount":
                PRO_PRICE,
            "currency_id": "BRL"
        },
        "back_url":
            f"{APP_URL}/area-pro.html"
    }

    # Se existir um plano criado no Mercado Pago,
    # usamos o plano.
    if MP_PLAN_ID:

        payload["preapproval_plan_id"] = (
            MP_PLAN_ID
        )

    response = requests.post(
        f"{MP_API}/preapproval",
        headers=mp_headers(),
        json=payload,
        timeout=30
    )

    if response.status_code not in (
        200,
        201
    ):

        try:
            error_data = response.json()
        except Exception:
            error_data = {
                "message": response.text
            }

        raise HTTPException(
            status_code=502,
            detail={
                "message":
                    "Mercado Pago recusou a criação da assinatura.",
                "mercadopago":
                    error_data
            }
        )

    subscription = response.json()

    subscription_id = subscription.get(
        "id"
    )

    status = subscription.get(
        "status",
        ""
    )

    if subscription_id:

        update_user_pro(
            user["id"],
            status_pro(status),
            str(subscription_id),
            status
        )

    checkout_url = (
        subscription.get("init_point")
        or subscription.get("sandbox_init_point")
    )

    return {
        "ok": True,
        "pro": status_pro(status),
        "subscription_id":
            subscription_id,
        "status": status,
        "checkout_url":
            checkout_url,
        "init_point":
            subscription.get("init_point"),
        "sandbox_init_point":
            subscription.get(
                "sandbox_init_point"
            )
    }


# =========================================================
# VERIFICAR PRO
# =========================================================

@app.get("/verificar-pro")
def verificar_pro(
    email: str
):

    email = normalize_email(
        email
    )

    conn = get_db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    conn.close()

    if not user:

        return {
            "ok": True,
            "pro": False,
            "status": "inactive"
        }

    subscription_id = (
        user["subscription_id"]
    )

    # Se houver assinatura, consulta o Mercado Pago
    # para evitar depender somente do banco local.
    if subscription_id:

        try:

            subscription = consultar_assinatura(
                subscription_id
            )

            status = subscription.get(
                "status",
                ""
            )

            ativo = status_pro(
                status
            )

            update_user_pro(
                user["id"],
                ativo,
                subscription_id,
                status
            )

            return {
                "ok": True,
                "pro": ativo,
                "status": status,
                "subscription_id":
                    subscription_id
            }

        except Exception:
            pass

    return {
        "ok": True,
        "pro": bool(user["pro"]),
        "status":
            user["subscription_status"]
            or "inactive",
        "subscription_id":
            subscription_id
    }


# =========================================================
# WEBHOOK MERCADO PAGO
# =========================================================

@app.post("/webhook/mercadopago")
async def webhook_mercadopago(
    request: Request
):

    # Segurança do webhook
    if not validar_webhook(request):

        raise HTTPException(
            status_code=401,
            detail="Webhook inválido."
        )

    body = await request.json()

    event_id = str(
        body.get("id")
        or body.get("data", {}).get("id")
        or secrets.token_urlsafe(16)
    )

    event_type = (
        body.get("type")
        or body.get("topic")
        or ""
    )

    # Idempotência
    conn = get_db()

    existing = conn.execute(
        """
        SELECT id
        FROM webhook_events
        WHERE id = ?
        """,
        (event_id,)
    ).fetchone()

    if existing:

        conn.close()

        return {
            "ok": True,
            "duplicate": True
        }

    conn.execute(
        """
        INSERT INTO webhook_events
        (
            id,
            type,
            received_at
        )
        VALUES (?, ?, ?)
        """,
        (
            event_id,
            event_type,
            now_iso()
        )
    )

    conn.commit()
    conn.close()

    object_id = (
        body.get("data", {}).get("id")
        or body.get("id")
    )

    # -----------------------------------------------------
    # ASSINATURA
    # -----------------------------------------------------

    if event_type in (
        "subscription_preapproval",
        "preapproval"
    ):

        if object_id:

            try:

                subscription = consultar_assinatura(
                    str(object_id)
                )

                external_reference = (
                    subscription.get(
                        "external_reference"
                    )
                )

                status = subscription.get(
                    "status",
                    ""
                )

                if external_reference and external_reference.startswith(
                    "SELLIUM_USER_"
                ):

                    try:

                        user_id = int(
                            external_reference.replace(
                                "SELLIUM_USER_",
                                ""
                            )
                        )

                        update_user_pro(
                            user_id,
                            status_pro(status),
                            str(object_id),
                            status
                        )

                    except ValueError:
                        pass

            except Exception:
                pass

    # -----------------------------------------------------
    # PAGAMENTO RECORRENTE
    # -----------------------------------------------------

    elif event_type == "subscription_authorized_payment":

        if object_id:

            try:

                response = requests.get(
                    f"{MP_API}/authorized_payments/{object_id}",
                    headers=mp_headers(),
                    timeout=20
                )

                if response.status_code == 200:

                    payment = response.json()

                    preapproval_id = (
                        payment.get(
                            "preapproval_id"
                        )
                        or payment.get(
                            "subscription_id"
                        )
                    )

                    if preapproval_id:

                        subscription = consultar_assinatura(
                            str(preapproval_id)
                        )

                        external_reference = (
                            subscription.get(
                                "external_reference"
                            )
                        )

                        status = subscription.get(
                            "status",
                            ""
                        )

                        if external_reference and external_reference.startswith(
                            "SELLIUM_USER_"
                        ):

                            try:

                                user_id = int(
                                    external_reference.replace(
                                        "SELLIUM_USER_",
                                        ""
                                    )
                                )

                                update_user_pro(
                                    user_id,
                                    status_pro(status),
                                    str(preapproval_id),
                                    status
                                )

                            except ValueError:
                                pass

            except Exception:
                pass

    return {
        "ok": True
    }


# =========================================================
# SINCRONIZAR PRO MANUALMENTE
# =========================================================

@app.post("/sincronizar-pro")
def sincronizar_pro(
    token: str
):

    user = get_user_by_token(
        token
    )

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Sessão inválida."
        )

    if not user["subscription_id"]:

        return {
            "ok": True,
            "pro": False,
            "status": "inactive"
        }

    subscription = consultar_assinatura(
        user["subscription_id"]
    )

    status = subscription.get(
        "status",
        ""
    )

    ativo = status_pro(
        status
    )

    update_user_pro(
        user["id"],
        ativo,
        user["subscription_id"],
        status
    )

    return {
        "ok": True,
        "pro": ativo,
        "status": status,
        "subscription_id":
            user["subscription_id"],
        "next_payment_date":
            subscription.get(
                "next_payment_date"
            )
}
