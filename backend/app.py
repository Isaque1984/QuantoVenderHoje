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


APP_URL = os.getenv(
    "APP_URL",
    "https://quantovenderhoje.onrender.com"
)

MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN", "")
MP_PLAN_ID = os.getenv("MP_PLAN_ID", "")
MP_WEBHOOK_SECRET = os.getenv("MP_WEBHOOK_SECRET", "")

DATABASE_PATH = os.getenv("DATABASE_PATH", "sellium.db")

MP_API = "https://api.mercadopago.com"
PRO_PRICE = 9.90

MP_TIMEOUT = 8


app = FastAPI(
    title="Sellium PRO API",
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
# BANCO
# =========================================================

def get_db():
    db = sqlite3.connect(
        DATABASE_PATH,
        timeout=30
    )

    db.row_factory = sqlite3.Row

    db.execute("PRAGMA busy_timeout = 30000")
    db.execute("PRAGMA synchronous = NORMAL")

    return db


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            pro INTEGER DEFAULT 0,
            subscription_id TEXT,
            subscription_status TEXT,
            created_at TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS webhook_events (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        )
    """)

    db.commit()
    db.close()


init_db()


# =========================================================
# UTILITÁRIOS
# =========================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_email(email: str):
    return email.strip().lower()


def hash_password(password: str):
    salt = secrets.token_bytes(16)

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200000
    )

    return salt.hex() + ":" + derived.hex()


def verify_password(password: str, stored: str):
    try:
        salt_hex, hash_hex = stored.split(":")

        salt = bytes.fromhex(salt_hex)

        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            200000
        )

        return hmac.compare_digest(
            derived.hex(),
            hash_hex
        )

    except Exception:
        return False


def create_session(user_id: int):
    token = secrets.token_urlsafe(32)

    db = get_db()

    try:
        db.execute(
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

        db.commit()

        return token

    finally:
        db.close()


def get_user_by_token(token: str):
    db = get_db()

    try:
        user = db.execute(
            """
            SELECT users.*
            FROM users
            JOIN sessions
            ON sessions.user_id = users.id
            WHERE sessions.token = ?
            """,
            (token,)
        ).fetchone()

        return user

    finally:
        db.close()


def update_user_pro(
    user_id: int,
    pro: bool,
    subscription_id: Optional[str] = None,
    subscription_status: Optional[str] = None
):
    db = get_db()

    try:
        db.execute(
            """
            UPDATE users
            SET
                pro = ?,
                subscription_id = COALESCE(?, subscription_id),
                subscription_status = COALESCE(?, subscription_status)
            WHERE id = ?
            """,
            (
                1 if pro else 0,
                subscription_id,
                subscription_status,
                user_id
            )
        )

        db.commit()

    finally:
        db.close()


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

    try:

        response = requests.get(
            f"{MP_API}/preapproval/{subscription_id}",
            headers=mp_headers(),
            timeout=MP_TIMEOUT
        )

        if response.status_code != 200:
            return None

        return response.json()

    except Exception:

        return None


def status_pro(status: Optional[str]):

    return status in (
        "authorized",
        "active"
    )


def escolher_assinatura(resultados):

    if not resultados:
        return None

    # Primeiro procura uma assinatura realmente ativa.
    for subscription in resultados:

        status = str(
            subscription.get("status") or ""
        ).lower()

        if status in (
            "authorized",
            "active"
        ):
            return subscription

    # Se não existe ativa, procura uma do Sellium.
    for subscription in resultados:

        reason = str(
            subscription.get("reason") or ""
        ).lower()

        external_reference = str(
            subscription.get("external_reference") or ""
        )

        if (
            "sellium" in reason
            or external_reference.startswith(
                "SELLIUM_USER_"
            )
        ):
            return subscription

    # Por último, se existir apenas uma,
    # permite identificar essa assinatura.
    if len(resultados) == 1:
        return resultados[0]

    return None


def buscar_assinaturas_por_email(email: str):

    try:

        response = requests.get(
            f"{MP_API}/preapproval/search",
            headers=mp_headers(),
            params={
                "payer_email": email
            },
            timeout=MP_TIMEOUT
        )

        if response.status_code != 200:
            return None

        data = response.json()

        return data.get(
            "results",
            []
        )

    except Exception:

        return None


# =========================================================
# MODELOS
# =========================================================

class CriarConta(BaseModel):
    email: EmailStr
    password: str


class Login(BaseModel):
    email: EmailStr
    password: str


class Assinar(BaseModel):
    token: str
    mp_email: EmailStr


# =========================================================
# BÁSICO
# =========================================================

@app.get("/")
def root():

    return {
        "app": "Sellium PRO API",
        "status": "online"
    }


@app.get("/health")
def health():

    return {
        "ok": True,
        "app": "Sellium PRO API"
    }


# =========================================================
# CRIAR CONTA
# =========================================================

@app.post("/criar-conta-pro")
def criar_conta(data: CriarConta):

    email = normalize_email(
        str(data.email)
    )

    password = data.password

    if len(password) < 6:

        raise HTTPException(
            status_code=400,
            detail="A senha precisa ter pelo menos 6 caracteres."
        )

    password_hash = hash_password(password)

    db = get_db()

    try:

        existing = db.execute(
            """
            SELECT id
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        if existing:

            raise HTTPException(
                status_code=400,
                detail="Este e-mail já possui uma conta."
            )

        cursor = db.execute(
            """
            INSERT INTO users
            (
                email,
                password_hash,
                pro,
                created_at
            )
            VALUES (?, ?, 0, ?)
            """,
            (
                email,
                password_hash,
                now_iso()
            )
        )

        user_id = cursor.lastrowid

        db.commit()

    except HTTPException:

        db.rollback()
        raise

    except sqlite3.IntegrityError:

        db.rollback()

        raise HTTPException(
            status_code=400,
            detail="Este e-mail já possui uma conta."
        )

    except sqlite3.OperationalError as e:

        db.rollback()

        if "locked" in str(e).lower():

            raise HTTPException(
                status_code=503,
                detail="O banco está ocupado. Tente novamente em alguns segundos."
            )

        raise HTTPException(
            status_code=500,
            detail="Não foi possível criar a conta."
        )

    finally:

        db.close()

    token = create_session(user_id)

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
        str(data.email)
    )

    db = get_db()

    try:

        user = db.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

    finally:

        db.close()

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
        "pro": bool(user["pro"])
    }


# =========================================================
# VERIFICAR SESSÃO
# =========================================================

@app.get("/verificar-sessao")
def verificar_sessao(token: str):

    user = get_user_by_token(token)

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Sessão inválida ou expirada."
        )

    return {
        "ok": True,
        "email": user["email"],
        "pro": bool(user["pro"]),
        "subscription_id": user["subscription_id"],
        "subscription_status": user["subscription_status"]
    }


# =========================================================
# ASSINAR PRO
# =========================================================

@app.post("/assinar")
def assinar(data: Assinar):

    user = get_user_by_token(
        data.token
    )

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Sessão inválida ou expirada."
        )

    if not MP_ACCESS_TOKEN:

        raise HTTPException(
            status_code=500,
            detail="Mercado Pago não configurado no servidor."
        )

    mp_email = normalize_email(
        str(data.mp_email)
    )

    # =====================================================
    # PRIMEIRO: PROCURA UMA ASSINATURA JÁ EXISTENTE
    # =====================================================

    resultados = buscar_assinaturas_por_email(
        mp_email
    )

    if resultados is not None:

        assinatura_existente = escolher_assinatura(
            resultados
        )

        if assinatura_existente:

            subscription_id = (
                assinatura_existente.get("id")
            )

            status = (
                assinatura_existente.get("status")
            )

            if (
                subscription_id
                and status_pro(status)
            ):

                update_user_pro(
                    user["id"],
                    True,
                    str(subscription_id),
                    status
                )

                return {
                    "ok": True,
                    "pro": True,
                    "already_pro": True,
                    "subscription_id":
                        str(subscription_id),
                    "status": status,
                    "checkout_url": None
                }

    # =====================================================
    # NÃO ENCONTROU PRO ATIVO
    # ENTÃO CRIA UMA NOVA ASSINATURA
    # =====================================================

    payload = {

        "reason": "Sellium PRO",

        "external_reference":
            f"SELLIUM_USER_{user['id']}",

        "payer_email": mp_email,

        "auto_recurring": {

            "frequency": 1,

            "frequency_type": "months",

            "transaction_amount": PRO_PRICE,

            "currency_id": "BRL"
        },

        "back_url":
            f"{APP_URL}/area-pro.html"
    }

    if MP_PLAN_ID:

        payload["preapproval_plan_id"] = MP_PLAN_ID

    try:

        response = requests.post(

            f"{MP_API}/preapproval",

            headers=mp_headers(),

            json=payload,

            timeout=MP_TIMEOUT

        )

    except requests.Timeout:

        raise HTTPException(

            status_code=504,

            detail="O Mercado Pago demorou para responder. Tente novamente."
        )

    except Exception:

        raise HTTPException(

            status_code=502,

            detail="Erro ao conectar ao Mercado Pago."
        )

    try:

        subscription = response.json()

    except Exception:

        subscription = {
            "raw": response.text
        }

    if response.status_code not in (
        200,
        201
    ):

        raise HTTPException(

            status_code=502,

            detail={
                "message":
                    "Mercado Pago recusou a criação da assinatura.",

                "mercadopago":
                    subscription
            }
        )

    subscription_id = subscription.get(
        "id"
    )

    status = subscription.get(
        "status"
    )

    checkout_url = (
        subscription.get("init_point")
        or subscription.get("checkout_url")
        or subscription.get("sandbox_init_point")
    )

    update_user_pro(
        user["id"],
        status_pro(status),
        subscription_id,
        status
    )

    return {

        "ok": True,

        "pro":
            status_pro(status),

        "subscription_id":
            subscription_id,

        "status":
            status,

        "checkout_url":
            checkout_url,

        "init_point":
            subscription.get("init_point"),

        "sandbox_init_point":
            subscription.get("sandbox_init_point")
    }


# =========================================================
# VERIFICAR PRO
# =========================================================

@app.get("/verificar-pro")
def verificar_pro(email: EmailStr):

    email = normalize_email(
        str(email)
    )

    db = get_db()

    try:

        user = db.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

    finally:

        db.close()

    if not user:

        return {
            "ok": True,
            "pro": False,
            "status": "inactive"
        }

    if user["subscription_id"]:

        subscription = consultar_assinatura(
            user["subscription_id"]
        )

        if subscription:

            status = subscription.get(
                "status"
            )

            update_user_pro(
                user["id"],
                status_pro(status),
                user["subscription_id"],
                status
            )

            return {
                "ok": True,
                "pro": status_pro(status),
                "status": status
            }

    return {
        "ok": True,
        "pro": bool(user["pro"]),
        "status":
            user["subscription_status"]
            or "inactive"
    }


# =========================================================
# WEBHOOK
# =========================================================

@app.post("/webhook/mercadopago")
async def webhook_mercadopago(
    request: Request
):

    body = await request.body()

    try:

        data = await request.json()

    except Exception:

        data = {}

    data_id = None

    if isinstance(data, dict):

        if isinstance(
            data.get("data"),
            dict
        ):

            data_id = data["data"].get(
                "id"
            )

    event_id = (
        request.headers.get(
            "x-request-id"
        )
        or hashlib.sha256(
            body
        ).hexdigest()
    )

    db = get_db()

    try:

        existing = db.execute(
            """
            SELECT id
            FROM webhook_events
            WHERE id = ?
            """,
            (event_id,)
        ).fetchone()

        if existing:

            return {
                "ok": True,
                "duplicate": True
            }

        db.execute(
            """
            INSERT INTO webhook_events
            (id, created_at)
            VALUES (?, ?)
            """,
            (
                event_id,
                now_iso()
            )
        )

        db.commit()

    finally:

        db.close()

    event_type = (
        data.get("type")
        or data.get("action")
        or ""
    )

    object_id = (
        str(data_id)
        if data_id
        else None
    )

    if event_type in (
        "subscription_preapproval",
        "preapproval"
    ):

        if object_id:

            subscription = consultar_assinatura(
                object_id
            )

            if subscription:

                external_reference = (
                    subscription.get(
                        "external_reference"
                    )
                )

                if (
                    external_reference
                    and external_reference.startswith(
                        "SELLIUM_USER_"
                    )
                ):

                    try:

                        user_id = int(
                            external_reference.replace(
                                "SELLIUM_USER_",
                                ""
                            )
                        )

                        status = subscription.get(
                            "status"
                        )

                        update_user_pro(
                            user_id,
                            status_pro(status),
                            object_id,
                            status
                        )

                    except Exception:

                        pass

    return {
        "ok": True
    }


# =========================================================
# SINCRONIZAR PRO
# =========================================================

@app.post("/sincronizar-pro")
def sincronizar_pro(
    token: str,
    mp_email: Optional[EmailStr] = None
):

    user = get_user_by_token(
        token
    )

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Sessão inválida ou expirada."
        )

    # =====================================================
    # COM E-MAIL DO MERCADO PAGO:
    # FAZ UMA ÚNICA BUSCA
    # =====================================================

    if mp_email:

        email = normalize_email(
            str(mp_email)
        )

        resultados = buscar_assinaturas_por_email(
            email
        )

        if resultados is not None:

            assinatura = escolher_assinatura(
                resultados
            )

            if assinatura:

                subscription_id = (
                    assinatura.get("id")
                )

                status = (
                    assinatura.get("status")
                )

                if subscription_id:

                    update_user_pro(
                        user["id"],
                        status_pro(status),
                        str(subscription_id),
                        status
                    )

                    return {
                        "ok": True,
                        "pro":
                            status_pro(status),
                        "status":
                            status,
                        "subscription_id":
                            str(subscription_id),
                        "recovered":
                            True
                    }

        # Nenhuma assinatura encontrada.
        update_user_pro(
            user["id"],
            False,
            None,
            "inactive"
        )

        return {
            "ok": True,
            "pro": False,
            "status": "inactive",
            "subscription_id": None
        }

    # =====================================================
    # SEM E-MAIL INFORMADO:
    # USA A ASSINATURA SALVA
    # =====================================================

    if user["subscription_id"]:

        subscription = consultar_assinatura(
            user["subscription_id"]
        )

        if subscription:

            status = subscription.get(
                "status"
            )

            update_user_pro(
                user["id"],
                status_pro(status),
                user["subscription_id"],
                status
            )

            return {
                "ok": True,
                "pro":
                    status_pro(status),
                "status":
                    status,
                "subscription_id":
                    user["subscription_id"]
            }

    # =====================================================
    # SEM ASSINATURA
    # =====================================================

    return {
        "ok": True,
        "pro": bool(user["pro"]),
        "status":
            user["subscription_status"]
            or "inactive"
    }
