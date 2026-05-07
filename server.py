import os
import jwt
import hashlib
import base64
import hmac
import secrets
import json
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional, Any, Dict, List
from urllib.parse import urlencode
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError, URLError
 
from fastapi import FastAPI, HTTPException, Depends, Header, Request, BackgroundTasks, Response, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from pymongo.errors import DuplicateKeyError, OperationFailure
import uvicorn
 
# === Config ===
MONGO_URL = os.getenv("MONGO_URL", "mongodb://127.0.0.1:27017")
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALG = "HS256"
PBKDF2_ALG = "sha256"
PBKDF2_ITERATIONS = 390000
PBKDF2_SALT_BYTES = 16
PBKDF2_KEY_BYTES = 32
CORS_ALLOW_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ALLOW_ORIGINS",
        "http://localhost:8080,http://127.0.0.1:8080",
    ).split(",")
    if origin.strip()
]
TINY_API_TOKEN = os.getenv("TINY_API_TOKEN", "").strip()
TINY_API_BASE_URL = os.getenv("TINY_API_BASE_URL", "https://api.tiny.com.br/api2").strip()
TINY_SYNC_INTERVAL_MINUTES = int(os.getenv("TINY_SYNC_INTERVAL_MINUTES", "30"))
JWT_ACCESS_TOKEN_HOURS = int(os.getenv("JWT_ACCESS_TOKEN_HOURS", "1"))
REFRESH_TOKEN_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "14"))
ACCESS_COOKIE_NAME = os.getenv("ACCESS_COOKIE_NAME", "mp_access_token")
REFRESH_COOKIE_NAME = os.getenv("REFRESH_COOKIE_NAME", "mp_refresh_token")
COOKIE_SECURE = os.getenv("AUTH_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}
COOKIE_SAMESITE = os.getenv("AUTH_COOKIE_SAMESITE", "lax").strip().lower()
PRICING_GROUPS_CACHE_TTL_SECONDS = int(os.getenv("PRICING_GROUPS_CACHE_TTL_SECONDS", "300"))
PRODUTOS_MAX_PAGE_LIMIT = int(os.getenv("PRODUTOS_MAX_PAGE_LIMIT", "100"))
PRODUTOS_MAX_EXPORT_LIMIT = int(os.getenv("PRODUTOS_MAX_EXPORT_LIMIT", "10000"))

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET não configurado. Defina a variável de ambiente JWT_SECRET.")
 
# === DB ===
client = AsyncIOMotorClient(MONGO_URL)
db = client.monitor_precos
produtos_col = db.produtos
historico_col = db.historico
usuarios_col = db.usuarios
pricing_groups_col = db.pricing_groups
tiny_sync_state_col = db.tiny_sync_state
app_state_col = db.app_state
admin_events_col = db.admin_events
 
# === App ===
app = FastAPI(title="Monitor de Preços")
 
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
 
CANAIS = ["mercado_livre", "amazon", "shopee", "droga_raia"]
PERFIS = ["master", "admin", "visualizador"]
CURVAS_ABC = ["A", "B", "C"]
 
 
# === Helpers ===
 
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def serial_value(value):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [serial_value(item) for item in value]
    if isinstance(value, dict):
        return {
            ("id" if k == "_id" else k): serial_value(v)
            for k, v in value.items()
        }
    return value


def serial(doc):
    if doc is None:
        return None
 
    return serial_value(dict(doc))


def normalizar_email(email: str) -> str:
    return str(email or "").strip().lower()


def sanitizar_usuario(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = serial(doc)
    for campo in (
        "senha_hash",
        "senha",
        "password",
        "refresh_token_hash",
        "refresh_token_expires_at",
    ):
        out.pop(campo, None)
    return out


async def registrar_evento_admin(
    acao: str,
    alvo_id: str,
    actor: Optional[Dict[str, Any]] = None,
    detalhes: Optional[Dict[str, Any]] = None,
) -> None:
    await admin_events_col.insert_one({
        "acao": acao,
        "alvo_id": alvo_id,
        "actor_id": actor.get("user_id") if actor else None,
        "actor_email": actor.get("email") if actor else None,
        "detalhes": detalhes or {},
        "criado_em": utcnow(),
    })


async def criar_indice_seguro(collection, keys, **kwargs) -> None:
    try:
        await collection.create_index(keys, **kwargs)
    except (OperationFailure, DuplicateKeyError) as exc:
        print(f"[startup] Falha ao criar índice {keys}: {exc}")


@app.on_event("startup")
async def startup_setup() -> None:
    await criar_indice_seguro(usuarios_col, [("email", 1)], unique=True)
    await criar_indice_seguro(
        usuarios_col,
        [("refresh_token_hash", 1)],
        unique=True,
        partialFilterExpression={"refresh_token_hash": {"$type": "string", "$gt": ""}},
    )
    await criar_indice_seguro(
        produtos_col,
        [("sku", 1)],
        unique=True,
        partialFilterExpression={"sku": {"$type": "string", "$gt": ""}},
    )
    await criar_indice_seguro(
        produtos_col,
        [("ean", 1)],
        partialFilterExpression={"ean": {"$type": "string", "$gt": ""}},
    )
    await criar_indice_seguro(
        produtos_col,
        [("tiny_id", 1)],
        unique=True,
        partialFilterExpression={"tiny_id": {"$type": "string", "$gt": ""}},
    )
    await criar_indice_seguro(historico_col, [("produto_id", 1), ("canal", 1), ("data", -1)])
    await criar_indice_seguro(pricing_groups_col, [("grupo", 1)], unique=True)
    await garantir_grupos_precificacao()
 
 
def hash_senha(senha: str) -> str:
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    chave = hashlib.pbkdf2_hmac(
        PBKDF2_ALG,
        senha.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=PBKDF2_KEY_BYTES,
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    chave_b64 = base64.b64encode(chave).decode("ascii")
    return f"pbkdf2_{PBKDF2_ALG}${PBKDF2_ITERATIONS}${salt_b64}${chave_b64}"


def is_hash_legacy_sha256(senha_hash: str) -> bool:
    return isinstance(senha_hash, str) and len(senha_hash) == 64 and "$" not in senha_hash


def verificar_senha(senha: str, senha_hash: str) -> bool:
    if not senha_hash:
        return False

    if is_hash_legacy_sha256(senha_hash):
        return hmac.compare_digest(
            senha_hash,
            hashlib.sha256(senha.encode("utf-8")).hexdigest(),
        )

    try:
        algoritmo, iteracoes_str, salt_b64, chave_b64 = senha_hash.split("$", 3)
        if algoritmo != f"pbkdf2_{PBKDF2_ALG}":
            return False

        iteracoes = int(iteracoes_str)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        chave_esperada = base64.b64decode(chave_b64.encode("ascii"))
        chave_recebida = hashlib.pbkdf2_hmac(
            PBKDF2_ALG,
            senha.encode("utf-8"),
            salt,
            iteracoes,
            dklen=len(chave_esperada),
        )
        return hmac.compare_digest(chave_esperada, chave_recebida)
    except Exception:
        return False
 
 
def criar_token(user_id: str, perfil: str) -> str:
    emitido_em = utcnow()
    payload = {
        "user_id": user_id,
        "perfil": perfil,
        "iat": emitido_em,
        "exp": emitido_em + timedelta(hours=JWT_ACCESS_TOKEN_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def hash_refresh_token(token: str) -> str:
    return hmac.new(
        JWT_SECRET.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def set_cookie_seguro(response: Response, nome: str, valor: str, max_age: int) -> None:
    response.set_cookie(
        key=nome,
        value=valor,
        max_age=max_age,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
    )


def limpar_cookies_auth(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE_NAME, path="/")
    response.delete_cookie(REFRESH_COOKIE_NAME, path="/")


async def emitir_cookies_auth(
    response: Response,
    user_id: str,
    perfil: str,
) -> str:
    access_token = criar_token(user_id, perfil)
    refresh_token = secrets.token_urlsafe(48)
    agora = utcnow()
    refresh_expira_em = agora + timedelta(days=REFRESH_TOKEN_DAYS)

    await usuarios_col.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "refresh_token_hash": hash_refresh_token(refresh_token),
                "refresh_token_expires_at": refresh_expira_em,
                "ultimo_login_em": agora,
            }
        },
    )

    set_cookie_seguro(
        response,
        ACCESS_COOKIE_NAME,
        access_token,
        JWT_ACCESS_TOKEN_HOURS * 60 * 60,
    )
    set_cookie_seguro(
        response,
        REFRESH_COOKIE_NAME,
        refresh_token,
        REFRESH_TOKEN_DAYS * 24 * 60 * 60,
    )
    return access_token
 
 
def object_id_or_400(value: str):
    try:
        return ObjectId(value)
    except Exception:
        raise HTTPException(status_code=400, detail="ID inválido")
 
 
def normalizar_canal(canal: Optional[str] = None) -> Optional[str]:
    if not canal or canal == "todos":
        return None
 
    if canal not in CANAIS:
        raise HTTPException(status_code=400, detail=f"Canal inválido. Use: {CANAIS}")
 
    return canal
 
 
async def get_user(
    authorization: Optional[str] = Header(None),
    access_cookie: Optional[str] = Cookie(None, alias=ACCESS_COOKIE_NAME),
):
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
    elif access_cookie:
        token = access_cookie

    if not token:
        raise HTTPException(status_code=401, detail="Não autenticado")
 
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("user_id")
        oid = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=401, detail="Token inválido")
 
    user_db = await usuarios_col.find_one({"_id": oid})
 
    if not user_db:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")
 
    if user_db.get("status", "aprovado") != "aprovado":
        raise HTTPException(status_code=403, detail="Usuário sem acesso aprovado")

    invalidado_em = user_db.get("token_invalidado_em")
    emitido_em = payload.get("iat")
    if invalidado_em and emitido_em:
        if isinstance(emitido_em, (int, float)):
            emitido_dt = datetime.fromtimestamp(float(emitido_em), tz=timezone.utc)
        elif isinstance(emitido_em, str):
            try:
                emitido_dt = datetime.fromisoformat(emitido_em.replace("Z", "+00:00"))
            except ValueError:
                emitido_dt = None
        else:
            emitido_dt = None

        if isinstance(invalidado_em, datetime) and invalidado_em.tzinfo is None:
            invalidado_em = invalidado_em.replace(tzinfo=timezone.utc)
        if emitido_dt and emitido_dt.tzinfo is None:
            emitido_dt = emitido_dt.replace(tzinfo=timezone.utc)
        if emitido_dt and invalidado_em and emitido_dt < invalidado_em:
            raise HTTPException(status_code=401, detail="Token expirado por alteração de acesso")
 
    return {
        "user_id": str(user_db["_id"]),
        "perfil": user_db.get("perfil", "visualizador"),
        "nome": user_db.get("nome", user_db.get("email", "")),
        "email": user_db.get("email", ""),
    }
 
 
async def master_required(user=Depends(get_user)):
    if user.get("perfil") != "master":
        raise HTTPException(status_code=403, detail="Acesso restrito ao master")
    return user
 
 
async def product_manager_required(user=Depends(get_user)):
    if user.get("perfil") not in ["master", "admin"]:
        raise HTTPException(status_code=403, detail="Acesso restrito ao master ou admin")
    return user
 
 
def classificar_gap(gap):
    if gap <= 0:
        return "Ganhando"
    if gap <= 3:
        return "Competitivo"
    if gap <= 10:
        return "Acima"
    return "Muito acima"


def normalizar_curva_abc(curva: Optional[str]) -> str:
    valor = str(curva or "C").strip().upper()
    return valor if valor in CURVAS_ABC else "C"


def to_float(valor: Any) -> Optional[float]:
    if valor is None:
        return None
    try:
        if isinstance(valor, str):
            txt = valor.strip()
            if "." in txt and "," in txt:
                txt = txt.replace(".", "").replace(",", ".")
            elif "," in txt:
                txt = txt.replace(",", ".")
            valor = txt
        return float(valor)
    except Exception:
        return None


def obter_grupo_default(grupo: str) -> Dict[str, Any]:
    grupo = normalizar_curva_abc(grupo)
    defaults = {
        "A": {
            "grupo": "A",
            "estrategia_base": "menor_preco",
            "ajuste_percentual": -1.0,
            "margem_minima_percentual": 8.0,
            "preco_minimo_grupo": 0.0,
            "estoque_baixo_limite": 5.0,
            "estoque_baixo_ajuste_percentual": 2.0,
            "ativo": True,
        },
        "B": {
            "grupo": "B",
            "estrategia_base": "preco_medio",
            "ajuste_percentual": 1.5,
            "margem_minima_percentual": 12.0,
            "preco_minimo_grupo": 0.0,
            "estoque_baixo_limite": 4.0,
            "estoque_baixo_ajuste_percentual": 3.0,
            "ativo": True,
        },
        "C": {
            "grupo": "C",
            "estrategia_base": "preco_medio",
            "ajuste_percentual": 4.0,
            "margem_minima_percentual": 18.0,
            "preco_minimo_grupo": 0.0,
            "estoque_baixo_limite": 3.0,
            "estoque_baixo_ajuste_percentual": 4.0,
            "ativo": True,
        },
    }
    return defaults[grupo]


pricing_groups_cache: Dict[str, Any] = {
    "expires_at": None,
    "data": None,
}


def invalidar_cache_grupos_precificacao() -> None:
    pricing_groups_cache["expires_at"] = None
    pricing_groups_cache["data"] = None


async def garantir_grupos_precificacao() -> None:
    for grupo in CURVAS_ABC:
        atual = await pricing_groups_col.find_one({"grupo": grupo})
        if not atual:
            doc = obter_grupo_default(grupo)
            doc["criado_em"] = utcnow()
            doc["atualizado_em"] = utcnow()
            await pricing_groups_col.insert_one(doc)


async def obter_mapa_grupos_precificacao() -> Dict[str, Dict[str, Any]]:
    agora = utcnow()
    expires_at = pricing_groups_cache.get("expires_at")
    data_cache = pricing_groups_cache.get("data")
    if data_cache and isinstance(expires_at, datetime) and expires_at > agora:
        return data_cache

    await garantir_grupos_precificacao()
    docs = await pricing_groups_col.find().to_list(20)
    mapa = {d.get("grupo", "C"): d for d in docs}
    for grupo in CURVAS_ABC:
        if grupo not in mapa:
            mapa[grupo] = obter_grupo_default(grupo)
    pricing_groups_cache["data"] = mapa
    pricing_groups_cache["expires_at"] = agora + timedelta(seconds=PRICING_GROUPS_CACHE_TTL_SECONDS)
    return mapa


def calcular_pendencias_produto(doc: Dict[str, Any]) -> List[str]:
    pendencias: List[str] = []
    sku = str(doc.get("sku") or "").strip()
    if not sku:
        pendencias.append("sem_sku")

    custo = to_float(doc.get("custo_unitario"))
    if custo is None or custo <= 0:
        pendencias.append("sem_custo")

    return pendencias


def validar_numero_nao_negativo(nome: str, valor: Any) -> None:
    num = to_float(valor)
    if num is not None and num < 0:
        raise HTTPException(status_code=400, detail=f"{nome} não pode ser negativo")


def validar_produto_negocio(produto: Any) -> None:
    if not str(produto.nome or "").strip():
        raise HTTPException(status_code=400, detail="Nome do produto é obrigatório")

    campos = {
        "Custo unitário": produto.custo_unitario,
        "Estoque atual": produto.estoque_atual,
        "Preço mínimo do produto": produto.preco_minimo_produto,
        "Preço máximo do produto": produto.preco_maximo_produto,
    }
    for nome, valor in campos.items():
        validar_numero_nao_negativo(nome, valor)

    pmin = to_float(produto.preco_minimo_produto)
    pmax = to_float(produto.preco_maximo_produto)
    if pmin is not None and pmax is not None and pmax > 0 and pmin > pmax:
        raise HTTPException(status_code=400, detail="Preço mínimo do produto não pode ser maior que o preço máximo")

    precos = produto.precos_praticados.dict() if produto.precos_praticados else {}
    for canal, valor in precos.items():
        num = to_float(valor)
        if num is not None and num <= 0:
            raise HTTPException(status_code=400, detail=f"Preço praticado de {canal} deve ser maior que zero")


def normalizar_doc_produto(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(doc)
    out["nome"] = str(out.get("nome") or "").strip()
    out["imagem_url"] = str(out.get("imagem_url") or out.get("imagem") or out.get("foto_url") or "").strip()
    out["palavra_chave_1"] = str(out.get("palavra_chave_1") or out.get("nome") or "").strip()
    out["curva_abc"] = normalizar_curva_abc(out.get("curva_abc"))
    out["custo_unitario"] = to_float(out.get("custo_unitario"))
    out["estoque_atual"] = to_float(out.get("estoque_atual"))
    out["preco_minimo_produto"] = to_float(out.get("preco_minimo_produto"))
    out["preco_maximo_produto"] = to_float(out.get("preco_maximo_produto"))
    out["tiny_id"] = str(out.get("tiny_id") or "").strip() or None
    out["sync_origem"] = out.get("sync_origem") or "manual"
    out["palavra_chave_2"] = out.get("palavra_chave_2") or ""

    pendencias = calcular_pendencias_produto(out)
    out["pendencias"] = pendencias
    out["status_integracao"] = "pendente" if pendencias else "ok"
    return out


async def obter_ultimos_precos_por_produto(
    produto_ids: List[str],
    desde: datetime,
) -> Dict[str, Dict[str, float]]:
    if not produto_ids:
        return {}

    pipeline_ultimos = [
        {
            "$match": {
                "produto_id": {"$in": produto_ids},
                "data": {"$gte": desde},
                "canal": {"$in": CANAIS},
            }
        },
        {"$sort": {"produto_id": 1, "canal": 1, "data": -1}},
        {
            "$group": {
                "_id": {"produto_id": "$produto_id", "canal": "$canal"},
                "preco": {"$first": "$preco"},
            }
        },
    ]
    ultimos = await historico_col.aggregate(pipeline_ultimos).to_list(length=200000)

    out: Dict[str, Dict[str, float]] = {}
    for item in ultimos:
        pid = item.get("_id", {}).get("produto_id")
        canal = item.get("_id", {}).get("canal")
        preco = to_float(item.get("preco"))
        if not pid or not canal or preco is None:
            continue
        if pid not in out:
            out[pid] = {}
        out[pid][canal] = preco
    return out


def consolidar_metricas_mercado(precos_por_canal: Dict[str, float]) -> Dict[str, Optional[float]]:
    if not precos_por_canal:
        return {
            "menor_preco_mercado": None,
            "maior_preco_mercado": None,
            "preco_medio_mercado": None,
            "menor_canal_mercado": None,
            "maior_canal_mercado": None,
        }

    valores = list(precos_por_canal.values())
    menor_canal, menor_preco = min(precos_por_canal.items(), key=lambda item: item[1])
    maior_canal, maior_preco = max(precos_por_canal.items(), key=lambda item: item[1])
    return {
        "menor_preco_mercado": menor_preco,
        "maior_preco_mercado": maior_preco,
        "preco_medio_mercado": sum(valores) / len(valores),
        "menor_canal_mercado": menor_canal,
        "maior_canal_mercado": maior_canal,
    }


def calcular_preco_sugerido(
    produto: Dict[str, Any],
    metricas: Dict[str, Optional[float]],
    config: Dict[str, Any],
) -> Dict[str, Any]:
    alertas: List[str] = []
    estrategia = config.get("estrategia_base") or "menor_preco"
    base = metricas.get("menor_preco_mercado") if estrategia == "menor_preco" else metricas.get("preco_medio_mercado")
    if base is None:
        return {
            "preco_sugerido": None,
            "base_estrategia": estrategia,
            "motivo": "Sem dados de mercado suficientes",
            "alertas": ["Sem dados de mercado suficientes"],
        }

    ajuste_percentual = to_float(config.get("ajuste_percentual")) or 0.0
    preco_ajustado = base * (1 + (ajuste_percentual / 100))

    estoque = to_float(produto.get("estoque_atual"))
    estoque_limite = to_float(config.get("estoque_baixo_limite"))
    estoque_ajuste = to_float(config.get("estoque_baixo_ajuste_percentual")) or 0.0
    estoque_baixo_aplicado = bool(
        estoque is not None
        and estoque_limite is not None
        and estoque <= estoque_limite
    )
    if estoque_baixo_aplicado:
        preco_ajustado *= (1 + (estoque_ajuste / 100))

    pisos: List[float] = []
    preco_minimo_grupo = to_float(config.get("preco_minimo_grupo"))
    if preco_minimo_grupo is not None:
        pisos.append(preco_minimo_grupo)

    preco_minimo_produto = to_float(produto.get("preco_minimo_produto"))
    if preco_minimo_produto is not None:
        pisos.append(preco_minimo_produto)

    custo = to_float(produto.get("custo_unitario"))
    margem_minima_percentual = to_float(config.get("margem_minima_percentual")) or 0.0
    piso_custo = None
    if custo is not None and custo > 0:
        piso_custo = custo * (1 + (margem_minima_percentual / 100))
        pisos.append(piso_custo)

    piso_final = max(pisos) if pisos else None
    preco_sugerido = max(preco_ajustado, piso_final) if piso_final is not None else preco_ajustado

    preco_maximo_produto = to_float(produto.get("preco_maximo_produto"))
    conflito_preco_maximo = bool(
        preco_maximo_produto is not None
        and preco_maximo_produto > 0
        and piso_final is not None
        and preco_maximo_produto < piso_final
    )
    if conflito_preco_maximo:
        alertas.append(
            "Preço máximo do produto está abaixo do piso mínimo calculado por custo/margem. Revise a regra antes de publicar."
        )
        return {
            "preco_sugerido": None,
            "base_estrategia": estrategia,
            "base_valor": round(base, 2),
            "ajuste_percentual": ajuste_percentual,
            "preco_ajustado": round(preco_ajustado, 2),
            "piso_custo": round(piso_custo, 2) if piso_custo is not None else None,
            "piso_final": round(piso_final, 2) if piso_final is not None else None,
            "preco_maximo_produto": round(preco_maximo_produto, 2),
            "preco_sem_teto": round(preco_sugerido, 2),
            "estoque_baixo_aplicado": estoque_baixo_aplicado,
            "conflito_preco_maximo": True,
            "motivo": "Conflito entre preço máximo e piso mínimo",
            "alertas": alertas,
        }

    if preco_maximo_produto is not None and preco_maximo_produto > 0:
        preco_sugerido = min(preco_sugerido, preco_maximo_produto)

    return {
        "preco_sugerido": round(preco_sugerido, 2),
        "base_estrategia": estrategia,
        "base_valor": round(base, 2),
        "ajuste_percentual": ajuste_percentual,
        "preco_ajustado": round(preco_ajustado, 2),
        "piso_custo": round(piso_custo, 2) if piso_custo is not None else None,
        "piso_final": round(piso_final, 2) if piso_final is not None else None,
        "estoque_baixo_aplicado": estoque_baixo_aplicado,
        "conflito_preco_maximo": False,
        "alertas": alertas,
    }


TINY_RATE_LIMIT_RETRY_WAIT = int(os.getenv("TINY_RATE_LIMIT_RETRY_WAIT", "20"))  # segundos de espera no rate limit
TINY_INTER_REQUEST_DELAY = float(os.getenv("TINY_INTER_REQUEST_DELAY", "0.4"))   # delay entre chamadas
TINY_HTTP_RETRY_STATUS = {429, 500, 502, 503, 504}
TINY_MAX_RECENT_ERRORS = 30


def tiny_retry_wait(tentativa: int, rate_limit: bool = False) -> float:
    if rate_limit:
        return TINY_RATE_LIMIT_RETRY_WAIT * (tentativa + 1)
    return min(2 ** tentativa, 12)


def tiny_error_message(retorno: Dict[str, Any]) -> str:
    erros = retorno.get("erros") or []
    mensagens: List[str] = []

    for item in erros:
        erro = item.get("erro") if isinstance(item, dict) else item
        if isinstance(erro, str):
            mensagens.append(erro)
        elif isinstance(erro, dict):
            msg = erro.get("msg") or erro.get("mensagem") or erro.get("descricao")
            if msg:
                mensagens.append(str(msg))

    codigo = str(retorno.get("codigo_erro") or retorno.get("codigo") or "").strip()
    detalhe = "; ".join(mensagens) if mensagens else "Erro sem detalhe retornado pelo Tiny"
    return f"[Codigo {codigo}] {detalhe}" if codigo else detalhe


def registrar_erro_sync(erros: List[str], mensagem: str) -> None:
    texto = " ".join(str(mensagem).split())[:300]
    if not texto:
        texto = "Erro desconhecido"
    erros.append(texto)
    if len(erros) > TINY_MAX_RECENT_ERRORS:
        del erros[:-TINY_MAX_RECENT_ERRORS]


async def tiny_api_post(metodo: str, payload: Dict[str, Any], _retries: int = 3) -> Dict[str, Any]:
    if not TINY_API_TOKEN:
        raise HTTPException(status_code=400, detail="TINY_API_TOKEN nao configurado no ambiente")

    body = {
        "token": TINY_API_TOKEN,
        "formato": "JSON",
    }
    body.update(payload or {})

    url = f"{TINY_API_BASE_URL.rstrip('/')}/{metodo}.php"
    encoded = urlencode(body).encode("utf-8")
    tentativas = max(1, _retries)

    for tentativa in range(tentativas):
        req = UrlRequest(url, data=encoded, headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            loop = asyncio.get_running_loop()
            raw_resp = await loop.run_in_executor(None, lambda: urlopen(req, timeout=30).read())

            try:
                data = json.loads(raw_resp.decode("utf-8", errors="ignore"))
            except json.JSONDecodeError:
                if tentativa < tentativas - 1:
                    await asyncio.sleep(tiny_retry_wait(tentativa))
                    continue
                raise HTTPException(status_code=502, detail="Tiny API retornou uma resposta invalida ou fora de JSON")

            if not isinstance(data, dict):
                raise HTTPException(status_code=502, detail="Tiny API retornou um formato inesperado")

            retorno = data.get("retorno") or {}
            if not isinstance(retorno, dict):
                raise HTTPException(status_code=502, detail="Resposta invalida da Tiny API")

            status_resp = str(retorno.get("status") or "").strip().lower()
            codigo_erro = str(retorno.get("codigo_erro") or retorno.get("codigo") or "").strip()
            if status_resp == "erro":
                if codigo_erro == "6" and tentativa < tentativas - 1:
                    await asyncio.sleep(tiny_retry_wait(tentativa, rate_limit=True))
                    continue
                status_code = 429 if codigo_erro == "6" else 502
                raise HTTPException(status_code=status_code, detail=f"Tiny API retornou erro: {tiny_error_message(retorno)}")

            return data
        except HTTPError as err:
            detalhe = err.read().decode("utf-8", errors="ignore")
            if err.code in TINY_HTTP_RETRY_STATUS and tentativa < tentativas - 1:
                await asyncio.sleep(tiny_retry_wait(tentativa, rate_limit=err.code == 429))
                continue
            raise HTTPException(status_code=502, detail=f"Tiny API HTTP {err.code}: {detalhe[:300]}")
        except URLError as err:
            if tentativa < tentativas - 1:
                await asyncio.sleep(tiny_retry_wait(tentativa))
                continue
            raise HTTPException(status_code=502, detail=f"Falha ao conectar Tiny API: {err.reason}")
        except TimeoutError:
            if tentativa < tentativas - 1:
                await asyncio.sleep(tiny_retry_wait(tentativa))
                continue
            raise HTTPException(status_code=504, detail="Tempo esgotado ao chamar Tiny API")
        except HTTPException:
            raise
        except Exception as err:
            if tentativa < tentativas - 1:
                await asyncio.sleep(tiny_retry_wait(tentativa))
                continue
            raise HTTPException(status_code=502, detail=f"Erro ao chamar Tiny API: {err}")

    raise HTTPException(status_code=429, detail="Tiny API: limite de requisicoes atingido apos multiplas tentativas.")


def tiny_get_retorno(resp: Dict[str, Any]) -> Dict[str, Any]:
    retorno = resp.get("retorno")
    if not isinstance(retorno, dict):
        raise HTTPException(status_code=502, detail="Resposta inválida da Tiny API")

    status = str(retorno.get("status") or "").strip().lower()
    if status == "erro":
        detalhe = tiny_error_message(retorno)
        raise HTTPException(status_code=502, detail=f"Tiny API retornou erro: {detalhe}")

    return retorno


def tiny_get_produtos_lista(resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    retorno = tiny_get_retorno(resp)
    bruto = retorno.get("produtos")
    if not isinstance(bruto, list):
        return []

    out: List[Dict[str, Any]] = []
    for item in bruto:
        if isinstance(item, dict) and isinstance(item.get("produto"), dict):
            out.append(item["produto"])
        elif isinstance(item, dict):
            out.append(item)
    return out


def tiny_get_produto_obj(resp: Dict[str, Any]) -> Dict[str, Any]:
    retorno = tiny_get_retorno(resp)
    produto = retorno.get("produto")
    if isinstance(produto, dict):
        if isinstance(produto.get("produto"), dict):
            return produto.get("produto") or {}
        return produto
    return {}


def tiny_get_estoque(resp: Dict[str, Any]) -> Optional[float]:
    retorno = tiny_get_retorno(resp)
    produto = retorno.get("produto") or {}
    if isinstance(produto, dict) and isinstance(produto.get("produto"), dict):
        produto = produto["produto"]

    candidatos = [
        produto.get("saldo"),
        produto.get("estoque"),
        retorno.get("saldo"),
        retorno.get("estoque"),
    ]
    for valor in candidatos:
        num = to_float(valor)
        if num is not None:
            return num
    return None


async def upsert_produto_tiny(base: Dict[str, Any], detalhe: Dict[str, Any], estoque: Optional[float]) -> Dict[str, Any]:
    tiny_id = str(detalhe.get("id") or base.get("id") or "").strip()
    sku = str(detalhe.get("codigo") or base.get("codigo") or detalhe.get("sku") or "").strip()
    ean = str(detalhe.get("gtin") or detalhe.get("ean") or base.get("gtin") or base.get("ean") or "").strip()
    nome = str(detalhe.get("nome") or base.get("nome") or "").strip() or f"Produto Tiny {tiny_id or sku or 'sem-id'}"
    custo = to_float(
        detalhe.get("preco_custo")
        or detalhe.get("custo")
        or detalhe.get("precoCusto")
    )

    selector: Dict[str, Any]
    if sku:
        selector = {"sku": sku}
    elif tiny_id:
        selector = {"tiny_id": tiny_id}
    else:
        raise HTTPException(status_code=400, detail="Produto Tiny sem SKU e sem ID")

    atual = await produtos_col.find_one(selector) or {}
    doc = dict(atual)

    # Extrair a URL do primeiro anexo como imagem do produto
    imagem_url = ""
    anexos = detalhe.get("anexos") or []
    if isinstance(anexos, list):
        for anexo_item in anexos:
            if isinstance(anexo_item, dict):
                url = str(anexo_item.get("anexo") or "").strip()
            elif isinstance(anexo_item, str):
                url = anexo_item.strip()
            else:
                url = ""
            if url:
                imagem_url = url
                break
    # Fallback para imagem já salva no banco ou campos alternativos
    if not imagem_url:
        imagem_url = doc.get("imagem_url") or doc.get("imagem") or doc.get("foto_url") or ""

    doc.update({
        "nome": nome,
        "sku": sku or doc.get("sku") or "",
        "ean": ean or doc.get("ean") or "",
        "imagem_url": imagem_url,
        "palavra_chave_1": doc.get("palavra_chave_1") or nome,
        "palavra_chave_2": doc.get("palavra_chave_2") or "",
        "precos_praticados": doc.get("precos_praticados") or {},
        "tiny_id": tiny_id or doc.get("tiny_id"),
        "custo_unitario": custo if custo is not None else doc.get("custo_unitario"),
        "estoque_atual": estoque if estoque is not None else doc.get("estoque_atual"),
        "tiny_updated_at": utcnow(),
        "sync_origem": "tiny",
        "atualizado_em": utcnow(),
    })
    doc = normalizar_doc_produto(doc)

    update_doc = {k: v for k, v in doc.items() if k != "_id"}
    await produtos_col.update_one(
        selector,
        {
            "$set": update_doc,
            "$setOnInsert": {"criado_em": utcnow()},
        },
        upsert=True,
    )

    return doc


async def executar_sync_tiny(full: bool) -> Dict[str, Any]:
    inicio = utcnow()
    total_lidos = 0
    total_sincronizados = 0
    total_pendentes = 0
    total_inativos = 0
    total_sem_ean = 0
    total_sem_identificador = 0
    total_erros = 0
    erros: List[str] = []
    total_avisos = 0
    avisos: List[str] = []

    produtos_brutos: List[Dict[str, Any]] = []

    if full:
        pagina = 1
        while True:
            if pagina > 1:
                await asyncio.sleep(TINY_INTER_REQUEST_DELAY * 3)  # delay maior entre páginas
            try:
                resp = await tiny_api_post("produtos.pesquisa", {"pagina": pagina})
            except HTTPException as exc:
                if pagina > 1 and produtos_brutos:
                    registrar_erro_sync(erros, f"Falha ao buscar pagina {pagina}: {exc.detail}")
                    total_erros += 1
                    break
                raise HTTPException(
                    status_code=exc.status_code,
                    detail=f"Falha ao buscar produtos no Tiny (página {pagina}): {exc.detail}. "
                           f"Verifique o token e a conectividade em GET /integracoes/tiny/testar",
                )
            itens = tiny_get_produtos_lista(resp)
            if not itens:
                break
            produtos_brutos.extend(itens)
            if len(itens) < 100:
                break
            pagina += 1
            if pagina > 500:
                break
    else:
        estado = await tiny_sync_state_col.find_one({"_id": "tiny"}) or {}
        dt_ref = estado.get("last_sync_at")
        params: Dict[str, Any] = {}
        if isinstance(dt_ref, datetime):
            params["dataAlteracao"] = dt_ref.strftime("%d/%m/%Y %H:%M:%S")
        try:
            pagina = 1
            while True:
                params_pagina = dict(params)
                params_pagina["pagina"] = pagina
                resp = await tiny_api_post("produtos.pesquisa", params_pagina)
                itens = tiny_get_produtos_lista(resp)
                if not itens:
                    break
                produtos_brutos.extend(itens)
                if len(itens) < 100:
                    break
                pagina += 1
                if pagina > 500:
                    break
        except HTTPException as exc:
            registrar_erro_sync(avisos, f"produtos.pesquisa incremental falhou: {exc.detail}. Fallback sem dataAlteracao acionado.")
            total_avisos += 1
            # Fallback: busca todos os produtos caso alterados falhe
            try:
                pagina = 1
                produtos_brutos = []
                while True:
                    if pagina > 1:
                        await asyncio.sleep(TINY_INTER_REQUEST_DELAY * 3)
                    resp = await tiny_api_post("produtos.pesquisa", {"pagina": pagina})
                    itens = tiny_get_produtos_lista(resp)
                    if not itens:
                        break
                    produtos_brutos.extend(itens)
                    if len(itens) < 100:
                        break
                    pagina += 1
                    if pagina > 500:
                        registrar_erro_sync(erros, "Fallback produtos.pesquisa interrompido no limite de 500 paginas.")
                        total_erros += 1
                        break
            except HTTPException as exc:
                raise HTTPException(
                    status_code=exc.status_code,
                    detail=f"Falha ao conectar com a API do Tiny: {exc.detail}. "
                           f"Use GET /integracoes/tiny/testar para diagnosticar.",
                )

    total_lidos = len(produtos_brutos)

    for base in produtos_brutos:
        try:
            # Respeitar rate limit: pequeno delay entre cada produto
            await asyncio.sleep(TINY_INTER_REQUEST_DELAY)

            # Filtrar apenas produtos ativos
            situacao = str(base.get("situacao") or "").strip().upper()
            if situacao and situacao != "A":
                total_inativos += 1
                continue

            pid = str(base.get("id") or "").strip()
            codigo = str(base.get("codigo") or "").strip()
            if not pid and not codigo:
                total_sem_identificador += 1
                registrar_erro_sync(erros, "Item Tiny sem id/codigo")
                total_erros += 1
                continue

            params = {"id": pid} if pid else {"codigo": codigo}
            detalhe_resp = await tiny_api_post("produto.obter", params)
            detalhe = tiny_get_produto_obj(detalhe_resp)

            # Verificar situação no detalhe (mais preciso que na lista)
            situacao_detalhe = str(detalhe.get("situacao") or situacao or "").strip().upper()
            if situacao_detalhe and situacao_detalhe != "A":
                total_inativos += 1
                continue

            # Exigir EAN/GTIN para sincronizar
            ean_check = str(
                detalhe.get("gtin") or detalhe.get("ean")
                or base.get("gtin") or base.get("ean") or ""
            ).strip()
            if not ean_check:
                total_sem_ean += 1
                continue

            estoque = None
            try:
                estoque_resp = await tiny_api_post("produto.obter.estoque", params)
                estoque = tiny_get_estoque(estoque_resp)
            except HTTPException:
                estoque = None

            doc = await upsert_produto_tiny(base, detalhe, estoque)
            total_sincronizados += 1
            if doc.get("status_integracao") == "pendente":
                total_pendentes += 1
        except Exception as err:
            ref = str(base.get("id") or base.get("codigo") or base.get("nome") or "sem identificador")
            registrar_erro_sync(erros, f"Produto {ref}: {err}")
            total_erros += 1

    total_ignorados = total_inativos + total_sem_ean + total_sem_identificador
    status_sync = "parcial" if total_erros else "sucesso"
    fim = utcnow()
    await tiny_sync_state_col.update_one(
        {"_id": "tiny"},
        {
            "$set": {
                "last_sync_at": fim,
                "last_sync_type": "full" if full else "incremental",
                "last_duration_seconds": round((fim - inicio).total_seconds(), 2),
                "total_lidos": total_lidos,
                "total_sincronizados": total_sincronizados,
                "total_pendentes": total_pendentes,
                "total_ignorados": total_ignorados,
                "total_inativos": total_inativos,
                "total_sem_ean": total_sem_ean,
                "total_sem_identificador": total_sem_identificador,
                "total_erros": total_erros,
                "total_avisos": total_avisos,
                "status": status_sync,
                "running": False,
                "erros_recentes": erros[-TINY_MAX_RECENT_ERRORS:],
                "avisos_recentes": avisos[-TINY_MAX_RECENT_ERRORS:],
                "updated_at": fim,
            },
            "$setOnInsert": {"created_at": inicio},
        },
        upsert=True,
    )

    return {
        "modo": "full" if full else "incremental",
        "inicio": inicio.isoformat(),
        "fim": fim.isoformat(),
        "duracao_segundos": round((fim - inicio).total_seconds(), 2),
        "total_lidos": total_lidos,
        "total_sincronizados": total_sincronizados,
        "total_pendentes": total_pendentes,
        "total_ignorados": total_ignorados,
        "total_inativos": total_inativos,
        "total_sem_ean": total_sem_ean,
        "total_sem_identificador": total_sem_identificador,
        "total_erros": total_erros,
        "total_avisos": total_avisos,
        "status": status_sync,
        "erros_recentes": erros[-TINY_MAX_RECENT_ERRORS:],
        "avisos_recentes": avisos[-TINY_MAX_RECENT_ERRORS:],
    }


async def executar_sync_tiny_background(full: bool, user_id: str) -> None:
    try:
        await executar_sync_tiny(full=full)
    except Exception as err:
        agora = utcnow()
        await tiny_sync_state_col.update_one(
            {"_id": "tiny"},
            {
                "$set": {
                    "running": False,
                    "status": "falha",
                    "last_error": str(err),
                    "total_erros": 1,
                    "updated_at": agora,
                    "finished_at": agora,
                },
                "$push": {
                    "erros_recentes": {
                        "$each": [str(err)[:300]],
                        "$slice": -TINY_MAX_RECENT_ERRORS,
                    }
                },
            },
            upsert=True,
        )


async def iniciar_sync_tiny_background(
    full: bool,
    user: Dict[str, Any],
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    agora = utcnow()
    stale_after = agora - timedelta(hours=2)
    modo = "full" if full else "incremental"

    try:
        res = await tiny_sync_state_col.update_one(
            {
                "_id": "tiny",
                "$or": [
                    {"running": {"$ne": True}},
                    {"started_at": {"$lt": stale_after}},
                ],
            },
            {
                "$set": {
                    "running": True,
                    "status": "em_andamento",
                    "last_sync_type": modo,
                    "started_at": agora,
                    "requested_by": user.get("user_id"),
                    "updated_at": agora,
                },
                "$setOnInsert": {"created_at": agora},
            },
            upsert=True,
        )
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Já existe uma sincronização Tiny em andamento")

    if res.matched_count == 0 and res.upserted_id is None:
        raise HTTPException(status_code=409, detail="Já existe uma sincronização Tiny em andamento")

    background_tasks.add_task(executar_sync_tiny_background, full, user.get("user_id", ""))
    return {
        "status": "iniciado",
        "modo": modo,
        "mensagem": "Sincronização Tiny iniciada em segundo plano.",
        "started_at": agora.isoformat(),
    }
 
 
# === Models ===
 
class PrecosPraticados(BaseModel):
    mercado_livre: Optional[float] = None
    amazon: Optional[float] = None
    shopee: Optional[float] = None
    droga_raia: Optional[float] = None
 
 
class Produto(BaseModel):
    nome: str
    imagem_url: Optional[str] = ""
    sku: Optional[str] = ""
    ean: Optional[str] = ""
    palavra_chave_1: Optional[str] = ""
    palavra_chave_2: Optional[str] = ""
    precos_praticados: Optional[PrecosPraticados] = None
    custo_unitario: Optional[float] = None
    estoque_atual: Optional[float] = None
    curva_abc: Optional[str] = "C"
    preco_minimo_produto: Optional[float] = None
    preco_maximo_produto: Optional[float] = None
    tiny_id: Optional[str] = None
    status_integracao: Optional[str] = None
    pendencias: Optional[List[str]] = Field(default_factory=list)
 
 
class LoginInput(BaseModel):
    email: str
    senha: str
 
 
class CadastroInput(BaseModel):
    nome: str
    email: str
    senha: str
 
 
class HistoricoInput(BaseModel):
    produto_id: str
    canal: str
    preco: float
    url: Optional[str] = ""


class PricingGrupoInput(BaseModel):
    estrategia_base: str
    ajuste_percentual: float = 0
    margem_minima_percentual: float = 0
    preco_minimo_grupo: float = 0
    estoque_baixo_limite: Optional[float] = None
    estoque_baixo_ajuste_percentual: Optional[float] = 0
    ativo: bool = True


class PricingSimulacaoInput(BaseModel):
    produto_id: Optional[str] = None
    sku: Optional[str] = None
    grupo: Optional[str] = None
    estrategia_base: Optional[str] = None
    ajuste_percentual: Optional[float] = None
    margem_minima_percentual: Optional[float] = None
    preco_minimo_grupo: Optional[float] = None
    preco_minimo_produto: Optional[float] = None
    preco_maximo_produto: Optional[float] = None
    estoque_baixo_limite: Optional[float] = None
    estoque_baixo_ajuste_percentual: Optional[float] = None
 
 
# === Auth ===
 
@app.post("/auth/registrar")
async def registrar(data: CadastroInput, response: Response):
    email = normalizar_email(data.email)
    if not email:
        raise HTTPException(status_code=400, detail="E-mail inválido")
    if len(data.senha or "") < 8:
        raise HTTPException(status_code=400, detail="A senha deve ter pelo menos 8 caracteres")

    existente = await usuarios_col.find_one({"email": email})
 
    if existente:
        raise HTTPException(status_code=400, detail="E-mail já cadastrado")
 
    total = await usuarios_col.count_documents({})
    primeiro_master = False
    if total == 0:
        try:
            await app_state_col.insert_one({
                "_id": "bootstrap_master",
                "email": email,
                "criado_em": utcnow(),
            })
            primeiro_master = True
        except DuplicateKeyError:
            primeiro_master = False
 
    novo = {
        "nome": data.nome,
        "email": email,
        "senha_hash": hash_senha(data.senha),
        "perfil": "master" if primeiro_master else "visualizador",
        "status": "aprovado" if primeiro_master else "pendente",
        "criado_em": utcnow(),
    }
 
    try:
        res = await usuarios_col.insert_one(novo)
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="E-mail já cadastrado")
    user_id = str(res.inserted_id)
 
    if primeiro_master:
        await emitir_cookies_auth(response, user_id, "master")
 
        return {
            "autenticado": True,
            "perfil": "master",
            "nome": data.nome,
            "primeiro_master": True,
        }
 
    return {
        "mensagem": "Solicitação enviada! Aguarde aprovação do administrador.",
        "primeiro_master": False,
    }
 
 
@app.post("/auth/login")
async def login(data: LoginInput, response: Response):
    email = normalizar_email(data.email)
    user = await usuarios_col.find_one({"email": email})
 
    if not user:
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos")
 
    senha_armazenada = (
        user.get("senha_hash")
        or user.get("senha")
        or user.get("password")
        or ""
    )
 
    senha_valida = verificar_senha(data.senha, senha_armazenada)
    if not senha_valida:
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos")

    # Migração automática de hash legado SHA-256 para PBKDF2.
    if is_hash_legacy_sha256(senha_armazenada):
        await usuarios_col.update_one(
            {"_id": user["_id"]},
            {
                "$set": {"senha_hash": hash_senha(data.senha)},
                "$unset": {"senha": "", "password": ""},
            },
        )
 
    status = user.get("status", "aprovado")
 
    if status == "pendente":
        raise HTTPException(status_code=403, detail="Cadastro aguardando aprovação")
 
    if status == "rejeitado":
        raise HTTPException(status_code=403, detail="Acesso negado")
 
    perfil = user.get("perfil", "visualizador")
 
    masters = await usuarios_col.count_documents({
        "perfil": "master",
        "status": "aprovado",
    })
 
    if masters == 0 and status == "aprovado":
        perfil = "master"
        await usuarios_col.update_one(
            {"_id": user["_id"]},
            {"$set": {"perfil": "master"}},
        )
 
    user_id = str(user["_id"])
    nome = user.get("nome", user.get("email", ""))
 
    await emitir_cookies_auth(response, user_id, perfil)
 
    return {
        "autenticado": True,
        "perfil": perfil,
        "nome": nome,
    }


@app.post("/auth/refresh")
async def refresh_session(
    response: Response,
    refresh_cookie: Optional[str] = Cookie(None, alias=REFRESH_COOKIE_NAME),
):
    if not refresh_cookie:
        limpar_cookies_auth(response)
        raise HTTPException(status_code=401, detail="Sessão expirada")

    token_hash = hash_refresh_token(refresh_cookie)
    usuario = await usuarios_col.find_one({"refresh_token_hash": token_hash})
    if not usuario:
        limpar_cookies_auth(response)
        raise HTTPException(status_code=401, detail="Sessão inválida")

    expira_em = usuario.get("refresh_token_expires_at")
    if isinstance(expira_em, datetime) and expira_em.tzinfo is None:
        expira_em = expira_em.replace(tzinfo=timezone.utc)
    if not isinstance(expira_em, datetime) or expira_em <= utcnow():
        limpar_cookies_auth(response)
        await usuarios_col.update_one(
            {"_id": usuario["_id"]},
            {"$unset": {"refresh_token_hash": "", "refresh_token_expires_at": ""}},
        )
        raise HTTPException(status_code=401, detail="Sessão expirada")

    if usuario.get("status", "aprovado") != "aprovado":
        limpar_cookies_auth(response)
        raise HTTPException(status_code=403, detail="Usuário sem acesso aprovado")

    perfil = usuario.get("perfil", "visualizador")
    await emitir_cookies_auth(response, str(usuario["_id"]), perfil)
    return {
        "autenticado": True,
        "perfil": perfil,
        "nome": usuario.get("nome", usuario.get("email", "")),
    }


@app.post("/auth/logout")
async def logout(
    response: Response,
    refresh_cookie: Optional[str] = Cookie(None, alias=REFRESH_COOKIE_NAME),
):
    limpar_cookies_auth(response)
    if refresh_cookie:
        await usuarios_col.update_one(
            {"refresh_token_hash": hash_refresh_token(refresh_cookie)},
            {
                "$unset": {
                    "refresh_token_hash": "",
                    "refresh_token_expires_at": "",
                },
                "$set": {"token_invalidado_em": utcnow()},
            },
        )
    return {"mensagem": "Sessão encerrada"}
 
 
@app.get("/auth/me")
async def me(user=Depends(get_user)):
    return {
        "perfil": user["perfil"],
        "user_id": user["user_id"],
        "nome": user["nome"],
        "email": user["email"],
    }
 
 
# === Usuários ===

async def buscar_usuario_ou_404(user_id: str) -> Dict[str, Any]:
    oid = object_id_or_400(user_id)
    doc = await usuarios_col.find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return doc


async def garantir_nao_ultimo_master_alterado(user_id: str, alvo: Optional[Dict[str, Any]] = None) -> None:
    alvo = alvo or await buscar_usuario_ou_404(user_id)
    if alvo.get("perfil") != "master" or alvo.get("status", "aprovado") != "aprovado":
        return

    masters = await usuarios_col.count_documents({
        "perfil": "master",
        "status": "aprovado",
    })
    if masters <= 1:
        raise HTTPException(status_code=400, detail="Não é permitido remover ou rebaixar o último master aprovado")
 
@app.get("/pendentes")
async def listar_pendentes(user=Depends(master_required)):
    docs = await usuarios_col.find({"status": "pendente"}).to_list(1000)
 
    return [sanitizar_usuario(d) for d in docs]
 
 
@app.get("/usuarios")
async def listar_usuarios(user=Depends(master_required)):
    docs = await usuarios_col.find().to_list(1000)
 
    return [sanitizar_usuario(d) for d in docs]
 
 
@app.post("/aprovar/{user_id}")
async def aprovar(
    user_id: str,
    perfil: str = "visualizador",
    user=Depends(master_required),
):
    if perfil not in PERFIS:
        raise HTTPException(status_code=400, detail="Perfil inválido")
 
    oid = object_id_or_400(user_id)
    agora = utcnow()
 
    res = await usuarios_col.update_one(
        {"_id": oid},
        {
            "$set": {
                "status": "aprovado",
                "perfil": perfil,
                "aprovado_por": user["user_id"],
                "aprovado_em": agora,
                "atualizado_em": agora,
            },
            "$unset": {"rejeitado_por": "", "rejeitado_em": ""},
        },
    )
 
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    await registrar_evento_admin("aprovar_usuario", user_id, user, {"perfil": perfil})
 
    return {"mensagem": "Usuário aprovado"}
 
 
@app.post("/rejeitar/{user_id}")
async def rejeitar(user_id: str, user=Depends(master_required)):
    alvo = await buscar_usuario_ou_404(user_id)
    await garantir_nao_ultimo_master_alterado(user_id, alvo)
    oid = alvo["_id"]
    agora = utcnow()
 
    res = await usuarios_col.update_one(
        {"_id": oid},
        {
            "$set": {
                "status": "rejeitado",
                "rejeitado_por": user["user_id"],
                "rejeitado_em": agora,
                "token_invalidado_em": agora,
                "atualizado_em": agora,
            },
            "$unset": {"refresh_token_hash": "", "refresh_token_expires_at": ""},
        },
    )
 
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    await registrar_evento_admin("rejeitar_usuario", user_id, user)
 
    return {"mensagem": "Usuário rejeitado"}
 
 
@app.put("/usuarios/{user_id}/perfil")
async def alterar_perfil_usuario(
    user_id: str,
    perfil: str,
    user=Depends(master_required),
):
    if perfil not in PERFIS:
        raise HTTPException(status_code=400, detail="Perfil inválido")
 
    alvo = await buscar_usuario_ou_404(user_id)
    if perfil != "master":
        await garantir_nao_ultimo_master_alterado(user_id, alvo)
    oid = alvo["_id"]
    agora = utcnow()
 
    res = await usuarios_col.update_one(
        {"_id": oid},
        {
            "$set": {
                "perfil": perfil,
                "perfil_alterado_por": user["user_id"],
                "perfil_alterado_em": agora,
                "token_invalidado_em": agora,
                "atualizado_em": agora,
            },
            "$unset": {"refresh_token_hash": "", "refresh_token_expires_at": ""},
        },
    )
 
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    await registrar_evento_admin(
        "alterar_perfil_usuario",
        user_id,
        user,
        {"perfil_anterior": alvo.get("perfil"), "perfil_novo": perfil},
    )
 
    return {"mensagem": "Função atualizada"}
 
 
@app.delete("/usuarios/{user_id}")
async def excluir_usuario(user_id: str, user=Depends(master_required)):
    alvo = await buscar_usuario_ou_404(user_id)
    await garantir_nao_ultimo_master_alterado(user_id, alvo)
    oid = alvo["_id"]
 
    res = await usuarios_col.delete_one({"_id": oid})
 
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    await registrar_evento_admin("excluir_usuario", user_id, user, {"email": alvo.get("email")})
 
    return {"mensagem": "Usuário excluído"}
 
 
# === Produtos ===
 
@app.get("/produtos")
async def listar_produtos(
    busca: Optional[str] = None,
    curva: Optional[str] = None,
    status: Optional[str] = None,
    page: Optional[int] = None,
    limit: Optional[int] = None,
    exportar: bool = False,
    user=Depends(get_user),
):
    filtros = []
 
    if busca:
        filtros.append({
            "$or": [
                {"nome": {"$regex": busca, "$options": "i"}},
                {"ean": {"$regex": busca, "$options": "i"}},
                {"sku": {"$regex": busca, "$options": "i"}},
            ]
        })

    curva_norm = normalizar_curva_abc(curva) if curva and curva != "todos" else None
    if curva_norm:
        filtros.append({"curva_abc": curva_norm})

    status_norm = str(status or "todos").strip().lower()
    if status_norm == "pendente":
        filtros.append({
            "$or": [
                {"status_integracao": "pendente"},
                {"pendencias.0": {"$exists": True}},
            ]
        })
    elif status_norm == "ok":
        filtros.append({"status_integracao": "ok"})

    filtro = {"$and": filtros} if filtros else {}
    paginar = page is not None or limit is not None
    page_num = max(1, int(page or 1))
    limite_maximo = PRODUTOS_MAX_EXPORT_LIMIT if exportar else PRODUTOS_MAX_PAGE_LIMIT
    limit_num = min(limite_maximo, max(1, int(limit or 9)))
    skip = (page_num - 1) * limit_num
 
    total = await produtos_col.count_documents(filtro)
    cursor = produtos_col.find(filtro).sort("nome", 1)
    if paginar:
        cursor = cursor.skip(skip).limit(limit_num)
        docs = await cursor.to_list(limit_num)
    else:
        docs = await cursor.to_list(5000)
    itens = [serial(d) for d in docs]

    produto_ids = [p["id"] for p in itens if p.get("id")]
    ultimos = await obter_ultimos_precos_por_produto(
        produto_ids,
        utcnow() - timedelta(days=30),
    )
    grupos = await obter_mapa_grupos_precificacao()

    for produto in itens:
        pid = produto.get("id")
        metricas = consolidar_metricas_mercado(ultimos.get(pid, {}))
        grupo = normalizar_curva_abc(produto.get("curva_abc"))
        config = grupos.get(grupo) or obter_grupo_default(grupo)
        simulacao = calcular_preco_sugerido(produto, metricas, config)

        produto["curva_abc"] = grupo
        produto["menor_preco_mercado"] = metricas.get("menor_preco_mercado")
        produto["maior_preco_mercado"] = metricas.get("maior_preco_mercado")
        produto["preco_medio_mercado"] = metricas.get("preco_medio_mercado")
        produto["menor_canal_mercado"] = metricas.get("menor_canal_mercado")
        produto["maior_canal_mercado"] = metricas.get("maior_canal_mercado")
        produto["preco_sugerido"] = simulacao.get("preco_sugerido")
        produto["pendencias"] = produto.get("pendencias") or []
        produto["status_integracao"] = "ignorado" if produto.get("pendencias_ignoradas") else produto.get("status_integracao") or ("pendente" if produto["pendencias"] else "ok")

    if not paginar:
        return itens

    return {
        "items": itens,
        "total": total,
        "page": page_num,
        "limit": limit_num,
    }


@app.get("/produtos/pendentes")
async def listar_produtos_pendentes(user=Depends(get_user)):
    docs = await produtos_col.find({
        "pendencias_ignoradas": {"$ne": True},
        "$or": [
            {"status_integracao": "pendente"},
            {"pendencias.0": {"$exists": True}},
        ]
    }).to_list(5000)

    return [serial(d) for d in docs]
  
  
@app.post("/produtos")
async def cadastrar_produto(produto: Produto, user=Depends(product_manager_required)):
    validar_produto_negocio(produto)
    sku = (produto.sku or "").strip()
    ean = (produto.ean or "").strip()

    if sku and await produtos_col.find_one({"sku": sku}):
        raise HTTPException(
            status_code=400,
            detail=f"Produto já cadastrado com o SKU {sku}",
        )
 
    if ean and await produtos_col.find_one({"ean": ean}):
        raise HTTPException(
            status_code=400,
            detail=f"Produto já cadastrado com o EAN {ean}",
        )
 
    doc = normalizar_doc_produto(produto.dict())
    doc["sku"] = sku
    doc["ean"] = ean
    doc["criado_em"] = utcnow()
    doc["atualizado_em"] = utcnow()
 
    try:
        res = await produtos_col.insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Produto já cadastrado com SKU, EAN ou ID Tiny informado")
 
    return {
        "id": str(res.inserted_id),
        "mensagem": "Produto cadastrado com sucesso!",
    }
 
 
@app.put("/produtos/{produto_id}")
async def editar_produto(
    produto_id: str,
    produto: Produto,
    user=Depends(product_manager_required),
):
    validar_produto_negocio(produto)
    oid = object_id_or_400(produto_id)
    sku = (produto.sku or "").strip()
    ean = (produto.ean or "").strip()
 
    if sku and await produtos_col.find_one({"sku": sku, "_id": {"$ne": oid}}):
        raise HTTPException(
            status_code=400,
            detail=f"Outro produto já usa o SKU {sku}",
        )
 
    if ean and await produtos_col.find_one({"ean": ean, "_id": {"$ne": oid}}):
        raise HTTPException(
            status_code=400,
            detail=f"Outro produto já usa o EAN {ean}",
        )

    doc = normalizar_doc_produto(produto.dict())
    doc["sku"] = sku
    doc["ean"] = ean
    doc["atualizado_em"] = utcnow()
 
    try:
        res = await produtos_col.update_one(
            {"_id": oid},
            {"$set": doc},
        )
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Outro produto já usa o SKU, EAN ou ID Tiny informado")
 
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Produto não encontrado")
 
    return {"mensagem": "Produto atualizado com sucesso!"}
 
 
@app.delete("/produtos/{produto_id}")
async def excluir_produto(produto_id: str, user=Depends(product_manager_required)):
    oid = object_id_or_400(produto_id)
 
    res = await produtos_col.delete_one({"_id": oid})
 
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Produto não encontrado")

    await historico_col.delete_many({"produto_id": produto_id})
 
    return {"mensagem": "Produto excluído"}


@app.post("/produtos/{produto_id}/pendencias/ignorar")
async def ignorar_pendencias_produto(produto_id: str, user=Depends(product_manager_required)):
    oid = object_id_or_400(produto_id)
    agora = utcnow()
    res = await produtos_col.update_one(
        {"_id": oid},
        {
            "$set": {
                "pendencias_ignoradas": True,
                "pendencias_ignoradas_por": user["user_id"],
                "pendencias_ignoradas_em": agora,
                "atualizado_em": agora,
            }
        },
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Produto não encontrado")
    return {"mensagem": "Pendências ignoradas para este produto"}


# === Histórico ===
 
@app.get("/produtos/{produto_id}/historico")
async def historico_produto(
    produto_id: str,
    dias: int = 30,
    canal: Optional[str] = None,
    user=Depends(get_user),
):
    canal = normalizar_canal(canal)
 
    desde = utcnow() - timedelta(days=dias)
 
    filtro = {
        "produto_id": produto_id,
        "data": {"$gte": desde},
    }
 
    if canal:
        filtro["canal"] = canal
 
    docs = await historico_col.find(filtro).sort("data", 1).to_list(10000)
 
    return [serial(d) for d in docs]
 
 
@app.get("/produtos/{produto_id}/canais")
async def canais_produto(
    produto_id: str,
    canal: Optional[str] = None,
    user=Depends(get_user),
):
    canal = normalizar_canal(canal)
 
    desde = utcnow() - timedelta(days=7)
    resultado = {}
 
    canais_consulta = [canal] if canal else CANAIS
 
    docs = await historico_col.find({
        "produto_id": produto_id,
        "canal": {"$in": canais_consulta},
        "data": {"$gte": desde},
    }).sort("data", 1).to_list(20000)

    por_canal: Dict[str, List[Dict[str, Any]]] = {c: [] for c in canais_consulta}
    for doc in docs:
        c = doc.get("canal")
        if c in por_canal:
            por_canal[c].append(doc)

    for c in canais_consulta:
        docs_canal = por_canal.get(c, [])
        if not docs_canal:
            resultado[c] = {
                "menor_preco_atual": None,
                "ultimo_preco": None,
                "variacao_media_7d": None,
                "registros": 0,
            }
            continue

        precos = [to_float(d.get("preco")) for d in docs_canal]
        precos = [p for p in precos if p is not None]
        if not precos:
            resultado[c] = {
                "menor_preco_atual": None,
                "ultimo_preco": None,
                "variacao_media_7d": None,
                "registros": len(docs_canal),
            }
            continue

        menor_atual = min(precos)
        ultimo_preco = precos[-1]

        variacoes = []
        anterior = precos[0]
 
        for preco in precos[1:]:
            if preco != anterior and anterior > 0:
                variacao = ((preco - anterior) / anterior) * 100
                variacoes.append(variacao)
                anterior = preco
 
        media = sum(variacoes) / len(variacoes) if variacoes else None
 
        resultado[c] = {
            "menor_preco_atual": menor_atual,
            "ultimo_preco": ultimo_preco,
            "variacao_media_7d": media,
            "registros": len(docs_canal),
        }
 
    return resultado
 
 
@app.post("/historico")
async def registrar_preco(data: HistoricoInput, user=Depends(product_manager_required)):
    if data.canal not in CANAIS:
        raise HTTPException(
            status_code=400,
            detail=f"Canal inválido. Use: {CANAIS}",
        )
 
    doc = {
        "produto_id": data.produto_id,
        "canal": data.canal,
        "preco": float(data.preco),
        "url": data.url or "",
        "data": utcnow(),
    }
 
    res = await historico_col.insert_one(doc)
 
    return {"id": str(res.inserted_id)}
 
 
# === Dashboard ===
 
@app.get("/dashboard")
async def dashboard(
    busca: Optional[str] = None,
    canal: Optional[str] = None,
    dias: int = 7,
    data_inicio: Optional[str] = None,
    data_fim: Optional[str] = None,
    user=Depends(get_user),
):
    canal = normalizar_canal(canal)
    if data_inicio and data_fim:
        try:
            desde = datetime.strptime(data_inicio, "%Y-%m-%d")
            ate = datetime.strptime(data_fim, "%Y-%m-%d") + timedelta(days=1)
            if desde >= ate:
                desde, ate = ate - timedelta(days=1), desde + timedelta(days=1)
        except ValueError:
            raise HTTPException(status_code=400, detail="Datas inválidas. Use o formato AAAA-MM-DD.")
    else:
        ate = utcnow() + timedelta(days=1)
        desde = utcnow() - timedelta(days=dias)
 
    filtro_produtos = {}
 
    if busca:
        filtro_produtos = {
            "$or": [
                {"nome": {"$regex": busca, "$options": "i"}},
                {"ean": {"$regex": busca, "$options": "i"}},
                {"sku": {"$regex": busca, "$options": "i"}},
            ]
        }
 
    produtos = await produtos_col.find(filtro_produtos).to_list(5000)
    produto_ids = [str(p["_id"]) for p in produtos]
 
    filtro_hist = {"data": {"$gte": desde, "$lt": ate}}
 
    if produto_ids:
        filtro_hist["produto_id"] = {"$in": produto_ids}
    elif busca:
        filtro_hist["produto_id"] = {"$in": []}
 
    total_produtos = len(produtos)
    total_registros = await historico_col.count_documents(filtro_hist)
 
    ultimo = await historico_col.find_one(filtro_hist, sort=[("data", -1)])
    ultima_coleta = ultimo["data"].isoformat() if ultimo else None
 
    comparacoes = []
    produtos_meta = []
    vitorias_ecommerce = {c: 0 for c in CANAIS}
    total_vitorias = 0
 
    canais_consulta = [canal] if canal else CANAIS
    ultimos_precos_por_produto = {}
    grupos_precificacao = await obter_mapa_grupos_precificacao()

    if produto_ids:
        pipeline_ultimos = [
            {
                "$match": {
                    "produto_id": {"$in": produto_ids},
                    "data": {"$gte": desde, "$lt": ate},
                    "canal": {"$in": CANAIS},
                }
            },
            {"$sort": {"produto_id": 1, "canal": 1, "data": -1}},
            {
                "$group": {
                    "_id": {"produto_id": "$produto_id", "canal": "$canal"},
                    "preco": {"$first": "$preco"},
                }
            },
        ]
        ultimos = await historico_col.aggregate(pipeline_ultimos).to_list(length=200000)

        for item in ultimos:
            pid = item.get("_id", {}).get("produto_id")
            c = item.get("_id", {}).get("canal")
            preco = item.get("preco")

            if pid is None or c is None or preco is None:
                continue

            if pid not in ultimos_precos_por_produto:
                ultimos_precos_por_produto[pid] = {}

            ultimos_precos_por_produto[pid][c] = float(preco)
 
    for produto in produtos:
        produto_id = str(produto["_id"])
        pp = produto.get("precos_praticados") or {}

        precos_por_canal = ultimos_precos_por_produto.get(produto_id, {})
        metricas_produto = consolidar_metricas_mercado(precos_por_canal)
        curva_produto = normalizar_curva_abc(produto.get("curva_abc"))
        config_produto = grupos_precificacao.get(curva_produto) or obter_grupo_default(curva_produto)
        simulacao_produto = calcular_preco_sugerido(serial(produto), metricas_produto, config_produto)
        produtos_meta.append({
            "id": produto_id,
            "nome": produto.get("nome", ""),
            "imagem_url": produto.get("imagem_url") or produto.get("imagem") or produto.get("foto_url") or "",
            "sku": produto.get("sku", ""),
            "ean": produto.get("ean", ""),
            "curva_abc": curva_produto,
            "preco_sugerido": simulacao_produto.get("preco_sugerido"),
            "status_integracao": "ignorado" if produto.get("pendencias_ignoradas") else produto.get("status_integracao") or ("pendente" if produto.get("pendencias") else "ok"),
            "pendencias": produto.get("pendencias") or [],
        })
 
        if precos_por_canal:
            menor_global = min(precos_por_canal.values())
            canais_vencedores = [
                c for c, preco in precos_por_canal.items()
                if preco == menor_global
            ]
 
            for c in canais_vencedores:
                vitorias_ecommerce[c] += 1
                total_vitorias += 1
 
        for c in canais_consulta:
            meu_preco = pp.get(c)
            menor_preco = precos_por_canal.get(c)
 
            if meu_preco is None or menor_preco is None or menor_preco <= 0:
                continue
 
            meu_preco = float(meu_preco)
            menor_preco = float(menor_preco)
            gap = ((meu_preco - menor_preco) / menor_preco) * 100
            status = classificar_gap(gap)
 
            comparacoes.append({
                "produto_id": produto_id,
                "produto": produto.get("nome", ""),
                "imagem_url": produto.get("imagem_url") or produto.get("imagem") or produto.get("foto_url") or "",
                "sku": produto.get("sku", ""),
                "ean": produto.get("ean", ""),
                "curva_abc": curva_produto,
                "canal": c,
                "meu_preco": meu_preco,
                "menor_preco": menor_preco,
                "preco_sugerido": simulacao_produto.get("preco_sugerido"),
                "status_integracao": produto.get("status_integracao") or ("pendente" if produto.get("pendencias") else "ok"),
                "pendencias": produto.get("pendencias") or [],
                "gap": gap,
                "status": status,
            })
 
    total_comparacoes = len(comparacoes)
    ganhando = len([x for x in comparacoes if x["gap"] <= 0])
    acima = len([x for x in comparacoes if x["gap"] > 3])
    muito_acima = len([x for x in comparacoes if x["gap"] > 10])
    gap_medio = (
        sum(x["gap"] for x in comparacoes) / total_comparacoes
        if total_comparacoes
        else None
    )
 
    percentual_ganhando = (
        (ganhando / total_comparacoes) * 100
        if total_comparacoes
        else 0
    )
 
    ranking_ecommerce = []
 
    for c in CANAIS:
        percentual = (
            (vitorias_ecommerce[c] / total_vitorias) * 100
            if total_vitorias
            else 0
        )
 
        ranking_ecommerce.append({
            "canal": c,
            "vitorias": vitorias_ecommerce[c],
            "percentual": percentual,
        })
 
    ranking_ecommerce.sort(key=lambda x: x["vitorias"], reverse=True)
    comparacoes.sort(key=lambda x: x["gap"], reverse=True)

    # Evolução real por canal (somente dias com coleta)
    evolucao_match = {
        "data": {"$gte": desde, "$lt": ate},
        "canal": {"$in": canais_consulta},
    }
    if produto_ids:
        evolucao_match["produto_id"] = {"$in": produto_ids}
    elif busca:
        evolucao_match["produto_id"] = {"$in": []}

    pipeline_evolucao = [
        {"$match": evolucao_match},
        {
            "$project": {
                "canal": 1,
                "preco_num": {"$toDouble": "$preco"},
                "dia": {"$dateToString": {"format": "%Y-%m-%d", "date": "$data"}},
            }
        },
        {
            "$group": {
                "_id": {"dia": "$dia", "canal": "$canal"},
                "preco_medio": {"$avg": "$preco_num"},
            }
        },
        {"$sort": {"_id.dia": 1}},
    ]
    evolucao_docs = await historico_col.aggregate(pipeline_evolucao).to_list(length=200000)

    labels_set = set()
    mapa_evolucao: Dict[str, Dict[str, float]] = {}
    for doc in evolucao_docs:
        dia = doc.get("_id", {}).get("dia")
        ch = doc.get("_id", {}).get("canal")
        preco_medio = to_float(doc.get("preco_medio"))
        if not dia or not ch or preco_medio is None:
            continue
        labels_set.add(dia)
        if dia not in mapa_evolucao:
            mapa_evolucao[dia] = {}
        mapa_evolucao[dia][ch] = round(float(preco_medio), 2)

    labels_ordenadas = sorted(labels_set)
    series = {c: [] for c in canais_consulta}
    for dia in labels_ordenadas:
        dados_dia = mapa_evolucao.get(dia, {})
        for c in canais_consulta:
            series[c].append(dados_dia.get(c))
 
    return {
        "total_produtos": total_produtos,
        "total_registros": total_registros,
        "ultima_coleta": ultima_coleta,
        "total_comparacoes": total_comparacoes,
        "percentual_ganhando": percentual_ganhando,
        "acima_mercado": acima,
        "muito_acima": muito_acima,
        "gap_medio": gap_medio,
        "ranking_ecommerce": ranking_ecommerce,
        "status_competitivo": comparacoes,
        "produtos_meta": produtos_meta,
        "evolucao_por_canal": {
            "labels": labels_ordenadas,
            "series": series,
        },
    }
 
 
@app.get("/estatisticas")
async def estatisticas(produto_id: Optional[str] = None, user=Depends(get_user)):
    if produto_id:
        try:
            oid = ObjectId(produto_id)
            total_produtos = await produtos_col.count_documents({"_id": oid})
        except Exception:
            total_produtos = 0
 
        filtro_hist = {"produto_id": produto_id}
    else:
        total_produtos = await produtos_col.count_documents({})
        filtro_hist = {}
 
    total_registros = await historico_col.count_documents(filtro_hist)
 
    ultimo = await historico_col.find_one(
        filtro_hist,
        sort=[("data", -1)],
    )
 
    ultima_coleta = ultimo["data"].isoformat() if ultimo else None
 
    return {
        "total_produtos": total_produtos,
        "total_registros": total_registros,
        "ultima_coleta": ultima_coleta,
    }


# === Pricing (A/B/C) ===

@app.get("/pricing/grupos")
async def listar_grupos_precificacao(user=Depends(product_manager_required)):
    await garantir_grupos_precificacao()
    docs = await pricing_groups_col.find().to_list(20)
    docs.sort(key=lambda x: CURVAS_ABC.index(x.get("grupo", "C")))
    return [serial(d) for d in docs]


@app.put("/pricing/grupos/{grupo}")
async def atualizar_grupo_precificacao(
    grupo: str,
    data: PricingGrupoInput,
    user=Depends(product_manager_required),
):
    grupo_raw = str(grupo or "").strip().upper()
    if grupo_raw not in CURVAS_ABC:
        raise HTTPException(status_code=400, detail="Grupo inválido. Use A, B ou C.")
    grupo = grupo_raw

    doc = {
        "grupo": grupo,
        "estrategia_base": data.estrategia_base if data.estrategia_base in ["menor_preco", "preco_medio"] else "menor_preco",
        "ajuste_percentual": float(data.ajuste_percentual),
        "margem_minima_percentual": float(data.margem_minima_percentual),
        "preco_minimo_grupo": float(data.preco_minimo_grupo),
        "estoque_baixo_limite": to_float(data.estoque_baixo_limite),
        "estoque_baixo_ajuste_percentual": to_float(data.estoque_baixo_ajuste_percentual) or 0.0,
        "ativo": bool(data.ativo),
        "atualizado_em": utcnow(),
    }

    await pricing_groups_col.update_one(
        {"grupo": grupo},
        {
            "$set": doc,
            "$setOnInsert": {"criado_em": utcnow()},
        },
        upsert=True,
    )
    invalidar_cache_grupos_precificacao()
    novo = await pricing_groups_col.find_one({"grupo": grupo})
    return serial(novo)


@app.post("/pricing/simular")
async def simular_precificacao(
    data: PricingSimulacaoInput,
    user=Depends(product_manager_required),
):
    filtro = None
    if data.produto_id:
        filtro = {"_id": object_id_or_400(data.produto_id)}
    elif data.sku:
        filtro = {"sku": data.sku.strip()}

    if not filtro:
        raise HTTPException(status_code=400, detail="Informe produto_id ou sku para simular")

    produto = await produtos_col.find_one(filtro)
    if not produto:
        raise HTTPException(status_code=404, detail="Produto não encontrado")

    produto_serial = serial(produto)
    if data.preco_minimo_produto is not None:
        if data.preco_minimo_produto < 0:
            raise HTTPException(status_code=400, detail="Preço mínimo do produto não pode ser negativo")
        produto_serial["preco_minimo_produto"] = data.preco_minimo_produto
    if data.preco_maximo_produto is not None:
        if data.preco_maximo_produto < 0:
            raise HTTPException(status_code=400, detail="Preço máximo do produto não pode ser negativo")
        produto_serial["preco_maximo_produto"] = data.preco_maximo_produto
    if (
        data.preco_minimo_produto is not None
        and data.preco_maximo_produto is not None
        and data.preco_maximo_produto > 0
        and data.preco_minimo_produto > data.preco_maximo_produto
    ):
        raise HTTPException(status_code=400, detail="Preço mínimo do produto não pode ser maior que o preço máximo")
    pid = produto_serial.get("id")
    mapa_ultimos = await obter_ultimos_precos_por_produto([pid], utcnow() - timedelta(days=30))
    metricas = consolidar_metricas_mercado(mapa_ultimos.get(pid, {}))

    grupo = normalizar_curva_abc(data.grupo or produto_serial.get("curva_abc"))
    mapa_grupos = await obter_mapa_grupos_precificacao()
    config = dict(mapa_grupos.get(grupo) or obter_grupo_default(grupo))

    overrides = {
        "estrategia_base": data.estrategia_base,
        "ajuste_percentual": data.ajuste_percentual,
        "margem_minima_percentual": data.margem_minima_percentual,
        "preco_minimo_grupo": data.preco_minimo_grupo,
        "estoque_baixo_limite": data.estoque_baixo_limite,
        "estoque_baixo_ajuste_percentual": data.estoque_baixo_ajuste_percentual,
    }
    for k, v in overrides.items():
        if v is not None:
            config[k] = v

    sim = calcular_preco_sugerido(produto_serial, metricas, config)
    return {
        "produto": produto_serial,
        "grupo": grupo,
        "config_aplicada": serial(config),
        "metricas_mercado": metricas,
        "simulacao": sim,
    }


@app.get("/integracoes/tiny/testar")
async def tiny_testar(user=Depends(product_manager_required)):
    """Testa a conectividade com a API do Tiny e retorna diagnóstico detalhado."""
    if not TINY_API_TOKEN:
        return {
            "ok": False,
            "problema": "TINY_API_TOKEN não configurado",
            "solucao": "Defina a variável de ambiente TINY_API_TOKEN com o token da API do Tiny.",
        }

    url_teste = f"{TINY_API_BASE_URL.rstrip('/')}/produtos.pesquisa.php"

    try:
        resp_raw = await tiny_api_post("produtos.pesquisa", {"pagina": 1})
        retorno = resp_raw.get("retorno", {})
        status = str(retorno.get("status") or "").lower()

        if status == "ok":
            return {
                "ok": True,
                "url_chamada": url_teste,
                "token_configurado": True,
                "status_tiny": status,
                "retorno_bruto": retorno,
            }

        # Extrair mensagem de erro do retorno do Tiny
        erros_raw = retorno.get("erros") or []
        mensagens_erro: List[str] = []
        for item in erros_raw:
            if isinstance(item, dict):
                erro = item.get("erro")
                if isinstance(erro, str):
                    mensagens_erro.append(erro)
                elif isinstance(erro, dict):
                    msg = erro.get("msg") or erro.get("mensagem") or str(erro)
                    mensagens_erro.append(msg)
            elif isinstance(item, str):
                mensagens_erro.append(item)

        codigo_erro = retorno.get("codigo_erro") or retorno.get("codigo") or ""
        problema = "; ".join(mensagens_erro) if mensagens_erro else f"Tiny retornou status '{status}'"
        if codigo_erro:
            problema = f"[Código {codigo_erro}] {problema}"

        return {
            "ok": False,
            "url_chamada": url_teste,
            "token_configurado": True,
            "status_tiny": status,
            "problema": problema,
            "retorno_bruto": retorno,
            "dicas": [
                "Token inválido ou expirado: acesse Tiny → Configurações → Integrações → API e gere um novo token.",
                "Confirme que a variável de ambiente TINY_API_TOKEN no servidor contém o token correto.",
                "O token da API v2 do Tiny é diferente do token OAuth v3 — use o token da aba 'API' do Tiny.",
                f"URL chamada: {url_teste}",
            ],
        }
    except HTTPException as exc:
        return {
            "ok": False,
            "url_chamada": url_teste,
            "token_configurado": True,
            "problema": exc.detail,
            "dicas": [
                "Verifique se TINY_API_TOKEN é um token válido da API v2 do Tiny ERP.",
                "No Tiny, acesse: Configurações → Integrações → API → Gerar token.",
                f"A URL usada foi: {url_teste}",
                "Confirme que o servidor tem acesso à internet (curl https://api.tiny.com.br).",
            ],
        }


# === Tiny integration ===

@app.post("/integracoes/tiny/sync/full")
async def tiny_sync_full(
    background_tasks: BackgroundTasks,
    user=Depends(product_manager_required),
):
    return await iniciar_sync_tiny_background(True, user, background_tasks)


@app.post("/integracoes/tiny/sync/incremental")
async def tiny_sync_incremental(
    background_tasks: BackgroundTasks,
    user=Depends(product_manager_required),
):
    return await iniciar_sync_tiny_background(False, user, background_tasks)


@app.get("/integracoes/tiny/status")
async def tiny_sync_status(user=Depends(get_user)):
    estado = await tiny_sync_state_col.find_one({"_id": "tiny"})
    if not estado:
        return {
            "configurado": bool(TINY_API_TOKEN),
            "intervalo_recomendado_minutos": TINY_SYNC_INTERVAL_MINUTES,
            "status": "nunca_sincronizado",
        }

    return {
        "configurado": bool(TINY_API_TOKEN),
        "intervalo_recomendado_minutos": TINY_SYNC_INTERVAL_MINUTES,
        "estado": serial(estado),
    }
 
 
# === Static ===
 
@app.get("/")
async def root():
    base_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
    index_candidates = [
        os.path.join(base_dir, p)
        for p in ("index.html", "index.txt")
        if os.path.exists(os.path.join(base_dir, p))
    ]
    index_path = max(index_candidates, key=os.path.getmtime) if index_candidates else os.path.join(base_dir, "index.html")
    return FileResponse(
        index_path,
        media_type="text/html; charset=utf-8",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
            "Content-Type": "text/html; charset=utf-8",
        },
    )

# === Webhook ML ===

@app.post("/ml/notificacoes")
async def ml_notificacoes(request: Request):
    """
    Endpoint de notificações do Mercado Livre.
    Necessário para certificação do app no portal de desenvolvedores.
    """
    try:
        body = await request.json()
        print(f"[ML Webhook] Notificação recebida: {body}")
    except Exception:
        pass
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
    )
