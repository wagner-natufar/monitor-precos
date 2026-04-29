import os
import jwt
import hashlib
import base64
import hmac
import secrets
import json
from datetime import datetime, timedelta
from typing import Optional, Any, Dict, List
from urllib.parse import urlencode
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError, URLError
 
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
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

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET nÃ£o configurado. Defina a variÃ¡vel de ambiente JWT_SECRET.")
 
# === DB ===
client = AsyncIOMotorClient(MONGO_URL)
db = client.monitor_precos
produtos_col = db.produtos
historico_col = db.historico
usuarios_col = db.usuarios
pricing_groups_col = db.pricing_groups
tiny_sync_state_col = db.tiny_sync_state
 
# === App ===
app = FastAPI(title="Monitor de PreÃ§os")
 
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
 
CANAIS = ["mercado_livre", "amazon", "shopee", "droga_raia"]
PERFIS = ["master", "admin", "visualizador"]
CURVAS_ABC = ["A", "B", "C"]
 
 
# === Helpers ===
 
def serial(doc):
    if doc is None:
        return None
 
    out = {}
 
    for k, v in dict(doc).items():
        key = "id" if k == "_id" else k
 
        if isinstance(v, ObjectId):
            out[key] = str(v)
        elif isinstance(v, datetime):
            out[key] = v.isoformat()
        elif isinstance(v, dict):
            out[key] = {
                kk: (
                    str(vv) if isinstance(vv, ObjectId)
                    else vv.isoformat() if isinstance(vv, datetime)
                    else vv
                )
                for kk, vv in v.items()
            }
        else:
            out[key] = v
 
    return out
 
 
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
    payload = {
        "user_id": user_id,
        "perfil": perfil,
        "exp": datetime.utcnow() + timedelta(days=30),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
 
 
def object_id_or_400(value: str):
    try:
        return ObjectId(value)
    except Exception:
        raise HTTPException(status_code=400, detail="ID invÃ¡lido")
 
 
def normalizar_canal(canal: Optional[str] = None) -> Optional[str]:
    if not canal or canal == "todos":
        return None
 
    if canal not in CANAIS:
        raise HTTPException(status_code=400, detail=f"Canal invÃ¡lido. Use: {CANAIS}")
 
    return canal
 
 
async def get_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="NÃ£o autenticado")
 
    token = authorization.split(" ", 1)[1]
 
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("user_id")
        oid = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=401, detail="Token invÃ¡lido")
 
    user_db = await usuarios_col.find_one({"_id": oid})
 
    if not user_db:
        raise HTTPException(status_code=401, detail="UsuÃ¡rio nÃ£o encontrado")
 
    if user_db.get("status", "aprovado") != "aprovado":
        raise HTTPException(status_code=403, detail="UsuÃ¡rio sem acesso aprovado")
 
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


async def garantir_grupos_precificacao() -> None:
    for grupo in CURVAS_ABC:
        atual = await pricing_groups_col.find_one({"grupo": grupo})
        if not atual:
            doc = obter_grupo_default(grupo)
            doc["criado_em"] = datetime.utcnow()
            doc["atualizado_em"] = datetime.utcnow()
            await pricing_groups_col.insert_one(doc)


async def obter_mapa_grupos_precificacao() -> Dict[str, Dict[str, Any]]:
    await garantir_grupos_precificacao()
    docs = await pricing_groups_col.find().to_list(20)
    mapa = {d.get("grupo", "C"): d for d in docs}
    for grupo in CURVAS_ABC:
        if grupo not in mapa:
            mapa[grupo] = obter_grupo_default(grupo)
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


def normalizar_doc_produto(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(doc)
    out["nome"] = str(out.get("nome") or "").strip()
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
        }

    valores = list(precos_por_canal.values())
    return {
        "menor_preco_mercado": min(valores),
        "maior_preco_mercado": max(valores),
        "preco_medio_mercado": sum(valores) / len(valores),
    }


def calcular_preco_sugerido(
    produto: Dict[str, Any],
    metricas: Dict[str, Optional[float]],
    config: Dict[str, Any],
) -> Dict[str, Any]:
    estrategia = config.get("estrategia_base") or "menor_preco"
    base = metricas.get("menor_preco_mercado") if estrategia == "menor_preco" else metricas.get("preco_medio_mercado")
    if base is None:
        return {
            "preco_sugerido": None,
            "base_estrategia": estrategia,
            "motivo": "Sem dados de mercado suficientes",
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
    }


def tiny_api_post(metodo: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if not TINY_API_TOKEN:
        raise HTTPException(status_code=400, detail="TINY_API_TOKEN nÃ£o configurado no ambiente")

    body = {
        "token": TINY_API_TOKEN,
        "formato": "JSON",
    }
    body.update(payload or {})

    url = f"{TINY_API_BASE_URL.rstrip('/')}/{metodo}.php"
    encoded = urlencode(body).encode("utf-8")
    req = UrlRequest(url, data=encoded, headers={"Content-Type": "application/x-www-form-urlencoded"})

    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as err:
        detalhe = err.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=502, detail=f"Tiny API HTTP {err.code}: {detalhe[:300]}")
    except URLError as err:
        raise HTTPException(status_code=502, detail=f"Falha ao conectar Tiny API: {err.reason}")
    except Exception as err:
        raise HTTPException(status_code=502, detail=f"Erro ao chamar Tiny API: {err}")


def tiny_get_retorno(resp: Dict[str, Any]) -> Dict[str, Any]:
    retorno = resp.get("retorno")
    if not isinstance(retorno, dict):
        raise HTTPException(status_code=502, detail="Resposta invÃ¡lida da Tiny API")

    status = str(retorno.get("status") or "").strip().lower()
    if status == "erro":
        erros = retorno.get("erros") or []
        mensagens: List[str] = []
        for item in erros:
            if isinstance(item, dict):
                if isinstance(item.get("erro"), str):
                    mensagens.append(item["erro"])
                elif isinstance(item.get("erro"), dict):
                    msg = item["erro"].get("msg") or item["erro"].get("mensagem")
                    if isinstance(msg, str):
                        mensagens.append(msg)
        detalhe = "; ".join(mensagens) if mensagens else "Erro sem detalhe"
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
    produto = tiny_get_produto_obj(resp)

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
    doc.update({
        "nome": nome,
        "sku": sku or doc.get("sku") or "",
        "ean": ean or doc.get("ean") or "",
        "palavra_chave_1": doc.get("palavra_chave_1") or nome,
        "palavra_chave_2": doc.get("palavra_chave_2") or "",
        "precos_praticados": doc.get("precos_praticados") or {},
        "tiny_id": tiny_id or doc.get("tiny_id"),
        "custo_unitario": custo if custo is not None else doc.get("custo_unitario"),
        "estoque_atual": estoque if estoque is not None else doc.get("estoque_atual"),
        "tiny_updated_at": datetime.utcnow(),
        "sync_origem": "tiny",
        "atualizado_em": datetime.utcnow(),
    })
    doc = normalizar_doc_produto(doc)

    update_doc = {k: v for k, v in doc.items() if k != "_id"}
    await produtos_col.update_one(
        selector,
        {
            "$set": update_doc,
            "$setOnInsert": {"criado_em": datetime.utcnow()},
        },
        upsert=True,
    )

    return doc


async def executar_sync_tiny(full: bool) -> Dict[str, Any]:
    inicio = datetime.utcnow()
    total_lidos = 0
    total_sincronizados = 0
    total_pendentes = 0
    erros: List[str] = []

    produtos_brutos: List[Dict[str, Any]] = []

    if full:
        pagina = 1
        while True:
            resp = tiny_api_post("produtos.pesquisa", {"pagina": pagina})
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
                resp = tiny_api_post("produtos.alterados", params_pagina)
                itens = tiny_get_produtos_lista(resp)
                if not itens:
                    break
                produtos_brutos.extend(itens)
                if len(itens) < 100:
                    break
                pagina += 1
                if pagina > 500:
                    break
        except HTTPException:
            resp = tiny_api_post("produtos.pesquisa", {"pagina": 1})
            produtos_brutos = tiny_get_produtos_lista(resp)

    total_lidos = len(produtos_brutos)

    for base in produtos_brutos:
        try:
            pid = str(base.get("id") or "").strip()
            codigo = str(base.get("codigo") or "").strip()
            if not pid and not codigo:
                erros.append("Item Tiny sem id/codigo")
                continue

            params = {"id": pid} if pid else {"codigo": codigo}
            detalhe_resp = tiny_api_post("produto.obter", params)
            detalhe = tiny_get_produto_obj(detalhe_resp)

            estoque = None
            try:
                estoque_resp = tiny_api_post("produto.obter.estoque", params)
                estoque = tiny_get_estoque(estoque_resp)
            except HTTPException:
                estoque = None

            doc = await upsert_produto_tiny(base, detalhe, estoque)
            total_sincronizados += 1
            if doc.get("status_integracao") == "pendente":
                total_pendentes += 1
        except Exception as err:
            erros.append(str(err)[:300])

    fim = datetime.utcnow()
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
                "total_erros": len(erros),
                "erros_recentes": erros[-20:],
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
        "total_erros": len(erros),
        "erros_recentes": erros[-20:],
    }
 
 
# === Models ===
 
class PrecosPraticados(BaseModel):
    mercado_livre: Optional[float] = None
    amazon: Optional[float] = None
    shopee: Optional[float] = None
    droga_raia: Optional[float] = None
 
 
class Produto(BaseModel):
    nome: str
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
    estoque_baixo_limite: Optional[float] = None
    estoque_baixo_ajuste_percentual: Optional[float] = None
 
 
# === Auth ===
 
@app.post("/auth/registrar")
async def registrar(data: CadastroInput):
    existente = await usuarios_col.find_one({"email": data.email})
 
    if existente:
        raise HTTPException(status_code=400, detail="E-mail jÃ¡ cadastrado")
 
    total = await usuarios_col.count_documents({})
    primeiro_master = total == 0
 
    novo = {
        "nome": data.nome,
        "email": data.email,
        "senha_hash": hash_senha(data.senha),
        "perfil": "master" if primeiro_master else "visualizador",
        "status": "aprovado" if primeiro_master else "pendente",
        "criado_em": datetime.utcnow(),
    }
 
    res = await usuarios_col.insert_one(novo)
    user_id = str(res.inserted_id)
 
    if primeiro_master:
        token = criar_token(user_id, "master")
 
        return {
            "token": token,
            "perfil": "master",
            "nome": data.nome,
            "primeiro_master": True,
        }
 
    return {
        "mensagem": "SolicitaÃ§Ã£o enviada! Aguarde aprovaÃ§Ã£o do administrador.",
        "primeiro_master": False,
    }
 
 
@app.post("/auth/login")
async def login(data: LoginInput):
    user = await usuarios_col.find_one({"email": data.email})
 
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

    # MigraÃ§Ã£o automÃ¡tica de hash legado SHA-256 para PBKDF2.
    if is_hash_legacy_sha256(senha_armazenada):
        await usuarios_col.update_one(
            {"_id": user["_id"]},
            {"$set": {"senha_hash": hash_senha(data.senha)}},
        )
 
    status = user.get("status", "aprovado")
 
    if status == "pendente":
        raise HTTPException(status_code=403, detail="Cadastro aguardando aprovaÃ§Ã£o")
 
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
 
    token = criar_token(user_id, perfil)
 
    return {
        "token": token,
        "perfil": perfil,
        "nome": nome,
    }
 
 
@app.get("/auth/me")
async def me(user=Depends(get_user)):
    return {
        "perfil": user["perfil"],
        "user_id": user["user_id"],
        "nome": user["nome"],
        "email": user["email"],
    }
 
 
# === UsuÃ¡rios ===
 
@app.get("/pendentes")
async def listar_pendentes(user=Depends(master_required)):
    docs = await usuarios_col.find({"status": "pendente"}).to_list(1000)
 
    return [
        {**serial(d), "senha_hash": None}
        for d in docs
    ]
 
 
@app.get("/usuarios")
async def listar_usuarios(user=Depends(master_required)):
    docs = await usuarios_col.find().to_list(1000)
 
    return [
        {**serial(d), "senha_hash": None}
        for d in docs
    ]
 
 
@app.post("/aprovar/{user_id}")
async def aprovar(
    user_id: str,
    perfil: str = "visualizador",
    user=Depends(master_required),
):
    if perfil not in PERFIS:
        raise HTTPException(status_code=400, detail="Perfil invÃ¡lido")
 
    oid = object_id_or_400(user_id)
 
    res = await usuarios_col.update_one(
        {"_id": oid},
        {"$set": {"status": "aprovado", "perfil": perfil}},
    )
 
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="UsuÃ¡rio nÃ£o encontrado")
 
    return {"mensagem": "UsuÃ¡rio aprovado"}
 
 
@app.post("/rejeitar/{user_id}")
async def rejeitar(user_id: str, user=Depends(master_required)):
    oid = object_id_or_400(user_id)
 
    res = await usuarios_col.update_one(
        {"_id": oid},
        {"$set": {"status": "rejeitado"}},
    )
 
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="UsuÃ¡rio nÃ£o encontrado")
 
    return {"mensagem": "UsuÃ¡rio rejeitado"}
 
 
@app.put("/usuarios/{user_id}/perfil")
async def alterar_perfil_usuario(
    user_id: str,
    perfil: str,
    user=Depends(master_required),
):
    if perfil not in PERFIS:
        raise HTTPException(status_code=400, detail="Perfil invÃ¡lido")
 
    oid = object_id_or_400(user_id)
 
    res = await usuarios_col.update_one(
        {"_id": oid},
        {"$set": {"perfil": perfil}},
    )
 
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="UsuÃ¡rio nÃ£o encontrado")
 
    return {"mensagem": "FunÃ§Ã£o atualizada"}
 
 
@app.delete("/usuarios/{user_id}")
async def excluir_usuario(user_id: str, user=Depends(master_required)):
    oid = object_id_or_400(user_id)
 
    res = await usuarios_col.delete_one({"_id": oid})
 
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="UsuÃ¡rio nÃ£o encontrado")
 
    return {"mensagem": "UsuÃ¡rio excluÃ­do"}
 
 
# === Produtos ===
 
@app.get("/produtos")
async def listar_produtos(busca: Optional[str] = None, user=Depends(get_user)):
    filtro = {}
 
    if busca:
        filtro = {
            "$or": [
                {"nome": {"$regex": busca, "$options": "i"}},
                {"ean": {"$regex": busca, "$options": "i"}},
                {"sku": {"$regex": busca, "$options": "i"}},
            ]
        }
 
    docs = await produtos_col.find(filtro).to_list(5000)
    itens = [serial(d) for d in docs]

    produto_ids = [p["id"] for p in itens if p.get("id")]
    ultimos = await obter_ultimos_precos_por_produto(
        produto_ids,
        datetime.utcnow() - timedelta(days=30),
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
        produto["preco_sugerido"] = simulacao.get("preco_sugerido")
        produto["pendencias"] = produto.get("pendencias") or []
        produto["status_integracao"] = produto.get("status_integracao") or ("pendente" if produto["pendencias"] else "ok")

    return itens
 
 
@app.post("/produtos")
async def cadastrar_produto(produto: Produto, user=Depends(product_manager_required)):
    sku = (produto.sku or "").strip()
    ean = (produto.ean or "").strip()

    if sku and await produtos_col.find_one({"sku": sku}):
        raise HTTPException(
            status_code=400,
            detail=f"Produto jÃ¡ cadastrado com o SKU {sku}",
        )
 
    if ean and await produtos_col.find_one({"ean": ean}):
        raise HTTPException(
            status_code=400,
            detail=f"Produto jÃ¡ cadastrado com o EAN {ean}",
        )
 
    doc = normalizar_doc_produto(produto.dict())
    doc["sku"] = sku
    doc["ean"] = ean
    doc["criado_em"] = datetime.utcnow()
    doc["atualizado_em"] = datetime.utcnow()
 
    res = await produtos_col.insert_one(doc)
 
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
    oid = object_id_or_400(produto_id)
    sku = (produto.sku or "").strip()
    ean = (produto.ean or "").strip()
 
    if sku and await produtos_col.find_one({"sku": sku, "_id": {"$ne": oid}}):
        raise HTTPException(
            status_code=400,
            detail=f"Outro produto jÃ¡ usa o SKU {sku}",
        )
 
    if ean and await produtos_col.find_one({"ean": ean, "_id": {"$ne": oid}}):
        raise HTTPException(
            status_code=400,
            detail=f"Outro produto jÃ¡ usa o EAN {ean}",
        )

    doc = normalizar_doc_produto(produto.dict())
    doc["sku"] = sku
    doc["ean"] = ean
    doc["atualizado_em"] = datetime.utcnow()
 
    res = await produtos_col.update_one(
        {"_id": oid},
        {"$set": doc},
    )
 
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Produto nÃ£o encontrado")
 
    return {"mensagem": "Produto atualizado com sucesso!"}
 
 
@app.delete("/produtos/{produto_id}")
async def excluir_produto(produto_id: str, user=Depends(product_manager_required)):
    oid = object_id_or_400(produto_id)
 
    res = await produtos_col.delete_one({"_id": oid})
 
    await historico_col.delete_many({"produto_id": produto_id})
 
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Produto nÃ£o encontrado")
 
    return {"mensagem": "Produto excluÃ­do"}


@app.get("/produtos/pendentes")
async def listar_produtos_pendentes(user=Depends(get_user)):
    docs = await produtos_col.find({
        "$or": [
            {"status_integracao": "pendente"},
            {"pendencias.0": {"$exists": True}},
        ]
    }).to_list(5000)

    return [serial(d) for d in docs]
 
 
# === HistÃ³rico ===
 
@app.get("/produtos/{produto_id}/historico")
async def historico_produto(
    produto_id: str,
    dias: int = 30,
    canal: Optional[str] = None,
    user=Depends(get_user),
):
    canal = normalizar_canal(canal)
 
    desde = datetime.utcnow() - timedelta(days=dias)
 
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
 
    desde = datetime.utcnow() - timedelta(days=7)
    resultado = {}
 
    canais_consulta = [canal] if canal else CANAIS
 
    for c in canais_consulta:
        docs = await historico_col.find({
            "produto_id": produto_id,
            "canal": c,
            "data": {"$gte": desde},
        }).sort("data", 1).to_list(10000)
 
        if not docs:
            resultado[c] = {
                "menor_preco_atual": None,
                "variacao_media_7d": None,
                "registros": 0,
            }
            continue
 
        precos = [d["preco"] for d in docs]
        menor_atual = precos[-1]
 
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
            "variacao_media_7d": media,
            "registros": len(docs),
        }
 
    return resultado
 
 
@app.post("/historico")
async def registrar_preco(data: HistoricoInput, user=Depends(product_manager_required)):
    if data.canal not in CANAIS:
        raise HTTPException(
            status_code=400,
            detail=f"Canal invÃ¡lido. Use: {CANAIS}",
        )
 
    doc = {
        "produto_id": data.produto_id,
        "canal": data.canal,
        "preco": float(data.preco),
        "url": data.url or "",
        "data": datetime.utcnow(),
    }
 
    res = await historico_col.insert_one(doc)
 
    return {"id": str(res.inserted_id)}
 
 
# === Dashboard ===
 
@app.get("/dashboard")
async def dashboard(
    busca: Optional[str] = None,
    canal: Optional[str] = None,
    dias: int = 30,
    user=Depends(get_user),
):
    canal = normalizar_canal(canal)
    desde = datetime.utcnow() - timedelta(days=dias)
 
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
 
    filtro_hist = {}
 
    if produto_ids:
        filtro_hist["produto_id"] = {"$in": produto_ids}
    elif busca:
        filtro_hist["produto_id"] = {"$in": []}
 
    total_produtos = len(produtos)
    total_registros = await historico_col.count_documents(filtro_hist)
 
    ultimo = await historico_col.find_one(filtro_hist, sort=[("data", -1)])
    ultima_coleta = ultimo["data"].isoformat() if ultimo else None
 
    comparacoes = []
    vitorias_ecommerce = {c: 0 for c in CANAIS}
    total_vitorias = 0
 
    canais_consulta = [canal] if canal else CANAIS
    ultimos_precos_por_produto = {}

    if produto_ids:
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
                "sku": produto.get("sku", ""),
                "ean": produto.get("ean", ""),
                "canal": c,
                "meu_preco": meu_preco,
                "menor_preco": menor_preco,
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
    grupo = normalizar_curva_abc(grupo)
    if grupo not in CURVAS_ABC:
        raise HTTPException(status_code=400, detail="Grupo invÃ¡lido. Use A, B ou C.")

    doc = {
        "grupo": grupo,
        "estrategia_base": data.estrategia_base if data.estrategia_base in ["menor_preco", "preco_medio"] else "menor_preco",
        "ajuste_percentual": float(data.ajuste_percentual),
        "margem_minima_percentual": float(data.margem_minima_percentual),
        "preco_minimo_grupo": float(data.preco_minimo_grupo),
        "estoque_baixo_limite": to_float(data.estoque_baixo_limite),
        "estoque_baixo_ajuste_percentual": to_float(data.estoque_baixo_ajuste_percentual) or 0.0,
        "ativo": bool(data.ativo),
        "atualizado_em": datetime.utcnow(),
    }

    await pricing_groups_col.update_one(
        {"grupo": grupo},
        {
            "$set": doc,
            "$setOnInsert": {"criado_em": datetime.utcnow()},
        },
        upsert=True,
    )
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
        raise HTTPException(status_code=404, detail="Produto nÃ£o encontrado")

    produto_serial = serial(produto)
    pid = produto_serial.get("id")
    mapa_ultimos = await obter_ultimos_precos_por_produto([pid], datetime.utcnow() - timedelta(days=30))
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
        "config_aplicada": config,
        "metricas_mercado": metricas,
        "simulacao": sim,
    }


# === Tiny integration ===

@app.post("/integracoes/tiny/sync/full")
async def tiny_sync_full(user=Depends(product_manager_required)):
    return await executar_sync_tiny(full=True)


@app.post("/integracoes/tiny/sync/incremental")
async def tiny_sync_incremental(user=Depends(product_manager_required)):
    return await executar_sync_tiny(full=False)


@app.get("/integracoes/tiny/status")
async def tiny_sync_status(user=Depends(product_manager_required)):
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
    index_path = "index.html" if os.path.exists("index.html") else "index.txt"
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
    Endpoint de notificaÃ§Ãµes do Mercado Livre.
    NecessÃ¡rio para certificaÃ§Ã£o do app no portal de desenvolvedores.
    """
    try:
        body = await request.json()
        print(f"[ML Webhook] NotificaÃ§Ã£o recebida: {body}")
    except Exception:
        pass
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
    )


