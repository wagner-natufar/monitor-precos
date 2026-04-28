import os
import jwt
import hashlib
import base64
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Optional
 
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
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

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET nÃ£o configurado. Defina a variÃ¡vel de ambiente JWT_SECRET.")
 
# === DB ===
client = AsyncIOMotorClient(MONGO_URL)
db = client.monitor_precos
produtos_col = db.produtos
historico_col = db.historico
usuarios_col = db.usuarios
 
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
 
 
# === Models ===
 
class PrecosPraticados(BaseModel):
    mercado_livre: Optional[float] = None
    amazon: Optional[float] = None
    shopee: Optional[float] = None
    droga_raia: Optional[float] = None
 
 
class Produto(BaseModel):
    nome: str
    sku: str
    ean: str
    palavra_chave_1: str
    palavra_chave_2: Optional[str] = ""
    precos_praticados: Optional[PrecosPraticados] = None
 
 
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
 
    return [serial(d) for d in docs]
 
 
@app.post("/produtos")
async def cadastrar_produto(produto: Produto, user=Depends(product_manager_required)):
    if await produtos_col.find_one({"sku": produto.sku}):
        raise HTTPException(
            status_code=400,
            detail=f"Produto jÃ¡ cadastrado com o SKU {produto.sku}",
        )
 
    if await produtos_col.find_one({"ean": produto.ean}):
        raise HTTPException(
            status_code=400,
            detail=f"Produto jÃ¡ cadastrado com o EAN {produto.ean}",
        )
 
    doc = produto.dict()
    doc["criado_em"] = datetime.utcnow()
 
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
 
    if await produtos_col.find_one({"sku": produto.sku, "_id": {"$ne": oid}}):
        raise HTTPException(
            status_code=400,
            detail=f"Outro produto jÃ¡ usa o SKU {produto.sku}",
        )
 
    if await produtos_col.find_one({"ean": produto.ean, "_id": {"$ne": oid}}):
        raise HTTPException(
            status_code=400,
            detail=f"Outro produto jÃ¡ usa o EAN {produto.ean}",
        )
 
    res = await produtos_col.update_one(
        {"_id": oid},
        {"$set": produto.dict()},
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
 
 
# === Static ===
 
@app.get("/")
async def root():
    return FileResponse(
        "index.html",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
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

