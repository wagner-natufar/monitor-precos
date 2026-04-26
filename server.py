import os
import jwt
import hashlib
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import uvicorn

# === Config ===
MONGO_URL = os.getenv("MONGO_URL", "mongodb://127.0.0.1:27017")
JWT_SECRET = os.getenv("JWT_SECRET", "monitor-precos-secret-key-change-me")
JWT_ALG = "HS256"

# === DB ===
client = AsyncIOMotorClient(MONGO_URL)
db = client.monitor_precos
produtos_col = db.produtos
historico_col = db.historico
usuarios_col = db.usuarios

# === App ===
app = FastAPI(title="Monitor de Preços")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CANAIS = ["mercado_livre", "amazon", "shopee", "droga_raia"]


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
    return hashlib.sha256(senha.encode()).hexdigest()


def criar_token(user_id: str, perfil: str) -> str:
    payload = {
        "user_id": user_id,
        "perfil": perfil,
        "exp": datetime.utcnow() + timedelta(days=30),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def normalizar_canal(canal: Optional[str] = None) -> Optional[str]:
    if not canal or canal == "todos":
        return None

    if canal not in CANAIS:
        raise HTTPException(status_code=400, detail=f"Canal inválido. Use: {CANAIS}")

    return canal


def object_id_or_400(value: str):
    try:
        return ObjectId(value)
    except Exception:
        raise HTTPException(status_code=400, detail="ID inválido")


async def get_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Não autenticado")

    token = authorization.split(" ", 1)[1]

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")


async def admin_required(user=Depends(get_user)):
    if user.get("perfil") != "admin":
        raise HTTPException(status_code=403, detail="Acesso restrito ao admin")
    return user


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
    vendedor: Optional[str] = ""
    url: Optional[str] = ""


# === Auth ===

@app.post("/auth/registrar")
async def registrar(data: CadastroInput):
    existente = await usuarios_col.find_one({"email": data.email})

    if existente:
        raise HTTPException(status_code=400, detail="E-mail já cadastrado")

    total = await usuarios_col.count_documents({})
    primeiro_admin = total == 0

    novo = {
        "nome": data.nome,
        "email": data.email,
        "senha_hash": hash_senha(data.senha),
        "perfil": "admin" if primeiro_admin else "visualizador",
        "status": "aprovado" if primeiro_admin else "pendente",
        "criado_em": datetime.utcnow(),
    }

    res = await usuarios_col.insert_one(novo)
    user_id = str(res.inserted_id)

    if primeiro_admin:
        token = criar_token(user_id, "admin")

        return {
            "token": token,
            "perfil": "admin",
            "nome": data.nome,
            "primeiro_admin": True,
        }

    return {
        "mensagem": "Solicitação enviada! Aguarde aprovação do administrador.",
        "primeiro_admin": False,
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

    if senha_armazenada != hash_senha(data.senha):
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos")

    status = user.get("status", "aprovado")

    if status == "pendente":
        raise HTTPException(status_code=403, detail="Cadastro aguardando aprovação")

    if status == "rejeitado":
        raise HTTPException(status_code=403, detail="Acesso negado")

    user_id = str(user["_id"])
    perfil = user.get("perfil", "visualizador")
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
    }


# === Usuários ===

@app.get("/pendentes")
async def listar_pendentes(user=Depends(admin_required)):
    docs = await usuarios_col.find({"status": "pendente"}).to_list(1000)

    return [
        {**serial(d), "senha_hash": None}
        for d in docs
    ]


@app.get("/usuarios")
async def listar_usuarios(user=Depends(admin_required)):
    docs = await usuarios_col.find().to_list(1000)

    return [
        {**serial(d), "senha_hash": None}
        for d in docs
    ]


@app.post("/aprovar/{user_id}")
async def aprovar(
    user_id: str,
    perfil: str = "visualizador",
    user=Depends(admin_required),
):
    if perfil not in ["admin", "visualizador"]:
        raise HTTPException(status_code=400, detail="Perfil inválido")

    oid = object_id_or_400(user_id)

    res = await usuarios_col.update_one(
        {"_id": oid},
        {"$set": {"status": "aprovado", "perfil": perfil}},
    )

    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    return {"mensagem": "Usuário aprovado"}


@app.post("/rejeitar/{user_id}")
async def rejeitar(user_id: str, user=Depends(admin_required)):
    oid = object_id_or_400(user_id)

    res = await usuarios_col.update_one(
        {"_id": oid},
        {"$set": {"status": "rejeitado"}},
    )

    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    return {"mensagem": "Usuário rejeitado"}


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
async def cadastrar_produto(produto: Produto, user=Depends(admin_required)):
    if await produtos_col.find_one({"sku": produto.sku}):
        raise HTTPException(
            status_code=400,
            detail=f"Produto já cadastrado com o SKU {produto.sku}",
        )

    if await produtos_col.find_one({"ean": produto.ean}):
        raise HTTPException(
            status_code=400,
            detail=f"Produto já cadastrado com o EAN {produto.ean}",
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
    user=Depends(admin_required),
):
    oid = object_id_or_400(produto_id)

    if await produtos_col.find_one({"sku": produto.sku, "_id": {"$ne": oid}}):
        raise HTTPException(
            status_code=400,
            detail=f"Outro produto já usa o SKU {produto.sku}",
        )

    if await produtos_col.find_one({"ean": produto.ean, "_id": {"$ne": oid}}):
        raise HTTPException(
            status_code=400,
            detail=f"Outro produto já usa o EAN {produto.ean}",
        )

    res = await produtos_col.update_one(
        {"_id": oid},
        {"$set": produto.dict()},
    )

    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Produto não encontrado")

    return {"mensagem": "Produto atualizado com sucesso!"}


@app.delete("/produtos/{produto_id}")
async def excluir_produto(produto_id: str, user=Depends(admin_required)):
    oid = object_id_or_400(produto_id)

    res = await produtos_col.delete_one({"_id": oid})

    await historico_col.delete_many({"produto_id": produto_id})

    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Produto não encontrado")

    return {"mensagem": "Produto excluído"}


# === Histórico ===

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
async def registrar_preco(data: HistoricoInput, user=Depends(admin_required)):
    if data.canal not in CANAIS:
        raise HTTPException(
            status_code=400,
            detail=f"Canal inválido. Use: {CANAIS}",
        )

    doc = {
        "produto_id": data.produto_id,
        "canal": data.canal,
        "preco": float(data.preco),
        "vendedor": data.vendedor or "",
        "url": data.url or "",
        "data": datetime.utcnow(),
    }

    res = await historico_col.insert_one(doc)

    return {"id": str(res.inserted_id)}


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


if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
    )
