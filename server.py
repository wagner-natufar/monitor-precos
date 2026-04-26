from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timedelta
from bson import ObjectId
import uvicorn
import hashlib
import jwt
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Conexão com MongoDB
MONGO_URL = os.getenv("MONGO_URL", "mongodb://127.0.0.1:27017")
client = AsyncIOMotorClient(MONGO_URL)
db = client["monitor_precos"]
col_produtos   = db["produtos"]
col_historico  = db["historico"]
col_usuarios   = db["usuarios"]

JWT_SECRET = "monitor-precos-secret-2026"
JWT_ALGORITHM = "HS256"
security = HTTPBearer()

# ── HELPERS ──────────────────────────────────────────────

def hash_senha(senha: str) -> str:
    return hashlib.sha256(senha.encode()).hexdigest()

def criar_token(usuario_id: str, perfil: str) -> str:
    payload = {
        "sub": usuario_id,
        "perfil": perfil,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verificar_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

def exigir_admin(payload = Depends(verificar_token)):
    if payload.get("perfil") != "admin":
        raise HTTPException(status_code=403, detail="Acesso negado — somente administradores")
    return payload

def usuario_aprovado(payload = Depends(verificar_token)):
    return payload

def serial(doc):
    doc = dict(doc)
    doc["id"] = str(doc["_id"])
    del doc["_id"]
    return doc

# ── MODELS ──────────────────────────────────────────────

class SolicitacaoAcesso(BaseModel):
    nome: str
    email: str
    senha: str

class Login(BaseModel):
    email: str
    senha: str

class AprovarUsuario(BaseModel):
    perfil: str

class Produto(BaseModel):
    nome: str
    sku: str
    ean: str
    kw1: str
    kw2: Optional[str] = ""

class RegistroPreco(BaseModel):
    produto_id: str
    preco: float
    vendedor: str
    canal: str = "Mercado Livre"

# ── AUTH ──────────────────────────────────────────────

@app.post("/auth/solicitar")
async def solicitar_acesso(dados: SolicitacaoAcesso):
    existente = await col_usuarios.find_one({"email": dados.email})
    if existente:
        raise HTTPException(status_code=400, detail="E-mail já cadastrado")

    total = await col_usuarios.count_documents({})
    if total == 0:
        status_usuario = "aprovado"
        perfil = "admin"
    else:
        status_usuario = "pendente"
        perfil = "visualizador"

    doc = {
        "nome": dados.nome,
        "email": dados.email,
        "senha": hash_senha(dados.senha),
        "perfil": perfil,
        "status": status_usuario,
        "criadoEm": datetime.now().isoformat()
    }
    result = await col_usuarios.insert_one(doc)
    doc["id"] = str(result.inserted_id)

    if status_usuario == "aprovado":
        token = criar_token(doc["id"], perfil)
        return {"mensagem": "Conta admin criada!", "token": token, "perfil": perfil, "nome": dados.nome}

    return {"mensagem": "Solicitação enviada! Aguarde aprovação do administrador."}

@app.post("/auth/login")
async def login(dados: Login):
    usuario = await col_usuarios.find_one({"email": dados.email, "senha": hash_senha(dados.senha)})
    if not usuario:
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos")
    if usuario["status"] == "pendente":
        raise HTTPException(status_code=403, detail="Sua conta ainda não foi aprovada")
    if usuario["status"] == "rejeitado":
        raise HTTPException(status_code=403, detail="Sua solicitação foi rejeitada")

    token = criar_token(str(usuario["_id"]), usuario["perfil"])
    return {"token": token, "perfil": usuario["perfil"], "nome": usuario["nome"]}

@app.get("/auth/me")
async def me(payload = Depends(verificar_token)):
    usuario = await col_usuarios.find_one({"_id": ObjectId(payload["sub"])})
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return {"id": str(usuario["_id"]), "nome": usuario["nome"], "email": usuario["email"], "perfil": usuario["perfil"]}

# ── USUÁRIOS (admin) ──────────────────────────────────────────────

@app.get("/usuarios")
async def listar_usuarios(payload = Depends(exigir_admin)):
    usuarios = []
    async for u in col_usuarios.find().sort("criadoEm", -1):
        u = serial(u)
        del u["senha"]
        usuarios.append(u)
    return usuarios

@app.get("/usuarios/pendentes")
async def pendentes(payload = Depends(exigir_admin)):
    count = await col_usuarios.count_documents({"status": "pendente"})
    return {"pendentes": count}

@app.put("/usuarios/{usuario_id}/aprovar")
async def aprovar(usuario_id: str, dados: AprovarUsuario, payload = Depends(exigir_admin)):
    await col_usuarios.update_one(
        {"_id": ObjectId(usuario_id)},
        {"$set": {"status": "aprovado", "perfil": dados.perfil, "aprovadoEm": datetime.now().isoformat()}}
    )
    return {"ok": True}

@app.put("/usuarios/{usuario_id}/rejeitar")
async def rejeitar(usuario_id: str, payload = Depends(exigir_admin)):
    await col_usuarios.update_one(
        {"_id": ObjectId(usuario_id)},
        {"$set": {"status": "rejeitado"}}
    )
    return {"ok": True}

@app.delete("/usuarios/{usuario_id}")
async def excluir_usuario(usuario_id: str, payload = Depends(exigir_admin)):
    if usuario_id == payload["sub"]:
        raise HTTPException(status_code=400, detail="Você não pode excluir sua própria conta")
    await col_usuarios.delete_one({"_id": ObjectId(usuario_id)})
    return {"ok": True}

# ── PRODUTOS ──────────────────────────────────────────────

@app.get("/produtos")
async def listar_produtos(payload = Depends(usuario_aprovado)):
    produtos = []
    async for p in col_produtos.find():
        p = serial(p)
        produtos.append(p)
    return produtos

@app.post("/produtos")
async def cadastrar_produto(produto: Produto, payload = Depends(exigir_admin)):
    existente = await col_produtos.find_one({"sku": produto.sku})
    if existente:
        raise HTTPException(status_code=400, detail="Produto já cadastrado com esse SKU")
    doc = produto.dict()
    doc["criadoEm"] = datetime.now().isoformat()
    result = await col_produtos.insert_one(doc)
    return {"id": str(result.inserted_id), "mensagem": "Produto cadastrado com sucesso"}

@app.put("/produtos/{produto_id}")
async def editar_produto(produto_id: str, produto: Produto, payload = Depends(exigir_admin)):
    existente = await col_produtos.find_one({"sku": produto.sku, "_id": {"$ne": ObjectId(produto_id)}})
    if existente:
        raise HTTPException(status_code=400, detail="Já existe outro produto com esse SKU")
    await col_produtos.update_one(
        {"_id": ObjectId(produto_id)},
        {"$set": produto.dict()}
    )
    return {"ok": True}

@app.delete("/produtos/{produto_id}")
async def excluir_produto(produto_id: str, payload = Depends(exigir_admin)):
    await col_produtos.delete_one({"_id": ObjectId(produto_id)})
    await col_historico.delete_many({"produto_id": produto_id})
    return {"ok": True}

# ── HISTÓRICO ──────────────────────────────────────────────

@app.get("/historico/{produto_id}")
async def listar_historico(produto_id: str, dias: int = 7, payload = Depends(usuario_aprovado)):
    inicio = datetime.now() - timedelta(days=dias)
    registros = []
    async for r in col_historico.find(
        {"produto_id": produto_id, "data": {"$gte": inicio.isoformat()}}
    ).sort("data", 1):
        r = serial(r)
        registros.append(r)
    return registros

@app.post("/historico")
async def salvar_preco(registro: RegistroPreco):
    doc = registro.dict()
    doc["data"] = datetime.now().isoformat()
    result = await col_historico.insert_one(doc)
    doc["id"] = str(result.inserted_id)
    return doc

@app.get("/stats")
async def stats(payload = Depends(usuario_aprovado)):
    total_produtos = await col_produtos.count_documents({})
    total_registros = await col_historico.count_documents({})
    ultimo = await col_historico.find_one(sort=[("data", -1)])
    ultima_coleta = ultimo["data"] if ultimo else None
    return {
        "total_produtos": total_produtos,
        "total_registros": total_registros,
        "ultima_coleta": ultima_coleta
    }

# Serve o site estático
app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8080, reload=True)
