from fastapi import FastAPI, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
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

MONGO_URL = os.getenv("MONGO_URL", "mongodb://127.0.0.1:27017")
client = AsyncIOMotorClient(MONGO_URL)
db = client["monitor_precos"]
col_produtos  = db["produtos"]
col_historico = db["historico"]
col_usuarios  = db["usuarios"]

JWT_SECRET    = "monitor-precos-secret-2026"
JWT_ALGORITHM = "HS256"
security      = HTTPBearer()

# ── HELPERS ──────────────────────────────────────────────

def hash_senha(s): return hashlib.sha256(s.encode()).hexdigest()

def criar_token(uid, perfil):
    return jwt.encode({"sub": uid, "perfil": perfil, "exp": datetime.utcnow() + timedelta(days=7)}, JWT_SECRET, algorithm=JWT_ALGORITHM)

def serial(doc):
    d = {}
    for k, v in doc.items():
        if k == "_id":
            d["id"] = str(v)
        elif isinstance(v, ObjectId):
            d[k] = str(v)
        else:
            d[k] = v
    return d

def verificar_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

def exigir_admin(payload=Depends(verificar_token)):
    if payload.get("perfil") != "admin":
        raise HTTPException(status_code=403, detail="Acesso negado")
    return payload

def usuario_aprovado(payload=Depends(verificar_token)):
    return payload

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
    if await col_usuarios.find_one({"email": dados.email}):
        raise HTTPException(status_code=400, detail="E-mail já cadastrado")
    total = await col_usuarios.count_documents({})
    status_u = "aprovado" if total == 0 else "pendente"
    perfil   = "admin"    if total == 0 else "visualizador"
    doc = {"nome": dados.nome, "email": dados.email, "senha": hash_senha(dados.senha),
           "perfil": perfil, "status": status_u, "criadoEm": datetime.now().isoformat()}
    result = await col_usuarios.insert_one(doc)
    uid = str(result.inserted_id)
    if status_u == "aprovado":
        return {"mensagem": "Conta admin criada!", "token": criar_token(uid, perfil), "perfil": perfil, "nome": dados.nome}
    return {"mensagem": "Solicitação enviada! Aguarde aprovação."}

@app.post("/auth/login")
async def login(dados: Login):
    u = await col_usuarios.find_one({"email": dados.email, "senha": hash_senha(dados.senha)})
    if not u:
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos")
    if u["status"] == "pendente":
        raise HTTPException(status_code=403, detail="Conta ainda não aprovada")
    if u["status"] == "rejeitado":
        raise HTTPException(status_code=403, detail="Solicitação rejeitada")
    return {"token": criar_token(str(u["_id"]), u["perfil"]), "perfil": u["perfil"], "nome": u["nome"]}

@app.get("/auth/me")
async def me(payload=Depends(verificar_token)):
    u = await col_usuarios.find_one({"_id": ObjectId(payload["sub"])})
    if not u:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return {"id": str(u["_id"]), "nome": u["nome"], "email": u["email"], "perfil": u["perfil"]}

# ── USUÁRIOS ──────────────────────────────────────────────

@app.get("/usuarios")
async def listar_usuarios(payload=Depends(exigir_admin)):
    return [serial({k: v for k, v in u.items() if k != "senha"}) async for u in col_usuarios.find().sort("criadoEm", -1)]

@app.get("/usuarios/pendentes")
async def pendentes(payload=Depends(exigir_admin)):
    return {"pendentes": await col_usuarios.count_documents({"status": "pendente"})}

@app.put("/usuarios/{uid}/aprovar")
async def aprovar(uid: str, dados: AprovarUsuario, payload=Depends(exigir_admin)):
    await col_usuarios.update_one({"_id": ObjectId(uid)}, {"$set": {"status": "aprovado", "perfil": dados.perfil, "aprovadoEm": datetime.now().isoformat()}})
    return {"ok": True}

@app.put("/usuarios/{uid}/rejeitar")
async def rejeitar(uid: str, payload=Depends(exigir_admin)):
    await col_usuarios.update_one({"_id": ObjectId(uid)}, {"$set": {"status": "rejeitado"}})
    return {"ok": True}

@app.delete("/usuarios/{uid}")
async def excluir_usuario(uid: str, payload=Depends(exigir_admin)):
    if uid == payload["sub"]:
        raise HTTPException(status_code=400, detail="Não pode excluir sua própria conta")
    await col_usuarios.delete_one({"_id": ObjectId(uid)})
    return {"ok": True}

# ── PRODUTOS ──────────────────────────────────────────────

@app.get("/produtos")
async def listar_produtos(payload=Depends(usuario_aprovado)):
    return [serial(p) async for p in col_produtos.find()]

@app.post("/produtos")
async def cadastrar_produto(produto: Produto, payload=Depends(exigir_admin)):
    if await col_produtos.find_one({"sku": produto.sku}):
        raise HTTPException(status_code=400, detail="Produto já cadastrado com esse SKU")
    doc = produto.dict()
    doc["criadoEm"] = datetime.now().isoformat()
    result = await col_produtos.insert_one(doc)
    return {"id": str(result.inserted_id), "mensagem": "Produto cadastrado com sucesso"}

@app.put("/produtos/{pid}")
async def editar_produto(pid: str, produto: Produto, payload=Depends(exigir_admin)):
    existente = await col_produtos.find_one({"sku": produto.sku, "_id": {"$ne": ObjectId(pid)}})
    if existente:
        raise HTTPException(status_code=400, detail="Já existe outro produto com esse SKU")
    await col_produtos.update_one({"_id": ObjectId(pid)}, {"$set": produto.dict()})
    return {"ok": True, "mensagem": "Produto atualizado com sucesso"}

@app.delete("/produtos/{pid}")
async def excluir_produto(pid: str, payload=Depends(exigir_admin)):
    await col_produtos.delete_one({"_id": ObjectId(pid)})
    await col_historico.delete_many({"produto_id": pid})
    return {"ok": True}

# ── HISTÓRICO ──────────────────────────────────────────────

@app.get("/historico/{produto_id}")
async def listar_historico(produto_id: str, dias: int = 7, payload=Depends(usuario_aprovado)):
    inicio = (datetime.now() - timedelta(days=dias)).isoformat()
    return [serial(r) async for r in col_historico.find({"produto_id": produto_id, "data": {"$gte": inicio}}).sort("data", 1)]

@app.post("/historico")
async def salvar_preco(registro: RegistroPreco):
    doc = registro.dict()
    doc["data"] = datetime.now().isoformat()
    result = await col_historico.insert_one(doc)
    return {"id": str(result.inserted_id)}

@app.get("/stats")
async def stats(payload=Depends(usuario_aprovado)):
    total_produtos  = await col_produtos.count_documents({})
    total_registros = await col_historico.count_documents({})
    ultimo = await col_historico.find_one(sort=[("data", -1)])
    return {"total_produtos": total_produtos, "total_registros": total_registros, "ultima_coleta": ultimo["data"] if ultimo else None}

app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8080)
