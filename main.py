import os
import uuid
import json
from datetime import datetime
from typing import Optional, List

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext

from dotenv import load_dotenv
import gspread
from google.oauth2.service_account import Credentials
import hashlib

# Load environment variables from .env
load_dotenv()

app = FastAPI(title="Slash Chat API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve uploaded files
UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# Use bcrypt_sha256 to avoid 72-byte password limit while remaining bcrypt-based
# Include bcrypt as secondary for legacy hashes; disable truncate errors if it gets picked.
pwd_context = CryptContext(
    schemes=["bcrypt_sha256", "bcrypt"],
    deprecated="auto",
    bcrypt__truncate_error=False,
)

# Google Sheets Setup (globals initialized, refreshed inside init_sheets)
SPREADSHEET_ID = os.getenv("GOOGLE_SHEETS_SPREADSHEET_ID")
SERVICE_ACCOUNT_JSON = os.getenv("GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON")

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]

gc = None
sh = None
users_ws = None
messages_ws = None


def init_sheets():
    """Ensure gspread client and target worksheets are ready.
    Re-reads environment variables on each call to support late-binding.
    """
    global gc, sh, users_ws, messages_ws, SPREADSHEET_ID, SERVICE_ACCOUNT_JSON

    # Re-read envs in case they were set/updated after startup
    SPREADSHEET_ID = os.getenv("GOOGLE_SHEETS_SPREADSHEET_ID")
    SERVICE_ACCOUNT_JSON = os.getenv("GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON")

    if not SPREADSHEET_ID or not SERVICE_ACCOUNT_JSON:
        return False
    try:
        # Parse JSON safely
        try:
            sa_info = json.loads(SERVICE_ACCOUNT_JSON)
        except json.JSONDecodeError:
            # Some environments may double-encode; try once more
            sa_info = json.loads(json.loads(SERVICE_ACCOUNT_JSON))
        creds = Credentials.from_service_account_info(sa_info, scopes=SCOPES)
        gc = gspread.authorize(creds)
        global sh
        sh = gc.open_by_key(SPREADSHEET_ID)
        # Ensure worksheets exist and have headers
        try:
            users_ws_local = sh.worksheet("Users")
        except gspread.exceptions.WorksheetNotFound:
            users_ws_local = sh.add_worksheet(title="Users", rows=1000, cols=10)
        try:
            messages_ws_local = sh.worksheet("Messages")
        except gspread.exceptions.WorksheetNotFound:
            messages_ws_local = sh.add_worksheet(title="Messages", rows=2000, cols=12)

        # Ensure headers
        def ensure_headers(ws, headers):
            values = ws.get_all_values()
            if not values or not values[0] or values[0] != headers:
                if not values:
                    ws.append_row(headers, value_input_option="RAW")
                else:
                    ws.update('A1', [headers])

        ensure_headers(users_ws_local, ["id", "name", "username", "email", "password_hash", "created_at"])
        ensure_headers(messages_ws_local, ["id", "sender", "receiver", "type", "text", "media_url", "created_at"])

        global users_ws, messages_ws
        users_ws = users_ws_local
        messages_ws = messages_ws_local
        return True
    except Exception as e:
        print("Sheets init error:", e)
        return False


@app.on_event("startup")
def startup_event():
    init_sheets()


class RegisterRequest(BaseModel):
    name: str
    username: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    identifier: str  # username or email
    password: str


@app.get("/")
def health():
    return {"ok": True, "service": "Slash API"}


@app.get("/test")
def test():
    ok = init_sheets()
    return {
        "sheets": "connected" if ok else "not_configured",
        "spreadsheet_id": bool(SPREADSHEET_ID),
        "have_creds": bool(SERVICE_ACCOUNT_JSON),
    }


def read_all(ws) -> List[List[str]]:
    # returns all rows excluding header
    values = ws.get_all_values()
    if not values:
        return []
    if values and values[0] and values[0][0] == "id":
        return values[1:]
    return values


@app.get("/__debug/users")
def debug_users():
    if not init_sheets():
        return {"ok": False, "error": "sheets not configured"}
    return {"head": users_ws.get_all_values()[:20]}


def is_passphrase(password: str) -> bool:
    """Heuristic: if password has more than 5 whitespace-separated words, treat as passphrase."""
    parts = [p for p in password.strip().split() if p]
    return len(parts) > 5


@app.get("/__debug/hash")
def debug_hash(pw: str):
    """Hash a password, applying the 5+ words passphrase rule before hashing.
    Reports whether the rule was applied or a fallback due to backend error occurred.
    """
    used_rule = is_passphrase(pw)
    try:
        if used_rule:
            digest = hashlib.sha256(pw.encode("utf-8")).hexdigest()
            h = pwd_context.hash(digest)
            ok = pwd_context.verify(digest, h)
            return {"scheme": "bcrypt_sha256", "hash": h, "verify": ok, "passphrase_rule": True, "fallback_used": False}
        else:
            h = pwd_context.hash(pw)
            ok = pwd_context.verify(pw, h)
            return {"scheme": "bcrypt_sha256", "hash": h, "verify": ok, "passphrase_rule": False, "fallback_used": False}
    except Exception as e:
        # Fallback due to backend constraints
        digest = hashlib.sha256(pw.encode("utf-8")).hexdigest()
        h = pwd_context.hash(digest)
        ok = pwd_context.verify(digest, h)
        return {"scheme": "bcrypt_sha256", "hash": h, "verify": ok, "passphrase_rule": used_rule, "fallback_used": True, "error": str(e)}


def hash_password_safe(password: str) -> str:
    """Hash password using bcrypt_sha256.
    If it has more than 5 words, prehash with sha256 first.
    Also catches backend 72-byte issues and falls back to prehashing.
    """
    if is_passphrase(password):
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return pwd_context.hash(digest)
    try:
        return pwd_context.hash(password)
    except Exception:
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return pwd_context.hash(digest)


def verify_password_safe(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash.
    If it has more than 5 words, try verifying a sha256 prehash first, then direct.
    Otherwise try direct first, then sha256 prehash as fallback.
    """
    if is_passphrase(password):
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        try:
            if pwd_context.verify(digest, stored_hash):
                return True
        except Exception:
            pass
        # Try direct just in case existing accounts were created without the rule
        try:
            return pwd_context.verify(password, stored_hash)
        except Exception:
            return False
    else:
        try:
            if pwd_context.verify(password, stored_hash):
                return True
        except Exception:
            pass
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        try:
            return pwd_context.verify(digest, stored_hash)
        except Exception:
            return False


@app.post("/register")
def register(req: RegisterRequest):
    if not init_sheets():
        raise HTTPException(status_code=500, detail="Google Sheets not configured")

    # Basic password sanity check (allow any length, but not empty or all spaces)
    if not req.password or not req.password.strip():
        raise HTTPException(status_code=400, detail="Password cannot be empty")

    try:
        # Check duplicates by username/email
        rows = read_all(users_ws)
        for row in rows:
            _, _, u_username, u_email, *_ = row + [None] * 6
            if u_username == req.username:
                raise HTTPException(status_code=400, detail="Username already exists")
            if u_email == req.email:
                raise HTTPException(status_code=400, detail="Email already exists")

        uid = str(uuid.uuid4())
        try:
            password_hash = hash_password_safe(req.password)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Password hashing failed: {str(e)}")
        created_at = datetime.utcnow().isoformat()

        users_ws.append_row([uid, req.name, req.username, req.email, password_hash, created_at], value_input_option="RAW")
        return {"id": uid, "name": req.name, "username": req.username, "email": req.email, "created_at": created_at}
    except HTTPException:
        raise
    except Exception as e:
        # Surface errors to client for easier debugging
        raise HTTPException(status_code=500, detail=f"Register failed: {str(e)}")


@app.post("/login")
def login(req: LoginRequest):
    if not init_sheets():
        raise HTTPException(status_code=500, detail="Google Sheets not configured")

    rows = read_all(users_ws)
    for row in rows:
        u_id, u_name, u_username, u_email, u_hash, *_ = row + [None] * 6
        if req.identifier in (u_username, u_email):
            try:
                ok = verify_password_safe(req.password, u_hash or "")
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Password verify failed: {str(e)}")
            if not ok:
                raise HTTPException(status_code=401, detail="Invalid credentials")
            return {"id": u_id, "name": u_name, "username": u_username, "email": u_email}

    raise HTTPException(status_code=404, detail="User not found")


@app.get("/users/search")
def search_users(q: str):
    if not init_sheets():
        raise HTTPException(status_code=500, detail="Google Sheets not configured")
    q = q.lower()
    results = []
    for row in read_all(users_ws):
        u_id, u_name, u_username, u_email, *_ = row + [None] * 6
        if u_username and q in u_username.lower():
            results.append({"id": u_id, "name": u_name, "username": u_username})
    return {"results": results}


@app.post("/messages/send")
async def send_message(
    sender: str = Form(...),
    receiver: str = Form(...),
    type: str = Form("text"),  # text | image | video | audio
    text: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    if not init_sheets():
        raise HTTPException(status_code=500, detail="Google Sheets not configured")

    try:
        msg_id = str(uuid.uuid4())
        created_at = datetime.utcnow().isoformat()
        media_url = None

        if file is not None:
            ext = os.path.splitext(file.filename)[1]
            fname = f"{msg_id}{ext}"
            fpath = os.path.join(UPLOAD_DIR, fname)
            with open(fpath, "wb") as out:
                out.write(await file.read())
            media_url = f"/uploads/{fname}"

        if type == "text" and not text:
            raise HTTPException(status_code=400, detail="Text is required for text messages")

        messages_ws.append_row([msg_id, sender, receiver, type, text or "", media_url or "", created_at], value_input_option="RAW")

        return {
            "id": msg_id,
            "sender": sender,
            "receiver": receiver,
            "type": type,
            "text": text,
            "media_url": media_url,
            "created_at": created_at,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Send failed: {str(e)}")


@app.get("/messages/history")
def history(user1: str, user2: str, limit: int = 100):
    if not init_sheets():
        raise HTTPException(status_code=500, detail="Google Sheets not configured")

    all_rows = read_all(messages_ws)
    convo = []
    for r in all_rows:
        m_id, sender, receiver, m_type, m_text, m_media, m_created = r + [None] * 7
        if (sender == user1 and receiver == user2) or (sender == user2 and receiver == user1):
            convo.append({
                "id": m_id,
                "sender": sender,
                "receiver": receiver,
                "type": m_type,
                "text": m_text,
                "media_url": m_media if m_media else None,
                "created_at": m_created,
            })
    convo = sorted(convo, key=lambda x: x["created_at"])[:limit]
    return {"messages": convo}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
