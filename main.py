import os
import uuid
import json
from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr

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


def _parse_service_account_env(raw: str):
    """Parse SERVICE_ACCOUNT_JSON robustly.
    - Strips surrounding single quotes if present (common in .env).
    - Attempts JSON parse; if fails, tries a double-decoding fallback.
    Returns dict on success; raises on failure.
    """
    if raw is None:
        raise ValueError("Missing SERVICE_ACCOUNT_JSON env")
    s = raw.strip()
    # Strip wrapping single quotes often used in .env files
    if s.startswith("'") and s.endswith("'"):
        s = s[1:-1]
    # First attempt: direct JSON
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    # Some environments double-encode the JSON string
    try:
        inner = json.loads(s)
        if isinstance(inner, str):
            return json.loads(inner)
    except Exception:
        pass
    # As a last resort, replace escaped newlines in private key then parse
    try:
        s2 = s.replace('\\n', '\n')
        return json.loads(s2)
    except Exception as e:
        raise ValueError(f"Could not parse SERVICE_ACCOUNT_JSON: {e}")


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
        sa_info = _parse_service_account_env(SERVICE_ACCOUNT_JSON)
        creds = Credentials.from_service_account_info(sa_info, scopes=SCOPES)
        gc_local = gspread.authorize(creds)
        sh_local = gc_local.open_by_key(SPREADSHEET_ID)
        # Ensure worksheets exist and have headers
        try:
            users_ws_local = sh_local.worksheet("Users")
        except gspread.exceptions.WorksheetNotFound:
            users_ws_local = sh_local.add_worksheet(title="Users", rows=1000, cols=10)
        try:
            messages_ws_local = sh_local.worksheet("Messages")
        except gspread.exceptions.WorksheetNotFound:
            messages_ws_local = sh_local.add_worksheet(title="Messages", rows=2000, cols=12)

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

        # Assign globals last upon success
        global gc, sh, users_ws, messages_ws
        gc = gc_local
        sh = sh_local
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


# Simple, bcrypt-free password hashing using PBKDF2-HMAC-SHA256
# Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
PBKDF2_ALGO = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16


def hash_password(password: str) -> str:
    salt = os.urandom(SALT_BYTES).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return f"{PBKDF2_ALGO}${PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations_str, salt_hex, hash_hex = stored.split("$")
        if algo != PBKDF2_ALGO:
            # Unknown/legacy hash (e.g., bcrypt). Since bcrypt is removed, treat as non-match.
            return False
        iterations = int(iterations_str)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iterations)
        return dk.hex() == hash_hex
    except Exception:
        return False


@app.get("/__debug/hash")
def debug_hash(pw: str):
    h = hash_password(pw)
    ok = verify_password(pw, h)
    return {"scheme": PBKDF2_ALGO, "hash": h, "verify": ok}


@app.post("/register")
def register(req: RegisterRequest):
    if not init_sheets():
        raise HTTPException(status_code=500, detail="Google Sheets not configured")

    # Allow any password (including long passphrases); only reject empty/whitespace-only
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
            password_hash = hash_password(req.password)
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
                ok = verify_password(req.password, u_hash or "")
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


@app.get("/conversations")
def conversations(user: str, limit: int = 50):
    """Return recent conversations for a user with last message preview.
    Sorted by last activity desc.
    """
    if not init_sheets():
        raise HTTPException(status_code=500, detail="Google Sheets not configured")

    # Build username -> (id, name) map
    users_map: Dict[str, Dict[str, Any]] = {}
    for row in read_all(users_ws):
        u_id, u_name, u_username, *_ = row + [None] * 6
        if u_username:
            users_map[u_username] = {"id": u_id, "name": u_name, "username": u_username}

    # Aggregate last message per peer
    last_map: Dict[str, Dict[str, Any]] = {}
    for r in read_all(messages_ws):
        m_id, sender, receiver, m_type, m_text, m_media, m_created = r + [None] * 7
        if sender == user:
            peer = receiver
        elif receiver == user:
            peer = sender
        else:
            continue
        if not peer:
            continue
        cur = last_map.get(peer)
        if (not cur) or (m_created and m_created > cur["created_at"]):
            last_map[peer] = {
                "peer": peer,
                "last": {
                    "id": m_id,
                    "sender": sender,
                    "receiver": receiver,
                    "type": m_type,
                    "text": m_text,
                    "media_url": m_media if m_media else None,
                    "created_at": m_created,
                },
                "peer_name": users_map.get(peer, {}).get("name"),
                "peer_id": users_map.get(peer, {}).get("id"),
            }

    items = list(last_map.values())
    items.sort(key=lambda x: (x["last"].get("created_at") or ""), reverse=True)
    return {"conversations": items[:limit]}


@app.get("/__debug/selftest")
def selftest():
    """Create a throwaway account with a long passphrase and a short password, then verify both locally.
    Returns the usernames created and verification results. Writes rows to the Users sheet.
    """
    if not init_sheets():
        raise HTTPException(status_code=500, detail="Google Sheets not configured")

    created = []
    tests = [
        ("Pass One", f"u_{uuid.uuid4().hex[:8]}", f"u_{uuid.uuid4().hex[:8]}@example.com", "this is a really really really long pass phrase with many words"),
        ("Pass Two", f"u_{uuid.uuid4().hex[:8]}", f"u_{uuid.uuid4().hex[:8]}@example.com", "Test123!"),
    ]
    results = []
    for name, username, email, pw in tests:
        uid = str(uuid.uuid4())
        ph = hash_password(pw)
        users_ws.append_row([uid, name, username, email, ph, datetime.utcnow().isoformat()], value_input_option="RAW")
        # verify locally
        ok = verify_password(pw, ph)
        created.append({"id": uid, "username": username, "email": email})
        results.append({"username": username, "verified": ok})

    return {"created": created, "verify_results": results}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
