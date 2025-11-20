from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Literal
from datetime import datetime
import os
import hashlib
import uuid

# Google Sheets
import json
import gspread
from google.oauth2.service_account import Credentials

APP_NAME = "Slash"

app = FastAPI(title=f"{APP_NAME} Backend")

# CORS for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# File uploads directory and static mount
UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# ---------- Google Sheets Helpers ----------
USERS_SHEET_NAME = "Users"
MESSAGES_SHEET_NAME = "Messages"
BLOCKS_SHEET_NAME = "Blocks"

_cached_client = None
_cached_spreadsheet = None


def get_gspread_client():
    global _cached_client
    if _cached_client:
        return _cached_client
    service_json = os.getenv("GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON")
    if not service_json:
        raise RuntimeError("GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON env var not set")
    try:
        info = json.loads(service_json)
    except json.JSONDecodeError:
        raise RuntimeError("Invalid GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON JSON")
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive.file",
        "https://www.googleapis.com/auth/drive",
    ]
    creds = Credentials.from_service_account_info(info, scopes=scopes)
    _cached_client = gspread.authorize(creds)
    return _cached_client


def get_spreadsheet():
    global _cached_spreadsheet
    if _cached_spreadsheet:
        return _cached_spreadsheet
    sheet_id = os.getenv("GOOGLE_SHEETS_SPREADSHEET_ID")
    if not sheet_id:
        raise RuntimeError("GOOGLE_SHEETS_SPREADSHEET_ID env var not set")
    client = get_gspread_client()
    _cached_spreadsheet = client.open_by_key(sheet_id)
    # Ensure worksheets exist with headers
    ensure_worksheets(_cached_spreadsheet)
    return _cached_spreadsheet


def ensure_header(ws, required_headers: List[str]):
    """Ensure the worksheet contains required headers; append missing ones."""
    headers = ws.row_values(1)
    changed = False
    for h in required_headers:
        if h not in headers:
            headers.append(h)
            changed = True
    if changed:
        ws.update("1:1", [headers])


def ensure_worksheets(spreadsheet):
    existing = {ws.title for ws in spreadsheet.worksheets()}
    if USERS_SHEET_NAME not in existing:
        ws = spreadsheet.add_worksheet(title=USERS_SHEET_NAME, rows=1000, cols=12)
        ws.append_row(["id", "name", "username", "email", "password_hash", "created_at", "avatar_url"]) 
    else:
        ws = spreadsheet.worksheet(USERS_SHEET_NAME)
        ensure_header(ws, ["id", "name", "username", "email", "password_hash", "created_at", "avatar_url"])

    if MESSAGES_SHEET_NAME not in existing:
        ws2 = spreadsheet.add_worksheet(title=MESSAGES_SHEET_NAME, rows=2000, cols=12)
        ws2.append_row(["id", "sender", "receiver", "type", "text", "media_url", "created_at"]) 
    
    if BLOCKS_SHEET_NAME not in existing:
        ws3 = spreadsheet.add_worksheet(title=BLOCKS_SHEET_NAME, rows=1000, cols=6)
        ws3.append_row(["blocker", "blocked", "created_at"]) 


def users_sheet():
    ss = get_spreadsheet()
    return ss.worksheet(USERS_SHEET_NAME)


def messages_sheet():
    ss = get_spreadsheet()
    return ss.worksheet(MESSAGES_SHEET_NAME)


def blocks_sheet():
    ss = get_spreadsheet()
    return ss.worksheet(BLOCKS_SHEET_NAME)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ---------- Models ----------
class RegisterRequest(BaseModel):
    name: str
    username: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    username_or_email: str
    password: str


class UserPublic(BaseModel):
    id: str
    name: str
    username: str
    email: EmailStr
    created_at: str
    avatar_url: Optional[str] = None


class Message(BaseModel):
    id: str
    sender: str
    receiver: str
    type: Literal["text", "image", "video", "audio"]
    text: Optional[str] = None
    media_url: Optional[str] = None
    created_at: str


class BlockStatus(BaseModel):
    blocked: bool
    blocked_by: Optional[str] = None  # username of who placed the block


# ---------- Utility ----------

def header_index_map(ws) -> dict:
    headers = ws.row_values(1)
    return {h: i + 1 for i, h in enumerate(headers)}


def is_blocked(u1: str, u2: str) -> BlockStatus:
    """Return whether messaging between u1 and u2 is blocked and by whom."""
    try:
        ws = blocks_sheet()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sheets error: {e}")
    records = ws.get_all_records()
    for r in records:
        blocker = str(r.get("blocker", "")).strip()
        blocked = str(r.get("blocked", "")).strip()
        if (blocker == u1 and blocked == u2) or (blocker == u2 and blocked == u1):
            # If either side blocked the other, it's blocked for both
            # Prefer to report the real blocker
            return BlockStatus(blocked=True, blocked_by=blocker)
    return BlockStatus(blocked=False, blocked_by=None)


# ---------- Routes ----------
@app.get("/")
async def root():
    return {"app": APP_NAME, "status": "ok"}


@app.get("/test")
async def test():
    # Verify Sheets connectivity
    try:
        _ = get_spreadsheet()
        return {"google_sheets": "connected"}
    except Exception as e:
        return {"google_sheets": f"error: {e}"}


@app.post("/register", response_model=UserPublic)
async def register(req: RegisterRequest):
    try:
        ws = users_sheet()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sheets error: {e}")

    # Lowercase unique keys
    username = req.username.strip()
    email = req.email.strip().lower()

    # Fetch all users and check uniqueness
    records = ws.get_all_records()
    for r in records:
        if r.get("username", "").strip().lower() == username.lower():
            raise HTTPException(status_code=400, detail="Username already exists")
        if r.get("email", "").strip().lower() == email:
            raise HTTPException(status_code=400, detail="Email already registered")

    user_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()
    password_hash = hash_password(req.password)

    # Ensure avatar_url column exists
    ensure_header(ws, ["avatar_url"])  # no-op if exists

    ws.append_row([user_id, req.name, username, email, password_hash, created_at, ""])  # avatar empty

    return UserPublic(id=user_id, name=req.name, username=username, email=email, created_at=created_at, avatar_url=None)


@app.post("/login", response_model=UserPublic)
async def login(req: LoginRequest):
    try:
        ws = users_sheet()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sheets error: {e}")

    key = req.username_or_email.strip().lower()
    records = ws.get_all_records()
    password_hash = hash_password(req.password)
    for i, r in enumerate(records, start=2):  # start=2 because row 1 is header
        if r.get("username", "").strip().lower() == key or r.get("email", "").strip().lower() == key:
            if r.get("password_hash") == password_hash:
                return UserPublic(
                    id=str(r.get("id")),
                    name=r.get("name"),
                    username=r.get("username"),
                    email=r.get("email"),
                    created_at=r.get("created_at"),
                    avatar_url=r.get("avatar_url") or None,
                )
            else:
                raise HTTPException(status_code=401, detail="Invalid credentials")
    raise HTTPException(status_code=404, detail="User not found")


@app.get("/users/search", response_model=List[UserPublic])
async def search_users(q: str):
    try:
        ws = users_sheet()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sheets error: {e}")

    ql = q.strip().lower()
    results: List[UserPublic] = []
    for r in ws.get_all_records():
        if ql in str(r.get("username", "")).strip().lower():
            results.append(
                UserPublic(
                    id=str(r.get("id")),
                    name=r.get("name"),
                    username=r.get("username"),
                    email=r.get("email"),
                    created_at=r.get("created_at"),
                    avatar_url=r.get("avatar_url") or None,
                )
            )
    return results[:50]


@app.get("/users/public", response_model=List[UserPublic])
async def list_public_users():
    try:
        ws = users_sheet()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sheets error: {e}")

    users: List[UserPublic] = []
    for r in ws.get_all_records():
        users.append(
            UserPublic(
                id=str(r.get("id")),
                name=r.get("name"),
                username=r.get("username"),
                email=r.get("email"),
                created_at=r.get("created_at"),
                avatar_url=r.get("avatar_url") or None,
            )
        )
    # Sort by name, then username
    users.sort(key=lambda u: (u.name or "", u.username))
    return users


@app.post("/users/avatar", response_model=UserPublic)
async def upload_avatar(username: str = Form(...), file: UploadFile = File(...)):
    try:
        ws = users_sheet()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sheets error: {e}")

    headers = ws.row_values(1)
    if "avatar_url" not in headers:
        headers.append("avatar_url")
        ws.update("1:1", [headers])
    col_map = {h: i + 1 for i, h in enumerate(ws.row_values(1))}

    # Save file
    ext = os.path.splitext(file.filename or "")[1]
    fname = f"avatar-{username}-{uuid.uuid4()}{ext}"
    dest_path = os.path.join(UPLOAD_DIR, fname)
    with open(dest_path, "wb") as f:
        f.write(await file.read())
    avatar_url = f"/uploads/{fname}"

    # Find user row
    records = ws.get_all_records()
    for idx, r in enumerate(records, start=2):
        if str(r.get("username", "")).strip() == username:
            ws.update_cell(idx, col_map["avatar_url"], avatar_url)
            return UserPublic(
                id=str(r.get("id")),
                name=r.get("name"),
                username=r.get("username"),
                email=r.get("email"),
                created_at=r.get("created_at"),
                avatar_url=avatar_url,
            )
    raise HTTPException(status_code=404, detail="User not found")


@app.post("/block")
async def block_user(blocker: str = Form(...), blocked: str = Form(...)):
    if blocker == blocked:
        raise HTTPException(status_code=400, detail="Cannot block yourself")
    try:
        ws = blocks_sheet()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sheets error: {e}")
    # Check existing
    for r in ws.get_all_records():
        if str(r.get("blocker")) == blocker and str(r.get("blocked")) == blocked:
            return {"status": "ok"}
    ws.append_row([blocker, blocked, datetime.utcnow().isoformat()])
    return {"status": "ok"}


@app.post("/unblock")
async def unblock_user(blocker: str = Form(...), blocked: str = Form(...)):
    try:
        ws = blocks_sheet()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sheets error: {e}")
    records = ws.get_all_records()
    # Find rows to delete; gspread row indices
    rows_to_delete = []
    for idx, r in enumerate(records, start=2):
        if str(r.get("blocker")) == blocker and str(r.get("blocked")) == blocked:
            rows_to_delete.append(idx)
    # Delete from bottom to top
    for row in reversed(rows_to_delete):
        ws.delete_rows(row)
    return {"status": "ok"}


@app.get("/block/status", response_model=BlockStatus)
async def block_status(user1: str, user2: str):
    return is_blocked(user1, user2)


@app.post("/messages/send", response_model=Message)
async def send_message(
    sender: str = Form(...),
    receiver: str = Form(...),
    type: Literal["text", "image", "video", "audio"] = Form(...),
    text: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    # Enforce blocks in both directions
    status = is_blocked(sender, receiver)
    if status.blocked:
        raise HTTPException(status_code=403, detail=f"Messaging blocked by {status.blocked_by}")

    try:
        ws = messages_sheet()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sheets error: {e}")

    media_url = None
    if file is not None:
        ext = os.path.splitext(file.filename or "")[1]
        fname = f"{uuid.uuid4()}{ext}"
        dest_path = os.path.join(UPLOAD_DIR, fname)
        with open(dest_path, "wb") as f:
            f.write(await file.read())
        media_url = f"/uploads/{fname}"

    if type == "text" and not text:
        raise HTTPException(status_code=400, detail="Text required for type=text")

    msg_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()

    ws.append_row([
        msg_id,
        sender,
        receiver,
        type,
        text or "",
        media_url or "",
        created_at,
    ])

    return Message(
        id=msg_id,
        sender=sender,
        receiver=receiver,
        type=type,
        text=text,
        media_url=media_url,
        created_at=created_at,
    )


@app.get("/messages/history", response_model=List[Message])
async def get_history(user1: str, user2: str, limit: int = 50):
    try:
        ws = messages_sheet()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sheets error: {e}")

    rows = ws.get_all_records()
    conv: List[Message] = []
    for r in rows:
        s = str(r.get("sender"))
        rv = str(r.get("receiver"))
        if {s, rv} == {user1, user2}:
            conv.append(
                Message(
                    id=str(r.get("id")),
                    sender=s,
                    receiver=rv,
                    type=r.get("type"),
                    text=r.get("text") or None,
                    media_url=r.get("media_url") or None,
                    created_at=r.get("created_at"),
                )
            )
    # Sort by timestamp
    conv.sort(key=lambda m: m.created_at)
    return conv[-limit:]
