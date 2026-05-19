"""
How To Pick Up Flakes - Chatroom Server
Single-file websocket server backed by SQLite.

Run:
    pip install -r requirements.txt
    python main.py
"""

import asyncio
import base64
import copy
import json
import math
import mimetypes
import os
import random
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from http import HTTPStatus

import aiosqlite
import bcrypt
from websockets.asyncio.server import serve
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Response

DB_PATH = "chatroom.db"
IMAGES_DIR = "chatroom_uploads"
HOST = "0.0.0.0"
PORT = 8765
HISTORY_PAGE_SIZE = 50
MAX_MESSAGE_LEN = 2000
MAX_USERNAME_LEN = 32
MIN_USERNAME_LEN = 2
MIN_PASSWORD_LEN = 4

MAX_IMAGE_BYTES = 8 * 1024 * 1024          # 8 MB per image
MAX_IMAGES_PER_MESSAGE = 5
MAX_WS_PAYLOAD = 50 * 1024 * 1024          # 50 MB, fits multi-image uploads
ALLOWED_IMAGE_MIMES = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/gif": "gif",
    "image/webp": "webp",
}
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

connections = {}      # websocket -> {"username": str, "role": str}
admin_sockets = set() # websockets that belong to admin users
db_lock = asyncio.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def init_db() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0,
                images TEXT NOT NULL DEFAULT '[]',
                metadata TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        async with db.execute("PRAGMA table_info(messages)") as cur:
            msg_cols = [row[1] for row in await cur.fetchall()]
        if "deleted" not in msg_cols:
            await db.execute("ALTER TABLE messages ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0")
        if "images" not in msg_cols:
            await db.execute("ALTER TABLE messages ADD COLUMN images TEXT NOT NULL DEFAULT '[]'")
        if "metadata" not in msg_cols:
            await db.execute("ALTER TABLE messages ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")
        if "reply_to" not in msg_cols:
            await db.execute("ALTER TABLE messages ADD COLUMN reply_to INTEGER")
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS reactions (
                message_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                emoji TEXT NOT NULL DEFAULT '❤️',
                PRIMARY KEY (message_id, username, emoji),
                FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
            )
            """
        )
        async with db.execute("PRAGMA table_info(reactions)") as cur:
            cols = [row[1] for row in await cur.fetchall()]
        if "emoji" not in cols:
            await db.execute("ALTER TABLE reactions RENAME TO reactions_old")
            await db.execute(
                """
                CREATE TABLE reactions (
                    message_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    emoji TEXT NOT NULL DEFAULT '❤️',
                    PRIMARY KEY (message_id, username, emoji),
                    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
                )
                """
            )
            await db.execute(
                "INSERT INTO reactions (message_id, username, emoji) "
                "SELECT message_id, username, '❤️' FROM reactions_old"
            )
            await db.execute("DROP TABLE reactions_old")
        await db.commit()


async def db_fetchone(query: str, params=()):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(query, params) as cur:
            return await cur.fetchone()


async def db_fetchall(query: str, params=()):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(query, params) as cur:
            return await cur.fetchall()


async def db_execute(query: str, params=()):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(query, params)
        await db.commit()
        return cur.lastrowid


async def count_users() -> int:
    row = await db_fetchone("SELECT COUNT(*) FROM users")
    return row[0] if row else 0


async def get_user(username: str):
    row = await db_fetchone(
        "SELECT username, password_hash, role, status FROM users WHERE username = ?",
        (username,),
    )
    if not row:
        return None
    return {
        "username": row[0],
        "password_hash": row[1],
        "role": row[2],
        "status": row[3],
    }


async def create_user(username: str, password: str):
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    async with db_lock:
        total = await count_users()
        if total == 0:
            role, status = "admin", "approved"
        else:
            role, status = "user", "pending"
        try:
            await db_execute(
                "INSERT INTO users (username, password_hash, role, status, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (username, pw_hash, role, status, now_iso()),
            )
        except sqlite3.IntegrityError:
            return None
    return {"username": username, "role": role, "status": status}


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


async def get_reactions(message_id: int):
    """Return reactions grouped by emoji, preserving first-reactor ordering."""
    rows = await db_fetchall(
        "SELECT emoji, username FROM reactions WHERE message_id = ? "
        "ORDER BY rowid ASC",
        (message_id,),
    )
    grouped: dict[str, list[str]] = {}
    for emoji, username in rows:
        grouped.setdefault(emoji, []).append(username)
    return grouped


async def get_reactions_bulk(message_ids):
    if not message_ids:
        return {}
    placeholders = ",".join("?" for _ in message_ids)
    rows = await db_fetchall(
        f"SELECT message_id, emoji, username FROM reactions "
        f"WHERE message_id IN ({placeholders}) ORDER BY rowid ASC",
        tuple(message_ids),
    )
    out: dict[int, dict[str, list[str]]] = {mid: {} for mid in message_ids}
    for mid, emoji, username in rows:
        out.setdefault(mid, {}).setdefault(emoji, []).append(username)
    return out


REPLY_PREVIEW_LEN = 120


def _build_reply_preview(row):
    """row: (id, username, content, deleted, images_json) of the parent message."""
    pid, pusername, pcontent, pdeleted, pimages_json = row
    is_deleted = bool(pdeleted)
    try:
        pimages = json.loads(pimages_json) if pimages_json else []
        if not isinstance(pimages, list):
            pimages = []
    except json.JSONDecodeError:
        pimages = []
    snippet = "" if is_deleted else (pcontent or "")
    if len(snippet) > REPLY_PREVIEW_LEN:
        snippet = snippet[:REPLY_PREVIEW_LEN].rstrip() + "…"
    return {
        "id": pid,
        "username": pusername,
        "content": snippet,
        "deleted": is_deleted,
        "has_image": (not is_deleted) and bool(pimages),
    }


async def get_reply_previews_bulk(reply_ids):
    """Given a list of parent message ids, return {id: preview_dict}."""
    ids = [i for i in reply_ids if isinstance(i, int)]
    if not ids:
        return {}
    placeholders = ",".join("?" for _ in ids)
    rows = await db_fetchall(
        f"SELECT id, username, content, deleted, images FROM messages "
        f"WHERE id IN ({placeholders})",
        tuple(ids),
    )
    return {r[0]: _build_reply_preview(r) for r in rows}


def _serialize_message(row, reactions, reply_preview=None):
    mid, username, content, created_at, deleted, images_json, metadata_json, reply_to = row
    is_deleted = bool(deleted)
    try:
        images = json.loads(images_json) if images_json else []
        if not isinstance(images, list):
            images = []
    except json.JSONDecodeError:
        images = []
    try:
        metadata = json.loads(metadata_json) if metadata_json else {}
        if not isinstance(metadata, dict):
            metadata = {}
    except json.JSONDecodeError:
        metadata = {}
    return {
        "id": mid,
        "username": username,
        "content": "" if is_deleted else content,
        "created_at": created_at,
        "reactions": {} if is_deleted else reactions,
        "deleted": is_deleted,
        "images": [] if is_deleted else images,
        "metadata": {} if is_deleted else metadata,
        "reply_to": reply_to,
        "reply_preview": reply_preview,
    }


async def get_messages_page(before_id=None, limit=HISTORY_PAGE_SIZE):
    if before_id is None:
        rows = await db_fetchall(
            "SELECT id, username, content, created_at, deleted, images, metadata, reply_to "
            "FROM messages ORDER BY id DESC LIMIT ?",
            (limit + 1,),
        )
    else:
        rows = await db_fetchall(
            "SELECT id, username, content, created_at, deleted, images, metadata, reply_to "
            "FROM messages WHERE id < ? ORDER BY id DESC LIMIT ?",
            (before_id, limit + 1),
        )
    has_more = len(rows) > limit
    rows = rows[:limit]
    ids = [r[0] for r in rows]
    rx = await get_reactions_bulk(ids)
    reply_ids = [r[7] for r in rows if r[7] is not None]
    rp = await get_reply_previews_bulk(reply_ids)
    msgs = [
        _serialize_message(r, rx.get(r[0], {}), rp.get(r[7]) if r[7] is not None else None)
        for r in rows
    ]
    msgs.reverse()
    return msgs, has_more


async def insert_message(username: str, content: str, images=None, metadata=None, reply_to=None):
    created = now_iso()
    images = images or []
    metadata = metadata or {}
    mid = await db_execute(
        "INSERT INTO messages (username, content, created_at, images, metadata, reply_to) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (username, content, created, json.dumps(images), json.dumps(metadata), reply_to),
    )
    reply_preview = None
    if reply_to is not None:
        previews = await get_reply_previews_bulk([reply_to])
        reply_preview = previews.get(reply_to)
    return {
        "id": mid,
        "username": username,
        "content": content,
        "created_at": created,
        "reactions": {},
        "deleted": False,
        "images": images,
        "metadata": metadata,
        "reply_to": reply_to,
        "reply_preview": reply_preview,
    }


async def update_message_metadata(message_id: int, metadata: dict, content: str | None = None):
    """Update the metadata (and optionally content) of an existing message, broadcasting."""
    if content is None:
        await db_execute(
            "UPDATE messages SET metadata = ? WHERE id = ?",
            (json.dumps(metadata), message_id),
        )
    else:
        await db_execute(
            "UPDATE messages SET metadata = ?, content = ? WHERE id = ?",
            (json.dumps(metadata), content, message_id),
        )
    payload = {"type": "message_updated", "message_id": message_id, "metadata": metadata}
    if content is not None:
        payload["content"] = content
    await broadcast(payload)


async def delete_message(message_id: int, requester: str, is_admin: bool):
    """Return ('ok', author_username) on success, or ('not_found',) / ('forbidden',)."""
    async with db_lock:
        row = await db_fetchone(
            "SELECT username, deleted, images FROM messages WHERE id = ?",
            (message_id,),
        )
        if not row:
            return ("not_found",)
        author, already_deleted, images_json = row[0], bool(row[1]), row[2]
        if already_deleted:
            return ("ok", author)
        if author != requester and not is_admin:
            return ("forbidden",)
        await db_execute(
            "UPDATE messages SET deleted = 1, content = '', images = '[]', metadata = '{}' WHERE id = ?",
            (message_id,),
        )
        await db_execute(
            "DELETE FROM reactions WHERE message_id = ?", (message_id,)
        )
    try:
        urls = json.loads(images_json) if images_json else []
        for url in urls:
            if isinstance(url, str) and url.startswith("/uploads/"):
                fname = url[len("/uploads/"):]
                if SAFE_FILENAME_RE.fullmatch(fname):
                    full = os.path.join(IMAGES_DIR, fname)
                    if os.path.isfile(full):
                        os.remove(full)
    except Exception:
        pass
    return ("ok", author)


def _valid_emoji(value) -> bool:
    if not isinstance(value, str):
        return False
    s = value.strip()
    if not s or len(s) > 32:
        return False
    return True


async def toggle_reaction(message_id: int, username: str, emoji: str):
    async with db_lock:
        msg = await db_fetchone(
            "SELECT 1 FROM messages WHERE id = ?", (message_id,)
        )
        if not msg:
            return None
        exists = await db_fetchone(
            "SELECT 1 FROM reactions WHERE message_id = ? AND username = ? AND emoji = ?",
            (message_id, username, emoji),
        )
        if exists:
            await db_execute(
                "DELETE FROM reactions WHERE message_id = ? AND username = ? AND emoji = ?",
                (message_id, username, emoji),
            )
        else:
            await db_execute(
                "INSERT INTO reactions (message_id, username, emoji) VALUES (?, ?, ?)",
                (message_id, username, emoji),
            )
    return await get_reactions(message_id)


async def get_pending_users():
    rows = await db_fetchall(
        "SELECT username, created_at FROM users WHERE status = 'pending' "
        "ORDER BY created_at ASC"
    )
    return [{"username": r[0], "created_at": r[1]} for r in rows]


async def set_user_status(username: str, status: str) -> None:
    await db_execute(
        "UPDATE users SET status = ? WHERE username = ? AND status = 'pending'",
        (status, username),
    )


async def safe_send(ws, payload) -> bool:
    try:
        await ws.send(json.dumps(payload))
        return True
    except Exception:
        return False


async def broadcast(payload, exclude=None) -> None:
    data = json.dumps(payload)
    dead = []
    for ws in list(connections.keys()):
        if ws is exclude:
            continue
        try:
            await ws.send(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        connections.pop(ws, None)
        admin_sockets.discard(ws)


async def notify_admins(payload) -> None:
    data = json.dumps(payload)
    for ws in list(admin_sockets):
        try:
            await ws.send(data)
        except Exception:
            admin_sockets.discard(ws)


def online_user_list():
    return sorted({c["username"] for c in connections.values()})


async def push_pending_to_admins() -> None:
    pending = await get_pending_users()
    await notify_admins({"type": "pending_users", "users": pending})


async def handle_register(ws, data) -> None:
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if len(username) < MIN_USERNAME_LEN or len(username) > MAX_USERNAME_LEN:
        await safe_send(ws, {
            "type": "register_result",
            "success": False,
            "message": f"Username must be {MIN_USERNAME_LEN}-{MAX_USERNAME_LEN} characters",
        })
        return
    if not all(c.isalnum() or c in "_-." for c in username):
        await safe_send(ws, {
            "type": "register_result",
            "success": False,
            "message": "Username may only contain letters, digits, '_', '-', '.'",
        })
        return
    if len(password) < MIN_PASSWORD_LEN:
        await safe_send(ws, {
            "type": "register_result",
            "success": False,
            "message": f"Password must be at least {MIN_PASSWORD_LEN} characters",
        })
        return
    if await get_user(username):
        await safe_send(ws, {
            "type": "register_result",
            "success": False,
            "message": "Username already taken",
        })
        return
    user = await create_user(username, password)
    if not user:
        await safe_send(ws, {
            "type": "register_result",
            "success": False,
            "message": "Could not create user",
        })
        return
    if user["status"] == "approved":
        await safe_send(ws, {
            "type": "register_result",
            "success": True,
            "auto_approved": True,
            "role": user["role"],
            "message": "Account created. You are the admin.",
        })
    else:
        await safe_send(ws, {
            "type": "register_result",
            "success": True,
            "auto_approved": False,
            "role": user["role"],
            "message": "Account created. Awaiting admin approval.",
        })
        await push_pending_to_admins()


async def handle_login(ws, data) -> None:
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    user = await get_user(username)
    if not user or not verify_password(password, user["password_hash"]):
        await safe_send(ws, {
            "type": "login_result",
            "success": False,
            "message": "Invalid username or password",
        })
        return
    if user["status"] == "pending":
        await safe_send(ws, {
            "type": "login_result",
            "success": False,
            "status": "pending",
            "message": "Account pending admin approval",
        })
        return
    if user["status"] == "denied":
        await safe_send(ws, {
            "type": "login_result",
            "success": False,
            "status": "denied",
            "message": "Account denied",
        })
        return

    for existing_ws, info in list(connections.items()):
        if info["username"] == username:
            try:
                await existing_ws.close(code=4000, reason="Logged in elsewhere")
            except Exception:
                pass
            connections.pop(existing_ws, None)
            admin_sockets.discard(existing_ws)

    connections[ws] = {"username": username, "role": user["role"]}
    if user["role"] == "admin":
        admin_sockets.add(ws)

    online = online_user_list()
    await safe_send(ws, {
        "type": "login_result",
        "success": True,
        "username": username,
        "role": user["role"],
        "online_users": online,
    })
    msgs, has_more = await get_messages_page()
    await safe_send(ws, {
        "type": "hydrate",
        "messages": msgs,
        "has_more": has_more,
    })
    if user["role"] == "admin":
        pending = await get_pending_users()
        await safe_send(ws, {"type": "pending_users", "users": pending})

    await broadcast(
        {
            "type": "user_joined",
            "username": username,
            "online_users": online,
        },
        exclude=ws,
    )


def _decode_and_save_image(raw_b64: str, mime: str):
    """Decode a base64 image payload, save it to disk, return the URL path."""
    if not isinstance(raw_b64, str) or not raw_b64:
        return None
    if "," in raw_b64 and raw_b64.lstrip().startswith("data:"):
        raw_b64 = raw_b64.split(",", 1)[1]
    mime = (mime or "").lower().strip()
    ext = ALLOWED_IMAGE_MIMES.get(mime)
    if not ext:
        return None
    try:
        blob = base64.b64decode(raw_b64, validate=True)
    except Exception:
        return None
    if not blob or len(blob) > MAX_IMAGE_BYTES:
        return None
    fname = f"{uuid.uuid4().hex}.{ext}"
    full = os.path.join(IMAGES_DIR, fname)
    try:
        with open(full, "wb") as f:
            f.write(blob)
    except OSError:
        return None
    return f"/uploads/{fname}"


async def handle_send_message(ws, data) -> None:
    info = connections.get(ws)
    if not info:
        await safe_send(ws, {"type": "error", "message": "Not authenticated"})
        return
    content = (data.get("content") or "").strip()
    if len(content) > MAX_MESSAGE_LEN:
        content = content[:MAX_MESSAGE_LEN]

    raw_images = data.get("images") or []
    if not isinstance(raw_images, list):
        raw_images = []
    raw_images = raw_images[:MAX_IMAGES_PER_MESSAGE]

    saved_urls = []
    for item in raw_images:
        if not isinstance(item, dict):
            continue
        url = await asyncio.get_event_loop().run_in_executor(
            None, _decode_and_save_image, item.get("data_b64"), item.get("mime")
        )
        if url:
            saved_urls.append(url)

    if not content and not saved_urls:
        return

    reply_to = data.get("reply_to")
    try:
        reply_to = int(reply_to) if reply_to is not None else None
    except (TypeError, ValueError):
        reply_to = None
    if reply_to is not None:
        parent = await db_fetchone(
            "SELECT 1 FROM messages WHERE id = ? AND deleted = 0", (reply_to,)
        )
        if not parent:
            reply_to = None

    msg = await insert_message(info["username"], content, saved_urls, reply_to=reply_to)
    await broadcast({"type": "message", "message": msg})


async def handle_load_history(ws, data) -> None:
    if ws not in connections:
        return
    before_id = data.get("before_id")
    try:
        before_id = int(before_id) if before_id is not None else None
    except (TypeError, ValueError):
        return
    msgs, has_more = await get_messages_page(before_id=before_id)
    await safe_send(
        ws,
        {
            "type": "load_history_result",
            "messages": msgs,
            "has_more": has_more,
            "before_id": before_id,
        },
    )


async def handle_react(ws, data) -> None:
    info = connections.get(ws)
    if not info:
        return
    try:
        message_id = int(data.get("message_id"))
    except (TypeError, ValueError):
        return
    emoji = data.get("emoji") or "❤️"
    if not _valid_emoji(emoji):
        return
    emoji = emoji.strip()
    reactions = await toggle_reaction(message_id, info["username"], emoji)
    if reactions is None:
        return
    await broadcast(
        {
            "type": "reaction_update",
            "message_id": message_id,
            "reactions": reactions,
        }
    )


async def handle_delete_message(ws, data) -> None:
    info = connections.get(ws)
    if not info:
        await safe_send(ws, {"type": "error", "message": "Not authenticated"})
        return
    try:
        message_id = int(data.get("message_id"))
    except (TypeError, ValueError):
        return
    result = await delete_message(message_id, info["username"], info["role"] == "admin")
    if result[0] == "not_found":
        return
    if result[0] == "forbidden":
        await safe_send(ws, {"type": "error", "message": "You can only delete your own messages"})
        return
    await broadcast(
        {
            "type": "message_deleted",
            "message_id": message_id,
            "by": info["username"],
        }
    )


async def handle_admin_action(ws, data, action: str) -> None:
    info = connections.get(ws)
    if not info or info["role"] != "admin":
        await safe_send(ws, {"type": "error", "message": "Admin only"})
        return
    username = (data.get("username") or "").strip()
    user = await get_user(username)
    if not user or user["status"] != "pending":
        await push_pending_to_admins()
        return
    new_status = "approved" if action == "approve" else "denied"
    await set_user_status(username, new_status)
    await push_pending_to_admins()


# ===========================================================================
# GAMES (Word Hunt, 8-Ball, Chess, Wordle, UNO)
# ===========================================================================

GAME_TYPES = {"word_hunt", "eight_ball", "chess", "wordle", "uno"}
games: dict[str, "Game"] = {}
game_invites: dict[str, dict] = {}
user_games: dict[str, set[str]] = {}  # username -> set of game_ids they're in


def _ws_for_user(username: str):
    for ws, info in connections.items():
        if info["username"] == username:
            return ws
    return None


async def _send_to_user(username: str, payload) -> bool:
    ws = _ws_for_user(username)
    if not ws:
        return False
    return await safe_send(ws, payload)


async def _send_to_players(player_list, payload):
    for u in player_list:
        await _send_to_user(u, payload)


def _register_user_game(username: str, game_id: str):
    user_games.setdefault(username, set()).add(game_id)


def _unregister_user_game(username: str, game_id: str):
    s = user_games.get(username)
    if s:
        s.discard(game_id)
        if not s:
            user_games.pop(username, None)


# ---------------------------------------------------------------------------
# Word list loading (for Word Hunt + Wordle)
# ---------------------------------------------------------------------------
WORD_DICT: set[str] = set()                # all valid words for Word Hunt
WORDLE_ANSWERS: set[str] = set()           # 5-letter answers allowed

_FALLBACK_WORDS = (
    "able about above accept access account across action active actor add address adult after again against age "
    "agency agent ago agree air album all allow almost alone along already also always among amount and animal "
    "another answer any anyone anything appear apple apply area argue arm army around arrive art article ask away "
    "baby back bad ball band bank base battle beach bear beat beautiful because become bed before begin behind being "
    "believe below benefit best better between beyond big bill bird bit black blood blue board body book born both "
    "box boy break bring brother brown build building business buy call camera camp can cancer candidate cannot "
    "capital car card care career carry case catch cause century chair chance change character charge check chief "
    "child choice choose church city civil claim class clear close coach cold collect college come common community "
    "company computer concern condition conference consider continue control cost could country couple course court "
    "cover create cross cup cut data daughter day deal death decade decide decision deep defense degree democratic "
    "describe design despite detail determine develop dies different difficult dinner direction director discover "
    "discuss dog door down draw dream drive drop drug during each early east easy eat economic economy edge education "
    "effect effort eight either election else employee end energy enjoy enough enter entire environment especially "
    "establish even evening event ever every everybody everyone everything evidence exactly example exist expect "
    "experience explain eye face fact factor fail fall family far father fear federal feel few field fight figure "
    "final finally find fine finger finish fire firm first fish five floor fly focus follow food foot for force "
    "foreign forget form former forward four free friend from front full fund future game garden gas general get "
    "girl give glass goal good government great green ground group grow guess guy half hand hang happen happy hard "
    "have head health hear heart heat heavy help her here high him himself his hit hold home hope hospital hot hotel "
    "hour house however huge human hundred husband idea identify image imagine impact important improve include "
    "income indeed indicate individual industry information inside instead institution interest interview into "
    "investment involve issue item itself job join keep key kid kill kind kitchen know knowledge land language large "
    "last late laugh law lawyer lay lead leader learn least leave leg legal less let letter level lie life light "
    "like likely line list listen little live local long look lose loss lot love low machine magazine main maintain "
    "major majority make manage management manager many market marriage material matter may maybe mean measure media "
    "medical meet meeting member memory mention message method middle might military million mind minute miss model "
    "modern moment money month more morning most mother mouth move movement movie much music must myself name nation "
    "national natural nature near nearly necessary need network never new news newspaper next nice night nine nor "
    "north not note nothing notice now number occur off offer office officer often oil old once one only onto open "
    "operation opportunity option order organization other our out outside over own owner page pain painting paper "
    "parent part particular particularly partner party pass past patient pattern pay peace people per perform perhaps "
    "period person personal phone physical pick picture piece place plan plant play player point police policy "
    "political politics poor popular population position positive possible power practice prepare present president "
    "pretty prevent price private probably problem process produce product professional program project property "
    "protect prove provide public pull purpose push put quality question quickly quite race radio raise range rate "
    "rather read ready real reality realize really reason receive recent recognize record red reduce reflect region "
    "relate relationship religious remain remember remove report represent require research resource respond "
    "response responsibility rest result return reveal rich right rise risk road rock role room rule run safe same "
    "save say scene school science scientist score sea season seat second section security see seek seem sell send "
    "senior sense series serious serve service set seven several shake share shoot short should shoulder show side "
    "sign significant similar simple simply since sing sister sit site situation six size skill skin small smile "
    "social society soldier some somebody someone something sometimes son song soon sort sound source south space "
    "speak special specific speech spend sport spring staff stage stand standard star start state statement station "
    "stay step still stock stop store story strategy street strong structure student study stuff style subject "
    "success successful such suddenly suffer suggest summer support sure surface system table take talk task tax "
    "teach teacher team technology television tell ten tend term test than thank that the their them themselves then "
    "theory there these they thing think third this those though thought thousand threat three through throughout "
    "throw thus time today together tonight too top total tough toward town trade traditional training travel "
    "treat treatment tree trial trip trouble true truth try turn type under understand union unit until upon use "
    "usually value various very victim view violence visit voice vote wait walk wall want war watch water way week "
    "weight well west western what whatever when where whether which while white who whole whom whose why wide wife "
    "will win wind window wish with within without woman wonder word work worker world worry would write writer "
    "wrong yard yeah year yes yet young your yourself "
    "ace acre also area lake bake make take care fare gate hate late mate mile pile rule cube tube cute mute "
    "ample apple cable fable label maple noble table able battle little bottle cattle settle "
    "barn born corn darn earn fern horn iron lawn morn warn worn yarn "
    "best dust east fast fist gust hast jest just last lest list mast must nest past pest post rest test vast "
    "rage page sage cage wage age beg leg log dog cog fog hog jog log mug bug dug hug jug pug rug tug "
    "yam ban can dan fan man pan ran tan van wan "
    "dare bare care fare hare mare pare rare ware "
    "side hide ride tide wide bide fide "
    "bone cone done gone hone lone none tone zone "
    "alarm armor archer artist axe ant arm "
    "ear eat ego emu eel egg end era eye "
    "icy ice ill imp ink ion ire "
    "ode odd off oil old one orb our out own "
    "use urn ump ugh "
    "yawn yeah year yarn yard yard yet yes yew yon you yum "
    "zen zip zoo zap zed "
    "rat tar bat tab car arc cat act tea eat era ear are ate "
    "bear deer fox owl ape bee cat dog elk fly hen pig rat sow yak "
    "love hope wish life heart smile dance peace dream play stars moon sun rain wind cloud fire ice snow leaf seed"
).split()


EXTERNAL_DICT_URL = "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
EXTERNAL_DICT_CACHE = "word_dictionary.txt"


def _ingest_words(text: str, target: set[str]):
    for line in text.splitlines():
        w = line.strip().lower()
        if w.isalpha() and 3 <= len(w) <= 16:
            target.add(w)


def _load_word_dict():
    """Populate WORD_DICT — prefer external dwyl/english-words (~370k entries)
    cached locally; fall back to system dictionaries then a small built-in list.
    """
    words: set[str] = set()

    if os.path.isfile(EXTERNAL_DICT_CACHE):
        try:
            with open(EXTERNAL_DICT_CACHE, "r", encoding="utf-8", errors="ignore") as f:
                _ingest_words(f.read(), words)
        except OSError:
            pass

    if not words:
        try:
            import urllib.request
            print(f"[chatroom] Fetching word dictionary from {EXTERNAL_DICT_URL} …")
            req = urllib.request.Request(EXTERNAL_DICT_URL, headers={"User-Agent": "chatroom/1.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = resp.read().decode("utf-8", errors="ignore")
            try:
                with open(EXTERNAL_DICT_CACHE, "w", encoding="utf-8") as f:
                    f.write(data)
            except OSError:
                pass
            _ingest_words(data, words)
        except Exception as e:
            print(f"[chatroom] External dictionary fetch failed ({e}); falling back.")

    if not words:
        for p in ("/usr/share/dict/words",
                  "/usr/share/dict/american-english",
                  "/usr/share/dict/british-english"):
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        _ingest_words(f.read(), words)
                    if words:
                        break
                except OSError:
                    pass

    if not words:
        _ingest_words(" ".join(_FALLBACK_WORDS), words)

    WORD_DICT.update(words)
    for w in WORD_DICT:
        if len(w) == 5:
            WORDLE_ANSWERS.add(w)


# ---------------------------------------------------------------------------
# Game base class
# ---------------------------------------------------------------------------
class Game:
    type_id = ""
    min_players = 2
    max_players = 2
    display_name = ""

    def __init__(self, game_id: str, players: list[str]):
        self.id = game_id
        self.players = list(players)
        self.created_at = now_iso()
        self.ended = False
        self.winner: str | None = None
        self.result_text: str = ""
        self.chat_message_id: int | None = None  # for open challenges

    def is_player(self, username: str) -> bool:
        return username in self.players

    def public_state(self, viewer: str | None = None) -> dict:
        return {
            "id": self.id,
            "type": self.type_id,
            "players": list(self.players),
            "ended": self.ended,
            "winner": self.winner,
            "result_text": self.result_text,
        }

    async def handle_action(self, player: str, action: dict) -> None:
        raise NotImplementedError

    async def broadcast_state(self):
        for p in self.players:
            await _send_to_user(p, {
                "type": "game_state",
                "game_id": self.id,
                "state": self.public_state(p),
            })

    async def end_game(self, winner: str | None, result_text: str):
        self.ended = True
        self.winner = winner
        self.result_text = result_text
        for p in self.players:
            await _send_to_user(p, {
                "type": "game_ended",
                "game_id": self.id,
                "state": self.public_state(p),
            })
        for p in self.players:
            _unregister_user_game(p, self.id)
        games.pop(self.id, None)
        if self.chat_message_id is not None:
            meta = {
                "type": "game_open_challenge",
                "game": self.type_id,
                "status": "finished",
                "players": list(self.players),
                "winner": winner,
                "result_text": result_text,
            }
            try:
                await update_message_metadata(self.chat_message_id, meta)
            except Exception:
                pass

    async def player_left(self, username: str):
        if self.ended or username not in self.players:
            return
        remaining = [p for p in self.players if p != username]
        winner = remaining[0] if len(remaining) == 1 else None
        await self.end_game(winner, f"{username} left the game")


# ---------------------------------------------------------------------------
# WORDLE CHALLENGE
# ---------------------------------------------------------------------------
class WordleGame(Game):
    type_id = "wordle"
    min_players = 2
    max_players = 2
    display_name = "Wordle Challenge"
    MAX_GUESSES = 6

    def __init__(self, game_id, players):
        super().__init__(game_id, players)
        self.secret: dict[str, str | None] = {p: None for p in players}
        self.guesses: dict[str, list[str]] = {p: [] for p in players}
        self.solved: dict[str, bool] = {p: False for p in players}
        self.solved_in: dict[str, int | None] = {p: None for p in players}
        self.phase = "setup"  # setup -> playing -> ended

    def public_state(self, viewer=None):
        base = super().public_state(viewer)
        base["phase"] = self.phase
        base["max_guesses"] = self.MAX_GUESSES
        # mask secrets
        secrets_set = {p: bool(self.secret[p]) for p in self.players}
        base["secrets_set"] = secrets_set
        # each player sees their own guess results for opponent's word
        # and during playing, opponent's color pattern only (not letters)
        my_guesses = []
        opp_guesses = []
        if viewer in self.players:
            opponent = next((p for p in self.players if p != viewer), None)
            opp_secret = self.secret.get(opponent)
            for g in self.guesses[viewer]:
                row = {"word": g, "score": _wordle_score(g, opp_secret) if opp_secret else None}
                my_guesses.append(row)
            if opponent:
                my_secret = self.secret.get(viewer)
                for g in self.guesses[opponent]:
                    row = {"score": _wordle_score(g, my_secret) if my_secret else None}
                    if self.phase == "ended":
                        row["word"] = g
                    opp_guesses.append(row)
        base["my_guesses"] = my_guesses
        base["opp_guesses"] = opp_guesses
        base["my_solved"] = self.solved.get(viewer, False) if viewer else False
        base["opp_solved"] = False
        if viewer:
            opp = next((p for p in self.players if p != viewer), None)
            if opp:
                base["opp_solved"] = self.solved.get(opp, False)
                base["opp_name"] = opp
        if self.phase == "ended":
            base["secrets"] = {p: self.secret.get(p) for p in self.players}
        return base

    async def handle_action(self, player, action):
        kind = action.get("kind")
        if self.ended:
            return
        if kind == "set_secret" and self.phase == "setup":
            word = (action.get("word") or "").strip().lower()
            if len(word) != 5 or not word.isalpha():
                await _send_to_user(player, {"type": "game_error", "message": "Word must be 5 letters"})
                return
            self.secret[player] = word
            if all(self.secret[p] for p in self.players):
                self.phase = "playing"
            await self.broadcast_state()
        elif kind == "guess" and self.phase == "playing":
            if self.solved[player] or len(self.guesses[player]) >= self.MAX_GUESSES:
                return
            guess = (action.get("word") or "").strip().lower()
            if len(guess) != 5 or not guess.isalpha():
                await _send_to_user(player, {"type": "game_error", "message": "Guess must be 5 letters"})
                return
            self.guesses[player].append(guess)
            opponent = next(p for p in self.players if p != player)
            if guess == self.secret[opponent]:
                self.solved[player] = True
                self.solved_in[player] = len(self.guesses[player])
            await self.broadcast_state()
            # End conditions: both done, or 6 used by both
            done = []
            for p in self.players:
                if self.solved[p] or len(self.guesses[p]) >= self.MAX_GUESSES:
                    done.append(True)
                else:
                    done.append(False)
            if all(done):
                await self._finish()

    async def _finish(self):
        p1, p2 = self.players
        # winner: fewest guesses (and solved), else whoever solved if other didn't, else draw
        s1 = self.solved_in[p1] if self.solved[p1] else None
        s2 = self.solved_in[p2] if self.solved[p2] else None
        if s1 is not None and s2 is None:
            winner = p1
            text = f"{p1} guessed the word in {s1}"
        elif s2 is not None and s1 is None:
            winner = p2
            text = f"{p2} guessed the word in {s2}"
        elif s1 is not None and s2 is not None:
            if s1 < s2:
                winner = p1
                text = f"{p1} won ({s1} vs {s2} guesses)"
            elif s2 < s1:
                winner = p2
                text = f"{p2} won ({s2} vs {s1} guesses)"
            else:
                winner = None
                text = f"Both solved in {s1} guesses — draw!"
        else:
            winner = None
            text = "Neither player solved it"
        self.phase = "ended"
        await self.end_game(winner, text)


def _wordle_score(guess: str, secret: str) -> list[str]:
    """Return per-letter scores: 'g' green, 'y' yellow, 'b' black."""
    result = ["b"] * 5
    secret_remaining = list(secret)
    # greens
    for i in range(5):
        if guess[i] == secret[i]:
            result[i] = "g"
            secret_remaining[i] = None
    # yellows
    for i in range(5):
        if result[i] == "g":
            continue
        if guess[i] in secret_remaining:
            result[i] = "y"
            secret_remaining[secret_remaining.index(guess[i])] = None
    return result


# ---------------------------------------------------------------------------
# WORD HUNT (Boggle-style)
# ---------------------------------------------------------------------------
BOGGLE_DICE = [
    "AAEEGN","ELRTTY","AOOTTW","ABBJOO","EHRTVW","CIMOTU","DISTTY","EIOSST",
    "DELRVY","ACHOPS","HIMNQU","EEINSU","EEGHNW","AFFKPS","HLNNRZ","DEILRX",
]

class WordHuntGame(Game):
    type_id = "word_hunt"
    min_players = 2
    max_players = 2
    display_name = "Word Hunt"
    DURATION_S = 80

    SCORES = {3: 100, 4: 400, 5: 800, 6: 1400, 7: 1800, 8: 2200}

    def __init__(self, game_id, players):
        super().__init__(game_id, players)
        self.board = self._make_board()
        self.start_time = time.time()
        self.duration = self.DURATION_S
        self.scores: dict[str, int] = {p: 0 for p in players}
        self.words: dict[str, list[str]] = {p: [] for p in players}
        self.timer_task: asyncio.Task | None = None

    def _make_board(self):
        dice = random.sample(BOGGLE_DICE, len(BOGGLE_DICE))
        return [d[random.randrange(len(d))] for d in dice]  # list of 16 letters

    def _score_for(self, word):
        L = len(word)
        if L >= 8:
            return self.SCORES[8]
        return self.SCORES.get(L, 0)

    def public_state(self, viewer=None):
        base = super().public_state(viewer)
        base["board"] = self.board
        base["duration"] = self.duration
        base["elapsed"] = max(0, time.time() - self.start_time)
        base["scores"] = dict(self.scores)
        if self.ended:
            # reveal both players' words
            base["all_words"] = {p: list(self.words[p]) for p in self.players}
        else:
            base["my_words"] = list(self.words.get(viewer, [])) if viewer else []
        return base

    async def start_timer(self):
        async def _t():
            try:
                await asyncio.sleep(self.duration)
                if not self.ended:
                    await self._finish_round()
            except asyncio.CancelledError:
                pass
        self.timer_task = asyncio.create_task(_t())

    async def handle_action(self, player, action):
        if self.ended:
            return
        kind = action.get("kind")
        if kind == "submit":
            word = (action.get("word") or "").strip().lower()
            if not (3 <= len(word) <= 16) or not word.isalpha():
                return
            if word in self.words[player]:
                await _send_to_user(player, {"type": "game_error", "message": f"Already used: {word}"})
                return
            if word not in WORD_DICT:
                await _send_to_user(player, {"type": "game_error", "message": f"Not a word: {word}"})
                return
            if not self._can_trace(word):
                await _send_to_user(player, {"type": "game_error", "message": f"Can't trace: {word}"})
                return
            self.words[player].append(word)
            self.scores[player] += self._score_for(word)
            await self.broadcast_state()

    def _can_trace(self, word):
        word = word.upper()
        # treat 'Q' as 'QU' for Boggle? Standard boggle uses 'Qu' tile. We use raw letters.
        for r in range(4):
            for c in range(4):
                if self.board[r * 4 + c] == word[0]:
                    if self._dfs(word, 1, r, c, {(r, c)}):
                        return True
        return False

    def _dfs(self, word, idx, r, c, visited):
        if idx == len(word):
            return True
        for dr in (-1, 0, 1):
            for dc in (-1, 0, 1):
                if dr == 0 and dc == 0:
                    continue
                nr, nc = r + dr, c + dc
                if 0 <= nr < 4 and 0 <= nc < 4 and (nr, nc) not in visited:
                    if self.board[nr * 4 + nc] == word[idx]:
                        if self._dfs(word, idx + 1, nr, nc, visited | {(nr, nc)}):
                            return True
        return False

    async def _finish_round(self):
        p1, p2 = self.players
        if self.scores[p1] > self.scores[p2]:
            winner = p1
        elif self.scores[p2] > self.scores[p1]:
            winner = p2
        else:
            winner = None
        text = f"Final score: {p1} {self.scores[p1]} – {p2} {self.scores[p2]}"
        if self.timer_task:
            self.timer_task.cancel()
        await self.end_game(winner, text)


# ---------------------------------------------------------------------------
# CHESS (with full legal move validation including castling, en-passant, promotion)
# ---------------------------------------------------------------------------
class ChessGame(Game):
    type_id = "chess"
    min_players = 2
    max_players = 2
    display_name = "Chess"

    def __init__(self, game_id, players):
        super().__init__(game_id, players)
        random.shuffle(self.players)  # randomize colors
        self.white = self.players[0]
        self.black = self.players[1]
        self.board = self._initial_board()
        self.turn = "w"
        self.history: list[dict] = []
        self.castling = {"K": True, "Q": True, "k": True, "q": True}
        self.en_passant: tuple[int, int] | None = None  # (row, col) of skipped square
        self.halfmove = 0  # for 50-move rule
        self.fullmove = 1
        self.last_move = None

    def _initial_board(self):
        back = ["R", "N", "B", "Q", "K", "B", "N", "R"]
        b = [["." for _ in range(8)] for _ in range(8)]
        b[0] = [p.lower() for p in back]
        b[1] = ["p"] * 8
        b[6] = ["P"] * 8
        b[7] = back
        return b

    def color_of(self, username):
        if username == self.white: return "w"
        if username == self.black: return "b"
        return None

    def public_state(self, viewer=None):
        base = super().public_state(viewer)
        base["white"] = self.white
        base["black"] = self.black
        base["board"] = [row[:] for row in self.board]
        base["turn"] = self.turn
        base["last_move"] = self.last_move
        base["in_check"] = self._in_check(self.turn)
        base["history"] = list(self.history[-20:])
        return base

    async def handle_action(self, player, action):
        if self.ended:
            return
        kind = action.get("kind")
        if kind != "move":
            return
        color = self.color_of(player)
        if color != self.turn:
            await _send_to_user(player, {"type": "game_error", "message": "Not your turn"})
            return
        try:
            fr, fc = int(action["from"][0]), int(action["from"][1])
            tr, tc = int(action["to"][0]), int(action["to"][1])
        except (KeyError, ValueError, TypeError):
            return
        promotion = (action.get("promotion") or "q").lower()
        if promotion not in ("q", "r", "b", "n"):
            promotion = "q"
        ok, err = self._try_move(fr, fc, tr, tc, promotion)
        if not ok:
            await _send_to_user(player, {"type": "game_error", "message": err or "Illegal move"})
            return
        # Check end conditions
        opp = "b" if self.turn == "w" else "w"
        self.turn = opp
        if self.turn == "w":
            self.fullmove += 1
        if not self._has_any_legal_move(self.turn):
            if self._in_check(self.turn):
                winner_color = "w" if self.turn == "b" else "b"
                winner = self.white if winner_color == "w" else self.black
                await self.broadcast_state()
                await self.end_game(winner, f"Checkmate — {winner} wins")
                return
            else:
                await self.broadcast_state()
                await self.end_game(None, "Stalemate — draw")
                return
        if self.halfmove >= 100:
            await self.broadcast_state()
            await self.end_game(None, "Draw by 50-move rule")
            return
        await self.broadcast_state()

    def _try_move(self, fr, fc, tr, tc, promotion):
        if not (0 <= fr < 8 and 0 <= fc < 8 and 0 <= tr < 8 and 0 <= tc < 8):
            return False, "Off board"
        piece = self.board[fr][fc]
        if piece == ".":
            return False, "Empty square"
        if self._piece_color(piece) != self.turn:
            return False, "Not your piece"
        legal = self._legal_moves_for(fr, fc)
        # legal is list of (tr, tc, special) where special is None|"K-castle"|"Q-castle"|"ep"|"promo"
        match = None
        for m in legal:
            if m[0] == tr and m[1] == tc:
                match = m
                break
        if not match:
            return False, "Illegal move"
        # Execute
        moved_piece = piece
        captured = self.board[tr][tc]
        special = match[2]

        # Reset en passant
        new_ep = None

        # Castling
        if special == "K-castle":
            self.board[fr][fc] = "."
            self.board[fr][fc + 2] = moved_piece
            self.board[fr][7] = "."
            self.board[fr][fc + 1] = "R" if self.turn == "w" else "r"
        elif special == "Q-castle":
            self.board[fr][fc] = "."
            self.board[fr][fc - 2] = moved_piece
            self.board[fr][0] = "."
            self.board[fr][fc - 1] = "R" if self.turn == "w" else "r"
        elif special == "ep":
            self.board[fr][fc] = "."
            self.board[tr][tc] = moved_piece
            cap_row = fr
            self.board[cap_row][tc] = "."
        else:
            self.board[fr][fc] = "."
            self.board[tr][tc] = moved_piece
            # Pawn double push: set en passant
            if moved_piece.lower() == "p" and abs(tr - fr) == 2:
                new_ep = ((fr + tr) // 2, fc)
            # Promotion
            if moved_piece.lower() == "p" and (tr == 0 or tr == 7):
                self.board[tr][tc] = promotion.upper() if self.turn == "w" else promotion.lower()

        # Update castling rights
        if moved_piece == "K":
            self.castling["K"] = False
            self.castling["Q"] = False
        elif moved_piece == "k":
            self.castling["k"] = False
            self.castling["q"] = False
        elif moved_piece == "R":
            if fr == 7 and fc == 0:
                self.castling["Q"] = False
            elif fr == 7 and fc == 7:
                self.castling["K"] = False
        elif moved_piece == "r":
            if fr == 0 and fc == 0:
                self.castling["q"] = False
            elif fr == 0 and fc == 7:
                self.castling["k"] = False
        # Rook captured?
        if tr == 7 and tc == 0:
            self.castling["Q"] = False
        if tr == 7 and tc == 7:
            self.castling["K"] = False
        if tr == 0 and tc == 0:
            self.castling["q"] = False
        if tr == 0 and tc == 7:
            self.castling["k"] = False

        self.en_passant = new_ep
        if moved_piece.lower() == "p" or captured != ".":
            self.halfmove = 0
        else:
            self.halfmove += 1
        self.last_move = {"from": [fr, fc], "to": [tr, tc], "piece": moved_piece, "captured": captured, "special": special}
        self.history.append(self.last_move)
        return True, None

    @staticmethod
    def _piece_color(p):
        if p == ".":
            return None
        return "w" if p.isupper() else "b"

    def _legal_moves_for(self, fr, fc):
        moves = self._pseudo_moves(self.board, fr, fc, self.castling, self.en_passant)
        legal = []
        for tr, tc, special in moves:
            saved_board = [row[:] for row in self.board]
            saved_castle = dict(self.castling)
            saved_ep = self.en_passant
            saved_hm = self.halfmove
            self._apply_pseudo(fr, fc, tr, tc, special)
            color = self._piece_color(saved_board[fr][fc])
            if not self._in_check(color):
                legal.append((tr, tc, special))
            # rollback
            self.board = saved_board
            self.castling = saved_castle
            self.en_passant = saved_ep
            self.halfmove = saved_hm
        return legal

    def _apply_pseudo(self, fr, fc, tr, tc, special):
        piece = self.board[fr][fc]
        if special == "K-castle":
            self.board[fr][fc] = "."
            self.board[fr][fc + 2] = piece
            rook = self.board[fr][7]
            self.board[fr][7] = "."
            self.board[fr][fc + 1] = rook
        elif special == "Q-castle":
            self.board[fr][fc] = "."
            self.board[fr][fc - 2] = piece
            rook = self.board[fr][0]
            self.board[fr][0] = "."
            self.board[fr][fc - 1] = rook
        elif special == "ep":
            self.board[fr][fc] = "."
            self.board[tr][tc] = piece
            self.board[fr][tc] = "."
        else:
            self.board[fr][fc] = "."
            self.board[tr][tc] = piece
            if piece.lower() == "p" and (tr == 0 or tr == 7):
                self.board[tr][tc] = "Q" if piece.isupper() else "q"

    def _pseudo_moves(self, board, fr, fc, castling, en_passant):
        piece = board[fr][fc]
        if piece == ".":
            return []
        color = "w" if piece.isupper() else "b"
        moves = []
        pt = piece.lower()

        def add(tr, tc, special=None):
            if 0 <= tr < 8 and 0 <= tc < 8:
                target = board[tr][tc]
                if target == "." or self._piece_color(target) != color:
                    moves.append((tr, tc, special))

        def ray(dr, dc):
            tr, tc = fr + dr, fc + dc
            while 0 <= tr < 8 and 0 <= tc < 8:
                tgt = board[tr][tc]
                if tgt == ".":
                    moves.append((tr, tc, None))
                else:
                    if self._piece_color(tgt) != color:
                        moves.append((tr, tc, None))
                    break
                tr += dr; tc += dc

        if pt == "p":
            dir_r = -1 if color == "w" else 1
            start_row = 6 if color == "w" else 1
            # forward
            if 0 <= fr + dir_r < 8 and board[fr + dir_r][fc] == ".":
                moves.append((fr + dir_r, fc, None))
                if fr == start_row and board[fr + 2 * dir_r][fc] == ".":
                    moves.append((fr + 2 * dir_r, fc, None))
            # captures
            for dc in (-1, 1):
                tr, tc = fr + dir_r, fc + dc
                if 0 <= tr < 8 and 0 <= tc < 8:
                    if board[tr][tc] != "." and self._piece_color(board[tr][tc]) != color:
                        moves.append((tr, tc, None))
                    elif en_passant and (tr, tc) == en_passant:
                        moves.append((tr, tc, "ep"))
        elif pt == "n":
            for dr, dc in ((-2,-1),(-2,1),(-1,-2),(-1,2),(1,-2),(1,2),(2,-1),(2,1)):
                add(fr+dr, fc+dc)
        elif pt == "b":
            for dr, dc in ((-1,-1),(-1,1),(1,-1),(1,1)): ray(dr, dc)
        elif pt == "r":
            for dr, dc in ((-1,0),(1,0),(0,-1),(0,1)): ray(dr, dc)
        elif pt == "q":
            for dr, dc in ((-1,-1),(-1,1),(1,-1),(1,1),(-1,0),(1,0),(0,-1),(0,1)): ray(dr, dc)
        elif pt == "k":
            for dr in (-1,0,1):
                for dc in (-1,0,1):
                    if dr == 0 and dc == 0: continue
                    add(fr+dr, fc+dc)
            # Castling
            home = 7 if color == "w" else 0
            ck = "K" if color == "w" else "k"
            cq = "Q" if color == "w" else "q"
            if fr == home and fc == 4 and castling.get(ck) and not self._in_check(color):
                if board[home][5] == "." and board[home][6] == "." and board[home][7].lower() == "r":
                    if not self._square_attacked(home, 5, "b" if color == "w" else "w") \
                       and not self._square_attacked(home, 6, "b" if color == "w" else "w"):
                        moves.append((home, 6, "K-castle"))
            if fr == home and fc == 4 and castling.get(cq) and not self._in_check(color):
                if board[home][3] == "." and board[home][2] == "." and board[home][1] == "." and board[home][0].lower() == "r":
                    if not self._square_attacked(home, 3, "b" if color == "w" else "w") \
                       and not self._square_attacked(home, 2, "b" if color == "w" else "w"):
                        moves.append((home, 2, "Q-castle"))
        return moves

    def _in_check(self, color):
        # find king
        kp = "K" if color == "w" else "k"
        for r in range(8):
            for c in range(8):
                if self.board[r][c] == kp:
                    return self._square_attacked(r, c, "b" if color == "w" else "w")
        return False

    def _square_attacked(self, r, c, by_color):
        # Look at all pieces of by_color, see if any pseudo move attacks (r,c).
        # Use simplified attack generation that ignores castling and in-check.
        for fr in range(8):
            for fc in range(8):
                p = self.board[fr][fc]
                if p == "." or self._piece_color(p) != by_color:
                    continue
                if self._attacks(fr, fc, r, c):
                    return True
        return False

    def _attacks(self, fr, fc, tr, tc):
        p = self.board[fr][fc]
        pt = p.lower()
        color = self._piece_color(p)
        dr_p = -1 if color == "w" else 1
        if pt == "p":
            return (tr == fr + dr_p) and abs(tc - fc) == 1
        if pt == "n":
            return (abs(tr - fr), abs(tc - fc)) in ((1, 2), (2, 1))
        if pt == "k":
            return max(abs(tr - fr), abs(tc - fc)) == 1
        if pt in ("b", "r", "q"):
            dr = tr - fr; dc = tc - fc
            if dr == 0 and dc == 0:
                return False
            if pt == "b" and abs(dr) != abs(dc):
                return False
            if pt == "r" and dr != 0 and dc != 0:
                return False
            if pt == "q" and not (abs(dr) == abs(dc) or dr == 0 or dc == 0):
                return False
            sr = 0 if dr == 0 else (1 if dr > 0 else -1)
            sc = 0 if dc == 0 else (1 if dc > 0 else -1)
            r, c = fr + sr, fc + sc
            while (r, c) != (tr, tc):
                if self.board[r][c] != ".":
                    return False
                r += sr; c += sc
            return True
        return False

    def _has_any_legal_move(self, color):
        for r in range(8):
            for c in range(8):
                p = self.board[r][c]
                if p == "." or self._piece_color(p) != color:
                    continue
                if self._legal_moves_for(r, c):
                    return True
        return False


# ---------------------------------------------------------------------------
# UNO (2-4 players)
# ---------------------------------------------------------------------------
UNO_COLORS = ("R", "Y", "G", "B")
UNO_VALUES_NUM = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9")
UNO_VALUES_ACT = ("skip", "rev", "d2")

def _build_uno_deck():
    deck = []
    for c in UNO_COLORS:
        deck.append({"color": c, "value": "0"})
        for v in UNO_VALUES_NUM[1:]:
            deck.append({"color": c, "value": v})
            deck.append({"color": c, "value": v})
        for v in UNO_VALUES_ACT:
            deck.append({"color": c, "value": v})
            deck.append({"color": c, "value": v})
    for _ in range(4):
        deck.append({"color": "W", "value": "wild"})
        deck.append({"color": "W", "value": "wd4"})
    return deck


class UnoGame(Game):
    type_id = "uno"
    min_players = 2
    max_players = 4
    display_name = "UNO"

    def __init__(self, game_id, players):
        super().__init__(game_id, players)
        random.shuffle(self.players)
        deck = _build_uno_deck()
        random.shuffle(deck)
        self.hands: dict[str, list[dict]] = {p: [] for p in self.players}
        for p in self.players:
            for _ in range(7):
                self.hands[p].append(deck.pop())
        # ensure first discard is a non-wild numeric card (simple rule)
        while True:
            top = deck.pop()
            if top["color"] != "W" and top["value"] in UNO_VALUES_NUM:
                break
            deck.insert(0, top)
        self.discard: list[dict] = [top]
        self.deck = deck
        self.current_idx = 0
        self.direction = 1
        self.chosen_color = top["color"]
        self.must_draw = 0  # accumulated draw count
        self.awaiting_color: str | None = None  # username who just played wild

    def public_state(self, viewer=None):
        base = super().public_state(viewer)
        top = self.discard[-1]
        base["top_card"] = top
        base["chosen_color"] = self.chosen_color
        base["current"] = self.players[self.current_idx] if self.players else None
        base["direction"] = self.direction
        base["counts"] = {p: len(self.hands[p]) for p in self.players}
        base["deck_size"] = len(self.deck)
        base["must_draw"] = self.must_draw
        base["awaiting_color"] = self.awaiting_color
        if viewer in self.players:
            base["my_hand"] = list(self.hands[viewer])
        return base

    def _draw_one(self):
        if not self.deck:
            if len(self.discard) <= 1:
                return None
            top = self.discard.pop()
            self.deck = self.discard[:]
            random.shuffle(self.deck)
            self.discard = [top]
        if not self.deck:
            return None
        return self.deck.pop()

    def _next_idx(self, advance=1):
        n = len(self.players)
        return (self.current_idx + self.direction * advance) % n

    def _can_play(self, card, top):
        if self.must_draw > 0:
            # can only play d2 on d2 chain, or wd4 on wd4 chain
            if top["value"] == "d2" and card["value"] == "d2":
                return True
            if top["value"] == "wd4" and card["value"] == "wd4":
                return True
            return False
        if card["color"] == "W":
            return True
        if card["color"] == self.chosen_color:
            return True
        if card["value"] == top["value"] and top["color"] != "W":
            return True
        return False

    async def handle_action(self, player, action):
        if self.ended:
            return
        kind = action.get("kind")
        cur = self.players[self.current_idx]
        if kind == "choose_color":
            if self.awaiting_color != player:
                return
            color = (action.get("color") or "").upper()
            if color not in UNO_COLORS:
                return
            self.chosen_color = color
            self.awaiting_color = None
            await self._advance_after_play()
            await self.broadcast_state()
            return
        if player != cur:
            await _send_to_user(player, {"type": "game_error", "message": "Not your turn"})
            return
        if self.awaiting_color:
            return
        if kind == "play":
            try:
                idx = int(action.get("card_index"))
            except (TypeError, ValueError):
                return
            hand = self.hands[player]
            if not (0 <= idx < len(hand)):
                return
            card = hand[idx]
            top = self.discard[-1]
            if not self._can_play(card, top):
                await _send_to_user(player, {"type": "game_error", "message": "Card can't be played"})
                return
            hand.pop(idx)
            self.discard.append(card)
            if card["color"] != "W":
                self.chosen_color = card["color"]
            # Apply special
            if card["value"] == "skip":
                # next player skipped: advance two
                if not hand:
                    await self.broadcast_state()
                    await self.end_game(player, f"{player} wins UNO!")
                    return
                self.current_idx = self._next_idx(2)
            elif card["value"] == "rev":
                self.direction *= -1
                if len(self.players) == 2:
                    # acts as skip in 2-player
                    if not hand:
                        await self.broadcast_state()
                        await self.end_game(player, f"{player} wins UNO!")
                        return
                    # current stays (since reversed and advance 1 puts us back, advance 2 keeps current)
                    self.current_idx = self._next_idx(2) if False else self.current_idx
                    # simpler: re-grant turn to player by skipping opponent: but next call should give opponent... we want player to play again? Standard UNO: in 2p reverse = skip = same player plays again.
                    self.current_idx = self.current_idx  # no advance, same player
                else:
                    if not hand:
                        await self.broadcast_state()
                        await self.end_game(player, f"{player} wins UNO!")
                        return
                    self.current_idx = self._next_idx(1)
            elif card["value"] == "d2":
                self.must_draw += 2
                if not hand:
                    await self.broadcast_state()
                    await self.end_game(player, f"{player} wins UNO!")
                    return
                self.current_idx = self._next_idx(1)
            elif card["value"] == "wild":
                self.awaiting_color = player
            elif card["value"] == "wd4":
                self.must_draw += 4
                self.awaiting_color = player
            else:
                if not hand:
                    await self.broadcast_state()
                    await self.end_game(player, f"{player} wins UNO!")
                    return
                self.current_idx = self._next_idx(1)
            await self.broadcast_state()
        elif kind == "draw":
            top = self.discard[-1]
            if self.must_draw > 0:
                drawn = []
                for _ in range(self.must_draw):
                    c = self._draw_one()
                    if c is None:
                        break
                    drawn.append(c)
                    self.hands[player].append(c)
                self.must_draw = 0
                self.current_idx = self._next_idx(1)
                await _send_to_user(player, {"type": "game_event", "message": f"You drew {len(drawn)} cards"})
            else:
                c = self._draw_one()
                if c is None:
                    return
                self.hands[player].append(c)
                if self._can_play(c, self.discard[-1]):
                    # let them choose to play or pass
                    await _send_to_user(player, {"type": "game_event", "message": f"You drew a playable card"})
                else:
                    self.current_idx = self._next_idx(1)
            await self.broadcast_state()

    async def _advance_after_play(self):
        top = self.discard[-1]
        if top["value"] == "wd4":
            # next player draws 4 done already, must_draw set; skip them after they draw
            if len(self.players) == 2:
                # since 2 players advance 1
                pass
            self.current_idx = self._next_idx(1)
        else:
            self.current_idx = self._next_idx(1)


# ---------------------------------------------------------------------------
# 8-BALL POOL (GamePigeon-style)
# ---------------------------------------------------------------------------
TABLE_W = 800.0
TABLE_H = 400.0
BALL_R = 11.0
POCKET_R = 20.0
KITCHEN_X = TABLE_W / 4.0           # head string: cue must be placed left of this on break
FRICTION = 0.988
MIN_VEL = 0.05
MAX_SHOT_POWER = 28.0
CUSHION_BOUNCE = 0.92
COLLISION_DAMP = 0.985
PHYS_STEPS_PER_FRAME = 3

POCKETS = [
    (POCKET_R * 0.65, POCKET_R * 0.65),
    (TABLE_W / 2,     POCKET_R * 0.50),
    (TABLE_W - POCKET_R * 0.65, POCKET_R * 0.65),
    (POCKET_R * 0.65, TABLE_H - POCKET_R * 0.65),
    (TABLE_W / 2,     TABLE_H - POCKET_R * 0.50),
    (TABLE_W - POCKET_R * 0.65, TABLE_H - POCKET_R * 0.65),
]

SOLID_IDS = (1, 2, 3, 4, 5, 6, 7)
STRIPE_IDS = (9, 10, 11, 12, 13, 14, 15)


def _ball_group(ball_id: int) -> str | None:
    if ball_id == 0: return "cue"
    if ball_id == 8: return "eight"
    if ball_id in SOLID_IDS: return "solid"
    if ball_id in STRIPE_IDS: return "stripe"
    return None


def _rack_balls():
    """Standard 8-ball racking: 1 at apex, 8 in center of 3rd row, last row alternates,
    corners of last row are different groups."""
    balls = [{"id": 0, "x": TABLE_W * 0.22, "y": TABLE_H / 2,
              "vx": 0.0, "vy": 0.0, "in": True, "type": "cue"}]
    # Regulation rack arrangement (apex first, 8 in center, mixed row)
    rack_layout = [
        [1],
        [9, 2],
        [10, 8, 3],
        [11, 4, 12, 5],
        [6, 13, 7, 14, 15],
    ]
    types = {n: ("solid" if n in SOLID_IDS else "stripe" if n in STRIPE_IDS else "eight")
             for n in range(1, 16)}
    rack_x = TABLE_W * 0.72
    rack_y = TABLE_H / 2
    spacing = BALL_R * 2.0 + 0.4   # almost touching
    for col, row_ids in enumerate(rack_layout):
        x = rack_x + col * (spacing * math.cos(math.pi / 6))
        for row_i, n in enumerate(row_ids):
            y = rack_y + (row_i - col / 2.0) * spacing
            balls.append({"id": n, "x": x, "y": y, "vx": 0.0, "vy": 0.0,
                          "in": True, "type": types[n]})
    return balls


class EightBallGame(Game):
    type_id = "eight_ball"
    min_players = 2
    max_players = 2
    display_name = "8-Ball Pool"

    def __init__(self, game_id, players):
        super().__init__(game_id, players)
        random.shuffle(self.players)
        self.balls = _rack_balls()
        self.current_idx = 0
        self.assignments: dict[str, str | None] = {p: None for p in self.players}
        self.last_shot_frames: list | None = None
        self.last_pocketed: list[int] = []
        self.cue_in_hand = True            # initial break or after foul
        self.kitchen_only = True            # break: cue must be in left quarter
        self.last_event: str = f"{self.players[0]} breaks. Place cue ball in the kitchen and shoot!"
        self.last_foul: bool = False
        self.shot_no = 0

    def public_state(self, viewer=None):
        base = super().public_state(viewer)
        base["balls"] = [dict(b) for b in self.balls]
        base["table"] = {
            "w": TABLE_W, "h": TABLE_H,
            "ball_r": BALL_R, "pocket_r": POCKET_R,
            "pockets": POCKETS,
            "kitchen_x": KITCHEN_X,
            "max_power": MAX_SHOT_POWER,
        }
        base["current"] = self.players[self.current_idx]
        base["assignments"] = dict(self.assignments)
        base["cue_in_hand"] = self.cue_in_hand
        base["kitchen_only"] = self.kitchen_only
        base["last_shot_frames"] = self.last_shot_frames
        base["last_pocketed"] = list(self.last_pocketed)
        base["last_event"] = self.last_event
        base["last_foul"] = self.last_foul
        base["shot_no"] = self.shot_no
        # pocketed balls trays
        base["pocketed_solids"] = sorted(
            [b["id"] for b in self.balls if not b["in"] and b["id"] in SOLID_IDS]
        )
        base["pocketed_stripes"] = sorted(
            [b["id"] for b in self.balls if not b["in"] and b["id"] in STRIPE_IDS]
        )
        base["pocketed_eight"] = any(not b["in"] and b["id"] == 8 for b in self.balls)
        return base

    async def handle_action(self, player, action):
        if self.ended:
            return
        kind = action.get("kind")
        cur = self.players[self.current_idx]
        if player != cur:
            await _send_to_user(player, {"type": "game_error", "message": "Not your turn"})
            return
        if kind == "place_cue" and self.cue_in_hand:
            try:
                x = float(action.get("x")); y = float(action.get("y"))
            except (TypeError, ValueError):
                return
            cue = next((b for b in self.balls if b["type"] == "cue"), None)
            if not cue:
                return
            x = max(BALL_R + 1, min(TABLE_W - BALL_R - 1, x))
            y = max(BALL_R + 1, min(TABLE_H - BALL_R - 1, y))
            if self.kitchen_only and x > KITCHEN_X - BALL_R:
                x = KITCHEN_X - BALL_R - 0.5
            for b in self.balls:
                if b is cue or not b["in"]:
                    continue
                if (b["x"] - x) ** 2 + (b["y"] - y) ** 2 < (2 * BALL_R + 0.2) ** 2:
                    return
            cue["x"] = x; cue["y"] = y
            cue["in"] = True
            cue["vx"] = 0; cue["vy"] = 0
            self.cue_in_hand = False
            self.kitchen_only = False
            self.last_shot_frames = None
            await self.broadcast_state()
        elif kind == "shoot" and not self.cue_in_hand:
            try:
                dx = float(action.get("dx")); dy = float(action.get("dy"))
            except (TypeError, ValueError):
                return
            mag = math.hypot(dx, dy)
            if mag < 0.5:
                return
            power = min(MAX_SHOT_POWER, max(2.0, mag))
            cue = next((b for b in self.balls if b["type"] == "cue"), None)
            if not cue or not cue["in"]:
                return
            cue["vx"] = (dx / mag) * power
            cue["vy"] = (dy / mag) * power
            frames, pocketed, first_hit, cushion_after_hit = self._simulate()
            self.last_shot_frames = frames
            self.last_pocketed = pocketed
            self.shot_no += 1
            await self._post_shot(pocketed, first_hit, cushion_after_hit)
            await self.broadcast_state()

    def _simulate(self):
        frames = []
        max_steps = 1600
        pocketed: list[int] = []
        first_hit: int | None = None
        cushion_after_first_hit = False
        # capture initial frame as t=0
        frames.append([
            {"id": b["id"], "x": round(b["x"], 2), "y": round(b["y"], 2), "in": b["in"]}
            for b in self.balls
        ])
        for step in range(max_steps):
            still = True
            # integrate
            for b in self.balls:
                if not b["in"]:
                    continue
                b["x"] += b["vx"]
                b["y"] += b["vy"]
                b["vx"] *= FRICTION
                b["vy"] *= FRICTION
                if abs(b["vx"]) < MIN_VEL: b["vx"] = 0
                if abs(b["vy"]) < MIN_VEL: b["vy"] = 0
                if b["vx"] != 0 or b["vy"] != 0:
                    still = False
                # cushions
                cushion_hit = False
                if b["x"] - BALL_R < 0:
                    b["x"] = BALL_R; b["vx"] = -b["vx"] * CUSHION_BOUNCE; cushion_hit = True
                if b["x"] + BALL_R > TABLE_W:
                    b["x"] = TABLE_W - BALL_R; b["vx"] = -b["vx"] * CUSHION_BOUNCE; cushion_hit = True
                if b["y"] - BALL_R < 0:
                    b["y"] = BALL_R; b["vy"] = -b["vy"] * CUSHION_BOUNCE; cushion_hit = True
                if b["y"] + BALL_R > TABLE_H:
                    b["y"] = TABLE_H - BALL_R; b["vy"] = -b["vy"] * CUSHION_BOUNCE; cushion_hit = True
                if cushion_hit and first_hit is not None:
                    cushion_after_first_hit = True
            # ball-ball collisions
            for i in range(len(self.balls)):
                a = self.balls[i]
                if not a["in"]: continue
                for j in range(i + 1, len(self.balls)):
                    b = self.balls[j]
                    if not b["in"]: continue
                    dx = b["x"] - a["x"]; dy = b["y"] - a["y"]
                    d2 = dx * dx + dy * dy
                    if d2 < (2 * BALL_R) ** 2 and d2 > 0:
                        d = math.sqrt(d2)
                        nx = dx / d; ny = dy / d
                        overlap = 2 * BALL_R - d
                        a["x"] -= nx * overlap / 2; a["y"] -= ny * overlap / 2
                        b["x"] += nx * overlap / 2; b["y"] += ny * overlap / 2
                        va = a["vx"] * nx + a["vy"] * ny
                        vb = b["vx"] * nx + b["vy"] * ny
                        if va - vb > 0 or vb - va > 0:
                            # swap normal components with mild damping
                            a["vx"] += (vb - va) * nx * COLLISION_DAMP
                            a["vy"] += (vb - va) * ny * COLLISION_DAMP
                            b["vx"] += (va - vb) * nx * COLLISION_DAMP
                            b["vy"] += (va - vb) * ny * COLLISION_DAMP
                        # record first object the cue contacted
                        if first_hit is None:
                            if a["type"] == "cue":
                                first_hit = b["id"]
                            elif b["type"] == "cue":
                                first_hit = a["id"]
            # pockets
            for b in self.balls:
                if not b["in"]: continue
                for (px, py) in POCKETS:
                    if (b["x"] - px) ** 2 + (b["y"] - py) ** 2 < POCKET_R ** 2:
                        b["in"] = False
                        b["vx"] = 0; b["vy"] = 0
                        pocketed.append(b["id"])
                        break
            if step % PHYS_STEPS_PER_FRAME == 0:
                frames.append([
                    {"id": b["id"], "x": round(b["x"], 2), "y": round(b["y"], 2), "in": b["in"]}
                    for b in self.balls
                ])
            if still:
                break
        # final frame to settle visuals
        frames.append([
            {"id": b["id"], "x": round(b["x"], 2), "y": round(b["y"], 2), "in": b["in"]}
            for b in self.balls
        ])
        return frames, pocketed, first_hit, cushion_after_first_hit

    async def _post_shot(self, pocketed, first_hit, cushion_after_hit):
        shooter = self.players[self.current_idx]
        opp = self.players[1 - self.current_idx]
        cue = next((b for b in self.balls if b["type"] == "cue"), None)
        cue_pocketed = (cue is None) or (not cue["in"])

        # Assignments ----------------------------------------------------
        eight_pocketed = 8 in pocketed
        non_eight_pocketed = [p for p in pocketed if p != 8]
        solids_p = [p for p in non_eight_pocketed if p in SOLID_IDS]
        stripes_p = [p for p in non_eight_pocketed if p in STRIPE_IDS]

        # Assignment happens on first ball pocketed cleanly (and not foul-only)
        # Cue scratch on the same shot still assigns groups based on what was sunk.
        if self.assignments[shooter] is None and (solids_p or stripes_p):
            if solids_p and not stripes_p:
                self.assignments[shooter] = "solid"
                self.assignments[opp] = "stripe"
            elif stripes_p and not solids_p:
                self.assignments[shooter] = "stripe"
                self.assignments[opp] = "solid"
            # if both groups pocketed simultaneously, table stays open

        my_type = self.assignments[shooter]

        # Foul detection -------------------------------------------------
        foul_reasons: list[str] = []
        if cue_pocketed:
            foul_reasons.append("cue ball scratched")
        if first_hit is None and not cue_pocketed:
            foul_reasons.append("cue hit nothing")
        if first_hit is not None and not cue_pocketed:
            hit_group = _ball_group(first_hit)
            if my_type is not None:
                # need to clear group before legally hitting 8
                cleared_my_group = not any(
                    b["in"] and ((my_type == "solid" and b["id"] in SOLID_IDS) or
                                 (my_type == "stripe" and b["id"] in STRIPE_IDS))
                    for b in self.balls
                )
                if hit_group == "eight" and not cleared_my_group:
                    foul_reasons.append("hit 8-ball before clearing group")
                elif hit_group != "eight" and hit_group != my_type:
                    foul_reasons.append("hit opponent's group first")
            else:
                # open table: cannot hit 8 first
                if hit_group == "eight":
                    foul_reasons.append("hit 8-ball on open table")

        # No-rail rule: at least one ball must hit a cushion or be pocketed
        if (not cushion_after_hit) and (not pocketed) and first_hit is not None:
            foul_reasons.append("no rail / no pocket")

        # 8-ball outcome -------------------------------------------------
        if eight_pocketed:
            cleared = True
            if my_type:
                remaining = [b for b in self.balls if b["in"] and (
                    (my_type == "solid" and b["id"] in SOLID_IDS) or
                    (my_type == "stripe" and b["id"] in STRIPE_IDS))]
                cleared = len(remaining) == 0
            else:
                cleared = False  # cannot legally pocket 8 on open break
            if cleared and not foul_reasons and not cue_pocketed:
                self.last_event = f"🏆 {shooter} sank the 8-ball — wins!"
                await self.end_game(shooter, f"{shooter} sank the 8-ball")
                return
            else:
                self.last_event = f"❌ {shooter} pocketed the 8-ball illegally — {opp} wins"
                await self.end_game(opp, f"{shooter} pocketed the 8-ball illegally")
                return

        # Respawn cue if scratched
        if cue_pocketed:
            for b in self.balls:
                if b["type"] == "cue":
                    b["x"] = TABLE_W * 0.22; b["y"] = TABLE_H / 2
                    b["vx"] = 0; b["vy"] = 0
                    b["in"] = True
            self.cue_in_hand = True
            self.kitchen_only = False  # foul: place anywhere

        # Determine what shooter "scored" (pocketed own group)
        if my_type:
            scored_own = any(
                (my_type == "solid" and p in SOLID_IDS) or
                (my_type == "stripe" and p in STRIPE_IDS)
                for p in non_eight_pocketed
            )
        else:
            # open table — treat any non-eight pocket as "scored own" only if no foul
            scored_own = bool(non_eight_pocketed)

        # Build status text and decide turn ------------------------------
        if foul_reasons:
            self.last_foul = True
            self.cue_in_hand = True
            self.kitchen_only = False
            reason_str = ", ".join(foul_reasons)
            pieces = [f"Foul: {reason_str}."]
            if non_eight_pocketed:
                pieces.append(f"Pocketed: {', '.join(str(n) for n in non_eight_pocketed)}.")
            pieces.append(f"{opp} has cue ball in hand.")
            self.last_event = " ".join(pieces)
            self.current_idx = 1 - self.current_idx
        else:
            self.last_foul = False
            if scored_own:
                bits = []
                if not my_type and non_eight_pocketed:
                    bits.append("Open table — pocketed " + ", ".join(str(n) for n in non_eight_pocketed) + ".")
                elif non_eight_pocketed:
                    bits.append(f"{shooter} pocketed " + ", ".join(str(n) for n in non_eight_pocketed) + ".")
                if my_type:
                    bits.append(f"{shooter} continues — group: {my_type}s.")
                else:
                    bits.append(f"{shooter} shoots again.")
                self.last_event = " ".join(bits)
                # same player continues
            else:
                if non_eight_pocketed:
                    # made opponent's ball, still ends turn
                    self.last_event = (f"{shooter} pocketed opponent's ball "
                                       + ", ".join(str(n) for n in non_eight_pocketed)
                                       + f". Turn passes to {opp}.")
                else:
                    self.last_event = f"{shooter} missed. {opp}'s turn."
                self.current_idx = 1 - self.current_idx


# ---------------------------------------------------------------------------
# Game factory and handlers
# ---------------------------------------------------------------------------
GAME_CLASSES = {
    "wordle": WordleGame,
    "word_hunt": WordHuntGame,
    "chess": ChessGame,
    "uno": UnoGame,
    "eight_ball": EightBallGame,
}


def _create_game(game_type: str, players: list[str]) -> Game:
    cls = GAME_CLASSES[game_type]
    gid = uuid.uuid4().hex[:10]
    g = cls(gid, players)
    games[gid] = g
    for p in players:
        _register_user_game(p, gid)
    return g


async def handle_game_open_challenge(ws, data):
    """Broadcast an open challenge in chat that anyone can join."""
    info = connections.get(ws)
    if not info:
        return
    sender = info["username"]
    gtype = data.get("game")
    if gtype not in GAME_TYPES:
        await safe_send(ws, {"type": "game_error", "message": "Unknown game"})
        return
    cls = GAME_CLASSES[gtype]
    # Currently UI only supports open challenge for 2-player games (wordle, etc.)
    invite_id = uuid.uuid4().hex[:10]
    msg = await insert_message(
        sender,
        f"🎮 {sender} started an open {cls.display_name} challenge",
        images=[],
        metadata={
            "type": "game_open_challenge",
            "game": gtype,
            "game_label": cls.display_name,
            "status": "open",
            "from": sender,
            "invite_id": invite_id,
            "players": [],
        },
    )
    game_invites[invite_id] = {
        "id": invite_id,
        "from": sender,
        "to": [],
        "accepted": [],
        "declined": [],
        "game": gtype,
        "game_label": cls.display_name,
        "created_at": now_iso(),
        "is_open": True,
        "chat_message_id": msg["id"],
    }
    await broadcast({"type": "message", "message": msg})


async def handle_game_open_join(ws, data):
    info = connections.get(ws)
    if not info:
        return
    joiner = info["username"]
    inv_id = data.get("invite_id")
    invite = game_invites.get(inv_id)
    if not invite or not invite.get("is_open"):
        await safe_send(ws, {"type": "game_error", "message": "Challenge no longer available"})
        return
    if invite["accepted"]:
        await safe_send(ws, {"type": "game_error", "message": "Already taken"})
        return
    if joiner == invite["from"]:
        await safe_send(ws, {"type": "game_error", "message": "You can't join your own challenge"})
        return
    invite["accepted"].append(joiner)
    chat_message_id = invite.get("chat_message_id")
    game_invites.pop(inv_id, None)
    players = [invite["from"], joiner]
    cls = GAME_CLASSES[invite["game"]]
    if chat_message_id is not None:
        await update_message_metadata(chat_message_id, {
            "type": "game_open_challenge",
            "game": invite["game"],
            "game_label": cls.display_name,
            "status": "in_progress",
            "from": invite["from"],
            "players": players,
            "invite_id": inv_id,
        })
    g = _create_game(invite["game"], players)
    g.chat_message_id = chat_message_id
    payload_base = {"type": "game_started", "game_id": g.id, "game_type": invite["game"]}
    for p in players:
        payload = dict(payload_base)
        payload["state"] = g.public_state(p)
        await _send_to_user(p, payload)
    if isinstance(g, WordHuntGame):
        await g.start_timer()


async def handle_game_invite_create(ws, data):
    info = connections.get(ws)
    if not info:
        return
    sender = info["username"]
    gtype = data.get("game")
    if gtype not in GAME_TYPES:
        await safe_send(ws, {"type": "game_error", "message": "Unknown game"})
        return
    targets = data.get("to") or []
    if isinstance(targets, str):
        targets = [targets]
    targets = [t for t in targets if isinstance(t, str) and t and t != sender]
    if not targets:
        return
    cls = GAME_CLASSES[gtype]
    if gtype != "uno" and len(targets) != 1:
        await safe_send(ws, {"type": "game_error", "message": f"{cls.display_name} is 2-player only"})
        return
    if gtype == "uno":
        # cap to max_players - 1 (host occupies one slot)
        targets = targets[:cls.max_players - 1]
    invite_id = uuid.uuid4().hex[:10]
    invite = {
        "id": invite_id,
        "from": sender,
        "to": list(targets),
        "accepted": [],
        "declined": [],
        "game": gtype,
        "game_label": cls.display_name,
        "created_at": now_iso(),
    }
    game_invites[invite_id] = invite
    await safe_send(ws, {"type": "game_invite_created", "invite": invite})
    for t in targets:
        await _send_to_user(t, {"type": "game_invite_received", "invite": invite})


async def handle_game_invite_accept(ws, data):
    info = connections.get(ws)
    if not info:
        return
    user = info["username"]
    inv_id = data.get("invite_id")
    invite = game_invites.get(inv_id)
    if not invite or user not in invite["to"] or user in invite["accepted"] or user in invite["declined"]:
        return
    invite["accepted"].append(user)
    if invite["game"] != "uno":
        # 2-player game: start now
        players = [invite["from"], user]
        await _broadcast_invite_resolved(invite, "accepted", user)
        game_invites.pop(inv_id, None)
        await _start_new_game(invite["game"], players)
    else:
        await _send_to_user(invite["from"], {"type": "game_invite_update", "invite": invite})
        await _send_to_user(user, {"type": "game_invite_update", "invite": invite})


async def handle_game_invite_decline(ws, data):
    info = connections.get(ws)
    if not info:
        return
    user = info["username"]
    inv_id = data.get("invite_id")
    invite = game_invites.get(inv_id)
    if not invite or user not in invite["to"]:
        return
    invite["declined"].append(user)
    invite["to"] = [t for t in invite["to"] if t != user]
    await _broadcast_invite_resolved(invite, "declined", user)
    # If all declined and no acceptances, cancel
    if not invite["to"] and not invite["accepted"]:
        game_invites.pop(inv_id, None)


async def handle_game_invite_cancel(ws, data):
    info = connections.get(ws)
    if not info:
        return
    user = info["username"]
    inv_id = data.get("invite_id")
    invite = game_invites.get(inv_id)
    if not invite or invite["from"] != user:
        return
    game_invites.pop(inv_id, None)
    for t in invite["to"] + invite["accepted"]:
        await _send_to_user(t, {"type": "game_invite_cancelled", "invite_id": inv_id})
    await safe_send(ws, {"type": "game_invite_cancelled", "invite_id": inv_id})


async def handle_game_invite_start(ws, data):
    """For UNO: the host starts the game with current accepted players."""
    info = connections.get(ws)
    if not info:
        return
    user = info["username"]
    inv_id = data.get("invite_id")
    invite = game_invites.get(inv_id)
    if not invite or invite["from"] != user:
        return
    if invite["game"] != "uno":
        return
    players = [invite["from"]] + list(invite["accepted"])
    if len(players) < 2:
        await safe_send(ws, {"type": "game_error", "message": "Need at least 2 players"})
        return
    game_invites.pop(inv_id, None)
    await _start_new_game(invite["game"], players)


async def _broadcast_invite_resolved(invite, action, user):
    payload = {"type": "game_invite_update", "invite": invite, "action": action, "user": user}
    await _send_to_user(invite["from"], payload)
    for t in invite["to"] + invite["accepted"] + invite["declined"]:
        await _send_to_user(t, payload)


async def _start_new_game(game_type: str, players: list[str]):
    g = _create_game(game_type, players)
    payload_base = {"type": "game_started", "game_id": g.id, "game_type": game_type}
    for p in players:
        payload = dict(payload_base)
        payload["state"] = g.public_state(p)
        await _send_to_user(p, payload)
    # game-specific kickoff
    if isinstance(g, WordHuntGame):
        await g.start_timer()


async def handle_game_action(ws, data):
    info = connections.get(ws)
    if not info:
        return
    user = info["username"]
    gid = data.get("game_id")
    g = games.get(gid)
    if not g or not g.is_player(user):
        return
    action = data.get("action") or {}
    if not isinstance(action, dict):
        return
    try:
        await g.handle_action(user, action)
    except Exception as e:
        await safe_send(ws, {"type": "game_error", "message": f"Error: {e}"})


async def handle_game_leave(ws, data):
    info = connections.get(ws)
    if not info:
        return
    user = info["username"]
    gid = data.get("game_id")
    g = games.get(gid)
    if not g or not g.is_player(user):
        return
    await g.player_left(user)


async def on_user_disconnect_for_games(username: str):
    gids = list(user_games.get(username, set()))
    for gid in gids:
        g = games.get(gid)
        if g:
            try:
                await g.player_left(username)
            except Exception:
                pass
    # cancel any pending invites involving this user
    to_remove = []
    for inv_id, invite in list(game_invites.items()):
        if invite["from"] == username:
            to_remove.append(inv_id)
            for t in invite["to"] + invite["accepted"]:
                await _send_to_user(t, {"type": "game_invite_cancelled", "invite_id": inv_id})
            if invite.get("is_open") and invite.get("chat_message_id") is not None:
                try:
                    await update_message_metadata(invite["chat_message_id"], {
                        "type": "game_open_challenge",
                        "game": invite["game"],
                        "game_label": invite.get("game_label", invite["game"]),
                        "status": "cancelled",
                        "from": username,
                    })
                except Exception:
                    pass
        elif username in invite["to"] or username in invite["accepted"]:
            invite["to"] = [t for t in invite["to"] if t != username]
            invite["accepted"] = [t for t in invite["accepted"] if t != username]
            await _send_to_user(invite["from"], {"type": "game_invite_update", "invite": invite, "action": "left", "user": username})
    for inv_id in to_remove:
        game_invites.pop(inv_id, None)


# ===========================================================================
# end games
# ===========================================================================


async def handle_connection(ws) -> None:
    await safe_send(ws, {"type": "welcome"})
    try:
        async for raw in ws:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            t = data.get("type")
            if t == "ping":
                await safe_send(ws, {"type": "pong"})
            elif t == "register":
                await handle_register(ws, data)
            elif t == "login":
                await handle_login(ws, data)
            elif t == "send_message":
                await handle_send_message(ws, data)
            elif t == "load_history":
                await handle_load_history(ws, data)
            elif t == "react":
                await handle_react(ws, data)
            elif t == "delete_message":
                await handle_delete_message(ws, data)
            elif t == "admin_approve":
                await handle_admin_action(ws, data, "approve")
            elif t == "admin_deny":
                await handle_admin_action(ws, data, "deny")
            elif t == "game_invite_create":
                await handle_game_invite_create(ws, data)
            elif t == "game_open_challenge":
                await handle_game_open_challenge(ws, data)
            elif t == "game_open_join":
                await handle_game_open_join(ws, data)
            elif t == "game_invite_accept":
                await handle_game_invite_accept(ws, data)
            elif t == "game_invite_decline":
                await handle_game_invite_decline(ws, data)
            elif t == "game_invite_cancel":
                await handle_game_invite_cancel(ws, data)
            elif t == "game_invite_start":
                await handle_game_invite_start(ws, data)
            elif t == "game_action":
                await handle_game_action(ws, data)
            elif t == "game_leave":
                await handle_game_leave(ws, data)
    except ConnectionClosed:
        pass
    finally:
        info = connections.pop(ws, None)
        admin_sockets.discard(ws)
        if info:
            await on_user_disconnect_for_games(info["username"])
            online = online_user_list()
            await broadcast(
                {
                    "type": "user_left",
                    "username": info["username"],
                    "online_users": online,
                }
            )


def process_request(connection, request):
    """Serve uploaded images over HTTP on the same port as the WebSocket.

    Important: do NOT intercept the WebSocket handshake. The browser
    connects with path '/' and an Upgrade: websocket header — returning
    a Response here would short-circuit the upgrade and the client
    would fail to connect. Only short-circuit explicit HTTP paths.
    """
    if request.headers.get("Upgrade", "").lower() == "websocket":
        return None

    raw_path = request.path or "/"
    path = raw_path.split("?", 1)[0]

    if path == "/healthz":
        body = b"chatroom ok\n"
        return Response(
            HTTPStatus.OK,
            "OK",
            Headers([
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Length", str(len(body))),
            ]),
            body,
        )

    if path.startswith("/uploads/"):
        rel = path[len("/uploads/"):]
        if not SAFE_FILENAME_RE.fullmatch(rel):
            return Response(
                HTTPStatus.BAD_REQUEST,
                "Bad Request",
                Headers([("Content-Type", "text/plain"), ("Content-Length", "11")]),
                b"Bad Request",
            )
        full = os.path.join(IMAGES_DIR, rel)
        if not os.path.isfile(full):
            return Response(
                HTTPStatus.NOT_FOUND,
                "Not Found",
                Headers([("Content-Type", "text/plain"), ("Content-Length", "9")]),
                b"Not Found",
            )
        try:
            with open(full, "rb") as f:
                body = f.read()
        except OSError:
            return Response(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "Server Error",
                Headers([("Content-Type", "text/plain"), ("Content-Length", "12")]),
                b"Server Error",
            )
        mime, _ = mimetypes.guess_type(rel)
        mime = mime or "application/octet-stream"
        return Response(
            HTTPStatus.OK,
            "OK",
            Headers([
                ("Content-Type", mime),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "public, max-age=86400"),
                ("Access-Control-Allow-Origin", "*"),
            ]),
            body,
        )

    return None


async def main() -> None:
    os.makedirs(IMAGES_DIR, exist_ok=True)
    _load_word_dict()
    await init_db()
    print(f"[chatroom] Loaded {len(WORD_DICT)} dictionary words ({len(WORDLE_ANSWERS)} wordle-eligible)")
    print(f"[chatroom] Listening on ws://{HOST}:{PORT}")
    print(f"[chatroom] HTTP uploads served at http://{HOST}:{PORT}/uploads/<file>")
    print(f"[chatroom] Database: {DB_PATH}")
    print(f"[chatroom] Image dir: {IMAGES_DIR}")
    async with serve(
        handle_connection,
        HOST,
        PORT,
        max_size=MAX_WS_PAYLOAD,
        process_request=process_request,
    ) as server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[chatroom] Shutting down.")
