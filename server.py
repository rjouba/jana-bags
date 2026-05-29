from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data.json"

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "3000"))
TOKEN_SECRET = os.environ.get("TOKEN_SECRET", "jana-bags-dev-secret").encode("utf-8")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "jana2040")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def sign_token(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    data = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    sig = hmac.new(TOKEN_SECRET, data, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64url_encode(sig)}"


def verify_token(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    h, p, s = parts
    data = f"{h}.{p}".encode("utf-8")
    expected = _b64url_encode(hmac.new(TOKEN_SECRET, data, hashlib.sha256).digest())
    if not hmac.compare_digest(expected, s):
        return None
    try:
        payload = json.loads(_b64url_decode(p).decode("utf-8"))
        if not isinstance(payload, dict):
            return None
        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and time.time() * 1000 > float(exp):
            return None
        return payload
    except Exception:
        return None


def seed_products() -> list[dict]:
    return [
        {
            "id": "jana-everyday-tote-ivory",
            "brand": "Jana",
            "name": "Everyday Tote",
            "category": "Tote",
            "price": 118,
            "featured": 14,
            "stock": 10,
            "color": "Ivory",
            "material": "Vegan leather",
            "size": "Fits 15” laptop",
            "variantCount": 8,
            "isNew": True,
            "description": "Structured tote with a clean silhouette, magnetic close, and interior sleeve for daily essentials.",
            "image": "",
        },
        {
            "id": "jana-mini-crossbody-black",
            "brand": "Jana",
            "name": "Mini Crossbody",
            "category": "Crossbody",
            "price": 92,
            "featured": 11,
            "stock": 10,
            "color": "Black",
            "material": "Vegan leather",
            "size": "Compact",
            "variantCount": 5,
            "isNew": True,
            "description": "Minimal mini crossbody with adjustable strap and secure flap.",
            "image": "",
        },
        {
            "id": "jana-shoulder-bag-sand",
            "brand": "Jana",
            "name": "Sculpt Shoulder",
            "category": "Shoulder",
            "price": 136,
            "featured": 9,
            "stock": 10,
            "color": "Sand",
            "material": "Vegan leather",
            "size": "Medium",
            "variantCount": 4,
            "isNew": False,
            "description": "Soft-structured shoulder bag with a sculpted profile and smooth zip closure.",
            "image": "",
        },
    ]


def load_data() -> dict:
    if not DATA_PATH.exists():
        data = {"products": seed_products(), "orders": []}
        DATA_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return data
    try:
        data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("bad data")
        if not isinstance(data.get("products"), list):
            data["products"] = []
        if not isinstance(data.get("orders"), list):
            data["orders"] = []
        changed = False
        for p in data.get("products", []):
            if not isinstance(p, dict):
                continue
            if "stock" not in p:
                p["stock"] = 999
                changed = True
        if changed:
            save_data(data)
        return data
    except Exception:
        data = {"products": seed_products(), "orders": []}
        DATA_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return data


def save_data(data: dict) -> None:
    DATA_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def uniq_sorted(values: list[str]) -> list[str]:
    return sorted(set(values), key=lambda s: s.lower())


def categories_from_products(products: list[dict]) -> list[str]:
    cats = [str(p.get("category", "")).strip() for p in products]
    cats = [c for c in cats if c]
    out = uniq_sorted(cats)
    if "Uncategorized" not in out:
        out.insert(0, "Uncategorized")
    return out


def normalize_product(obj: dict) -> dict:
    def s(key: str, default: str = "") -> str:
        return str(obj.get(key, default)).strip()

    def n(key: str, default: int = 0) -> int:
        try:
            v = int(float(obj.get(key, default)))
        except Exception:
            v = default
        return max(0, v)

    out = {
        "id": s("id"),
        "brand": s("brand", "Jana") or "Jana",
        "name": s("name", "New Bag") or "New Bag",
        "category": s("category", "Uncategorized") or "Uncategorized",
        "price": n("price", 0),
        "featured": n("featured", 0),
        "stock": n("stock", 0),
        "color": s("color", "Black") or "Black",
        "material": s("material", "Leather") or "Leather",
        "size": s("size", "Medium") or "Medium",
        "variantCount": n("variantCount", 0),
        "isNew": bool(obj.get("isNew", False)),
        "description": s("description", ""),
        "image": s("image", ""),
    }
    return out


def _delivery_fee(subtotal: int, city_code: str) -> int:
    if subtotal <= 0:
        return 0
    code = str(city_code or "").strip().lower()
    if code in ("amman", "عمّان", "عمان"):
        return 2
    return 3


def compute_order_totals(products_by_id: dict[str, dict], items: list[dict], city_code: str = "") -> tuple[list[dict], dict]:
    subtotal = 0
    normalized: list[dict] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        pid = str(it.get("productId", "")).strip()
        try:
            qty = int(float(it.get("qty", 0)))
        except Exception:
            qty = 0
        qty = min(99, max(1, qty))
        p = products_by_id.get(pid)
        if not p:
            continue
        price = int(p.get("price", 0) or 0)
        subtotal += price * qty
        normalized.append(
            {
                "productId": p.get("id", pid),
                "brand": p.get("brand", ""),
                "name": p.get("name", ""),
                "image": p.get("image", ""),
                "qty": qty,
                "unitPrice": price,
            }
        )
    shipping = _delivery_fee(subtotal, city_code)
    return normalized, {"subtotal": subtotal, "shipping": shipping, "total": subtotal + shipping}


class Handler(BaseHTTPRequestHandler):
    server_version = "JanaBags/1.0"

    def _send_json(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: int, text: str, content_type: str = "text/plain; charset=utf-8") -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict | None:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0:
            return None
        if length > 2_000_000:
            raise ValueError("Body too large")
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _auth_payload(self) -> dict | None:
        header = self.headers.get("Authorization") or ""
        if not header.lower().startswith("bearer "):
            return None
        token = header.split(" ", 1)[1].strip()
        return verify_token(token)

    def _require_admin(self) -> bool:
        payload = self._auth_payload()
        if not payload or payload.get("sub") != "admin":
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return False
        return True

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        pathname = parsed.path

        if pathname.startswith("/api/"):
            data = load_data()
            if pathname == "/api/products":
                return self._send_json(HTTPStatus.OK, {"products": data["products"]})
            if pathname == "/api/categories":
                return self._send_json(HTTPStatus.OK, {"categories": categories_from_products(data["products"])})
            if pathname == "/api/orders":
                if not self._require_admin():
                    return
                return self._send_json(HTTPStatus.OK, {"orders": data["orders"]})
            return self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        file_path = ROOT / ("index.html" if pathname == "/" else pathname.lstrip("/"))
        if not file_path.exists() or file_path.is_dir():
            return self._send_text(HTTPStatus.NOT_FOUND, "Not found")

        content_type = "application/octet-stream"
        ext = file_path.suffix.lower()
        if ext == ".html":
            content_type = "text/html; charset=utf-8"
        elif ext == ".css":
            content_type = "text/css; charset=utf-8"
        elif ext == ".js":
            content_type = "text/javascript; charset=utf-8"
        elif ext == ".png":
            content_type = "image/png"
        elif ext in (".jpg", ".jpeg"):
            content_type = "image/jpeg"
        elif ext == ".webp":
            content_type = "image/webp"
        elif ext == ".svg":
            content_type = "image/svg+xml"
        elif ext == ".json":
            content_type = "application/json; charset=utf-8"

        body = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        pathname = parsed.path

        try:
            body = self._read_json()
        except Exception as e:
            return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "bad_request", "message": str(e)})

        if pathname == "/api/admin/login":
            username = str((body or {}).get("username", "")).strip()
            password = str((body or {}).get("password", ""))
            if username != ADMIN_USER or password != ADMIN_PASS:
                return self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid_credentials"})
            token = sign_token({"sub": "admin", "exp": int(time.time() * 1000 + 8 * 60 * 60 * 1000)})
            return self._send_json(HTTPStatus.OK, {"token": token})

        data = load_data()

        if pathname == "/api/orders":
            customer = (body or {}).get("customer")
            items = (body or {}).get("items")
            if not isinstance(customer, dict):
                customer = {}
            if not isinstance(items, list):
                items = []
            city_code = str(customer.get("cityCode") or customer.get("city") or "").strip()
            products_by_id = {p.get("id"): p for p in data["products"] if isinstance(p, dict)}
            requested: list[tuple[str, int]] = []
            for it in items:
                if not isinstance(it, dict):
                    continue
                pid = str(it.get("productId", "")).strip()
                try:
                    qty = int(float(it.get("qty", 0)))
                except Exception:
                    qty = 0
                qty = min(99, max(1, qty))
                if pid:
                    requested.append((pid, qty))
            for pid, qty in requested:
                p = products_by_id.get(pid)
                if not p:
                    continue
                try:
                    stock = int(p.get("stock", 0) or 0)
                except Exception:
                    stock = 0
                if stock < qty:
                    return self._send_json(HTTPStatus.CONFLICT, {"error": "out_of_stock", "productId": pid, "stock": stock})
            normalized_items, totals = compute_order_totals(products_by_id, items, city_code=city_code)
            if totals["subtotal"] <= 0 or not normalized_items:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty_order"})
            for pid, qty in requested:
                p = products_by_id.get(pid)
                if not p:
                    continue
                try:
                    stock = int(p.get("stock", 0) or 0)
                except Exception:
                    stock = 0
                p["stock"] = max(0, stock - qty)
            order_id = f"JB-{secrets.token_hex(4).upper()}"
            order = {
                "id": order_id,
                "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "status": "new",
                "customer": {
                    "name": str(customer.get("name", "")).strip(),
                    "email": str(customer.get("email", "")).strip(),
                    "phone": str(customer.get("phone", "")).strip(),
                    "city": str(customer.get("city", "")).strip(),
                    "cityCode": str(customer.get("cityCode", "")).strip(),
                    "address": str(customer.get("address", "")).strip(),
                    "notes": str(customer.get("notes", "")).strip(),
                },
                "totals": totals,
                "items": normalized_items,
            }
            data["orders"] = [order, *data["orders"]]
            save_data(data)
            return self._send_json(HTTPStatus.CREATED, {"order": order})

        if pathname == "/api/products":
            if not self._require_admin():
                return
            product = normalize_product(body or {})
            if not product["id"]:
                product["id"] = f"p-{secrets.token_hex(4).upper()}"
            if any(p.get("id") == product["id"] for p in data["products"] if isinstance(p, dict)):
                return self._send_json(HTTPStatus.CONFLICT, {"error": "id_exists"})
            data["products"] = [product, *data["products"]]
            save_data(data)
            return self._send_json(HTTPStatus.CREATED, {"product": product})

        if pathname == "/api/categories/rename":
            if not self._require_admin():
                return
            from_cat = str((body or {}).get("from", "")).strip()
            to_cat = str((body or {}).get("to", "")).strip()
            if not from_cat or not to_cat:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing"})
            new_products = []
            for p in data["products"]:
                if not isinstance(p, dict):
                    continue
                if str(p.get("category", "")).strip() == from_cat:
                    p = {**p, "category": to_cat}
                new_products.append(p)
            data["products"] = new_products
            save_data(data)
            return self._send_json(HTTPStatus.OK, {"categories": categories_from_products(data["products"]), "products": data["products"]})

        if pathname == "/api/categories/delete":
            if not self._require_admin():
                return
            name = str((body or {}).get("name", "")).strip()
            if not name:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing"})
            if name == "Uncategorized":
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "cannot_delete_uncategorized"})
            new_products = []
            for p in data["products"]:
                if not isinstance(p, dict):
                    continue
                if str(p.get("category", "")).strip() == name:
                    p = {**p, "category": "Uncategorized"}
                new_products.append(p)
            data["products"] = new_products
            save_data(data)
            return self._send_json(HTTPStatus.OK, {"categories": categories_from_products(data["products"]), "products": data["products"]})

        return self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_PUT(self) -> None:
        parsed = urlparse(self.path)
        pathname = parsed.path

        if not pathname.startswith("/api/products/"):
            return self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        if not self._require_admin():
            return

        product_id = pathname.split("/")[-1]
        try:
            body = self._read_json()
        except Exception as e:
            return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "bad_request", "message": str(e)})

        data = load_data()
        idx = None
        for i, p in enumerate(data["products"]):
            if isinstance(p, dict) and p.get("id") == product_id:
                idx = i
                break
        if idx is None:
            return self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        incoming = normalize_product({**(body or {}), "id": product_id})
        data["products"][idx] = incoming
        save_data(data)
        return self._send_json(HTTPStatus.OK, {"product": incoming})

    def do_PATCH(self) -> None:
        parsed = urlparse(self.path)
        pathname = parsed.path

        if not pathname.startswith("/api/orders/"):
            return self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        if not self._require_admin():
            return

        order_id = pathname.split("/")[-1]
        try:
            body = self._read_json()
        except Exception as e:
            return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "bad_request", "message": str(e)})

        status = str((body or {}).get("status", "")).strip()
        if status not in ("new", "fulfilled", "cancelled"):
            return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_status"})

        data = load_data()
        idx = None
        for i, o in enumerate(data["orders"]):
            if isinstance(o, dict) and o.get("id") == order_id:
                idx = i
                break
        if idx is None:
            return self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        data["orders"][idx] = {**data["orders"][idx], "status": status}
        save_data(data)
        return self._send_json(HTTPStatus.OK, {"order": data["orders"][idx]})

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        pathname = parsed.path

        if pathname == "/api/orders":
            if not self._require_admin():
                return
            data = load_data()
            data["orders"] = []
            save_data(data)
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
            self.end_headers()
            return

        if pathname.startswith("/api/products/"):
            if not self._require_admin():
                return
            product_id = pathname.split("/")[-1]
            data = load_data()
            before = len(data["products"])
            data["products"] = [p for p in data["products"] if not (isinstance(p, dict) and p.get("id") == product_id)]
            if len(data["products"]) == before:
                return self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            save_data(data)
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
            self.end_headers()
            return

        return self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    shown_host = "127.0.0.1" if HOST in ("0.0.0.0", "::") else HOST
    print(f"Jana Bags server running at http://{shown_host}:{PORT}/")
    server.serve_forever()


if __name__ == "__main__":
    main()
