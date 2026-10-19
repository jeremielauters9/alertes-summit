#!/usr/bin/env python3
"""Surveillance de limites d'achat / vente avec alertes Telegram.

Conçu pour un dépôt GitHub public : la liste, l'historique et le tableau de bord sont chiffrés
avec le mot de passe du tableau de bord, et le robot n'écrit rien de confidentiel dans ses journaux.

Commandes :
  python alerts.py run [--dry-run]       récupère les cours, envoie les alertes, génère le tableau de bord
  python alerts.py import compo.csv      importe une composition (tickers Bloomberg) en gardant limites et watchlist
  python alerts.py export liste.csv      déchiffre la liste dans un CSV (pour la modifier dans Excel)
  python alerts.py load liste.csv        remplace la liste par ce CSV (colonnes de watchlist), puis chiffre
  python alerts.py apercu                ouvre le tableau de bord sur ce Mac (rien n'est envoyé ni publié)
  python alerts.py telegram-id           affiche l'identifiant du groupe Telegram (après y avoir écrit un message)

Variables d'environnement (secrets GitHub en production) :
  DASHBOARD_PASSWORD    mot de passe (demandé au clavier s'il est absent)
  TELEGRAM_BOT_TOKEN    jeton du bot (donné par @BotFather)
  TELEGRAM_CHAT_ID      identifiant du groupe Telegram (plusieurs : séparés par des virgules)
  WHATSAPP_RECIPIENTS   optionnel, "+41791234567:APIKEY;…" (CallMeBot)
  DASHBOARD_URL         lien ajouté en bas des messages (optionnel)
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import csv
import io
import json
import logging
import os
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG_FILE = ROOT / "config.json"
WATCHLIST_FILE = ROOT / "watchlist.enc.json"
STATE_FILE = ROOT / "state" / "state.enc.json"
DATA_FILE = ROOT / "site" / "data.enc.json"

FIELDS = ["liste", "ticker", "yahoo", "nom", "limite_achat", "limite_vente", "note"]
LISTS = ("portefeuille", "watchlist")
MAX_ALERTS_KEPT = 1000
PBKDF2_ITERATIONS = 250_000

# Sur GitHub (variable CI), les journaux sont publics : on n'y écrit que des compteurs.
VERBOSE = not os.environ.get("CI") or bool(os.environ.get("ALERTS_VERBOSE"))


def log(public: str, detail: str = "") -> None:
    print(public + (f"\n{detail}" if detail and VERBOSE else ""))


# Suffixe Bloomberg -> suffixe Yahoo Finance
EXCHANGE_SUFFIX = {
    "US": "", "UN": "", "UW": "", "UQ": "", "UA": "", "UP": "",
    "CN": ".TO", "CT": ".TO", "CV": ".V",
    "HK": ".HK", "JP": ".T", "JT": ".T", "AU": ".AX", "AT": ".AX", "KS": ".KS", "SP": ".SI",
    "SW": ".SW", "SE": ".SW", "VX": ".SW",
    "GF": ".F", "GR": ".DE", "GY": ".DE",
    "LN": ".L", "NA": ".AS", "FP": ".PA", "IM": ".MI", "SM": ".MC", "BB": ".BR",
    "SS": ".ST", "DC": ".CO", "NO": ".OL", "FH": ".HE", "AV": ".VI", "PL": ".LS", "ID": ".IR",
}


def bloomberg_to_yahoo(ticker: str) -> str:
    """'700 HK' -> '0700.HK', 'BRK/B US' -> 'BRK-B'. Un ticker sans espace est supposé déjà au format Yahoo."""
    ticker = ticker.strip()
    if " " not in ticker:
        return ticker.upper()
    code, exch = ticker.rsplit(" ", 1)
    code = code.strip().upper().replace("/", "-")
    exch = exch.strip().upper()
    if exch not in EXCHANGE_SUFFIX:
        raise ValueError(f"Place de cotation inconnue '{exch}' pour {ticker} : renseigner la colonne yahoo")
    if exch == "HK" and code.isdigit():
        code = code.zfill(4)
    return code + EXCHANGE_SUFFIX[exch]


# --------------------------------------------------------------------------- chiffrement

_password: str | None = None


def password(confirm: bool = False) -> str:
    global _password
    if _password is None:
        _password = os.environ.get("DASHBOARD_PASSWORD") or ""
        if not _password:
            import getpass
            _password = getpass.getpass("Mot de passe du tableau de bord : ")
            if confirm and getpass.getpass("Confirmer : ") != _password:
                sys.exit("Les mots de passe ne correspondent pas")
        if not _password:
            sys.exit("Mot de passe vide")
    return _password


def _key(salt: bytes, iterations: int) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations).derive(password().encode())


def encrypt(text: str) -> dict:
    """AES-256-GCM, clé dérivée par PBKDF2-SHA256 : même format que le déchiffrement du tableau de bord."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(_key(salt, PBKDF2_ITERATIONS)).encrypt(iv, text.encode(), None)
    b64 = lambda b: base64.b64encode(b).decode()
    return {"v": 1, "iter": PBKDF2_ITERATIONS, "salt": b64(salt), "iv": b64(iv), "data": b64(ct)}


def decrypt(blob: dict, strict: bool = True) -> str | None:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    d = lambda k: base64.b64decode(blob[k])
    try:
        return AESGCM(_key(d("salt"), blob["iter"])).decrypt(d("iv"), d("data"), None).decode()
    except InvalidTag:
        if strict:
            sys.exit("Mot de passe incorrect")
        return None


def write_encrypted(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(encrypt(text)), encoding="utf-8")


def read_encrypted(path: Path, strict: bool = True) -> str | None:
    return decrypt(json.loads(path.read_text(encoding="utf-8")), strict)


# --------------------------------------------------------------------------- liste et état

def load_config() -> dict:
    cfg = {"nom_portefeuille": "Mon portefeuille", "fuseau": "Europe/Zurich"}
    if CONFIG_FILE.exists():
        cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
    return cfg


def parse_limit(value: str | None) -> float | None:
    value = (value or "").strip().replace("'", "").replace(" ", "").replace(",", ".")
    return float(value) if value else None


def parse_watchlist(text: str) -> list[dict]:
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        if not (r.get("ticker") or "").strip():
            continue
        liste = (r.get("liste") or "portefeuille").strip().lower()
        rows.append({
            "liste": liste if liste in LISTS else "portefeuille",
            "ticker": r["ticker"].strip(),
            "yahoo": (r.get("yahoo") or "").strip() or bloomberg_to_yahoo(r["ticker"]),
            "nom": (r.get("nom") or "").strip(),
            "limite_achat": parse_limit(r.get("limite_achat")),
            "limite_vente": parse_limit(r.get("limite_vente")),
            "note": (r.get("note") or "").strip(),
        })
    return rows


def watchlist_csv(rows: list[dict]) -> str:
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=FIELDS, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in FIELDS})
    return out.getvalue()


def load_watchlist() -> list[dict]:
    return parse_watchlist(read_encrypted(WATCHLIST_FILE)) if WATCHLIST_FILE.exists() else []


def save_watchlist(rows: list[dict]) -> None:
    write_encrypted(WATCHLIST_FILE, watchlist_csv(rows))


def load_state() -> dict:
    text = read_encrypted(STATE_FILE, strict=False) if STATE_FILE.exists() else None
    if text:
        return json.loads(text)
    if STATE_FILE.exists():
        print("Historique illisible (mot de passe changé ?) : il repart de zéro.")
    return {"envoyees": {}, "alertes": [], "devises": {}}


def save_state(state: dict) -> None:
    write_encrypted(STATE_FILE, json.dumps(state, ensure_ascii=False))


# --------------------------------------------------------------------------- cours

@contextlib.contextmanager
def quiet():
    """yfinance écrit les tickers en échec dans les journaux : on le fait taire sur GitHub."""
    if VERBOSE:
        yield
        return
    logging.getLogger("yfinance").setLevel(logging.CRITICAL)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        yield


def fetch_quotes(symbols: list[str], devises: dict) -> dict[str, dict]:
    import yfinance as yf

    with quiet():
        data = yf.download(symbols, period="5d", interval="1d", group_by="ticker",
                           progress=False, auto_adjust=False, threads=True)
    quotes = {}
    for sym in symbols:
        try:
            df = data[sym] if len(symbols) > 1 else data
            df = df.dropna(subset=["Close"])
            if df.empty:
                continue
            last = df.iloc[-1]
            prev = float(df.iloc[-2]["Close"]) if len(df) > 1 else None
            quotes[sym] = {
                "date": df.index[-1].date().isoformat(),
                "dernier": float(last["Close"]),
                "plus_bas": float(last["Low"]),
                "plus_haut": float(last["High"]),
                "cloture_veille": prev,
            }
        except (KeyError, IndexError):
            continue
    for sym in symbols:  # la devise ne change pas : on la met en cache dans l'état
        if sym in quotes and sym not in devises:
            try:
                with quiet():
                    devises[sym] = yf.Ticker(sym).fast_info.get("currency") or ""
            except Exception:
                devises[sym] = ""
    return quotes


# --------------------------------------------------------------------------- alertes

def fmt(x: float | None) -> str:
    if x is None:
        return "–"
    return f"{x:,.4f}".rstrip("0").rstrip(".").replace(",", "'") if abs(x) < 10 else f"{x:,.2f}".replace(",", "'")


def detect(rows: list[dict], quotes: dict, state: dict) -> list[dict]:
    """Une limite est « touchée » si le plus bas (achat) ou le plus haut (vente) du jour l'a atteinte.
    Une alerte par titre / sens / niveau / séance : pas de doublon d'un passage à l'autre."""
    nouvelles = []
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for r in rows:
        q = quotes.get(r["yahoo"])
        if not q:
            continue
        checks = [("achat", r["limite_achat"], r["limite_achat"] is not None and q["plus_bas"] <= r["limite_achat"])]
        if r["liste"] == "portefeuille":
            checks.append(("vente", r["limite_vente"], r["limite_vente"] is not None and q["plus_haut"] >= r["limite_vente"]))
        for sens, limite, touche in checks:
            if not touche:
                continue
            key = f"{r['yahoo']}|{sens}|{limite}|{q['date']}"
            if key in state["envoyees"]:
                continue
            state["envoyees"][key] = now
            nouvelles.append({
                "horodatage": now, "seance": q["date"], "liste": r["liste"], "sens": sens,
                "ticker": r["ticker"], "nom": r["nom"], "limite": limite,
                "dernier": q["dernier"], "plus_bas": q["plus_bas"], "plus_haut": q["plus_haut"],
                "devise": state["devises"].get(r["yahoo"], ""),
            })
    return nouvelles


def build_message(alerts: list[dict], cfg: dict) -> str:
    """Message au format HTML Telegram (<b>…</b>)."""
    from html import escape
    from zoneinfo import ZoneInfo

    heure = datetime.now(ZoneInfo(cfg["fuseau"])).strftime("%d.%m %H:%M")
    lines = [f"🔔 <b>{escape(cfg['nom_portefeuille'])}</b> · {heure}", ""]
    for a in alerts:
        if a["sens"] == "vente":
            tete, extreme = "🔴 <b>VENTE</b> touchée", f"plus haut {fmt(a['plus_haut'])}"
        elif a["liste"] == "watchlist":
            tete, extreme = "👀 <b>ACHAT</b> (watchlist) touché", f"plus bas {fmt(a['plus_bas'])}"
        else:
            tete, extreme = "🟢 <b>ACHAT</b> touché", f"plus bas {fmt(a['plus_bas'])}"
        lines.append(f"{tete} · {escape(a['ticker'])} – {escape(a['nom'])}")
        lines.append(f"   limite {fmt(a['limite'])} {a['devise']} · {extreme} · dernier {fmt(a['dernier'])}")
    if os.environ.get("DASHBOARD_URL"):
        lines += ["", escape(os.environ["DASHBOARD_URL"])]
    return "\n".join(lines)


def send_telegram(html_text: str) -> None:
    import requests

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chats = [c.strip() for c in os.environ.get("TELEGRAM_CHAT_ID", "").split(",") if c.strip()]
    if not (token and chats):
        print("Telegram non configuré : message non envoyé")
        return
    for i, chat in enumerate(chats, 1):
        try:
            resp = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", timeout=30, json={
                "chat_id": chat, "text": html_text, "parse_mode": "HTML", "disable_web_page_preview": True})
            log(f"Telegram groupe {i} : HTTP {resp.status_code}", "" if resp.ok else resp.text[:200])
        except requests.RequestException:
            print(f"Telegram groupe {i} : échec de connexion", file=sys.stderr)


def send_whatsapp(html_text: str) -> None:
    """Optionnel (CallMeBot) : envoyé seulement si WHATSAPP_RECIPIENTS est défini."""
    import requests
    from html import unescape

    recipients = [x.strip() for x in os.environ.get("WHATSAPP_RECIPIENTS", "").split(";") if x.strip()]
    text = unescape(re.sub(r"</?b>", "*", html_text))
    for i, rec in enumerate(recipients, 1):
        phone, _, apikey = rec.partition(":")
        url = "https://api.callmebot.com/whatsapp.php?" + urllib.parse.urlencode(
            {"phone": phone.strip(), "text": text, "apikey": apikey.strip()})
        try:
            print(f"WhatsApp destinataire {i} : HTTP {requests.get(url, timeout=30).status_code}")
        except requests.RequestException:
            print(f"WhatsApp destinataire {i} : échec de connexion", file=sys.stderr)


# --------------------------------------------------------------------------- tableau de bord

def build_dashboard(rows: list[dict], quotes: dict, state: dict, cfg: dict) -> dict:
    out = []
    for r in rows:
        q = quotes.get(r["yahoo"], {})
        dernier = q.get("dernier")
        pct = lambda lim: None if (lim is None or not dernier) else (lim / dernier - 1) * 100
        out.append({
            **r, **q, "devise": state["devises"].get(r["yahoo"], ""),
            "variation": None if not (dernier and q.get("cloture_veille")) else (dernier / q["cloture_veille"] - 1) * 100,
            "ecart_achat": pct(r["limite_achat"]), "ecart_vente": pct(r["limite_vente"]) if r["liste"] == "portefeuille" else None,
        })
    return {
        "nom_portefeuille": cfg["nom_portefeuille"],
        "maj": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repo": os.environ.get("GITHUB_REPOSITORY", ""),
        "titres": out,
        "alertes": list(reversed(state["alertes"][-300:])),
    }


# --------------------------------------------------------------------------- commandes

def cmd_run(dry_run: bool) -> None:
    cfg = load_config()
    rows = load_watchlist()
    if not rows:
        sys.exit("Liste vide : lancer d'abord « import » ou « load »")
    state = load_state()
    quotes = fetch_quotes(sorted({r["yahoo"] for r in rows}), state["devises"])
    missing = [r["ticker"] for r in rows if r["yahoo"] not in quotes]
    log(f"{len(quotes)} cours récupérés sur {len(rows)} titres",
        f"Introuvables : {', '.join(missing)}" if missing else "")

    alerts = detect(rows, quotes, state)
    if alerts:
        msg = build_message(alerts, cfg)
        log(f"{len(alerts)} alerte(s)", msg)
        if not dry_run:
            send_telegram(msg)
            send_whatsapp(msg)
        state["alertes"] = (state["alertes"] + alerts)[-MAX_ALERTS_KEPT:]
    else:
        print("Aucune nouvelle alerte.")

    # on oublie les clés de plus de 10 jours
    cutoff = datetime.now(timezone.utc).timestamp() - 10 * 86400
    state["envoyees"] = {k: v for k, v in state["envoyees"].items() if datetime.fromisoformat(v).timestamp() > cutoff}
    if not dry_run:
        save_state(state)
    write_encrypted(DATA_FILE, json.dumps(build_dashboard(rows, quotes, state, cfg), ensure_ascii=False))
    print("Tableau de bord chiffré généré.")


def cmd_import(path: str) -> None:
    """Importe une composition (colonnes ticker, name, weight, asset_sub_class) en conservant les limites existantes."""
    password(confirm=not WATCHLIST_FILE.exists())
    existing = {r["ticker"]: r for r in load_watchlist()}
    rows, skipped = [], []
    with open(path, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            ticker = (r.get("ticker") or "").strip()
            if (r.get("asset_sub_class") or "").lower() == "cash" or not ticker:
                continue
            if float(r.get("weight") or 0) <= 0:
                skipped.append(ticker)
                continue
            old = existing.pop(ticker, {})
            rows.append({
                "liste": "portefeuille", "ticker": ticker, "yahoo": old.get("yahoo") or bloomberg_to_yahoo(ticker),
                "nom": r.get("name", "").strip(), "limite_achat": old.get("limite_achat"),
                "limite_vente": old.get("limite_vente"), "note": old.get("note", ""),
            })
    rows += [r for r in existing.values() if r["liste"] == "watchlist"]  # la watchlist est conservée
    save_watchlist(rows)
    print(f"{len(rows)} titres chiffrés dans {WATCHLIST_FILE.name} · ignorés (poids nul) : {', '.join(skipped) or 'aucun'}")


def cmd_export(path: str) -> None:
    Path(path).write_text(watchlist_csv(load_watchlist()), encoding="utf-8")
    print(f"Liste déchiffrée dans {path}. Ne pas l'envoyer sur GitHub : utiliser « load » pour la rechiffrer.")


def cmd_load(path: str) -> None:
    password(confirm=not WATCHLIST_FILE.exists())
    rows = parse_watchlist(Path(path).read_text(encoding="utf-8-sig"))
    save_watchlist(rows)
    print(f"{len(rows)} titres chiffrés dans {WATCHLIST_FILE.name}")


def cmd_apercu(port: int) -> None:
    """Tableau de bord en local : les modifications de la liste sont enregistrées dans watchlist.enc.json sur ce Mac."""
    import http.server
    import webbrowser

    if not WATCHLIST_FILE.exists():
        sys.exit("Pas encore de liste : lancer d'abord « import composition.csv »")
    password()
    cmd_run(dry_run=True)
    site = ROOT / "site"

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(site), **kw)

        def translate_path(self, path):
            if path.split("?")[0] == "/watchlist.enc.json":
                return str(WATCHLIST_FILE)
            return super().translate_path(path)

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def do_POST(self):
            if self.path.split("?")[0] != "/watchlist.enc.json":
                return self.send_error(404)
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            try:
                blob = json.loads(body)
                text = decrypt(blob, strict=False)
                if text is None:
                    raise ValueError("mot de passe différent")
                parse_watchlist(text)  # refuse une liste mal formée (ticker inconnu…)
            except Exception as e:
                return self.send_error(400, str(e))
            WATCHLIST_FILE.write_text(json.dumps(blob), encoding="utf-8")
            print("\nListe enregistrée, recalcul…")
            cmd_run(dry_run=True)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://localhost:{port}/"
    print(f"\nTableau de bord : {url}\n(Ctrl+C pour arrêter)")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAperçu arrêté.")


def cmd_telegram_id() -> None:
    """Affiche les identifiants des groupes / conversations où le bot a reçu un message."""
    import requests

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        import getpass
        token = getpass.getpass("Jeton du bot Telegram : ").strip()
    updates = requests.get(f"https://api.telegram.org/bot{token}/getUpdates", timeout=30).json().get("result", [])
    seen = {}
    for u in updates:
        msg = u.get("message") or u.get("my_chat_member") or u.get("channel_post") or {}
        chat = msg.get("chat")
        if chat:
            seen[chat["id"]] = chat.get("title") or chat.get("username") or chat.get("first_name")
    if not seen:
        print("Aucun message reçu : écris un message dans le groupe (après y avoir ajouté le bot), puis relance.")
    for cid, name in seen.items():
        print(f"{cid}\t{name}")


def main() -> None:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--dry-run", action="store_true", help="n'envoie rien et ne modifie pas l'historique")
    for name in ("import", "export", "load"):
        sub.add_parser(name).add_argument("csv")
    sub.add_parser("telegram-id")
    sub.add_parser("apercu").add_argument("--port", type=int, default=8000)
    a = p.parse_args()
    {"run": lambda: cmd_run(a.dry_run), "import": lambda: cmd_import(a.csv), "export": lambda: cmd_export(a.csv),
     "load": lambda: cmd_load(a.csv), "telegram-id": cmd_telegram_id, "apercu": lambda: cmd_apercu(a.port)}[a.cmd]()


if __name__ == "__main__":
    main()
