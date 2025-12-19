#!/usr/bin/env python3
import requests
import json
import time
import logging
import warnings
import os
import re
import math
from datetime import datetime, timezone
import splunklib.client as client
from pathlib import Path
import getpass

################################################################
# ==============================================================
# Authentication Helpers
# ==============================================================
_SPLUNK_AUTH = None
def get_splunk_auth():
    """Prompt once per run for SPLUNK_USER password; cache in memory."""
    global _SPLUNK_AUTH
    if _SPLUNK_AUTH is not None:
        return _SPLUNK_AUTH
    splunk_user = SPLUNK_USER
    print("*** === Run-time credential entry === ***")
    splunk_pass = getpass.getpass(f"\n\n##### Enter password for Splunk user '{splunk_user}' (input hidden): "
    ).strip()
    print("\n")
    _SPLUNK_AUTH = (splunk_user, splunk_pass)
    return _SPLUNK_AUTH

def get_hec_token():
    """Resolve HEC token from storage/passwords using the Splunk user credentials."""
    return get_secret(config["HEC_TOKEN_SECRET"])

def load_config():
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"config.json not found at {CONFIG_PATH}")

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            cfg = json.load(f)
    except json.JSONDecodeError as e:
        msg = (
            f"config.json is not valid JSON at {CONFIG_PATH}: "
            f"{e.msg} (line {e.lineno}, column {e.colno})"
        )
        logging.error(msg)
        print(f"[ERROR] {msg}")
        # Hard exit; nothing else can run without a valid config
        raise SystemExit(1)

    if not isinstance(cfg, dict):
        msg = f"config.json at {CONFIG_PATH} must contain a JSON object at the top level."
        logging.error(msg)
        print(f"[ERROR] {msg}")
        raise SystemExit(1)

    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8-sig") as f:
        json.dump(cfg, f, indent=4)
    print(f"[INFO] Updated {CONFIG_PATH}")

def secure_my_creds(cfg):
    splunk_server = cfg.get("SPLUNK_SERVER")
    print("=== One-time credential setup for backfill ===")

    # Admin creds, used only to write the HEC token into storage/passwords
    admin_user = input("Splunk admin username (for 8089 REST) - required for HEC Token creation: ").strip()
    admin_pass = getpass.getpass("Splunk admin password (input hidden): ").strip()

    # Connect as admin via SDK
    host = splunk_server.replace("https://", "").replace("http://", "").split(":")[0]
    port = 8089
    service = client.connect(
        host=host,
        port=port,
        scheme="https",
        username=admin_user,
        password=admin_pass,
        owner="nobody",
        app="search",
    )

    # Splunk user for REST (just record the username; do NOT store password)
    splunk_user = input("Splunk user (for 8089 REST): ").strip()
    cfg["SPLUNK_USER"] = splunk_user

    # HEC token -> storage/passwords via SDK (one-time write)
    hec_token = getpass.getpass("\n\n##### Enter HEC token (input hidden): ").strip()
    print("\n")

    realm = "backfill_hec"
    username = "hec_token"

    # Check if credential already exists
    existing = None
    for pw in service.storage_passwords:
        c = pw.content
        if c.get("realm") == realm and c.get("username") == username:
            existing = pw
            break

    if existing is not None:
        print(f"A credential already exists for realm='{realm}', username='{username}'.")
        choice = input("Reuse existing credential? (y = yes, o = overwrite, c = cancel) ").strip().lower()
        if choice == "o":
            # Delete and recreate
            existing.delete()
            service.storage_passwords.create(
                password=hec_token,
                realm=realm,
                username=username,
            )
        elif choice == "y":
            # Reuse; do nothing
            pass
        else:
            print("Cancelled credential setup; leaving existing credential unchanged.")
    else:
        # No existing credential, safe to create
        service.storage_passwords.create(
            password=hec_token,
            realm=realm,
            username=username,
        )

    # Remove any old cleartext fields
    cfg.pop("SPLUNKPASS", None)
    cfg.pop("HEC_TOKEN", None)

    # Store pointer only for HEC token
    cfg["HEC_TOKEN_SECRET"] = {
        "realm": realm,
        "username": username,
        "app": "search",
    }

    save_config(cfg)
    print("\n[DONE] HEC token stored in storage/passwords and config.json updated.")


def ensure_secrets_in_config():
    required_keys = ["HEC_TOKEN_SECRET", "SPLUNK_USER"]
    missing = [k for k in required_keys if k not in config]
    if missing:
        secure_my_creds(config)
        new_cfg = load_config()
        config.clear()
        config.update(new_cfg)

def get_secret(secret_cfg):
    splunk_server = config.get("SPLUNK_SERVER")
    realm = secret_cfg["realm"]
    username = secret_cfg["username"]
    app = secret_cfg.get("app", "search")
    user, pw = get_splunk_auth()
    # Use app context to match where the credential is stored
    url = f"{splunk_server}/servicesNS/nobody/{app}/storage/passwords"
    params = {"output_mode": "json"}
    r = requests.get(url, auth=(user, pw), params=params, verify=False)
    r.raise_for_status()
    data = r.json()

    for entry in data.get("entry", []):
        content = entry.get("content", {})
        if content.get("realm") == realm and content.get("username") == username:
            return content.get("clear_password") or content.get("password")

    raise RuntimeError(f"Secret {realm}:{username} not found in storage/passwords")

def handle_401(url, username_label):
    msg = (
        f"[ERROR] Received HTTP 401 (Unauthorized) from Splunk for user '{username_label}'.\n"
        f"        URL: {url}\n"
        "        Restart script to re-enter correct pw.\n"
    )
    logging.error(msg)
    print("\n" + msg + "\n")

def validate_splunk_user_auth() -> bool:
    """
    Validate the stored SPLUNK_USER credentials by calling /services/authentication/current-context.
    Returns True on success, False on auth/other failure.
    """
    user, pw = get_splunk_auth()
    url = f"{SPLUNK_SERVER}/services/authentication/current-context"
    params = {"output_mode": "json"}

    try:
        r = requests.get(url, auth=(user, pw), params=params, verify=False, timeout=10)
        if r.status_code == 401:
            logging.error(
                f"Splunk REST auth failed (HTTP 401) for user '{user}'. "
                "Restart script and enter correct credentials."
            )
            return False
        if not r.ok:
            logging.error(
                f"Splunk REST auth validation returned HTTP {r.status_code}: {r.text[:400]}"
            )
            return False
        logging.info("Splunk REST user authentication validated successfully.")
        return True
    except requests.RequestException as e:
        logging.error(f"Splunk REST auth validation error at '{url}': {e}")
        return False

# ==============================================================
# Define Configurations
# ==============================================================
CONFIG_PATH = Path(__file__).parent / "config.json"

config = load_config()
ensure_secrets_in_config()

#pull from config file 
SPLUNK_SERVER = config.get("SPLUNK_SERVER")
SPLUNK_USER   = config.get("SPLUNK_USER")
LOGGING_LEVEL = config.get("LOGGING_LEVEL")  # Can be "DEBUG", "WARNING", "ERROR", etc.
DEBUG_LEVEL = int(config.get("DEBUG_LEVEL", 1)) #Default to DEBUG level 1 if not defined (Levels 1 & 2)
BACKFILL_START = int(config.get("BACKFILL_START"))
BACKFILL_END = int(config.get("BACKFILL_END"))
CORRELATION_SEARCH_FILTER =  config.get("CORRELATION_SEARCH_FILTER")
LOG_DIR = config.get("LOG_DIRECTORY", "logs")
EVENTS_DIR = config.get("EVENTS_DIRECTORY", "events")
TEST_DIR = config.get("TEST_DIRECTORY", "test")

#create folders if needed
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(EVENTS_DIR, exist_ok=True)
os.makedirs(TEST_DIR, exist_ok=True)

# ==============================================================
#FILE NAME CONFIGS
# ==============================================================
def _events_dir_for_mode(mode: str) -> str:
    """
    Full runs write JSON/TXT under EVENTS_DIR, tests under TEST_DIR.
    """
    return EVENTS_DIR if mode == "full" else TEST_DIR
def backfill_events_path(backfill_key: str, mode: str = "full") -> str:
    base_dir = _events_dir_for_mode(mode)
    return os.path.join(base_dir, f"backfill_events_{backfill_key}.json")

def active_searches_path(backfill_key: str, mode: str = "full") -> str:
    base_dir = _events_dir_for_mode(mode)
    return os.path.join(base_dir, f"active_correlation_searches_{backfill_key}.json")

def risk_events_json_path(backfill_key: str, mode: str = "full") -> str:
    base_dir = _events_dir_for_mode(mode)
    return os.path.join(base_dir, f"risk_events_{backfill_key}.json")

def notable_events_txt_path(backfill_key: str, mode: str = "full") -> str:
    base_dir = _events_dir_for_mode(mode)
    return os.path.join(base_dir, f"notable_events_{backfill_key}.txt")

def risk_events_txt_path(backfill_key: str, mode: str = "full") -> str:
    base_dir = _events_dir_for_mode(mode)
    return os.path.join(base_dir, f"risk_events_{backfill_key}.txt")

def window_log_path(backfill_key: str, mode: str = "full") -> str:
    base_dir = LOG_DIR
    return os.path.join(base_dir, f"backfill_window_log_{backfill_key}.csv")

def risk_notable_events_txt_path(backfill_key: str) -> str:
    base_dir = _events_dir_for_mode("full")
    return os.path.join(base_dir, f"notable_events_risk_{backfill_key}.txt")

def risk_risk_events_txt_path(backfill_key: str) -> str:
    base_dir = _events_dir_for_mode("full")
    return os.path.join(base_dir, f"risk_events_risk_{backfill_key}.txt")

def risk_backfill_events_path(backfill_key: str, mode: str = "full") -> str:
    base_dir = _events_dir_for_mode(mode)
    return os.path.join(base_dir, f"backfill_events_risk_{backfill_key}.json")


#define global for fallback behavior
global POINTER_FILE,BACKFILL_EVENTS_FILE,ACTIVE_SEARCHES_FILE,RISK_EVENTS_FILE,NOTABLE_EVENTS_TXT,RISK_EVENTS_TXT

POINTER_FILE = os.path.join(LOG_DIR,"backfill_pointer.json")
RISK_POINTER_FILE  = os.path.join(LOG_DIR, "risk_backfill_pointer.json")
BACKFILL_EVENTS_FILE = None
ACTIVE_SEARCHES_FILE = None
RISK_EVENTS_FILE = None
NOTABLE_EVENTS_TXT = None
RISK_EVENTS_TXT = None
BACKFILL_WINDOW_LOG = None

# File Names for Testing
TEST_POINTER_FILE = os.path.join(LOG_DIR,"test_backfill_pointer.json")
TEST_SUFFIX = "test"

def get_test_backfill_key():
    return f"{TEST_SUFFIX}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"

################################################################
# ===============================
# Logging Setup
# ===============================
# Convert string-readable level to proper numeric logging constant
numeric_level = getattr(logging, LOGGING_LEVEL.upper(), logging.INFO)

logging.basicConfig(
    level=numeric_level,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "splunk_backfill.log")),
        logging.StreamHandler()
    ]
)

if DEBUG_LEVEL < 2:
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests.packages.urllib3").setLevel(logging.WARNING)
    logging.getLogger("http.client").setLevel(logging.WARNING)

def debug(msg, level=1):
    if DEBUG_LEVEL >= level:
        logging.debug(msg)
        # Optionally, can also print to console:
        # print(f"DEBUG{level}: {msg}")

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
logging.info(f"Logging initialized at level: {LOGGING_LEVEL}")

################################################################
# ===============================
# Helper Utilities
# ===============================

# # # # ===============================
# # # # Search Filter Configs
# # # # ===============================
def load_allowlist_from_file(path, label=None):
    """
    Load search_name_allowlist from a JSON file and return it as a set.
    Logs what it did; returns an empty set on any error.
    """
    if label is None:
        label = path

    if not os.path.exists(path):
        logging.info(f"Allowlist file not found: {path}; treating as no filter.")
        return set()

    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            cfg = json.load(f) or {}
        names = cfg.get("search_name_allowlist") or []
        if names:
            allowlist = set(names)
            logging.info(
                f"Loaded {len(allowlist)} search names from {label}"
            )
            return allowlist
        else:
            logging.info(
                f"Loaded {label}, but search_name_allowlist has no values; treating as no filter."
            )
            return set()
    except Exception as e:
        logging.error(f"Failed to load allowlist from {label}: {e}")
        return set()

BACKFILL_FILTER_CONFIG = "backfill_search_filters.json"
TEST_FILTER_CONFIG = "backfill_test_filters.json"
STATIC_FILTER_CONFIG = "backfill_static_filters.json"
RISK_FILTER_CONFIG = "backfill_risk_searches_filters.json"  # if using risk allowlist

BACKFILL_SEARCH_NAME_ALLOWLIST = load_allowlist_from_file(
    BACKFILL_FILTER_CONFIG, label="backfill_search_filters.json"
)

TEST_SEARCH_NAME_ALLOWLIST = load_allowlist_from_file(
    TEST_FILTER_CONFIG, label="backfill_test_filters.json"
)

STATIC_SEARCH_NAME_ALLOWLIST = load_allowlist_from_file(
    STATIC_FILTER_CONFIG, label="backfill_static_filters.json"
)


RISK_SEARCH_NAME_ALLOWLIST = load_allowlist_from_file(
    RISK_FILTER_CONFIG, label="backfill_risk_searches_filters.json"
)

def static_active_searches_path(backfill_key: str, mode: str = "full") -> str:
    base_dir = _events_dir_for_mode(mode)
    return os.path.join(base_dir, f"static_correlation_searches_{backfill_key}.json")

# # # # ===============================
# # # # Splunk Requests Function
# # # # ===============================
def splunk_request(method, endpoint, params=None, data=None, headers=None):
    """Perform REST API calls to Splunk with detailed diagnostics."""
    url = f"{SPLUNK_SERVER}{endpoint}"
    user, pw = get_splunk_auth()
    default_headers = {
        "Content-Type": "application/json"
    }

    if headers:
        default_headers.update(headers)

    try:
        debug(f"Sending {method.upper()} {url} with params={params}, data={data}", level=1)
        response = requests.request(
            method, url,
            auth=(user, pw),
            params=params, data=data,
            headers=default_headers,
            verify=False, stream=True, timeout=60
        )
        debug(f"Response status: {response.status_code}", level=1)
        if response.status_code != 200:
            logging.error(f"API error: {response.text}")
        if response.status_code == 401:
            handle_401(url, user)
            return None
        return response
    except Exception as e:
        logging.error(f"Request error for {url}: {e}")
        return None
    
# # # # ===============================
# # # # Manage Time Functions
# # # # ===============================
def epoch_to_iso_utc(epoch):
    """Convert epoch seconds to ISO 8601 UTC string."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_relative_time_spec(spec):
    """
    Subset parser for Splunk-style relative time:
      - 'now'
      - '-30m', '-15m', '-1h', '-2d', '-3w'
      - '-30m@m', '-1h@h', '-2d@d', '-3w@w'
    Returns a function(now_epoch) -> epoch.
    """
    spec = str(spec).strip()

    if spec == "now":
        # Example: snap now to the minute boundary
        def fn(nowepoch: int) -> int:
            snap_seconds = 60  # change to 600 for 10m, 3600 for hour, etc.
            return math.floor(nowepoch / snap_seconds) * snap_seconds
        return fn
    
    # Pattern: -<num><unit> optionally followed by @<snap_unit>
    m = re.fullmatch(r'(-\d+)([smhdw])(@[smhdw])?', spec)
    if not m:
        raise ValueError(f"Unsupported relative time spec: {spec}")

    offset_str, unit, snap = m.groups()
    offset_val = int(offset_str)  # e.g. -30
    unit_seconds = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]

    def fn(now_epoch):
        base = now_epoch + offset_val * unit_seconds
        if snap:
            snap_unit = snap[1]  # drop '@'
            snap_sec = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[snap_unit]
            # snap backwards to boundary, same semantics as Splunk snap-to. [web:21][web:25]
            return math.floor(base / snap_sec) * snap_sec
        return base

    return fn

# # # # ===============================
# # # # Initialize the Search Result Log File
# # # # ===============================
def init_window_log(path):
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write("search_number,search_name,window_start,window_end,results_returned,per_search_window_seconds\n")

# # # # ===============================
# # # # Determine Search windows
# # # # ===============================
def compute_window_seconds_from_dispatch(disp_earliest, disp_latest):
    """
    Compute window size (in seconds) from dispatch.earliest_time and dispatch.latest_time.
    If latest == "now" and there's no snapping, derive directly from earliest.
    If parsing fails, returns default 30m window.
    """
    DEFAULT_WINDOW_SECONDS = 1800

    if not disp_earliest or not disp_latest:
        logging.warning(
            f"Missing dispatch times '{disp_earliest}'/'{disp_latest}', using default 30m window"
        )
        return DEFAULT_WINDOW_SECONDS

    try:
        # Fast path: latest == "now" and earliest has no snapping (@)
        if disp_latest == "now" and "@" not in disp_earliest:
            earliest_fn = parse_relative_time_spec(disp_earliest)
            now_epoch = int(time.time())
            e_epoch = earliest_fn(now_epoch)
            window_seconds = int(now_epoch - e_epoch)
        else:
            earliest_fn = parse_relative_time_spec(disp_earliest)

            if disp_latest == "now" and "@" in disp_earliest:
                # derive snap unit from earliest spec, e.g. "-10m@m" -> "m"
                snap_char = disp_earliest.split("@", 1)[1][:1]
                snap_map = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
                unit_seconds = snap_map.get(snap_char, 60)  # default minute

                def latest_fn(nowepoch: int) -> int:
                    return math.floor(nowepoch / unit_seconds) * unit_seconds
            else:
                latest_fn = parse_relative_time_spec(disp_latest)

            now_epoch = int(time.time())
            e_epoch = earliest_fn(now_epoch)
            l_epoch = latest_fn(now_epoch)
            window_seconds = int(l_epoch - e_epoch)

    except Exception as e:
        logging.warning(
            f"Unable to parse dispatch times '{disp_earliest}'/'{disp_latest}' "
            f"({e}), using default 30m window"
        )
        return DEFAULT_WINDOW_SECONDS

    if window_seconds <= 0:
        logging.warning(
            f"Computed non-positive window ({window_seconds}) from "
            f"'{disp_earliest}'/'{disp_latest}', using default 30m window."
        )
        return DEFAULT_WINDOW_SECONDS

    return window_seconds

# # # # ===============================
# # # # HEC Ingest Utility
# # # # ===============================
def ingest_kv_txt_to_hec(file_path, hec_url, hec_token, index, sourcetype=None, source=None, verify_ssl=False, status_interval=25):
    """
    Reads a text file where each line is a comma-separated key="value" string.
    Sends each line to Splunk HEC as a raw event (not JSON).
    Logs progress every `status_interval` events.
    """
    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json"
    }

    logging.info(f"Ingesting KV lines from {file_path} into index '{index}' via HEC.")
    count = 0
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            payload = {
                "event": line,  # send raw string, not JSON
                "index": index
            }
            if sourcetype:
                payload["sourcetype"] = sourcetype
            if source:
                payload["source"] = source
            
            try:
                response = requests.post(
                    hec_url,
                    headers=headers,
                    data=json.dumps(payload),
                    verify=verify_ssl,
                    timeout=10
                )
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                logging.error(f"HEC ingest error for {file_path} line {count+1}: {e} "
                              f"(url={hec_url})"
                )
                break # stop HEC ingest if getting HEC ingest errors, likely HEC endpoint issue that needs resolved
            
            count += 1
            if count % status_interval == 0:
                logging.info(f"Ingested {count} events so far from {file_path}.")

    logging.info(f"KV ingest for {file_path} complete. Total events ingested: {count}.")

################################################################
# ===============================
# Get Active Correlation Searches
# ===============================
def get_active_correlation_searches(active_search_filter):
    filters = {
        "output_mode": "json",
        "search": active_search_filter,
        "count": -1
    }
    endpoint = "/servicesNS/-/-/saved/searches"
    logging.info("Getting active correlation searches.")

    response = splunk_request("GET", endpoint, params=filters)
    if not response or response.status_code != 200:
        logging.error("Failed to fetch correlation searches.")
        return []

    try:
        results = response.json().get("entry", [])
    except Exception:
        logging.error("Invalid JSON in API response.")
        return []

    active_searches = []
    for entry in results:
        content = entry.get("content", {})
        if content.get("disabled") == 1:
            continue
        
        search_name = entry.get("name")
        rule_title = (
            content.get("action.notable.param.rule_title")
            or content.get("action.correlationsearch.label")
        )

        filtered_data = {k: v for k, v in content.items() if k in [
            "action.correlationsearch.enabled",
            "action.correlationsearch.label",
            "action.risk",
            "action.risk.forceCsvResults",
            "action.risk.param._risk",
            "action.risk.param._risk_message",
            "action.risk.param._risk_object",
            "action.risk.param._risk_object_type",
            "action.risk.param._risk_score",
            "action.risk.param.verbose",
            "action.summary_index",
            "action.summary_index._name",
            "action.summary_index._type",
            "auto_summarize.cron_schedule",
            "search",
            "description",
            "action.notable.param.rule_title",
            "action.notable.param.severity",
            "action.notable.param.security_domain",
            "action.correlationsearch.annotations",
            "dispatch.earliest_time",
            "dispatch.latest_time",
            "cron_schedule"
        ]}
        filtered_data["Updated Title"] = f"BACKFILL - {content.get('action.correlationsearch.label')}"
        modified_search = content.get("search", "")
        modified_search = modified_search.replace("summariesonly=true", "summariesonly=false")
        modified_search = modified_search.replace("summariesonly=t", "summariesonly=false")
        modified_search = modified_search.replace("`summariesonly`", "summariesonly=false")
        modified_search = modified_search.replace("`security_content_summariesonly`", "summariesonly=false")

        filtered_data["modified_search"] = modified_search
        active_searches.append({"name": entry.get("name"), "content": filtered_data})

    with open(ACTIVE_SEARCHES_FILE, "w") as f:
        json.dump(active_searches, f, indent=2)
    logging.info(f"Saved {len(active_searches)} active searches to file.")

    extract_risk_searches_from_active()
    
    return active_searches

# ===============================
# Run Backfill Searches
# ===============================
def append_to_backfill_file(new_events, events_file):
    """Append search results to BACKFILL_EVENTS_FILE as a growing JSON array."""
    
    try:
        # If file doesn't exist, create it with a new list
        if not os.path.exists(events_file):
                with open(events_file, "w") as f:
                    json.dump(new_events, f, indent=2)
                return

        # Append to existing events safely
        with open(events_file, "r+") as f:
            try:
                existing_data = json.load(f)
                if not isinstance(existing_data, list):
                    existing_data = []
            except json.JSONDecodeError:
                existing_data = []

            existing_data.extend(new_events)
            f.seek(0)
            json.dump(existing_data, f, indent=2)
            f.truncate()
            debug(f"Backfill event added to {events_file}",level=1)

    except Exception as e:
        logging.error(f"Error appending to {events_file}: {e}")

def run_backfill(backfill_key=None, pointer_file=None, events_file=None, active_file=None, risk_file=None, backfill_end=None, per_search_window_limit=None,mode=None):
    if backfill_key is None:
        backfill_key = BACKFILL_KEY
    if pointer_file is None:
        pointer_file = POINTER_FILE
    if events_file is None:
        events_file = BACKFILL_EVENTS_FILE
    if active_file is None:
        active_file = ACTIVE_SEARCHES_FILE
    if risk_file is None:
        risk_file = RISK_EVENTS_FILE
    if per_search_window_limit is None:
        per_search_window_limit = float("inf")  # no limit by default
    
    # Derive mode if not explicitly passed via pointerfile 
    if mode is None:
        # Derive mode from pointer file for backward compatibility
        if pointer_file == TEST_POINTER_FILE:
            mode = "test"
        elif pointer_file == RISK_POINTER_FILE:
            mode = "risk"
        else:
            mode = "full"

    pointer_data = load_pointer(pointer_file)
    runs = pointer_data.get("runs", [])
    run_record = next((r for r in runs if r.get("backfill_key") == backfill_key), None)

    if run_record:
        last_index = run_record.get("last_search_index", 0)
        last_window = run_record.get("last_window_start", BACKFILL_START)
    else:
        last_index = 0
        last_window = BACKFILL_START
    
    try:
        with open(active_file) as f:
            searches = json.load(f)

    except FileNotFoundError:
        logging.error("No active_correlation_searches.json found.")
        return

    #flag for test run to check for some logging
    is_test_run = (pointer_file == TEST_POINTER_FILE)
    if mode == "risk":
        total_searches = len(RISK_SEARCH_NAME_ALLOWLIST)
    else:
        total_searches = len(searches)

    for idx, s in enumerate(searches[last_index:], start=last_index):
        content = s.get("content", {})
        search_name = s.get("name")
        rule_title =  content.get("action.correlationsearch.label")
             
        # Determine mode based on which pointer file you're using
        is_test_run = (pointer_file == TEST_POINTER_FILE)

        # Apply allowlist based on mode
        if mode == "test":
            allowlist = TEST_SEARCH_NAME_ALLOWLIST
        elif mode == "risk":
            allowlist = RISK_SEARCH_NAME_ALLOWLIST 
        else:  # "full"
            allowlist = BACKFILL_SEARCH_NAME_ALLOWLIST

        if allowlist:
            if (search_name not in allowlist) and (rule_title not in allowlist):
                continue
        
        # In full mode, explicitly exclude risk searches defined in backfill_risk_searches_filters.json
        if mode == "full" and RISK_SEARCH_NAME_ALLOWLIST:
            if (search_name in RISK_SEARCH_NAME_ALLOWLIST) or (rule_title in RISK_SEARCH_NAME_ALLOWLIST):
                logging.info(
                    f"Skipping risk search '{search_name}'/'{rule_title}' in full backfill "
                    f"because it is listed in backfill_risk_searches_filters.json."
                )
                #Log a skipped window entry for traceability
                try:
                    if BACKFILL_WINDOW_LOG:
                        with open(BACKFILL_WINDOW_LOG, "a") as f:
                            # Use empty timestamps and 0 results; you can adjust the marker string if you prefer
                            f.write(
                                f'"{idx+1} of {total_searches}",'
                                f'"{rule_title or search_name}",'
                                f',,0,SKIPPED_RISK\n'
                            )
                except Exception as e:
                    logging.warning(f"Failed to write SKIPPED_RISK window log entry: {e}")

                continue

        # always start at 0 per search
        local_breaker = 0
        
        #track total results for the search
        total_results_count = 0
        
        # Set the current search name variable
        current_search_name = s.get("content", {}).get("action.correlationsearch.label") \
            or s.get("content", {}).get("action.correlationsearch.label") \
            or s.get("name", "Unknown Search")
        
        logging.info(f"Starting backfill search for search # {idx + 1} of {total_searches}: {current_search_name}")

        content = s.get("content", {})

        disp_earliest = content.get("dispatch.earliest_time")
        disp_latest = content.get("dispatch.latest_time")

        per_search_window = compute_window_seconds_from_dispatch(disp_earliest, disp_latest)

        logging.info(
            f"Using window of {per_search_window} seconds for search '{current_search_name}' "
            f"(dispatch.earliest_time='{disp_earliest}', dispatch.latest_time='{disp_latest}')"
        )

        base_search = s.get("content", {}).get("modified_search", "")
        if not base_search.startswith("search") and not base_search.startswith("|"):
            base_search = "search " + base_search
        
        start_time = last_window if idx == last_index else BACKFILL_START

        if backfill_end is not None:
            end_time = backfill_end
        else:
            end_time = BACKFILL_END

        logging.info(f"Backfill timing for '{current_search_name}': "f"start_time={start_time}, end_time={end_time}")

        while start_time < end_time and local_breaker < per_search_window_limit:
            window_start = start_time
            window_end = start_time + per_search_window

            if local_breaker == 0:
                debug("Starting backfill of events", level=1)
            else:
                # For clarity, distinguish full vs test runs
                if is_test_run:
                    debug("Starting additional test window of backfill", level=1)
                else:
                    debug("Starting additional window of backfill", level=1)

            try:
                namespace = "SplunkEnterpriseSecuritySuite"
                url = f"{SPLUNK_SERVER}/servicesNS/nobody/{namespace}/search/jobs"

                search_payload = {  
                    "search": base_search,
                    "earliest_time": str(start_time),
                    "latest_time": str(window_end),
                    "output_mode": "json"
                }

                # Explicit URL-encoding fixes “search” loss in form body
                encoded_data = requests.models.RequestEncodingMixin._encode_params(search_payload)
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                logging.info(f"Submitting backfill for search: {current_search_name} "
                    f"({datetime.utcfromtimestamp(start_time)} to {datetime.utcfromtimestamp(window_end)})")
                debug(f"POST Request:\nURL: {url}\nHeaders: {headers}\nPayload: {encoded_data}", level=1)
                user, pw = get_splunk_auth()
                response = requests.post(
                    url,
                    data=encoded_data.encode("utf-8"),
                    auth=(user, pw),
                    headers=headers,
                    verify=False
                )
                
                debug(f"HTTP {response.status_code} - {response.text[:400]}", level=2)
                response.raise_for_status()

                # Parse job SID safely
                try:
                    sid_data = response.json()
                except json.JSONDecodeError:
                    logging.error("Splunk returned empty or invalid response when starting job.")
                    break
                sid = sid_data.get("sid")
                if not sid:
                    logging.warning("No SID returned, skipping window.")
                    start_time = window_end
                    continue

                # Poll job status until DONE
                job_failed = False
                job_url = f"{SPLUNK_SERVER}/servicesNS/nobody/{namespace}/search/jobs/{sid}"
                while True:
                    user, pw = get_splunk_auth()
                    status_r = requests.get(job_url,auth=(user, pw),
                                            params={"output_mode": "json"}, verify=False)
                    job_data = status_r.json()
                    dispatch_state = job_data.get("entry", [{}])[0].get("content", {}).get("dispatchState")
                    debug(f"Job {sid} status: {dispatch_state}", level=1)
                    if dispatch_state == "DONE":
                        break
                    if dispatch_state == "FAILED":
                        job_failed = True
                        logging.error(f"Backfill job {sid} FAILED for search '{current_search_name}' " 
                                      f"window [{window_start}-{window_end}]. Skipping this window.")
                        # write a skipped entry to the window log
                        try:
                            if BACKFILL_WINDOW_LOG:
                                human_start = datetime.utcfromtimestamp(window_start).isoformat()
                                human_end = datetime.utcfromtimestamp(window_end).isoformat()
                                with open(BACKFILL_WINDOW_LOG, "a") as f:
                                    f.write(
                                        f'"{idx+1} of {total_searches}",'
                                        f'"{current_search_name}",'f"{human_start},{human_end},FAILED,{per_search_window}\n"
                                    )
                            debug("Updated search windows log.",level=1)
                        except Exception as e:
                            logging.warning(f"Failed to write FAILED window log entry: {e}")

                        # update pointer so the loop can resume later at next window
                        upsert_run_record(
                            backfill_key=backfill_key,
                            mode=mode,
                            backfill_start=BACKFILL_START,
                            backfill_end=backfill_end or BACKFILL_END,
                            last_search_index=idx,
                            last_window_start=window_end,
                            pointer_file=pointer_file,
                            status = "last window failed"
                        )
                        break
                    time.sleep(2)
                if job_failed:
                    local_breaker += 1
                    start_time = window_end
                    continue

                # Fetch job results
                result_url = f"{job_url}/results"
                result_data = []
                page_size = 500
                offset = 0

                while True:
                    params = {"output_mode": "json", "count": page_size, "offset": offset}
                    user, pw = get_splunk_auth()
                    results_r = requests.get(
                        result_url,
                        auth=(user, pw),
                        params=params,
                        verify=False
                    )
                    page = results_r.json().get("results", [])
                    if not page:
                        break
                    result_data.extend(page)
                    logging.info(f"Fetched {len(page)} results at offset {offset} for search window [{window_start}-{window_end}].")
                    offset += page_size

                content = s.get("content", {})
  
                # Use the original window boundaries for metadata
                timestamp_now = datetime.utcnow().isoformat() + "Z"
                window_size = per_search_window  # explicit for clarity
                
                for r in result_data:
                    # Normalize keys to strings to avoid bytes/str issues
                    normalized = {}
                    for k, v in list(r.items()):
                        sk = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
                        # If key changed, move it
                        if sk != k:
                            normalized[sk] = v
                            del r[k]
                        else:
                            normalized[sk] = v
                    r.update(normalized)


                    # Map original Splunk fields to orig_* variants, if present
                    orig_map = {
                        "host": "orig_host",
                        "index": "orig_index",
                        "source": "orig_source",
                        "sourcetype": "orig_sourcetype",
                        "_time": "orig_time"
                    }

                    for src, dest in orig_map.items():
                        if src in r and dest not in r:
                            r[dest] = r[src]

                    r["info_min_time"] = window_start
                    r["info_max_time"] = window_end
                    r["info_search_time"] = timestamp_now
                    r["info_window_size"] = window_size
                    r["rule_title"] = content.get("Updated Title")
                    r["orig_rule_title"] = content.get("action.correlationsearch.label")
                    r["severity"] = content.get("action.notable.param.severity", "unknown")
                    r["search_name"] = content.get("action.notable.param.rule_title", "N/A")
                    r["security_domain"] = content.get("action.notable.param.security_domain", "")
                    r["annotations"] = content.get("action.correlationsearch.annotations", "")
                    r["risk_val"] = content.get("action.risk.param._risk", "FALSE")
                    r["risk_message"] = content.get("action.risk.param._risk_message", "")
                    r["risk_a"] = content.get("action.risk", "")
                    r["backfill_identifier"] = backfill_key

                    for field in ["_bkt","_cd","_indextime","_time", "_kv", "_raw", "_serial", "_si", "_sourcetype", "_subsecond", "linecount", "splunk_server","host", "index","source","sourcetype"]:
                        r.pop(field, None)

                # Append all results to global backfill file

                if result_data:
                    append_to_backfill_file(result_data, events_file)
                    logging.info(f"Appended {len(result_data)} records to {events_file}.")
                else:
                      logging.info(f"No results returned for search '{current_search_name}' "
                                   f"window [{window_start}-{window_end}]; skipping backfill append.")

                # Append window summary to CSV log
                try:
                    human_start = epoch_to_iso_utc(window_start)
                    human_end = epoch_to_iso_utc(window_end)
                    results_count = len(result_data)
                    
                    if BACKFILL_WINDOW_LOG:
                        human_start = datetime.utcfromtimestamp(window_start).isoformat()
                        human_end   = datetime.utcfromtimestamp(window_end).isoformat()
                        with open(BACKFILL_WINDOW_LOG, "a") as f:
                            f.write(
                                f'"{idx+1} of {total_searches}",'
                                f'"{current_search_name}",'
                                f"{human_start},{human_end},{results_count},{per_search_window}\n"
                            )
                        debug("Updated search windows log.",level=1)
                except Exception as e:
                    logging.warning(f"Failed to write window log entry: {e}")

                total_results_count = total_results_count + len(result_data)
                start_time = window_end
                local_breaker += 1
                
                # Update pointer to the next window's start since the last one completed
                upsert_run_record(
                    backfill_key=backfill_key,
                    mode=mode,
                    backfill_start=BACKFILL_START,
                    backfill_end=backfill_end or BACKFILL_END,
                    last_search_index=idx,
                    last_window_start=start_time,
                    pointer_file=pointer_file,
                    status = "next run"
                )
                logging.info(f"Pointer updated after successful window [{window_start}-{window_end}].")

            except Exception as e:
                logging.error(f"Error processing search window {start_time}-{window_end}: {e}", exc_info=True)
                break  # Stop current search loop if error

        
        #log end of current search results
        # Mark this search as complete in the pointer so next resume starts at the next search
        upsert_run_record(
            backfill_key=backfill_key,
            mode=mode,
            backfill_start=BACKFILL_START,
            backfill_end=backfill_end or BACKFILL_END,
            last_search_index=idx + 1,     # advance to next search
            last_window_start=BACKFILL_START,  # reset window for next search
            pointer_file=pointer_file,
            status="complete"
        )
        logging.info(f"Backfill for {current_search_name} completed.  Total events: {total_results_count}")


    logging.info(f"Backfill completed.")

# ===============================
# Generate Notable Events TXT File 
# ===============================
def generate_notable_events(textfile=None, events_file=None):
    if textfile is None:
        textfile = NOTABLE_EVENTS_TXT
    if events_file is None:
        events_file = BACKFILL_EVENTS_FILE

    if not events_file:
        logging.error("No events_file specified and BACKFILL_EVENTS_FILE is not set.")
        return

    try:
        with open(events_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        debug(f"Backfill events file not found for generating notable events, skipping: {events_file}",level=1)
        return

    if not events_file:
        logging.info(f"{events_file} contained 0 events; no notable_events file will be generated.")
        return
    
    with open(textfile, "w") as out:
        # Fields you do NOT want in the TXT output
        exclude_fields = {
            "_time",
            "_bkt",
            "_kv",
            "_raw",
            "_serial",
            "_si",
            "_sourcetype",
            "_subsecond",
            "linecount",
            "splunk_server",
            "info_window_size",
            "risk_a",
        }

        for e in data:
            # First column: epoch time (prefer _time, fall back to orig_time, then now)
            ts = e.get("_time", e.get("orig_time", int(time.time())))
            parts = [str(ts)]

            kv_pairs = []
            for k, v in e.items():
                if k in exclude_fields:
                    continue
                kv_pairs.append(f'{k}="{v}"')

            parts += kv_pairs
            line = ", ".join(parts).replace("\\", "")
            out.write(line + "\n")

    if not events_file:
        logging.info(f"{events_file} contained 0 events; no notable_events file will be generated.")
        return
    
    logging.info(f"Generated {textfile} successfully.")

# ===============================
# Generate Risk Events (JSON & TXT Files)
# ===============================
def generate_risk_events(textfile=None, events_file=None, risk_file=None,backfill_key=None):
    #Creates risk events from backfill_events.json by expanding each risk_val object into multiple individual risk events based on the fields inside it.
    if textfile is None:
        textfile = RISK_EVENTS_TXT
    if events_file is None:
        events_file = BACKFILL_EVENTS_FILE
    if risk_file is None:
        risk_file = RISK_EVENTS_FILE

    if not events_file:
        logging.error("No events_file specified and BACKFILL_EVENTS_FILE is not set.")
        return

    if not os.path.exists(events_file):
        debug(f"Backfill events file not found for generating Risk events, skipping: {events_file}",level=1)
        return

    try:
        with open(events_file, "r") as f:
            backfill_data = json.load(f)
    except Exception as e:
        logging.error(f"Failed to load {events_file}: {e}")
        return

    risk_events = []
    total_risk_count = 0

    for event in backfill_data:
        risk_val = event.get("risk_val")

        # Skip if no valid risk structure
        if not risk_val or risk_val == "FALSE":
            continue

        try:
            risk_objects = json.loads(risk_val)
        except Exception as e:
            logging.warning(f"Invalid JSON in risk_val for event: {e}")
            continue

        for risk_obj in risk_objects:
            risk_object_field = risk_obj.get("risk_object_field")
            risk_object_type = risk_obj.get("risk_object_type", "unknown")
            risk_score = risk_obj.get("risk_score", 0)

            # Use event's original field value as the risk_object
            risk_object_value = event.get(risk_object_field, None)
            if risk_object_value is None:
                # Fall back if field not present
                risk_object_value = f"unknown_{risk_object_field}"

            # Build risk_message
            if risk_object_type.lower() == "user":
                risk_message = f"User {risk_object_value} has added risk"
            else:
                risk_message = "Asset has added risk"

            # Construct contributing_events_search string
            search_name = event.get("search_name", "Unknown Search")
            contributing_events_search = (
                f'| savedsearch "{search_name}" | search {risk_object_field}={risk_object_value}'
            )

            # Build the risk event, excluding 'risk_val'
            risk_event = {
                "_time": int(time.time()),  # current epoch placeholder
                "risk_object": risk_object_value,
                "risk_object_type": risk_object_type,
                "risk_score": risk_score,
                "risk_score_type": "risk_object",
                ### NEED TO ADD LOGIC FOR RISK SCORE TYPE
                "risk_message": risk_message,
                "contributing_events_search": contributing_events_search,
                "backfill_identifier": backfill_key
            }

            # Add all original event fields except risk_val
            for k, v in event.items():
                if k != "risk_val":
                    risk_event[k] = v

            # Set _time from orig_time if present, else from info_max_time, else leave as current time
            orig_time_str = event.get("orig_time")
            info_max_time = event.get("info_max_time") 

            if orig_time_str:
                try:
                    if isinstance(orig_time_str, (int, float)):
                        risk_event["_time"] = int(orig_time_str)
                    else:
                        # Handle ISO 8601 with or without trailing Z
                        if str(orig_time_str).endswith("Z"):
                            dt = datetime.fromisoformat(str(orig_time_str).replace("Z", "+00:00"))
                        else:
                            dt = datetime.fromisoformat(str(orig_time_str))
                        risk_event["_time"] = int(dt.timestamp())
                except Exception:
                    logging.warning(f"Unable to parse orig_time '{orig_time_str}', falling back to info_max_time or now")
                    if isinstance(info_max_time, (int, float)):
                        risk_event["_time"] = int(info_max_time)
                    else:
                        risk_event["_time"] = int(time.time())
            elif isinstance(info_max_time, (int, float)):
                risk_event["_time"] = int(info_max_time)
            # last resort keeps the time risk event was processed in this script

            risk_events.append(risk_event)
            total_risk_count += 1

    # Write all risk events to json file
    try:
        with open(risk_file, "w") as f:
            json.dump(risk_events, f, indent=2)
        logging.info(f"Generated {total_risk_count} risk events in {risk_file}")
    except Exception as e:
        logging.error(f"Failed to write risk events: {e}")

    try:
        with open(risk_file) as f:
            data = json.load(f)
    except FileNotFoundError:
            debug(f"Backfill events file not found for generating risk events, skipping: {events_file}",level=1)
            return
    
    with open(textfile, "w") as out:
        # Fields you do NOT want in the risk TXT output
        exclude_fields = {"_time", "risk_a"}  # add others if needed
        for e in data:
            orig_time_str = e.get("orig_time")
            info_max_time = e.get("info_max_time")
            epoch_time = None

            if orig_time_str:
                try:
                    if isinstance(orig_time_str, (int, float)):
                        epoch_time = int(orig_time_str)
                    else:
                        if str(orig_time_str).endswith("Z"):
                            dt = datetime.fromisoformat(str(orig_time_str).replace("Z", "+00:00"))
                        else:
                            dt = datetime.fromisoformat(str(orig_time_str))
                        epoch_time = int(dt.timestamp())
                except Exception:
                    logging.warning(
                        f"Unable to parse orig_time '{orig_time_str}', "
                        "falling back to info_max_time or now"
                    )

            if epoch_time is None and isinstance(info_max_time, (int, float)):
                epoch_time = int(info_max_time)

            if epoch_time is None:
                epoch_time = int(time.time())

            parts = [str(epoch_time)]
            parts += [f'{k}="{v}"' for k, v in e.items() if k not in exclude_fields]
            line = ", ".join(parts).replace("\\", "")
            out.write(line + "\n")
            
    logging.info(f"Generated {textfile} successfully.")

# ===============================
# Static Filter Searches Fetch
# ===============================
def get_static_correlation_searches(backfill_key: str, mode: str = "full"):
    """
    Fetch correlation searches with action.correlationsearch.label=*,
    filter to STATIC_SEARCH_NAME_ALLOWLIST, and write a reduced JSON
    including action.correlationsearch.enabled to a dedicated file.
    Returns the list of saved searches (same structure as active list).
    """
    if not STATIC_SEARCH_NAME_ALLOWLIST:
        logging.info(
            "Static allowlist is empty; no static searches will be collected."
        )
        return []

    filters = {
        "output_mode": "json",
        "search": "action.correlationsearch.label=*",
        "count": -1,
    }
    endpoint = "/servicesNS/-/-/saved/searches"
    logging.info("Getting static correlation searches (label=*).")
    response = splunk_request("GET", endpoint, params=filters)
    if not response or response.status_code != 200:
        logging.error("Failed to fetch correlation searches for static list.")
        return []

    try:
        results = response.json().get("entry", [])
    except Exception:
        logging.error("Invalid JSON in API response for static searches.")
        return []

    static_searches = []
    for entry in results:
        content = entry.get("content", {}) or {}
        search_name = entry.get("name")
        label = content.get("action.correlationsearch.label")

        # Only keep entries in the static allowlist
        if (
            search_name not in STATIC_SEARCH_NAME_ALLOWLIST
            and label not in STATIC_SEARCH_NAME_ALLOWLIST
        ):
            continue

        filtered_data = {k: v for k, v in content.items() if k in [
            "action.correlationsearch.enabled",
            "action.correlationsearch.label",
            "action.risk",
            "action.risk.forceCsvResults",
            "action.risk.param._risk",
            "action.risk.param._risk_message",
            "action.risk.param._risk_object",
            "action.risk.param._risk_object_type",
            "action.risk.param._risk_score",
            "action.risk.param.verbose",
            "action.summary_index",
            "action.summary_index._name",
            "action.summary_index._type",
            "auto_summarize.cron_schedule",
            "search",
            "description",
            "action.notable.param.rule_title",
            "action.notable.param.severity",
            "action.notable.param.security_domain",
            "action.correlationsearch.annotations",
            "dispatch.earliest_time",
            "dispatch.latest_time",
            "cron_schedule"
        ]}
        filtered_data["Updated Title"] = f"BACKFILL - {content.get('action.correlationsearch.label')}"
        modified_search = content.get("search", "")
        modified_search = modified_search.replace("summariesonly=true", "summariesonly=false")
        modified_search = modified_search.replace("summariesonly=t", "summariesonly=false")
        modified_search = modified_search.replace("`summariesonly`", "summariesonly=false")
        modified_search = modified_search.replace("`security_content_summariesonly`", "summariesonly=false")

        filtered_data["modified_search"] = modified_search
        static_searches.append({"name": entry.get("name"), "content": filtered_data})
        static_searches.append({"name": search_name, "content": filtered_data})

    static_file = static_active_searches_path(backfill_key, mode=mode)
    with open(static_file, "w", encoding="utf-8-sig") as f:
        json.dump(static_searches, f, indent=2)
    logging.info(
        f"Saved {len(static_searches)} static searches to file '{static_file}'."
    )

    return static_searches

# ===============================
# Pointer and File Management Utilities
# ===============================

def get_backfill_key_from_pointer() -> str:
    global BACKFILL_EVENTS_FILE, ACTIVE_SEARCHES_FILE, RISK_EVENTS_FILE
    global NOTABLE_EVENTS_TXT, RISK_EVENTS_TXT, BACKFILL_WINDOW_LOG

    mode = "full"
    backfill_key = None

    # Load pointer and get current active key if present
    if os.path.exists(POINTER_FILE):
        try:
            pointer_data = load_pointer(POINTER_FILE)
            existing_key = pointer_data.get("active_backfill_key")
        except Exception as e:
            logging.error(f"Error reading pointer file for backfill_key: {e}")
            existing_key = None

        if existing_key:
            print(f"\nExisting backfill identifier found in pointer file: {existing_key}")
            choice = input(
                "Use this backfill identifier? (y = yes, n = generate new, e = enter new): "
            ).strip().lower()
            if choice == "y":
                backfill_key = existing_key
                logging.info(f"Using existing backfill_key from pointer: {backfill_key}")
            elif choice == "n":
                logging.info("Generating new backfill_key as requested.")
                backfill_key = datetime.utcnow().strftime("backfill_%Y%m%dT%H%M%S")
                logging.info(f"Auto-generated backfill_key for this sequence of event generation: {backfill_key}")
            elif choice == "e":
                user_key = input("Enter new backfill identifier: ").strip()
                if user_key:
                    backfill_key = user_key
                    logging.info(f"Using user-entered backfill_key: {backfill_key}")
                else:
                    logging.info("Empty input; auto-generating backfill_key instead.")
            else:
                logging.info("Generating new backfill_key.")
        else:
            logging.info("No backfill_key present in pointer file.")

    # If still no key, prompt or auto-generate
    if not backfill_key:
        user_input = input(
            "No active backfill identifier. Enter one now, or press Enter to auto-generate: "
        ).strip()
        if user_input:
            backfill_key = user_input
            logging.info(f"Using user-entered backfill_key: {backfill_key}")
        else:
            backfill_key = datetime.utcnow().strftime("backfill_%Y%m%dT%H%M%S")
            logging.info(
                f"Auto-generated backfill_key for this sequence of event generation: {backfill_key}"
            )

        # Update pointer with new record with index of 0
        upsert_run_record(
            backfill_key=backfill_key,
            mode=mode,
            backfill_start=BACKFILL_START,
            backfill_end=BACKFILL_END,
            last_search_index=0,
            last_window_start=BACKFILL_START,
            pointer_file=POINTER_FILE,
            status = "first search"
        )
    else:
        # Existing key: just mark it active, do NOT reset
        pointer_data = load_pointer(POINTER_FILE)
        pointer_data["active_backfill_key"] = backfill_key
        save_pointer(pointer_data, pointer_file=POINTER_FILE)

    # Set global file paths for this run (full mode)
    BACKFILL_EVENTS_FILE = backfill_events_path(backfill_key, mode=mode)
    ACTIVE_SEARCHES_FILE = active_searches_path(backfill_key, mode=mode)
    RISK_EVENTS_FILE = risk_events_json_path(backfill_key, mode=mode)
    NOTABLE_EVENTS_TXT = notable_events_txt_path(backfill_key, mode=mode)
    RISK_EVENTS_TXT = risk_events_txt_path(backfill_key, mode=mode)
    BACKFILL_WINDOW_LOG = window_log_path(backfill_key, mode=mode)

    return backfill_key

def save_pointer(pointer_data, pointer_file=POINTER_FILE):
    try:
        with open(pointer_file, "w") as f:
            json.dump(pointer_data, f, indent=2)
        debug("Updated pointer file.", level=1)
    except Exception as e:
        logging.error(f"Failed to update pointer file: {e}")

def load_pointer(pointer_file=POINTER_FILE):
    """
    Load pointer file as {"runs": [...], "active_backfill_key": "..."}.
    Backward-compatible with old flat dicts.
    """
    if not os.path.exists(pointer_file):
        return {"runs": [], "active_backfill_key": None}

    with open(pointer_file) as f:
        data = json.load(f)

    if "runs" not in data:
        # backward compatibility: old format → wrap into runs
        data = {
            "runs": [data],
            "active_backfill_key": data.get("backfill_key"),
        }
    return data

def is_test_pointer(backfill_key: str, context: str = "") -> bool:
    """
    Safety check: returns True if the given backfill_key looks like a TEST key.
    Logs and prints a warning so callers can simply:

        if is_test_pointer(BACKFILLKEY, "menu option a"): 
            continue

    """
    if not isinstance(backfill_key, str):
        return False

    if backfill_key.startswith(TEST_SUFFIX):
        msg = (
            f"Current backfill identifier '{backfill_key}' looks like a TEST key. "
            "Use test options (t/u) or change the backfill identifier (i) before running "
            f"{context or 'this operation'}."
        )
        logging.warning(msg)
        print(msg)
        return True

    return False


def assert_backfill_key_present_in_file(backfill_key, json_path=None, txt_path=None, field_name="backfill_identifier"):
    """
    Asserts that the given backfill_key exists in at least one event in the provided JSON or TXT file.
    Raises ValueError if not found.
    """
    found = False

    # Check JSON
    if json_path and os.path.exists(json_path):
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
            for event in data:
                if event.get(field_name) == backfill_key:
                    found = True
                    break
        except Exception as e:
            raise ValueError(f"Could not read or parse JSON from {json_path}: {e}")

    # Check TXT (KV format)
    if not found and txt_path and os.path.exists(txt_path):
        try:
            with open(txt_path, "r") as f:
                for line in f:
                    if f'{field_name}="{backfill_key}"' in line:
                        found = True
                        break
        except Exception as e:
            raise ValueError(f"Could not read TXT from {txt_path}: {e}")

    if not found:
        raise ValueError(
            f"backfill_key '{backfill_key}' NOT FOUND in files: {json_path if json_path else ''}, {txt_path if txt_path else ''}\n"
            "Aborting ingest/update to prevent accidental or mismatched action."
        )
    else:
        logging.info(f"Detected backfill_key '{backfill_key}' in event files.")

def upsert_run_record(backfill_key, mode, backfill_start, backfill_end,
                      last_search_index=0, last_window_start=None,
                      pointer_file=POINTER_FILE, status="in_progress"):
    pointer_data = load_pointer(pointer_file)
    runs = pointer_data.get("runs", [])

    # default last_window_start to backfill_start
    if last_window_start is None:
        last_window_start = backfill_start

    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # look for existing run
    for run in runs:
        if run.get("backfill_key") == backfill_key:
            run.update({
                "mode": mode,
                "backfill_start": backfill_start,
                "backfill_end": backfill_end,
                "last_search_index": last_search_index,
                "last_window_start": last_window_start,
                "updated_at": now_iso,
                "status" : status
            })
            break
    else:
        runs.append({
            "backfill_key": backfill_key,
            "created_at": now_iso,
            "mode": mode,
            "backfill_start": backfill_start,
            "backfill_end": backfill_end,
            "last_search_index": last_search_index,
            "last_window_start": last_window_start,
            "status" : status

        })

    # Debug log for pointer upsert
    debug(
        f"Pointer upsert for key='{backfill_key}': "
        f"mode={mode}, status={status}, "
        f"last_search_index={last_search_index}, last_window_start={last_window_start}, "
        f"backfill_start={backfill_start}, backfill_end={backfill_end}, "
        f"pointer_file='{pointer_file}' status= '{status}'",
        level=2
    )

    pointer_data["runs"] = runs
    pointer_data["active_backfill_key"] = backfill_key
    save_pointer(pointer_data, pointer_file=pointer_file)

# ===============================
# Upload Notable events, and change their status to specified value
# ===============================
def ingest_notables(file_path,backfill_key):
    assert_backfill_key_present_in_file(backfill_key, json_path=None, txt_path=file_path)
    hec_url = config.get("HEC_URL")
    if not hec_url:
        logging.error("HEC_URL is not set in config.json; aborting notable ingest.")
        return
    hec_token = get_hec_token()
    ingest_kv_txt_to_hec(
        file_path=file_path,
        hec_url=hec_url,
        hec_token=hec_token,
        index="notable",
        sourcetype="stash",
        source="backfill_notables"
    )

# ===============================
# Upload Risk events
# ===============================
def ingest_risk(file_path,backfill_key):
    assert_backfill_key_present_in_file(backfill_key, json_path=None, txt_path=file_path)
    """
    Ingest a file of risk events into Splunk using HEC, using the first field as event time.
    Each line format:
    1761141182, key1="value1", key2="value2", ...
    """
    hec_url = config.get("HEC_URL")
    if not hec_url:
        logging.error("HEC_URL is not set in config.json; aborting notable ingest.")
        return
    hec_token = get_secret(config["HEC_TOKEN_SECRET"])
    index = "risk"
    source = "backfill_risk"
    sourcetype = "stash"

    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json"
    }

    logging.info(f"Ingesting risk events from {file_path} into index '{index}' via HEC with explicit time per event.")

    with open(file_path, 'r') as f:
        for line in f:
            event=line
            line = line.strip()
            if not line:
                continue
            # Split at the first comma for time and the rest of the KV pairs
            parts = line.split(",", 1)
            if len(parts) != 2:
                logging.error(f"Malformed risk event line: {line}")
                continue
            try:
                epoch_time = int(parts[0].strip())
            except Exception as e:
                logging.error(f"Invalid epoch time: {parts[0]} ({e}) in line: {line}")
                continue
            event_body = parts[1].strip()
            payload = {
                "event": event,
                "index": index,
                "sourcetype": sourcetype,
                "source": source,
                "time": epoch_time
            }
            response = requests.post(
                hec_url,
                headers=headers,
                data=json.dumps(payload),
                verify=False
            )
            if response.status_code != 200:
                logging.error(f"HEC risk event ingest error: {response.status_code} {response.text}")
            else:
                debug(f"HEC risk event sent: {response.text}", level=2)

    logging.info(f"Risk event ingest to HEC complete for {file_path}.")

# ===============================
# Update Backfill Notable Statuses to defined 
# ===============================
def update_notable_status(backfill_key):
    """
    Searches for notable events with rule_title='Backfill*',
    computes event IDs, and bulk updates status using notable_update endpoint.
    Processes all results in pages of 100 rows for both fetching and updating.
    """
    namespace = "SplunkEnterpriseSecuritySuite"
    status_code = int(config.get("NOTABLE_STATUS_UPDATE", 1))  # Default to 'NEW'
    comment = "Status updated via automation for backfill events"

    search_string = (
        f'index=notable rule_title=Backfill* backfill_identifier="{backfill_key}" | '
        'eval indexer_guid=replace(_bkt,".*~(.+)","\\1"),'
        'event_hash=md5(_time._raw),'
        'event_id=indexer_guid."@@".index."@@".event_hash,'
        'rule_id=event_id | table event_id,rule_title'
    )
    search_payload = {
        "search": f"search {search_string}",
        "output_mode": "json"
    }
    debug(f"Search string: {search_string}", level=1)

    url = f"{SPLUNK_SERVER}/servicesNS/nobody/{namespace}/search/jobs"
    encoded_data = requests.models.RequestEncodingMixin._encode_params(search_payload)
    user, pw = get_splunk_auth()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(
        url,
        data=encoded_data.encode("utf-8"),
        auth=(user, pw),
        headers=headers,
        verify=False
    )
    if response.status_code not in [200, 201]:
        logging.error(f"Failed to start notable status search: {response.text}")
        return

    sid = response.json().get("sid")
    if not sid:
        logging.error("No SID returned for notable status search.")
        return

    # Poll job until DONE
    job_url = f"{SPLUNK_SERVER}/servicesNS/nobody/{namespace}/search/jobs/{sid}"
    while True:
        user, pw = get_splunk_auth()
        status_r = requests.get(job_url, auth=(user, pw),params={"output_mode": "json"}, verify=False)
        dispatch_state = status_r.json().get("entry", [{}])[0].get("content", {}).get("dispatchState")
        if dispatch_state == "DONE":
            break
        time.sleep(2)

    # Pagination for results (100 per page)
    results_url = f"{job_url}/results"
    page_size = 100
    offset = 0
    event_ids = []

    while True:
        params = {"output_mode": "json", "count": page_size, "offset": offset}
        results_r = requests.get(results_url, auth=(user, pw), params=params, verify=False)
        page = results_r.json().get("results", [])
        ids_page = [row.get("event_id") for row in page if "event_id" in row]
        event_ids.extend(ids_page)
        logging.info(f"Fetched {len(ids_page)} event_ids at offset {offset}.")
        if len(page) < page_size:
            break
        offset += page_size

    logging.info(f"Total event_ids found: {len(event_ids)} for bulk status update.")

    # Bulk update 100 event_ids at a time
    update_url = f"{SPLUNK_SERVER}/services/notable_update"
    for i in range(0, len(event_ids), 100):
        batch_ids = event_ids[i:i+100]
        params = [("ruleUIDs", uid) for uid in batch_ids]
        params.append(("status", status_code))
        params.append(("comment", comment))
        user, pw = get_splunk_auth()
        update_r = requests.post(
            update_url,
            data=params,
            verify=False,
            auth=(user, pw)
        )

        if update_r.status_code == 200:
            logging.info(f"Bulk updated status for {len(batch_ids)} notables in batch {i//100 + 1}.")
        else:
            logging.error(f"Bulk status update failed for batch {i//100 + 1}: {update_r.text}")

    if not event_ids:
        logging.warning("No notable events found to update.")

# ===============================
# Risk Search Allowlist Extractor
# ===============================

RISK_FILTER_CONFIG = "backfill_risk_searches_filters.json"

def extract_risk_searches_from_active(active_file=None, output_file=None):
    """
    Scan the active searches JSON, find searches whose SPL references
    the risk index or Risk data model, and write their names into a
    search_name_allowlist JSON file that can be used as a filter.

    A search qualifies if, after stripping spaces, its SPL contains
      - index=risk
      - index="risk"
      - datamodel=Risk
    """
    if active_file is None:
        active_file = ACTIVE_SEARCHES_FILE
    if output_file is None:
        output_file = RISK_FILTER_CONFIG

    if not active_file or not os.path.exists(active_file):
        logging.error(f"Active searches file not found or not set: {active_file}")
        return

    try:
        with open(active_file, "r", encoding="utf-8-sig") as f:
            searches = json.load(f)
    except Exception as e:
        logging.error(f"Failed to load active searches from {active_file}: {e}")
        return

    allowlist = set()

    for s in searches:
        content = s.get("content", {})
        # Prefer modified_search, fall back to search
        base_search = content.get("modified_search") or content.get("search") or ""
        normalized = base_search.replace(" ", "")  # strip all spaces

        if (
            "index=risk" in normalized
            or 'index="risk"' in normalized
            or "datamodel=Risk" in normalized
        ):
            # Use the human-facing rule title if available, else the savedsearch name
            rule_title = content.get("action.correlationsearch.label")
            search_name = s.get("name")
            name_for_list = rule_title or search_name
            if name_for_list:
                allowlist.add(name_for_list)

    allowlist_list = sorted(allowlist)
    risk_filter_obj = {"search_name_allowlist": allowlist_list}

    try:
        with open(output_file, "w", encoding="utf-8-sig") as f:
            json.dump(risk_filter_obj, f, indent=2)
        logging.info(
            f"Wrote {len(allowlist_list)} risk-related search names to {output_file}"
        )
    except Exception as e:
        logging.error(f"Failed to write risk search allowlist to {output_file}: {e}")



# ===============================
# Test Run Function
# ===============================
def test_run():
    global BACKFILL_EVENTS_FILE, ACTIVE_SEARCHES_FILE, RISK_EVENTS_FILE
    global NOTABLE_EVENTS_TXT, RISK_EVENTS_TXT, BACKFILL_WINDOW_LOG, BACKFILL_KEY

    mode = "test"
    test_key = get_test_backfill_key()
    BACKFILL_KEY = test_key  # so other functions can reference same key

    # Compute all test file paths via helpers
    test_events_file   = backfill_events_path(test_key, mode=mode)
    test_active_file   = active_searches_path(test_key, mode=mode)
    test_risk_file     = risk_events_json_path(test_key, mode=mode)
    test_notable_file  = notable_events_txt_path(test_key, mode=mode)
    test_risk_txt      = risk_events_txt_path(test_key, mode=mode)
    test_window_log    = window_log_path(test_key, mode=mode)

    # Persist these as globals only for the duration of test run (optional)
    BACKFILL_EVENTS_FILE = test_events_file
    ACTIVE_SEARCHES_FILE = test_active_file
    RISK_EVENTS_FILE     = test_risk_file
    NOTABLE_EVENTS_TXT   = test_notable_file
    RISK_EVENTS_TXT      = test_risk_txt
    BACKFILL_WINDOW_LOG  = test_window_log

    # Decide which searches to use for test
    all_searches = get_active_correlation_searches(active_search_filter=CORRELATION_SEARCH_FILTER)    

    with open(test_active_file, "w") as f:
        json.dump(all_searches, f, indent=2)

    pointer_data = {
        "last_search_index": 0,
        "last_window_start": BACKFILL_START,
        "backfill_key": test_key,
    }
    with open(TEST_POINTER_FILE, "w") as f:
        json.dump(pointer_data, f, indent=2)

    init_window_log(test_window_log)

    run_backfill(
        backfill_key=test_key,
        pointer_file=TEST_POINTER_FILE,
        events_file=test_events_file,
        active_file=test_active_file,
        risk_file=test_risk_file,
        per_search_window_limit=2,
    )

    generate_notable_events(textfile=test_notable_file, events_file=test_events_file)
    generate_risk_events(
        textfile=test_risk_txt,
        events_file=test_events_file,
        risk_file=test_risk_file,
    )


# ===============================
# Menu System
# ===============================
def menu():
    global BACKFILL_KEY
    global BACKFILL_EVENTS_FILE, ACTIVE_SEARCHES_FILE, RISK_EVENTS_FILE
    global NOTABLE_EVENTS_TXT, RISK_EVENTS_TXT, BACKFILL_WINDOW_LOG
    global RISK_SEARCH_NAME_ALLOWLIST
    resume_logging="\n\n##############################################\n#######################\n# Resume Logging\n#######################"

    while True:
        print("\n" + "#" * 46)
        print("#######################")
        print("# Main Menu")
        print("#######################")
        print("#")
        print("# Welcome to Splunk Correlation Search Backfill Script!")
        print("# This script outputs Notable Events at run time (today)")
        print("# while Risk events are backdated to the original event time.")
        print("#")
        print(f"# Current backfill identifier: {BACKFILL_KEY}")
        print("#")

        print("#######################")
        print("# Authentication")
        print("#######################")
        print("# a) Check Authentication")

        print("#")
        print("#######################")
        print("# Primary Functions (recommended order)")
        print("#######################")
        print("# b) Get Active Searches")
        print("# c) Run Searches to generate results (non-risk searches)")
        print("# d) Generate Notable Events from results")
        print("# e) Generate Risk Score Events from results")
        print("# f) Ingest Notable events")
        print("# g) Ingest Risk Score events")
        print("# h) Run Risk searches and generate notable/risk events")
        print("# i) Ingest Notable and Risk events for Risk searches")

        print("#")
        print("#######################")
        print("# Post-Verification Actions")
        print("#######################")
        print("# j) Bulk Update Notable Event status")

        print("#")
        print("#######################")
        print("# Additional Options")
        print("#######################")
        print("# n) Change Backfill Run Identifier")
        print("# o) Show last search status for current identifier")
        print("# r) Restart Searches from Pointer")

        print("#")
        print("#######################")
        print("# Testing")
        print("#######################")
        print("# t) Test Run - Get (filtered searches, limited windows)")
        print("# u) Test Run - Push (ingest test run results and update status)")

        print("#")
        print("#######################")
        print("# Exit")
        print("#######################")
        print("# x) Exit Script")
        print("#" * 46 + "\n")

        choice = input("Select an option: ").lower()

        if choice == 'a':
            validate_splunk_user_auth()
        
        elif choice == 'b':
            print(resume_logging)
            if is_test_pointer(BACKFILL_KEY, "menu option 'a'"):
                continue
            get_active_correlation_searches(active_search_filter=CORRELATION_SEARCH_FILTER)
       
        elif choice == 'c':
            print(resume_logging)
            if is_test_pointer(BACKFILL_KEY, "menu option 'a'"):
                continue
            init_window_log(BACKFILL_WINDOW_LOG)
            run_backfill(backfill_key=BACKFILL_KEY,mode="full")

        elif choice == 'd':
            print(resume_logging)
            if is_test_pointer(BACKFILL_KEY, "menu option 'a'"):
                continue
            generate_notable_events()
        elif choice == 'e':
            print(resume_logging)
            if is_test_pointer(BACKFILL_KEY, "menu option 'a'"):
                continue
            generate_risk_events()
        elif choice == 'f':
            print(resume_logging)
            if is_test_pointer(BACKFILL_KEY, "menu option 'a'"):
                continue
            ingest_notables(file_path=NOTABLE_EVENTS_TXT, backfill_key=BACKFILL_KEY)
        elif choice == 'g':
            print(resume_logging)
            if is_test_pointer(BACKFILL_KEY, "menu option 'a'"):
                continue
            ingest_risk(file_path=RISK_EVENTS_TXT, backfill_key=BACKFILL_KEY)
    
        elif choice == 'h':
            print(resume_logging)
            if is_test_pointer(BACKFILL_KEY, "menu option 'a'"):
                continue

            # Build risk-only filenames
            BACKFILL_EVENTS_FILE = risk_backfill_events_path(BACKFILL_KEY, mode="risk")
            NOTABLE_EVENTS_TXT = risk_notable_events_txt_path(BACKFILL_KEY)
            RISK_EVENTS_TXT    = risk_risk_events_txt_path(BACKFILL_KEY)

            # Use previously generated backfill_risk_searches_filters.json to run only those searches backfill.
            if not RISK_SEARCH_NAME_ALLOWLIST:
                logging.info("Risk allowlist is empty; no risk searches to backfill.")
            else:
                logging.info(
                    f"Backfilling only these risk searches: "
                    f"{sorted(RISK_SEARCH_NAME_ALLOWLIST)}"
                )

            init_window_log(BACKFILL_WINDOW_LOG)
            run_backfill(backfill_key=BACKFILL_KEY, pointer_file=RISK_POINTER_FILE, mode="risk")
            generate_notable_events(textfile=NOTABLE_EVENTS_TXT, events_file=BACKFILL_EVENTS_FILE)
            generate_risk_events(textfile=RISK_EVENTS_TXT, events_file=BACKFILL_EVENTS_FILE)

        elif choice == 'i':
            BACKFILL_EVENTS_FILE = risk_backfill_events_path(BACKFILL_KEY, mode="risk")
            NOTABLE_EVENTS_TXT = risk_notable_events_txt_path(BACKFILL_KEY)
            RISK_EVENTS_TXT    = risk_risk_events_txt_path(BACKFILL_KEY)
            if not (NOTABLE_EVENTS_TXT and os.path.exists(NOTABLE_EVENTS_TXT) and os.path.getsize(NOTABLE_EVENTS_TXT) > 0):
                logging.info("No notable events generated; skipping ingest_notables and ingest_risk.")
            else:
                ingest_notables(file_path=NOTABLE_EVENTS_TXT, backfill_key=BACKFILL_KEY)
                ingest_risk(file_path=RISK_EVENTS_TXT, backfill_key=BACKFILL_KEY)
                logging.info(f"Please verify new risk notables and events uploaded to Splunk and then run status update for:{BACKFILL_KEY}.")
        
        elif choice == 'j':
            print(resume_logging)
            if is_test_pointer(BACKFILL_KEY, "menu option 'a'"):
                continue
            update_notable_status(backfill_key=BACKFILL_KEY)

        elif choice == "n":
            print("##############################################")
            print("############ Change Backfill Identifier ############")
            BACKFILL_KEY = get_backfill_key_from_pointer()

        elif choice == 'o':
            # Show current search status for the active BACKFILL_KEY
            pointer_file = POINTER_FILE  # or TEST_POINTER_FILE if you want to branch
            pointer_data = load_pointer(pointer_file)
            runs = pointer_data.get("runs", [])
            run_record = next((r for r in runs if r.get("backfill_key") == BACKFILL_KEY), None)

            if not run_record:
                print(f"No run record found for backfill_key='{BACKFILL_KEY}' in {pointer_file}")
            else:
                idx = run_record.get("last_search_index", 0)
                last_window = run_record.get("last_window_start", BACKFILL_START)
                status = run_record.get("status", "unknown")
                mode = run_record.get("mode", "full")

                print("######## Current Pointer Status ########")
                print(f"Backfill key      : {BACKFILL_KEY}")
                print(f"Mode              : {mode}")
                print(f"Status            : {status}")
                print(f"Last search index : {idx}")
                print(f"Last window start : {last_window} "
                    f"({datetime.utcfromtimestamp(last_window)} UTC)")
                # Try to resolve next search name
                try:
                    with open(ACTIVE_SEARCHES_FILE) as f:
                        searches = json.load(f)
                    if 0 <= idx < len(searches):
                        next_search = searches[idx].get("content", {}).get(
                            "action.correlationsearch.label",
                            searches[idx].get("name", "Unknown Search")
                        )
                    else:
                        next_search = "None (index beyond list)"
                except Exception:
                    next_search = "Unknown (could not load active searches)"
                print(f"Next search name  : {next_search}")
       
        elif choice == 'r':
            print(resume_logging)
            if is_test_pointer(BACKFILL_KEY, "menu option 'a'"):
                continue
            run_backfill(backfill_key=BACKFILL_KEY)
            
        elif choice == 't':
            print(resume_logging)
            # Test Run - Get: get only filtered searches and limit backfill
            test_run()
            logging.info("Test backfill run completed. Review JSON/TXT output before ingest.")
        
        elif choice == 'u':
            print(resume_logging)
            # Load test pointer to get test key
            if os.path.exists(TEST_POINTER_FILE):
                with open(TEST_POINTER_FILE, "r") as f:
                    pointer_data = json.load(f)

                # New format: use active_backfill_key, fallback to first run
                test_key = pointer_data.get("active_backfill_key")
                if not test_key:
                    runs = pointer_data.get("runs", [])
                    if runs:
                        test_key = runs[0].get("backfill_key")

                if not test_key:
                    print("Test pointer file is missing a valid backfill_key. Please run 't' again.")
                    return

                test_notable_file = notable_events_txt_path(test_key, mode="test")
                test_risk_txt = risk_events_txt_path(test_key, mode="test")

                ingest_notables(file_path=test_notable_file, backfill_key=test_key)
                ingest_risk(file_path=test_risk_txt, backfill_key=test_key)
                update_notable_status(backfill_key=test_key)
            else:
                print("No test run found. Please run 't' first.")

        elif choice == 'x':
            print("Exiting script.")
            break
        else:
            logging.info("Invalid option.")

# ===============================
# Main Execution
# ===============================
def main():
    global BACKFILL_KEY
    logging.info("Starting Splunk Backfill Script (v9.3.3)")
    BACKFILL_KEY = get_backfill_key_from_pointer()
    menu()

if __name__ == "__main__":
    main()