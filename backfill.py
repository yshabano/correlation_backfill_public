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
    splunk_pass = getpass.getpass(
        f"\n\n##### Enter password for Splunk user '{splunk_user}' (input hidden): "
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
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=4)
    print(f"[INFO] Updated {CONFIG_PATH}")

def secure_my_creds(cfg):
    splunk_server = cfg.get("SPLUNK_SERVER")
    print("=== One-time credential setup for backfill ===")

    # Admin creds, used only to write the HEC token into storage/passwords
    admin_user = input("Splunk admin username (for 8089 REST): ").strip()
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
    # If already exists, you may want to delete or skip; for now just try to create
    service.storage_passwords.create(
        password=hec_token,
        realm="backfill_hec",
        username="hec_token",
    )

    # Remove any old cleartext fields
    cfg.pop("SPLUNKPASS", None)
    cfg.pop("HEC_TOKEN", None)

    # Store pointer only for HEC token
    cfg["HEC_TOKEN_SECRET"] = {
        "realm": "backfill_hec",
        "username": "hec_token",
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

#define global for fallback behavior
global POINTER_FILE,BACKFILL_EVENTS_FILE,ACTIVE_SEARCHES_FILE,RISK_EVENTS_FILE,NOTABLE_EVENTS_TXT,RISK_EVENTS_TXT

POINTER_FILE = os.path.join(LOG_DIR,"backfill_pointer.json")
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
BACKFILL_FILTER_CONFIG = "backfill_search_filters.json"
BACKFILL_SEARCH_NAME_ALLOWLIST = set()

if os.path.exists(BACKFILL_FILTER_CONFIG):
    try:
        with open(BACKFILL_FILTER_CONFIG) as f:
            backfill_cfg = json.load(f)
        BACKFILL_SEARCH_NAME_ALLOWLIST = set(
            backfill_cfg.get("search_name_allowlist", [])
        )
        logging.info(
            f"Loaded {len(BACKFILL_SEARCH_NAME_ALLOWLIST)} search names from {BACKFILL_FILTER_CONFIG}"
        )
    except Exception as e:
        logging.error(f"Failed to load {BACKFILL_FILTER_CONFIG}: {e}")

TEST_FILTER_CONFIG = "backfill_test_filters.json"
TEST_SEARCH_NAME_ALLOWLIST = set()


if os.path.exists(TEST_FILTER_CONFIG):
    try:
        with open(TEST_FILTER_CONFIG) as f:
            test_cfg = json.load(f)
        TEST_SEARCH_NAME_ALLOWLIST = set(test_cfg.get("search_name_allowlist", []))
        logging.info(f"Loaded {len(TEST_SEARCH_NAME_ALLOWLIST)} test search names from {TEST_FILTER_CONFIG}")
    except Exception as e:
        logging.error(f"Failed to load {TEST_FILTER_CONFIG}: {e}")

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
        return lambda now_epoch: now_epoch

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
            f.write("search_name,window_start,window_end,results_returned,per_search_window_seconds\n")

# # # # ===============================
# # # # Determine Search windows
# # # # ===============================
def compute_window_seconds_from_dispatch(disp_earliest, disp_latest):
    """
    Compute window size (in seconds) from dispatch.earliest_time and dispatch.latest_time.
    Both are expected to be relative time strings (no absolute, no infinity).
    If parsing fails, returns default 30m window.
    """

    DEFAULT_WINDOW_SECONDS = 1800

    if not disp_earliest or not disp_latest:
        logging.warning(f"Missing dispatch times '{disp_earliest}'/'{disp_latest}', "
                        f"using default 30m window")
        return DEFAULT_WINDOW_SECONDS

    try:
        earliest_fn = parse_relative_time_spec(disp_earliest)
        latest_fn = parse_relative_time_spec(disp_latest)
    except Exception as e:
        logging.warning(f"Unable to parse dispatch times '{disp_earliest}'/'{disp_latest}', "
                        f"using default 30m window")
        return DEFAULT_WINDOW_SECONDS

    # Use current time as reference. Only the difference matters.
    now_epoch = int(time.time())
    e_epoch = earliest_fn(now_epoch)
    l_epoch = latest_fn(now_epoch)

    window_seconds = int(l_epoch - e_epoch)
    if window_seconds <= 0:
        logging.warning(f"Computed non-positive window ({window_seconds}) from "
                        f"'{disp_earliest}'/'{disp_latest}', using default 30m window.")
        return DEFAULT_WINDOW_SECONDS
    logging.debug(f"Derived window_seconds={window_seconds} from "
                  f"earliest='{disp_earliest}', latest='{disp_latest}'")
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
            response = requests.post(
                hec_url,
                headers=headers,
                data=json.dumps(payload),
                verify=verify_ssl
            )
            if response.status_code != 200:
                logging.error(f"HEC ingest error: {response.status_code} {response.text}")
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
        "search": active_search_filter
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
    except Exception as e:
        logging.error(f"Error appending to {events_file}: {e}")

def run_backfill(backfill_key=None, pointer_file=None, events_file=None, active_file=None, risk_file=None, backfill_end=None, per_search_window_limit=None):
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

    for idx, s in enumerate(searches[last_index:], start=last_index):
        content = s.get("content", {})
        search_name = s.get("name")
        rule_title =  content.get("action.correlationsearch.label")

        # Determine mode based on which pointer file you're using
        is_test_run = (pointer_file == TEST_POINTER_FILE)

        if is_test_run:
            # Apply TEST_SEARCH_NAME_ALLOWLIST only for test runs
            if TEST_SEARCH_NAME_ALLOWLIST:
                if (
                    search_name not in TEST_SEARCH_NAME_ALLOWLIST
                    and rule_title not in TEST_SEARCH_NAME_ALLOWLIST
                ):
                    continue
        else:
            # Apply BACKFILL_SEARCH_NAME_ALLOWLIST only for full runs
            if BACKFILL_SEARCH_NAME_ALLOWLIST:
                if (
                    search_name not in BACKFILL_SEARCH_NAME_ALLOWLIST
                    and rule_title not in BACKFILL_SEARCH_NAME_ALLOWLIST
                ):
                    continue
                
        # always start at 0 per search
        local_breaker = 0
        
        # Set the current search name variable
        current_search_name = s.get("content", {}).get("action.notable.param.rule_title") \
            or s.get("content", {}).get("action.correlationsearch.label") \
            or s.get("name", "Unknown Search")
        
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
                debug("Running test portion of backfill", level=1)

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
                    time.sleep(2)
                
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
                append_to_backfill_file(result_data, events_file)
                logging.info(f"Appended {len(result_data)} records to {events_file}.")

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
                                f'"{current_search_name}",'
                                f"{human_start},{human_end},{results_count},{per_search_window}\n"
                            )
                except Exception as e:
                    logging.warning(f"Failed to write window log entry: {e}")


                # Update pointer after successful window
                upsert_run_record(
                    backfill_key=backfill_key,
                    mode="full" if pointer_file == POINTER_FILE else "test",
                    backfill_start=BACKFILL_START,
                    backfill_end=backfill_end or BACKFILL_END,
                    last_search_index=idx,
                    last_window_start=start_time,
                    pointer_file=pointer_file
                )
                logging.info(f"Pointer updated after successful window [{window_start}-{window_end}].")

            except Exception as e:
                logging.error(f"Error processing search window {start_time}-{window_end}: {e}", exc_info=True)
                break  # Stop current search loop if error
            
            start_time = window_end
            local_breaker += 1

    logging.info(f"Backfill completed. All results stored in {events_file}.")

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
        logging.error(f"No backfill events file found: {events_file}")
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
        logging.error(f"Backfill events file not found: {events_file}")
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
                "_time": int(time.time()),  # current epoch
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

            risk_events.append(risk_event)
            total_risk_count += 1

    # Write all risk events to file
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
            logging.error("No backfill events file found.")
            return
    with open(textfile, "w") as out:
        for e in data:
            # Try to get orig_time and convert to epoch
            orig_time_str = e.get("orig_time")
            epoch_time = None
            if orig_time_str:
                try:
                    # Handle both timezone-aware and 'Z' UTC ISO formats
                    if orig_time_str.endswith("Z"):
                        dt = datetime.fromisoformat(orig_time_str.replace("Z", "+00:00"))
                    else:
                        dt = datetime.fromisoformat(orig_time_str)
                    epoch_time = int(dt.timestamp())
                except Exception:
                    logging.warning(f"Unable to parse orig_time '{orig_time_str}', using system time")
                    epoch_time = int(time.time())
            else:
                epoch_time = int(time.time())

            # Use orig_time as the _time value
            parts = [str(epoch_time)]
            parts += [f'{k}="{v}"' for k, v in e.items() if k != "_time"]
            line = ", ".join(parts).replace("\\", "")
            out.write(line + "\n")
            
    logging.info(f"Generated {textfile} successfully.")

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
                      pointer_file=POINTER_FILE):
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
        })

    pointer_data["runs"] = runs
    pointer_data["active_backfill_key"] = backfill_key
    save_pointer(pointer_data, pointer_file=pointer_file)

# ===============================
# Upload Notable events, and change their status to specified value
# ===============================
def ingest_notables(file_path,backfill_key):
    assert_backfill_key_present_in_file(backfill_key, json_path=None, txt_path=file_path)
    hec_url = config.get("HEC_URL")
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
     resume_logging="\n\n##############################################\n#######################\n# Resume Logging\n#######################"

     while True:
        print("\n\n##############################################\n#######################\n# Main Menu\n#######################")
        print("#\n# Welcome to Splunk Correlation Search Backfill Script!")
        print("# This script currently outputs Notable Events with time the search ran (today), while Risk events are backdated to time of event\n#")
        print(f"# Current backfill identifier: {BACKFILL_KEY}")
        print("# a) Run All (b-g)")
        print("# b) Get Active Searches")
        print("# c) Start Backfill")
        print("# d) Generate Notable Events")
        print("# e) Generate Risk Events")
        print("# f) Ingest Notable events")
        print("# g) Ingest Risk events")

        print("#\n#######################\n# Update after verification of events in Analyst queue: \n#######################")
        print("# h) Bulk Update Notable Event status")

        print("#\n#######################\n# Additional Options: \n#######################")
        print("# i) Change Backfill Identifier")
        print("# r) Restart Backfill from Pointer - you will need to run d, e, f, g, and h manually afterwards.")
               
        print("#\n#######################\n# Testing Option: \n#######################")
        print("# t) Test Run - Get - (get all searches defined in filter OR only retrieve the first 3 searches backfill and use 2 search windows only)")
        print("# u) Test Run - Push - (push results from test run to Splunk, and update event status for these)")

        print("#\n#######################\n# EXIT \n#######################")
        print("# x) To Exit Script")
        print("\n\n##############################################\n")
        choice = input("Select an option: ").lower()

        if choice == 'a':
            print(resume_logging)
            get_active_correlation_searches(active_search_filter=CORRELATION_SEARCH_FILTER)
            init_window_log(BACKFILL_WINDOW_LOG)
            run_backfill(backfill_key=BACKFILL_KEY)
            generate_notable_events(textfile=NOTABLE_EVENTS_TXT,events_file=BACKFILL_EVENTS_FILE)
            generate_risk_events(textfile=RISK_EVENTS_TXT,events_file=BACKFILL_EVENTS_FILE)
    
            # Skip ingest if no notables file or empty
            if not (NOTABLE_EVENTS_TXT and os.path.exists(NOTABLE_EVENTS_TXT) and os.path.getsize(NOTABLE_EVENTS_TXT) > 0):
                logging.info("No notable events generated; skipping ingest_notables and status update.")
            else:
                ingest_notables(file_path=NOTABLE_EVENTS_TXT, backfill_key=BACKFILL_KEY)
                ingest_risk(file_path=RISK_EVENTS_TXT, backfill_key=BACKFILL_KEY)
        
        elif choice == 'b':
            print(resume_logging)
            get_active_correlation_searches(active_search_filter=CORRELATION_SEARCH_FILTER)
       
        elif choice == 'c':
            print(resume_logging)
            init_window_log(BACKFILL_WINDOW_LOG)
            run_backfill(backfill_key=BACKFILL_KEY)
       
        elif choice == 'r':
            print(resume_logging)
            # Disallow resuming test runs with 'r'
            if BACKFILL_KEY.startswith(TEST_SUFFIX + "_"):
                print(f"Current backfill identifier '{BACKFILL_KEY}' is a test run.")
                print("Use test options (t/u) or change the backfill identifier (option i) before resuming.")
                logging.warning(f"Refused to resume backfill for test key '{BACKFILL_KEY}' via 'r'.")
            else:
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

        elif choice == 'd':
            print(resume_logging)
            generate_notable_events()
        elif choice == 'e':
            print(resume_logging)
            generate_risk_events()
        elif choice == 'f':
            print(resume_logging)
            ingest_notables(file_path=NOTABLE_EVENTS_TXT, backfill_key=BACKFILL_KEY)
        elif choice == 'g':
            print(resume_logging)
            ingest_risk(file_path=RISK_EVENTS_TXT, backfill_key=BACKFILL_KEY)
        elif choice == 'h':
            print(resume_logging)
            update_notable_status(backfill_key=BACKFILL_KEY)

        elif choice == "i":
            print("##############################################")
            print("############ Change Backfill Identifier ############")
            BACKFILL_KEY = get_backfill_key_from_pointer()

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