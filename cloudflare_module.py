# cloudflare_module.py

import os
import time
import requests
from datetime import datetime, timedelta
from typing import List

# --- Configuración desde .env ---
CF_API_TOKEN       = os.getenv("CF_API_TOKEN")
VT_API_KEY         = os.getenv("VT_API_KEY")
UMBRAL_VT          = int(os.getenv("VT_THRESHOLD", 2))
LOOKBACK_MINUTES   = int(os.getenv("CF_LOOKBACK_MINUTES", 15))

# Paths
MODULE_DIR         = os.path.dirname(__file__)
VT_CACHE           = os.path.join(MODULE_DIR, "vt_checked.txt")
BLOCKED_IPS_FILE   = os.path.join(MODULE_DIR, "blocked_ips.txt")

# Headers Cloudflare
CF_HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json"
}


def _get_zones() -> dict:
    url = "https://api.cloudflare.com/client/v4/zones"
    zonas, page, per_page = {}, 1, 50

    while True:
        resp = requests.get(
            url,
            headers=CF_HEADERS,
            params={"page": page, "per_page": per_page},
            timeout=15
        ).json()

        if not resp.get("success", False):
            raise RuntimeError(f"Cloudflare error: {resp.get('errors')}")

        for z in resp["result"]:
            zonas[z["name"]] = z["id"]

        info = resp.get("result_info", {})
        total_pages = info.get("total_pages", 1)
        if page >= total_pages:
            break
        page += 1

    return zonas


def _query_firewall_events(zone_id: str) -> List[str]:
    fecha_min = (
        datetime.utcnow() - timedelta(minutes=LOOKBACK_MINUTES)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    gql = {
        "query": f"""
        query {{
          viewer {{
            zones(filter: {{zoneTag: "{zone_id}"}}) {{
              firewallEventsAdaptive(
                limit: 100,
                filter: {{ datetime_geq: "{fecha_min}", action_neq: "block" }}
              ) {{
                clientIP action
              }}
            }}
          }}
        }}"""
    }

    r = requests.post(
        "https://api.cloudflare.com/client/v4/graphql",
        headers=CF_HEADERS,
        json=gql,
        timeout=15
    )
    data = r.json()["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
    return list({e["clientIP"] for e in data if e["action"] != "block"})


def _is_malicious(ip: str) -> bool:
    # 1) Cache VT
    checked = set()
    if os.path.isfile(VT_CACHE):
        with open(VT_CACHE, "r") as f:
            checked = {line.strip() for line in f if line.strip()}

    if ip in checked:
        # Ya comprobada → no volver a VT
        return False

    # 2) Llamada a VT
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    resp = requests.get(vt_url, headers={"x-apikey": VT_API_KEY}, timeout=15)
    mal = False
    if resp.status_code == 200:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        mal   = stats.get("malicious", 0) >= UMBRAL_VT

    # 3) Guardar en cache temporal VT
    with open(VT_CACHE, "a") as f:
        f.write(ip + "\n")

    return mal


def _block_in_cf(ip: str, zone_id: str):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
    payload = {
        "mode": "block",
        "configuration": {"target": "ip", "value": ip},
        "notes": "Auto-block VT ≥ threshold"
    }
    requests.post(url, json=payload, headers=CF_HEADERS, timeout=15)


def collect_ips() -> List[str]:
    """
    Recorre zonas, filtra eventos recientes, verifica en VT y bloquea en CF.
    No verifica en VT IPs ya listadas en blocked_ips.txt.
    """
    # Cargar histórico de bloqueos
    historico = set()
    if os.path.isfile(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            historico = {line.strip() for line in f if line.strip()}

    maliciosas = []
    for zone_name, zone_id in _get_zones().items():
        for ip in _query_firewall_events(zone_id):
            # Saltar IPs ya bloqueadas históricamente
            if ip in historico:
                continue

            if _is_malicious(ip):
                _block_in_cf(ip, zone_id)
                maliciosas.append(ip)
                historico.add(ip)
                time.sleep(1)

    return maliciosas
