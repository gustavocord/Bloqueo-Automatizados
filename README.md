# Bloqueo-Automatizados

Automatiza el bloqueo de IPs maliciosas detectadas en Cloudflare y su registro en Trend Micro Vision One.

## 🗂️ Estructura

```
Bloqueo-Automatizados/
├── cloudflare_module.py    # Extrae y bloquea IPs en Cloudflare
├── visionone_module.py     # Envía y verifica IPs en Vision One
├── main.py                 # Orquesta el flujo completo
├── blocked_ips.txt         # Historial de IPs bloqueadas (no versionar)
├── vt_checked.txt          # Cache de IPs consultadas en VT (no versionar)
├── .env                    # Variables de entorno con credenciales
├── requirements.txt        # Dependencias
└── .gitignore              # Archivos a ignorar
```

## ⚙️ Requisitos

* Python 3.8 o superior
* requests
* python-dotenv

## 🔧 Instalación

```bash
git clone https://github.com/<usuario>/Bloqueo-Automatizados.git
cd Bloqueo-Automatizados
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## ⚙️ Configuración

Crear un archivo `.env` con:

```dotenv
CF_API_TOKEN=...
VT_API_KEY=...
TMVO_API_KEY=...
TMVO_ENDPOINT=https://api.xdr.trendmicro.com
CF_LOOKBACK_MINUTES=15
VT_THRESHOLD=2
```

> No versionar `.env`, `blocked_ips.txt` ni `vt_checked.txt`.

## 🚀 Uso

### Ejecución manual

```bash
python main.py
```

### Cron (cada 15 min)

```cron
*/15 * * * * cd /ruta/al/proyecto && venv/bin/python main.py >> cron.log 2>&1
```

## 🌲 .gitignore

```
venv/
.venv/
*.pyc
__pycache__/
.env
blocked_ips.txt
vt_checked.txt
cron.log
```

## 📄 Licencia

MIT © 2025
