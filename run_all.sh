#!/usr/bin/env bash
# run_all.sh - MITRE Mapper: her şeyi sırayla başlatır.
#
#   1) Ollama (Qwen için)      -> kapalıysa başlatır, hazır olana kadar bekler
#   2) soc_api.py (dashboard)  -> arka planda, http://127.0.0.1:8765
#   3) Arayüz                  -> tarayıcıda dashboard (veya --gui ile Tkinter)
#   4) live_soc.py             -> ön planda; Ctrl+C ile hepsi kapanır
#
# Kullanım:
#   ./run_all.sh              # web dashboard
#   ./run_all.sh --gui        # Tkinter arayüzü
#   ./run_all.sh --no-open    # tarayıcıyı otomatik açma
#   PORT=9000 ./run_all.sh    # farklı port
#
# live_soc.py proje klasöründe (bu dosyayla aynı yerde) olmalı.

set -u

cd "$(dirname "$0")" || exit 1
ROOT="$(pwd)"
LOG_DIR="$ROOT/logs"
mkdir -p "$LOG_DIR"

PORT="${PORT:-8765}"
OLLAMA_URL="http://127.0.0.1:11434"
USE_GUI=0
OPEN_BROWSER=1

for arg in "$@"; do
  case "$arg" in
    --gui)      USE_GUI=1 ;;
    --no-open)  OPEN_BROWSER=0 ;;
    -h|--help)  sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "Bilinmeyen argüman: $arg"; exit 1 ;;
  esac
done

# --- Python (.venv varsa onu kullan) ---------------------------------
if [ -x "$ROOT/.venv/bin/python" ]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="$(command -v python3 || command -v python)"
fi
[ -z "${PY:-}" ] && { echo "Python bulunamadı."; exit 1; }

# --- Ön kontroller ----------------------------------------------------
for f in live_soc.py soc_store.py soc_api.py dashboard.html soc_gui.py; do
  [ -f "$ROOT/$f" ] || { echo "Eksik dosya: $f"; exit 1; }
done

PIDS=()
STARTED_OLLAMA=0

# Yerel adreslere giderken proxy/VPN ortam değişkenlerini yok say.
probe() { curl -s -o /dev/null --noproxy '*' --max-time 3 "$1"; }

cleanup() {
  echo
  echo "Kapatılıyor..."
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  wait 2>/dev/null
  echo "Bitti."
}
trap cleanup EXIT INT TERM

# --- 1) Ollama --------------------------------------------------------
echo "[1/4] Ollama kontrol ediliyor..."
if probe "$OLLAMA_URL/api/tags"; then
  echo "      Ollama zaten çalışıyor."
elif command -v ollama >/dev/null 2>&1; then
  echo "      Ollama başlatılıyor (log: logs/ollama.log)..."
  ollama serve > "$LOG_DIR/ollama.log" 2>&1 &
  PIDS+=($!)
  STARTED_OLLAMA=1
  for i in $(seq 1 30); do
    if probe "$OLLAMA_URL/api/tags"; then
      echo "      Ollama hazır."
      break
    fi
    sleep 1
    [ "$i" -eq 30 ] && echo "      UYARI: Ollama 30 sn içinde hazır olmadı; MITRE analizi hata verebilir."
  done
else
  echo "      UYARI: 'ollama' bulunamadı. MITRE (Qwen) analizi çalışmayacak."
  echo "      Kurulum: brew install ollama"
fi

# --- 2) API / dashboard sunucusu -------------------------------------
if [ "$USE_GUI" -eq 0 ]; then
  echo "[2/4] Dashboard sunucusu başlatılıyor (port $PORT, log: logs/api.log)..."
  # -u: çıktıyı tamponlama, log anında yazılsın.
  "$PY" -u "$ROOT/soc_api.py" --host 0.0.0.0 --port "$PORT" > "$LOG_DIR/api.log" 2>&1 &
  API_PID=$!
  PIDS+=($API_PID)

  READY=0
  for i in $(seq 1 15); do
    if ! kill -0 "$API_PID" 2>/dev/null; then
      echo "      HATA: soc_api.py kendiliğinden kapandı. Son log:"
      sed 's/^/      | /' "$LOG_DIR/api.log"
      exit 1
    fi
    # 0.0.0.0 yerine 127.0.0.1 üzerinden health check yapıyoruz
    if probe "http://127.0.0.1:$PORT/api/health"; then READY=1; break; fi
    sleep 1
  done

  if [ "$READY" -ne 1 ]; then
    echo "      HATA: sunucu process olarak çalışıyor ama $PORT portundan cevap vermiyor."
    echo "      Port durumu:"
    lsof -nP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | sed 's/^/      | /' || true
    echo "      Proxy değişkenleri:"
    env | grep -i -E '^(http|https|all|no)_proxy=' | sed 's/^/      | /' || true
    echo "      Log:"
    sed 's/^/      | /' "$LOG_DIR/api.log"
    exit 1
  fi
  echo "      http://127.0.0.1:$PORT hazır."
else
  echo "[2/4] --gui seçildi, web sunucusu atlandı."
fi

# --- 3) Arayüz --------------------------------------------------------
if [ "$USE_GUI" -eq 1 ]; then
  echo "[3/4] Tkinter arayüzü açılıyor..."
  "$PY" "$ROOT/soc_gui.py" > "$LOG_DIR/gui.log" 2>&1 &
  PIDS+=($!)
elif [ "$OPEN_BROWSER" -eq 1 ]; then
  echo "[3/4] Tarayıcı açılıyor..."
  if command -v open >/dev/null 2>&1; then
    # MacOS üzerinde about:blank açmaması için 0.0.0.0 yerine 127.0.0.1
    open "http://127.0.0.1:$PORT"
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:$PORT" >/dev/null 2>&1
  else
    echo "      Tarayıcıyı elle aç: http://127.0.0.1:$PORT"
  fi
else
  echo "[3/4] Tarayıcı otomatik açılmadı (--no-open)."
fi

# --- 4) live_soc.py (ön planda) --------------------------------------
echo "[4/4] live_soc.py başlatılıyor. (Ağ dinlemek için MacOS parolanızı isteyebilir) Durdurmak için Ctrl+C."
echo "------------------------------------------------------------"
# Ağ arayüzünü (en0) dinlemek root yetkisi gerektirdiği için sudo ekledik
sudo "$PY" "$ROOT/live_soc.py"