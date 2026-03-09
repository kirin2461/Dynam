#!/bin/bash
# ============================================================================
#  NCP (Network Control Protocol) — Установщик зависимостей (Linux/macOS)
# ============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

NCP_ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$NCP_ROOT/build"
WEB_DIR="$NCP_ROOT/web"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           NCP — Network Control Protocol                    ║${NC}"
echo -e "${CYAN}║           Установка зависимостей и сборка                   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# --- Определяем ОС ---
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
fi

echo "[*] ОС: $OS"
echo "[*] Корневая папка: $NCP_ROOT"
echo ""

# ============================================================================
# ШАГ 1: Установка системных зависимостей
# ============================================================================
echo "════════════════════════════════════════════════════════════════"
echo " ШАГ 1/5: Установка системных зависимостей"
echo "════════════════════════════════════════════════════════════════"

if [[ "$OS" == "linux" ]]; then
    if command -v apt-get &> /dev/null; then
        echo "[*] Debian/Ubuntu detected"
        sudo apt-get update -qq
        sudo apt-get install -y \
            build-essential cmake git \
            libsodium-dev libssl-dev libsqlite3-dev \
            libgtest-dev nlohmann-json3-dev \
            libnetfilter-queue-dev \
            python3 python3-pip python3-venv \
            pkg-config
    elif command -v dnf &> /dev/null; then
        echo "[*] Fedora/RHEL detected"
        sudo dnf install -y \
            gcc-c++ cmake git \
            libsodium-devel openssl-devel sqlite-devel \
            gtest-devel json-devel \
            libnetfilter_queue-devel \
            python3 python3-pip \
            pkgconfig
    elif command -v pacman &> /dev/null; then
        echo "[*] Arch Linux detected"
        sudo pacman -Sy --noconfirm \
            base-devel cmake git \
            libsodium openssl sqlite \
            gtest nlohmann-json \
            libnetfilter_queue \
            python python-pip
    fi
elif [[ "$OS" == "macos" ]]; then
    if ! command -v brew &> /dev/null; then
        echo "[*] Устанавливаю Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install cmake libsodium openssl sqlite googletest nlohmann-json python@3.12
fi

echo -e "${GREEN}[OK] Системные зависимости установлены${NC}"
echo ""

# ============================================================================
# ШАГ 2: Сборка NCP
# ============================================================================
echo "════════════════════════════════════════════════════════════════"
echo " ШАГ 2/5: Сборка NCP"
echo "════════════════════════════════════════════════════════════════"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "[*] Конфигурирую CMake..."
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_TESTS=ON \
    -DHAVE_OPENSSL=ON \
    2>&1 || {
        echo -e "${YELLOW}[!] CMake конфигурация не полная. Пробую минимальную...${NC}"
        cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON
    }

echo "[*] Собираю проект..."
cmake --build . --config Release --parallel $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo -e "${GREEN}[OK] NCP собран${NC}"
cd "$NCP_ROOT"
echo ""

# ============================================================================
# ШАГ 3: Python зависимости
# ============================================================================
echo "════════════════════════════════════════════════════════════════"
echo " ШАГ 3/5: Python зависимости (веб-интерфейс)"
echo "════════════════════════════════════════════════════════════════"

python3 -m venv "$WEB_DIR/venv"
source "$WEB_DIR/venv/bin/activate"
pip install --upgrade pip -q
pip install -r "$WEB_DIR/requirements.txt" -q
deactivate

echo -e "${GREEN}[OK] Python зависимости установлены${NC}"
echo ""

# ============================================================================
# ШАГ 4: Конфигурация
# ============================================================================
echo "════════════════════════════════════════════════════════════════"
echo " ШАГ 4/5: Создание конфигурации"
echo "════════════════════════════════════════════════════════════════"

CONFIG_DIR="$HOME/.config/ncp"
mkdir -p "$CONFIG_DIR"

if [ ! -f "$CONFIG_DIR/config.json" ]; then
    cp "$NCP_ROOT/config_default.json" "$CONFIG_DIR/config.json" 2>/dev/null || \
    cat > "$CONFIG_DIR/config.json" << 'CONFIGEOF'
{
  "general": {"auto_start": false, "log_level": "INFO", "language": "ru"},
  "dpi": {"enabled": true, "strategy": "balanced", "tcp_fragmentation": true, "tls_record_splitting": true, "ttl_manipulation": true, "fake_packets": false, "packet_disorder": false, "sni_spoofing": false},
  "network": {"dns_provider": "cloudflare", "dns_over_https": true, "ech_enabled": false},
  "e2e": {"enabled": false, "post_quantum": false},
  "geneva": {"auto_evolve": false, "population_size": 50, "mutation_rate": 0.1, "preset": "tspu_2026"},
  "mimicry": {"protocol": "https", "tls_fingerprint": "chrome", "flow_profile": "web_browsing"},
  "i2p": {"enabled": false, "sam_port": 7656, "tunnel_hops": 3},
  "paranoid": {"enabled": false, "ram_only_mode": false, "wipe_on_exit": true},
  "web": {"port": 8080, "bind_address": "127.0.0.1"}
}
CONFIGEOF
    echo -e "${GREEN}[OK] Конфигурация создана: $CONFIG_DIR/config.json${NC}"
else
    echo "[OK] Конфигурация уже существует"
fi
echo ""

# ============================================================================
# ШАГ 5: Скрипты запуска
# ============================================================================
echo "════════════════════════════════════════════════════════════════"
echo " ШАГ 5/5: Создание скриптов запуска"
echo "════════════════════════════════════════════════════════════════"

cat > "$NCP_ROOT/run_ncp.sh" << 'RUNEOF'
#!/bin/bash
NCP_ROOT="$(cd "$(dirname "$0")" && pwd)"
source "$NCP_ROOT/web/venv/bin/activate"
echo ""
echo "  NCP запущен. Веб-интерфейс: http://127.0.0.1:8080"
echo "  Нажмите Ctrl+C для остановки."
echo ""
python "$NCP_ROOT/web/server.py" &
WEB_PID=$!
sleep 2
if command -v xdg-open &> /dev/null; then xdg-open http://127.0.0.1:8080
elif command -v open &> /dev/null; then open http://127.0.0.1:8080; fi
wait $WEB_PID
RUNEOF
chmod +x "$NCP_ROOT/run_ncp.sh"

cat > "$NCP_ROOT/run_tests.sh" << 'TESTEOF'
#!/bin/bash
cd "$(dirname "$0")/build"
ctest --build-config Release --output-on-failure --parallel $(nproc 2>/dev/null || echo 4)
TESTEOF
chmod +x "$NCP_ROOT/run_tests.sh"

echo -e "${GREEN}[OK] Созданы скрипты:${NC}"
echo "     - run_ncp.sh     (запуск NCP + веб-интерфейс)"
echo "     - run_tests.sh   (запуск тестов)"
echo ""

# ============================================================================
echo "════════════════════════════════════════════════════════════════"
echo -e " ${GREEN}УСТАНОВКА ЗАВЕРШЕНА${NC}"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  Запустить NCP:     ./run_ncp.sh"
echo "  Запустить тесты:   ./run_tests.sh"
echo "  Веб-интерфейс:     http://127.0.0.1:8080"
echo ""
