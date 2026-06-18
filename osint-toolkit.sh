#!/usr/bin/env bash
###############################################################################
#  OSINT TOOLKIT v3.0  --  Kali Linux  ·  HackShield (дипломный проект)
#
#  Новое в v3:
#   - конфиг API-ключей (~/.osint.conf): Shodan, VirusTotal, HIBP
#   - пассивные источники: crt.sh, Shodan InternetDB (без ключа), Wayback
#   - объединённый сбор поддоменов (sublist3r + subfinder + assetfinder + crt.sh)
#   - httpx: живые хосты со статусом, заголовком и технологиями
#   - скриншоты живых сайтов (gowitness / chromium headless)
#   - проверка subdomain takeover (nuclei)
#   - JSON-вывод + HTML-дашборд с галереей скринов + поиском
#   - PDF-отчёт (wkhtmltopdf / chromium)
#   - надёжность: проверка интернета, зависимостей, обработка ошибок
#
#  ВАЖНО: только открытая информация и РАЗРЕШЁННЫЕ цели (свои домены, CTF)!
###############################################################################
set -o pipefail

R="\e[31m"; G="\e[32m"; Y="\e[33m"; C="\e[36m"; W="\e[97m"; N="\e[0m"; BOLD="\e[1m"
OUT="$HOME/osint-results"; DATA="$OUT/data"; SHOTS="$OUT/screenshots"
mkdir -p "$DATA" "$SHOTS"

# ---------- конфиг API-ключей ----------
CONF="$HOME/.osint.conf"
if [ ! -f "$CONF" ]; then
  cat > "$CONF" <<EOF
# === OSINT API keys (бесплатные регистрации) ===
# Shodan:      https://account.shodan.io   (есть и бесплатный InternetDB без ключа)
# VirusTotal:  https://virustotal.com/gui/my-apikey
# HIBP:        https://haveibeenpwned.com/API/Key (платный)
SHODAN_KEY=""
VT_KEY=""
HIBP_KEY=""
EOF
  echo -e "${Y}[i] Создан конфиг ключей: $CONF (можно оставить пустым).${N}"
fi
# shellcheck disable=SC1090
source "$CONF" 2>/dev/null

# ---------- утилиты ----------
banner() {
  clear; echo -e "${C}${BOLD}"
  echo "  ╔══════════════════════════════════════════════╗"
  echo "  ║         O S I N T   T O O L K I T   v3        ║"
  echo "  ║      HackShield · Kali · Pro Edition          ║"
  echo "  ╚══════════════════════════════════════════════╝"
  echo -e "${N}${Y}  Результаты: ${W}$OUT${N}"
  echo -e "${R}  Только для разрешённых целей и открытой информации!${N}\n"
}
need() { command -v "$1" >/dev/null 2>&1 || { echo -e "${R}[!] '$1' нет (пункт 0).${N}"; return 1; }; }
have() { command -v "$1" >/dev/null 2>&1; }
pause() { echo; read -rp "$(echo -e "${C}Enter — назад...${N}")"; }
check_net() { ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 || { echo -e "${R}[!] Нет интернета.${N}"; return 1; }; }
grab_emails() { grep -aoE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u; }
grab_ips() { grep -aoE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u; }
html_esc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

# =============================================================================
#  0. УСТАНОВКА (apt + Go-инструменты)
# =============================================================================
install_tools() {
  banner; check_net || { pause; return; }
  echo -e "${G}[*] apt update...${N}"; sudo apt update
  echo -e "${G}[*] Базовые инструменты...${N}"
  sudo apt install -y whois dnsutils nmap theharvester dnsrecon dnsenum \
    whatweb wafw00f sublist3r sherlock recon-ng spiderfoot \
    libimage-exiftool-perl curl jq python3-pip pipx golang-go \
    chromium wkhtmltopdf 2>/dev/null
  echo -e "${G}[*] ProjectDiscovery / Go-инструменты (из apt, если есть)...${N}"
  sudo apt install -y subfinder httpx-toolkit nuclei assetfinder gowitness 2>/dev/null
  pipx ensurepath >/dev/null 2>&1
  pipx install holehe 2>/dev/null || true
  # fallback: go install для отсутствующих
  if have go; then
    export PATH="$PATH:$HOME/go/bin"
    have subfinder    || go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null
    have httpx        || go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null
    have assetfinder  || go install github.com/tomnomnom/assetfinder@latest 2>/dev/null
    have gau          || go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null
    grep -q 'go/bin' ~/.zshrc 2>/dev/null || echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc
  fi
  have nuclei && nuclei -update-templates -silent 2>/dev/null
  echo -e "\n${G}[+] Проверка:${N}"
  for t in whois dig nmap theHarvester whatweb wafw00f sublist3r subfinder assetfinder \
           httpx nuclei gowitness sherlock exiftool holehe chromium wkhtmltopdf curl jq; do
    have "$t" && echo -e "  ${G}ok $t${N}" || echo -e "  ${R}x  $t${N}"
  done
  echo -e "\n${Y}phoneinfoga — пункт 5. Ключи API — в $CONF${N}"; pause
}

# =============================================================================
#  1. ДОМЕН — ПОЛНАЯ РАЗВЕДКА (всё в data/<домен>/)
# =============================================================================
domain_recon() {
  banner; check_net || { pause; return; }
  read -rp "$(echo -e ${C}"Домен (example.com): "${N})" D
  [ -z "$D" ] && { echo -e "${R}Пусто.${N}"; pause; return; }
  export PATH="$PATH:$HOME/go/bin"
  local dir="$DATA/$D"; mkdir -p "$dir"
  echo -e "${G}[*] Полная разведка по $D ...${N}\n"

  # --- DNS (непустые) ---
  echo -e "${C}===== DNS =====${N}"; : > "$dir/dns.txt"
  if need dig; then
    for rec in A AAAA MX NS TXT SOA CNAME; do
      res=$(dig +short "$D" "$rec"); [ -n "$res" ] && echo -e "--- $rec ---\n$res" | tee -a "$dir/dns.txt"
    done
  fi
  dig +short "$D" A | grab_ips > "$dir/ips.txt"

  # --- веб-технологии + WAF ---
  echo -e "\n${C}===== Технологии / WAF =====${N}"
  have whatweb && whatweb -a 3 "$D" 2>/dev/null | tee "$dir/tech.txt"
  have wafw00f && wafw00f "$D" 2>/dev/null | grep -aiE 'is behind|seems to be|No WAF' | tee "$dir/waf.txt"

  # --- сбор поддоменов из всех источников ---
  echo -e "\n${C}===== Поддомены (sublist3r + subfinder + assetfinder + crt.sh) =====${N}"
  : > "$dir/subs_all.txt"
  have sublist3r   && sublist3r -d "$D" -o /tmp/_sl.txt >/dev/null 2>&1 && cat /tmp/_sl.txt >> "$dir/subs_all.txt"
  have subfinder   && subfinder -d "$D" -silent 2>/dev/null >> "$dir/subs_all.txt"
  have assetfinder && assetfinder --subs-only "$D" 2>/dev/null >> "$dir/subs_all.txt"
  # crt.sh (Certificate Transparency) — без ключа
  curl -s "https://crt.sh/?q=%25.$D&output=json" 2>/dev/null \
    | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' >> "$dir/subs_all.txt"
  sort -u "$dir/subs_all.txt" -o "$dir/subs_all.txt"
  echo -e "${Y}Уникальных поддоменов: $(wc -l < "$dir/subs_all.txt")${N}"

  # --- живые хосты через httpx ---
  echo -e "\n${C}===== Живые хосты (httpx) =====${N}"
  if have httpx && [ -s "$dir/subs_all.txt" ]; then
    httpx -silent -title -status-code -tech-detect -l "$dir/subs_all.txt" \
      2>/dev/null | tee "$dir/live.txt"
    grep -aoE 'https?://[^ ]+' "$dir/live.txt" | sort -u > "$dir/live_urls.txt"
  else
    # fallback: параллельный резолв
    cat "$dir/subs_all.txt" | xargs -P 20 -I{} bash -c \
      'ip=$(dig +short "{}" A 2>/dev/null|head -1); [ -n "$ip" ] && echo "https://{}"' \
      | sort -u | tee "$dir/live_urls.txt"
  fi
  echo -e "${Y}Живых: $(wc -l < "$dir/live_urls.txt" 2>/dev/null)${N}"

  # --- email через theHarvester ---
  echo -e "\n${C}===== Email =====${N}"
  have theHarvester && theHarvester -d "$D" -b duckduckgo,crtsh,bing -l 200 2>/dev/null \
    | grab_emails | tee "$dir/emails.txt"

  echo -e "\n${G}[+] Готово. Дальше: 6=скриншоты · 7=takeover · 8=Wayback · 9=VirusTotal · S=сводка · H=HTML · P=PDF${N}"
  pause
}

# =============================================================================
#  2. IP — с Shodan InternetDB (без ключа) и полным Shodan (с ключом)
# =============================================================================
ip_recon() {
  banner; check_net || { pause; return; }
  read -rp "$(echo -e ${C}"IP: "${N})" IP
  [ -z "$IP" ] && { echo -e "${R}Пусто.${N}"; pause; return; }
  local f="$OUT/ip_${IP}_$(date +%Y%m%d_%H%M%S).txt"
  {
    echo "===== Геолокация (ipinfo) ====="
    curl -s "https://ipinfo.io/$IP/json" | { have jq && jq . || cat; }
    echo -e "\n===== Shodan InternetDB (открытые порты/уязвимости, без ключа) ====="
    curl -s "https://internetdb.shodan.io/$IP" | { have jq && jq . || cat; }
    if [ -n "$SHODAN_KEY" ]; then
      echo -e "\n===== Shodan (полный, по ключу) ====="
      curl -s "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_KEY" | { have jq && jq '{org,os,ports,vulns,hostnames}' || cat; }
    fi
    echo -e "\n===== Reverse DNS ====="; dig +short -x "$IP"
    echo -e "\n===== nmap (топ-100) ====="; need nmap && sudo nmap -sS -F -T4 "$IP" | grep -aE '^[0-9]+/|open'
  } 2>&1 | tee "$f"
  echo -e "\n${G}[+] $f${N}"; pause
}

# =============================================================================
#  3. EMAIL (+ HIBP по ключу)
# =============================================================================
email_recon() {
  banner; read -rp "$(echo -e ${C}"Email: "${N})" E
  [ -z "$E" ] && { echo -e "${R}Пусто.${N}"; pause; return; }
  local f="$OUT/email_${E}_$(date +%Y%m%d_%H%M%S).txt"
  echo -e "${G}[*] Где зарегистрирован $E ...${N}\n"
  have holehe && holehe --only-used "$E" 2>/dev/null | tee "$f"
  if [ -n "$HIBP_KEY" ]; then
    echo -e "\n${C}===== Утечки (HaveIBeenPwned) =====${N}"
    curl -s -H "hibp-api-key: $HIBP_KEY" -H "user-agent: osint-toolkit" \
      "https://haveibeenpwned.com/api/v3/breachedaccount/$E?truncateResponse=false" \
      | { have jq && jq -r '.[].Name' || cat; } | tee -a "$f"
  else
    echo -e "\n${Y}HIBP-ключ не задан — проверь вручную: https://haveibeenpwned.com${N}"
  fi
  echo -e "${G}[+] $f${N}"; pause
}

# =============================================================================
#  4. USERNAME
# =============================================================================
username_recon() {
  banner; read -rp "$(echo -e ${C}"Username: "${N})" U
  [ -z "$U" ] && { echo -e "${R}Пусто.${N}"; pause; return; }
  echo -e "${G}[*] Ищу '$U' (только найденное)...${N}\n"
  need sherlock && sherlock "$U" --timeout 5 --folderoutput "$OUT" --print-found
  echo -e "\n${G}[+] $OUT/$U.txt${N}"; pause
}

# =============================================================================
#  5. PHONE
# =============================================================================
phone_recon() {
  banner
  if ! have phoneinfoga; then
    echo -e "${Y}phoneinfoga нет. Поставить? [y/N]${N}"; read -r ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      bash <(curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install)
      sudo mv ./phoneinfoga /usr/local/bin/ 2>/dev/null
    else pause; return; fi
  fi
  read -rp "$(echo -e ${C}"Номер (+77001234567): "${N})" P
  [ -z "$P" ] && { echo -e "${R}Пусто.${N}"; pause; return; }
  local f="$OUT/phone_$(date +%Y%m%d_%H%M%S).txt"
  phoneinfoga scan -n "$P" 2>&1 | tee "$f"; echo -e "\n${G}[+] $f${N}"; pause
}

# =============================================================================
#  6. СКРИНШОТЫ живых сайтов
# =============================================================================
screenshots() {
  banner; read -rp "$(echo -e ${C}"Домен (данные из пункта 1): "${N})" D
  local dir="$DATA/$D"
  [ ! -s "$dir/live_urls.txt" ] && { echo -e "${R}Нет живых хостов — сначала пункт 1.${N}"; pause; return; }
  local sdir="$SHOTS/$D"; mkdir -p "$sdir"
  echo -e "${G}[*] Делаю скриншоты живых сайтов...${N}"
  if have gowitness; then
    gowitness scan file -f "$dir/live_urls.txt" --screenshot-path "$sdir" 2>/dev/null \
      || gowitness file -f "$dir/live_urls.txt" -P "$sdir" 2>/dev/null
  elif have chromium; then
    local i=0
    while read -r url; do
      i=$((i+1)); fn="$sdir/$(echo "$url" | sed 's#https\?://##; s#[/:]#_#g').png"
      chromium --headless --disable-gpu --no-sandbox --window-size=1280,800 \
        --screenshot="$fn" "$url" >/dev/null 2>&1 &
      [ $((i % 5)) -eq 0 ] && wait
    done < "$dir/live_urls.txt"; wait
  else
    echo -e "${R}Нет gowitness/chromium (пункт 0).${N}"; pause; return
  fi
  ls "$sdir"/*.png >/dev/null 2>&1 && echo -e "${G}[+] Скрины: $sdir ($(ls "$sdir"/*.png 2>/dev/null | wc -l) шт)${N}"
  pause
}

# =============================================================================
#  7. SUBDOMAIN TAKEOVER (nuclei)
# =============================================================================
takeover() {
  banner; read -rp "$(echo -e ${C}"Домен: "${N})" D
  local dir="$DATA/$D"
  [ ! -s "$dir/subs_all.txt" ] && { echo -e "${R}Нет поддоменов — пункт 1.${N}"; pause; return; }
  if ! have nuclei; then echo -e "${R}nuclei не установлен (пункт 0).${N}"; pause; return; fi
  echo -e "${G}[*] Проверяю subdomain takeover...${N}\n"
  nuclei -l "$dir/subs_all.txt" -t http/takeovers/ -silent 2>/dev/null | tee "$dir/takeover.txt"
  [ -s "$dir/takeover.txt" ] && echo -e "${R}[!] Возможен takeover — см. выше!${N}" \
    || echo -e "${G}[+] Уязвимостей takeover не найдено.${N}"
  pause
}

# =============================================================================
#  8. WAYBACK (исторические URL)
# =============================================================================
wayback() {
  banner; check_net || { pause; return; }
  read -rp "$(echo -e ${C}"Домен: "${N})" D
  local dir="$DATA/$D"; mkdir -p "$dir"
  echo -e "${G}[*] Тяну архивные URL (web.archive.org)...${N}"
  curl -s "http://web.archive.org/cdx/search/cdx?url=*.$D/*&output=text&fl=original&collapse=urlkey&limit=1000" \
    2>/dev/null | sort -u | tee "$dir/wayback.txt"
  echo -e "\n${Y}Интересное (.json/.sql/.bak/.env/admin):${N}"
  grep -aiE '\.(json|sql|bak|env|config|log)$|admin|backup|api' "$dir/wayback.txt" 2>/dev/null | head -40
  echo -e "${G}[+] $dir/wayback.txt${N}"; pause
}

# =============================================================================
#  9. VIRUSTOTAL (репутация домена, по ключу)
# =============================================================================
virustotal() {
  banner; check_net || { pause; return; }
  [ -z "$VT_KEY" ] && { echo -e "${R}Нет VT_KEY в $CONF${N}"; pause; return; }
  read -rp "$(echo -e ${C}"Домен: "${N})" D
  local dir="$DATA/$D"; mkdir -p "$dir"
  curl -s --request GET --url "https://www.virustotal.com/api/v3/domains/$D" \
    --header "x-apikey: $VT_KEY" \
    | jq '{reputation: .data.attributes.reputation, analysis: .data.attributes.last_analysis_stats, categories: .data.attributes.categories}' \
    | tee "$dir/virustotal.txt"
  echo -e "${G}[+] $dir/virustotal.txt${N}"; pause
}

# =============================================================================
#  МЕТАДАННЫЕ / SPIDERFOOT
# =============================================================================
metadata_recon() {
  banner; read -rp "$(echo -e ${C}"Путь к файлу: "${N})" FILE
  [ ! -f "$FILE" ] && { echo -e "${R}Не найден.${N}"; pause; return; }
  local f="$OUT/meta_$(basename "$FILE")_$(date +%Y%m%d_%H%M%S).txt"
  need exiftool && exiftool "$FILE" 2>/dev/null \
    | grep -aiE 'GPS|Author|Creator|Software|Camera|Make|Model|Date|Owner|Company' | tee "$f"
  [ -s "$f" ] || echo -e "${Y}Чувствительных данных нет.${N}"
  echo -e "${G}[+] $f${N}"; pause
}
spiderfoot_start() {
  banner; need spiderfoot || { pause; return; }
  echo -e "${G}[*] SpiderFoot: http://127.0.0.1:5001 (Ctrl+C — стоп)${N}\n"
  spiderfoot -l 127.0.0.1:5001; pause
}

# =============================================================================
#  СВОДКА (txt)
# =============================================================================
make_summary() {
  banner; read -rp "$(echo -e ${C}"Домен: "${N})" D
  local dir="$DATA/$D"
  [ ! -d "$dir" ] && { echo -e "${R}Нет данных — пункт 1.${N}"; pause; return; }
  local sum="$OUT/SUMMARY_${D}_$(date +%Y%m%d).txt"
  {
    echo "########## OSINT СВОДКА: $D ##########"; echo "Дата: $(date)"
    echo -e "\n--- Email ---";        cat "$dir/emails.txt" 2>/dev/null
    echo -e "\n--- Живые хосты ---";  cat "$dir/live.txt" 2>/dev/null || cat "$dir/live_urls.txt" 2>/dev/null
    echo -e "\n--- IP ---";           cat "$dir/ips.txt" 2>/dev/null
    echo -e "\n--- DNS ---";          cat "$dir/dns.txt" 2>/dev/null
    echo -e "\n--- Технологии ---";   cat "$dir/tech.txt" 2>/dev/null
    echo -e "\n--- Takeover ---";     cat "$dir/takeover.txt" 2>/dev/null
  } | tee "$sum"; echo -e "\n${G}[+] $sum${N}"; pause
}

# =============================================================================
#  HTML-ДАШБОРД (галерея скринов + поиск)
# =============================================================================
make_html() {
  banner; read -rp "$(echo -e ${C}"Домен: "${N})" D
  local dir="$DATA/$D"; local sdir="$SHOTS/$D"
  [ ! -d "$dir" ] && { echo -e "${R}Нет данных — пункт 1.${N}"; pause; return; }
  local html="$OUT/report_${D}_$(date +%Y%m%d).html"
  block(){ echo "<div class='card'><h2>$1</h2><pre>"; [ -s "$2" ] && html_esc < "$2" || echo "— нет данных —"; echo "</pre></div>"; }
  {
    cat <<HEAD
<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>OSINT — $D</title><style>
body{background:#0a0e17;color:#cfe3ff;font-family:'Segoe UI',monospace;margin:0;padding:30px}
h1{color:#22d3ee;text-shadow:0 0 10px #22d3ee55;border-bottom:1px solid #22d3ee33;padding-bottom:10px}
h2{color:#34d399;margin:0 0 10px}.meta{color:#7891b5;font-size:13px;margin-bottom:20px}
.card{background:#111827;border:1px solid #1f2b45;border-radius:10px;padding:18px 22px;margin:16px 0;box-shadow:0 0 20px #00f0ff10}
pre{white-space:pre-wrap;word-break:break-word;color:#a7f3d0;font-size:13px;margin:0;line-height:1.5}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.gallery figure{margin:0;background:#0d1320;border:1px solid #1f2b45;border-radius:8px;overflow:hidden}
.gallery img{width:100%;display:block}.gallery figcaption{font-size:11px;color:#7891b5;padding:6px 8px;word-break:break-all}
#q{width:100%;padding:10px;background:#0d1320;border:1px solid #22d3ee44;border-radius:8px;color:#cfe3ff;margin-bottom:16px}
.footer{margin-top:30px;color:#475569;font-size:12px;text-align:center}
.badge{background:#22d3ee22;color:#22d3ee;padding:3px 10px;border-radius:20px;font-size:12px}</style></head><body>
<h1>🛡️ OSINT Report — $D</h1>
<div class="meta">Сгенерировано: $(date) · <span class="badge">HackShield OSINT Toolkit v3</span></div>
<input id="q" placeholder="🔎 фильтр по содержимому карточек...">
HEAD
    block "📧 Email" "$dir/emails.txt"
    block "🌐 Живые хосты (httpx)" "$dir/live.txt"
    block "📍 IP" "$dir/ips.txt"
    block "🗂️ DNS" "$dir/dns.txt"
    block "⚙️ Технологии" "$dir/tech.txt"
    block "🧱 WAF" "$dir/waf.txt"
    block "⚠️ Subdomain Takeover" "$dir/takeover.txt"
    # галерея скриншотов
    if ls "$sdir"/*.png >/dev/null 2>&1; then
      echo "<div class='card'><h2>📸 Скриншоты сайтов</h2><div class='gallery'>"
      for img in "$sdir"/*.png; do
        echo "<figure><img src='file://$img' loading='lazy'><figcaption>$(basename "$img")</figcaption></figure>"
      done
      echo "</div></div>"
    fi
    cat <<'FOOT'
<div class="footer">Только открытые данные. · HackShield</div>
<script>
const q=document.getElementById('q'),cards=[...document.querySelectorAll('.card')];
q.addEventListener('input',()=>{const v=q.value.toLowerCase();cards.forEach(c=>c.style.display=c.textContent.toLowerCase().includes(v)?'':'none')});
</script></body></html>
FOOT
  } > "$html"
  echo -e "${G}[+] HTML-дашборд: $html${N}"
  have xdg-open && { read -rp "Открыть? [y/N] " a; [[ "$a" =~ ^[Yy]$ ]] && xdg-open "$html" >/dev/null 2>&1 & }
  pause
}

# =============================================================================
#  PDF-ОТЧЁТ
# =============================================================================
make_pdf() {
  banner; read -rp "$(echo -e ${C}"Домен: "${N})" D
  local html="$OUT/report_${D}_$(date +%Y%m%d).html"
  [ ! -f "$html" ] && { echo -e "${R}Сначала сделай HTML (пункт H).${N}"; pause; return; }
  local pdf="$OUT/report_${D}_$(date +%Y%m%d).pdf"
  if have wkhtmltopdf; then
    wkhtmltopdf --enable-local-file-access "$html" "$pdf" 2>/dev/null
  elif have chromium; then
    chromium --headless --disable-gpu --no-sandbox --print-to-pdf="$pdf" "file://$html" >/dev/null 2>&1
  else echo -e "${R}Нет wkhtmltopdf/chromium (пункт 0).${N}"; pause; return; fi
  [ -f "$pdf" ] && echo -e "${G}[+] PDF: $pdf${N}" || echo -e "${R}Не удалось.${N}"; pause
}

# =============================================================================
#  МЕНЮ
# =============================================================================
while true; do
  banner
  echo -e "${W}${BOLD}  Сбор:${N}"
  echo -e "   ${G}0${N}) Установить/проверить    ${G}1${N}) Домен (полная разведка)"
  echo -e "   ${G}2${N}) IP (+Shodan)            ${G}3${N}) Email (+HIBP)"
  echo -e "   ${G}4${N}) Username                ${G}5${N}) Телефон"
  echo -e "   ${G}M${N}) Метаданные файла        ${G}F${N}) SpiderFoot (веб)"
  echo -e "\n${W}${BOLD}  Анализ домена (после п.1):${N}"
  echo -e "   ${C}6${N}) Скриншоты сайтов        ${C}7${N}) Subdomain takeover"
  echo -e "   ${C}8${N}) Wayback (архив URL)     ${C}9${N}) VirusTotal"
  echo -e "\n${W}${BOLD}  Отчёты:${N}"
  echo -e "   ${Y}S${N}) Сводка (txt)            ${Y}H${N}) HTML-дашборд"
  echo -e "   ${Y}P${N}) PDF-отчёт               ${R}q${N}) Выход\n"
  read -rp "$(echo -e ${C}"  > "${N})" ch
  case "${ch,,}" in
    0) install_tools;; 1) domain_recon;; 2) ip_recon;; 3) email_recon;;
    4) username_recon;; 5) phone_recon;; m) metadata_recon;; f) spiderfoot_start;;
    6) screenshots;; 7) takeover;; 8) wayback;; 9) virustotal;;
    s) make_summary;; h) make_html;; p) make_pdf;;
    q) exit 0;; *) echo -e "${R}Неверно.${N}"; sleep 1;;
  esac
done
