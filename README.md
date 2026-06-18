# 🛡️ OSINT Toolkit

Модульный меню-инструмент для **OSINT-разведки** (сбор открытой информации) на Kali Linux.
Создан как часть дипломного проекта **HackShield** — образовательной платформы по кибербезопасности.

> ⚠️ **Только для разрешённых целей.** Инструмент предназначен для сбора **открытой (публичной)** информации о **собственных** ресурсах, в рамках авторизованного пентеста, CTF или учебных стендов. Использование против чужих систем без разрешения **незаконно**.

---

## Возможности

| Модуль | Что делает |
|--------|-----------|
| 🌐 **Домен** | DNS-записи, поддомены (sublist3r + subfinder + assetfinder + crt.sh), живые хосты (httpx), email |
| 📍 **IP** | геолокация (ipinfo), Shodan InternetDB (без ключа), порты (nmap), reverse DNS |
| 📧 **Email** | где зарегистрирован аккаунт (holehe), проверка утечек (HIBP) |
| 👤 **Username** | поиск ника на сотнях сайтов (sherlock) |
| 📱 **Телефон** | разведка по номеру (phoneinfoga) |
| 🗂️ **Метаданные** | EXIF: GPS, автор, ПО, камера (exiftool) |
| 📸 **Скриншоты** | автоснимки живых сайтов (gowitness / chromium headless) |
| ⚠️ **Subdomain Takeover** | поиск висячих поддоменов (nuclei) |
| 🕰️ **Wayback** | архивные URL + подсветка чувствительных путей |
| 🦠 **VirusTotal** | репутация домена |

### Отчёты
- **TXT-сводка** — только реальные находки
- **HTML-дашборд** — киберстиль, галерея скриншотов, живой поиск
- **PDF** — для печати/защиты

---

## Установка

```bash
chmod +x osint-toolkit.sh
./osint-toolkit.sh
# в меню выбери пункт 0 — установит все зависимости
```

### API-ключи (опционально)
При первом запуске создаётся `~/.osint.conf`. Добавь бесплатные ключи для расширенных данных:
- [Shodan](https://account.shodan.io) · [VirusTotal](https://www.virustotal.com/gui/my-apikey) · [HaveIBeenPwned](https://haveibeenpwned.com/API/Key)

---

## Docker

```bash
docker build -t osint-toolkit .
docker run -it --rm -v "$PWD/results:/root/osint-results" osint-toolkit
```

---

## Рабочий процесс

```
0  → установка инструментов (один раз)
1  → полная разведка по домену
6  → скриншоты найденных сайтов
7  → проверка subdomain takeover
H  → HTML-дашборд
P  → PDF-отчёт для диплома
```

---

## Стек / инструменты

`bash` · `nmap` · `theHarvester` · `sublist3r` · `subfinder` · `assetfinder` · `httpx` · `nuclei` · `gowitness` · `sherlock` · `holehe` · `exiftool` · `whatweb` · `wafw00f` · `crt.sh API` · `Shodan API` · `VirusTotal API`

---

## Лицензия

Образовательный проект. Используй ответственно и только легально.

**Автор:** Dauren · HackShield Diploma Project
