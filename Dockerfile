# OSINT Toolkit v3 — портативный образ
# Сборка:  docker build -t osint-toolkit -f Dockerfile.osint .
# Запуск:  docker run -it --rm -v "$PWD/results:/root/osint-results" osint-toolkit
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    whois dnsutils nmap theharvester dnsrecon dnsenum \
    whatweb wafw00f sublist3r sherlock recon-ng \
    libimage-exiftool-perl curl jq python3-pip pipx golang-go \
    chromium wkhtmltopdf subfinder httpx-toolkit nuclei assetfinder \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN pipx install holehe || true
RUN go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true
ENV PATH="${PATH}:/root/go/bin:/root/.local/bin"

COPY osint-toolkit-v3.sh /usr/local/bin/osint
RUN chmod +x /usr/local/bin/osint

WORKDIR /root
ENTRYPOINT ["/usr/local/bin/osint"]
