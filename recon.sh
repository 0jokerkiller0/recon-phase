#!/usr/bin/env bash
#
# recon.sh — Bug Bounty Recon Automation
# Phase 1: Subdomain enumeration
# Phase 2: Port scanning + service/version detection
# Phase 3: Live host probing (HTTP)
# Phase 4: Directory / content busting
# Phase 5: Historical URL collection (wayback/gau) + JS file harvesting
# Phase 6: Basic subdomain takeover check
#
# ⚠️  ONLY run this against targets you are authorized to test
#     (your own assets, or in-scope assets under a bug bounty / pentest program).
#     Unauthorized scanning of systems you don't own or have permission to test
#     is illegal in most jurisdictions. Port scanning in particular is more
#     likely to trip IDS/IPS or violate a program's rate-limit rules — check
#     the program scope page before enabling it.
#
# Requirements (installed via setup_tools() below, or install manually):
#   subfinder, assetfinder, amass, httpx, ffuf, jq, curl        (recon)
#   naabu, nmap                                                 (port scan)
#   gau or waybackurls                                          (historical URLs)
#
# Usage:
#   ./recon.sh -d example.com
#   ./recon.sh -d example.com -w /path/to/wordlist.txt -t 50
#   ./recon.sh -d example.com -p            # also run port scan + service detection
#
set -euo pipefail

# ---------- Defaults ----------
DOMAIN=""
THREADS=50
OUTDIR=""
WORDLIST=""
EXTENSIONS="php,html,js,txt,bak,zip,json,env,config,old"
SKIP_INSTALL=false
PORT_SCAN=false
TOP_PORTS=1000

# ---------- Helpers ----------
usage() {
    cat <<EOF
Usage: $0 -d <domain> [options]

Options:
  -d <domain>      Target root domain (required), e.g. example.com
  -w <wordlist>    Path to a custom wordlist for dir busting (default: auto-selected)
  -t <threads>     Thread count for httpx/ffuf/naabu (default: $THREADS)
  -o <dir>         Output directory (default: ./recon_<domain>_<timestamp>)
  -p               Enable port scanning + service/version detection (naabu + nmap -sV)
  -P <ports>       Top N ports to scan with naabu (default: $TOP_PORTS)
  -s               Skip tool installation check
  -h               Show this help

Example:
  $0 -d example.com -t 100 -p
EOF
    exit 1
}

log()  { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
err()  { echo -e "\033[1;31m[-]\033[0m $*" >&2; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# ---------- Parse args ----------
while getopts "d:w:t:o:P:psh" opt; do
    case "$opt" in
        d) DOMAIN="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        p) PORT_SCAN=true ;;
        P) TOP_PORTS="$OPTARG" ;;
        s) SKIP_INSTALL=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$DOMAIN" ]] && { err "Domain is required (-d example.com)"; usage; }

OUTDIR="${OUTDIR:-recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"/{subdomains,httpx,dirbusting,wordlists,portscan,urls,js,takeover}

log "Target: $DOMAIN"
log "Output directory: $OUTDIR"

# ---------- Tool check / install ----------
setup_tools() {
    log "Checking required tools..."
    local core_tools=(subfinder assetfinder httpx ffuf jq curl)
    if [[ "$PORT_SCAN" == true ]]; then
        core_tools+=(naabu nmap)
    fi
    core_tools+=(gau)

    local missing=()
    for tool in "${core_tools[@]}"; do
        require_cmd "$tool" || missing+=("$tool")
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        log "All core tools present."
        return
    fi

    warn "Missing tools: ${missing[*]}"
    if ! require_cmd go; then
        err "Go is not installed. Install Go first: https://go.dev/doc/install"
        err "Then re-run this script, or install the missing tools manually."
        exit 1
    fi

    for tool in "${missing[@]}"; do
        case "$tool" in
            subfinder)    log "Installing subfinder..."; go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest ;;
            assetfinder)  log "Installing assetfinder..."; go install -v github.com/tomnomnom/assetfinder@latest ;;
            httpx)        log "Installing httpx..."; go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest ;;
            ffuf)         log "Installing ffuf..."; go install -v github.com/ffuf/ffuf/v2@latest ;;
            naabu)        log "Installing naabu..."; go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest ;;
            gau)          log "Installing gau..."; go install -v github.com/lc/gau/v2/cmd/gau@latest ;;
            nmap)         warn "nmap must be installed via your system package manager, e.g.: sudo apt install nmap" ;;
            jq|curl)      warn "Please install '$tool' via your system package manager (apt/brew)." ;;
        esac
    done
    export PATH="$PATH:$(go env GOPATH)/bin"
}

[[ "$SKIP_INSTALL" == false ]] && setup_tools

# ---------- Phase 1: Subdomain enumeration ----------
enumerate_subdomains() {
    log "Phase 1: Subdomain enumeration for $DOMAIN"
    local sd="$OUTDIR/subdomains"

    if require_cmd subfinder; then
        log "  -> running subfinder..."
        subfinder -d "$DOMAIN" -all -silent -o "$sd/subfinder.txt" || true
    fi

    if require_cmd assetfinder; then
        log "  -> running assetfinder..."
        assetfinder --subs-only "$DOMAIN" > "$sd/assetfinder.txt" || true
    fi

    if require_cmd amass; then
        log "  -> running amass (passive, faster)..."
        amass enum -passive -d "$DOMAIN" -o "$sd/amass.txt" || true
    else
        warn "  amass not found — skipping (optional but recommended: https://github.com/owasp-amass/amass)"
    fi

    # crt.sh certificate transparency lookup (no tool dependency, just curl+jq)
    log "  -> querying crt.sh (certificate transparency logs)..."
    curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' \
        | sort -u > "$sd/crtsh.txt" || true

    # Merge, dedupe, filter to only in-scope domain
    cat "$sd"/*.txt 2>/dev/null \
        | grep -E "(^|\.)${DOMAIN}$" \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u > "$OUTDIR/all_subdomains.txt"

    local count
    count=$(wc -l < "$OUTDIR/all_subdomains.txt")
    log "Found $count unique subdomains -> $OUTDIR/all_subdomains.txt"
}

# ---------- Phase 3: Port scanning + service/version detection ----------
port_scan() {
    if [[ "$PORT_SCAN" == false ]]; then
        log "Phase 3: Port scanning skipped (enable with -p)"
        return
    fi

    log "Phase 3: Port scanning + service/version detection"
    local ps="$OUTDIR/portscan"

    if ! require_cmd naabu; then
        warn "naabu not found — skipping fast port discovery, falling back to nmap directly (slower)."
    fi

    if require_cmd naabu; then
        log "  -> running naabu (top $TOP_PORTS ports) across all live hosts..."
        naabu -l "$OUTDIR/live_hosts.txt" \
            -top-ports "$TOP_PORTS" \
            -c "$THREADS" \
            -silent \
            -o "$ps/naabu_ports.txt" || true
    fi

    if ! require_cmd nmap; then
        err "nmap not found — cannot run service/version detection. Install it: sudo apt install nmap"
        return
    fi

    # Build a host -> ports map from naabu output (format: host:port) and run
    # nmap -sV against exactly those ports per host (fast + accurate).
    if [[ -s "$ps/naabu_ports.txt" ]]; then
        log "  -> running nmap -sV -sC on discovered ports (per host)..."
        awk -F: '{print $1}' "$ps/naabu_ports.txt" | sort -u | while read -r host; do
            ports=$(grep "^${host}:" "$ps/naabu_ports.txt" | awk -F: '{print $2}' | paste -sd, -)
            [[ -z "$ports" ]] && continue
            log "     nmap -sV on $host (ports: $ports)"
            nmap -sV -sC -Pn -p "$ports" "$host" -oN "$ps/${host}_nmap.txt" -oX "$ps/${host}_nmap.xml" >/dev/null 2>&1 || true
        done
    else
        warn "  No open ports from naabu — running a light nmap top-1000 -sV scan on live hosts instead (slower)."
        while read -r url; do
            host=$(echo "$url" | sed -E 's#https?://##; s#/.*##; s#:[0-9]+$##')
            [[ -z "$host" ]] && continue
            nmap -sV -sC -Pn --top-ports "$TOP_PORTS" "$host" -oN "$ps/${host}_nmap.txt" -oX "$ps/${host}_nmap.xml" >/dev/null 2>&1 || true
        done < "$OUTDIR/live_hosts.txt"
    fi

    # Roll up a quick human-readable summary: host, port, service, version
    {
        echo -e "HOST\tPORT\tSERVICE\tVERSION"
        for f in "$ps"/*_nmap.txt; do
            [[ -f "$f" ]] || continue
            local host
            host=$(basename "$f" _nmap.txt)
            grep -E "^[0-9]+/tcp" "$f" | while read -r line; do
                port=$(echo "$line" | awk '{print $1}' | cut -d/ -f1)
                svc=$(echo "$line" | awk '{print $3}')
                ver=$(echo "$line" | cut -d' ' -f4- )
                echo -e "${host}\t${port}\t${svc}\t${ver}"
            done
        done
    } > "$ps/summary.tsv" 2>/dev/null || true

    log "Port scan + service detection results in $ps/ (per-host .txt/.xml, summary.tsv)"
}

# ---------- Phase 2: Probe for live hosts ----------
probe_live_hosts() {
    log "Phase 2: Probing for live hosts with httpx"
    if ! require_cmd httpx; then
        err "httpx not found, cannot continue to live-host probing."
        exit 1
    fi

    httpx -l "$OUTDIR/all_subdomains.txt" \
        -silent \
        -threads "$THREADS" \
        -status-code -title -tech-detect -follow-redirects \
        -o "$OUTDIR/httpx/httpx_full.txt" || true

    # Clean list of just live URLs for the next phase
    awk '{print $1}' "$OUTDIR/httpx/httpx_full.txt" > "$OUTDIR/live_hosts.txt"

    local count
    count=$(wc -l < "$OUTDIR/live_hosts.txt" 2>/dev/null || echo 0)
    log "Live hosts: $count -> $OUTDIR/live_hosts.txt"
}

# ---------- Wordlist selection ----------
get_wordlist() {
    if [[ -n "$WORDLIST" && -f "$WORDLIST" ]]; then
        echo "$WORDLIST"
        return
    fi

    local wl_dir="$OUTDIR/wordlists"
    local target="$wl_dir/raft-medium-directories.txt"

    if [[ -f "$target" ]]; then
        echo "$target"
        return
    fi

    log "No custom wordlist supplied — fetching SecLists raft-medium-directories.txt" >&2
    if curl -s -f -o "$target" \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"; then
        echo "$target"
    else
        warn "Could not download wordlist automatically. Falling back to a tiny built-in list." >&2
        printf "admin\nlogin\napi\nbackup\nconfig\ntest\nuploads\ndev\nstaging\n.git\n.env\n" > "$target"
        echo "$target"
    fi
}

# ---------- Phase 4: Directory busting ----------
dir_bust() {
    log "Phase 4: Directory busting on live hosts"
    if ! require_cmd ffuf; then
        err "ffuf not found, cannot run directory busting."
        exit 1
    fi

    local wl
    wl=$(get_wordlist)
    log "Using wordlist: $wl ($(wc -l < "$wl") entries)"

    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        local host
        host=$(echo "$url" | sed -E 's#https?://##; s#/.*##')
        log "  -> fuzzing $url"
        ffuf -u "${url}/FUZZ" \
            -w "$wl" \
            -e ".${EXTENSIONS//,/,.}" \
            -mc 200,204,301,302,307,401,403 \
            -t "$THREADS" \
            -recursion -recursion-depth 1 \
            -of json -o "$OUTDIR/dirbusting/${host}.json" \
            -s 2>/dev/null || true
    done < "$OUTDIR/live_hosts.txt"

    log "Directory busting results saved under $OUTDIR/dirbusting/*.json"
}

# ---------- Phase 5: Historical URLs + JS file harvesting ----------
historical_urls() {
    log "Phase 5: Historical URL collection (Wayback/gau) + JS harvesting"
    local urls_dir="$OUTDIR/urls"
    local js_dir="$OUTDIR/js"

    if require_cmd gau; then
        log "  -> running gau (pulls from Wayback, CommonCrawl, OTX, URLScan)..."
        gau --subs "$DOMAIN" > "$urls_dir/gau.txt" 2>/dev/null || true
    else
        warn "  gau not found — falling back to raw Wayback CDX API query."
        curl -s "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey" \
            > "$urls_dir/wayback.txt" || true
    fi

    cat "$urls_dir"/*.txt 2>/dev/null | sort -u > "$urls_dir/all_urls.txt"
    local ucount
    ucount=$(wc -l < "$urls_dir/all_urls.txt" 2>/dev/null || echo 0)
    log "  Collected $ucount historical URLs -> $urls_dir/all_urls.txt"

    # Pull out just the .js files for manual/automated secret & endpoint review
    grep -Ei '\.js($|\?)' "$urls_dir/all_urls.txt" 2>/dev/null | sort -u > "$js_dir/js_urls.txt" || true
    local jcount
    jcount=$(wc -l < "$js_dir/js_urls.txt" 2>/dev/null || echo 0)
    log "  Found $jcount JS file URLs -> $js_dir/js_urls.txt"
    log "  (Feed js_urls.txt into a secrets scanner e.g. trufflehog, mantra, or nuclei's exposed-tokens templates.)"

    # Highlight historical URLs carrying interesting parameters (common vuln surface)
    grep -Ei '\?.*=' "$urls_dir/all_urls.txt" 2>/dev/null \
        | grep -Ei '(id|file|page|url|redirect|next|dest|path|include|template|debug|cmd|q)=' \
        | sort -u > "$urls_dir/interesting_params.txt" || true
    log "  Flagged $(wc -l < "$urls_dir/interesting_params.txt" 2>/dev/null || echo 0) URLs with interesting parameters -> $urls_dir/interesting_params.txt"
}

# ---------- Phase 6: Basic subdomain takeover check ----------
takeover_check() {
    log "Phase 6: Basic subdomain takeover fingerprinting"
    local tk="$OUTDIR/takeover"

    # Known fingerprint snippets for common dangling-CNAME takeover targets.
    # This is a *lightweight* pass, not a substitute for a dedicated tool
    # (e.g. nuclei -tags takeover, or 'subzy').
    declare -A FINGERPRINTS=(
        ["github.io"]="There isn't a GitHub Pages site here"
        ["herokuapp.com"]="No such app"
        ["s3.amazonaws.com"]="NoSuchBucket"
        ["azurewebsites.net"]="404 Web Site not found"
        ["cloudfront.net"]="Bad request"
        ["surge.sh"]="project not found"
        ["readme.io"]="Project doesnt exist"
        ["ghost.io"]="The thing you were looking for is no longer here"
        ["zendesk.com"]="Help Center Closed"
    )

    : > "$tk/candidates.txt"
    while read -r sub; do
        [[ -z "$sub" ]] && continue
        cname=$(dig +short CNAME "$sub" 2>/dev/null | sed 's/\.$//')
        [[ -z "$cname" ]] && continue
        for svc in "${!FINGERPRINTS[@]}"; do
            if [[ "$cname" == *"$svc"* ]]; then
                body=$(curl -s -m 8 "http://$sub" || true)
                if echo "$body" | grep -qi "${FINGERPRINTS[$svc]}"; then
                    echo -e "${sub}\t${cname}\t${svc}\tLIKELY_TAKEOVER" | tee -a "$tk/candidates.txt"
                else
                    echo -e "${sub}\t${cname}\t${svc}\tdangling_cname_no_match" >> "$tk/candidates.txt"
                fi
            fi
        done
    done < "$OUTDIR/all_subdomains.txt"

    local tcount
    tcount=$(grep -c "LIKELY_TAKEOVER" "$tk/candidates.txt" 2>/dev/null || echo 0)
    if [[ "$tcount" -gt 0 ]]; then
        warn "  $tcount potential subdomain takeover candidate(s) found -> $tk/candidates.txt"
    else
        log "  No obvious takeover candidates found (verify manually / with 'subzy' or nuclei's takeover templates for confidence)."
    fi
}

# ---------- Summary ----------
summarize() {
    log "Recon complete for $DOMAIN"
    echo "------------------------------------------------------------"
    echo " Subdomains found     : $(wc -l < "$OUTDIR/all_subdomains.txt" 2>/dev/null || echo 0)"
    echo " Live hosts           : $(wc -l < "$OUTDIR/live_hosts.txt" 2>/dev/null || echo 0)"
    if [[ "$PORT_SCAN" == true ]]; then
    echo " Hosts port-scanned   : $(find "$OUTDIR/portscan" -name '*_nmap.txt' 2>/dev/null | wc -l)"
    fi
    echo " Dir-busting jobs     : $(find "$OUTDIR/dirbusting" -name '*.json' 2>/dev/null | wc -l)"
    echo " Historical URLs      : $(wc -l < "$OUTDIR/urls/all_urls.txt" 2>/dev/null || echo 0)"
    echo " JS files found       : $(wc -l < "$OUTDIR/js/js_urls.txt" 2>/dev/null || echo 0)"
    echo " Takeover candidates  : $(grep -c "LIKELY_TAKEOVER" "$OUTDIR/takeover/candidates.txt" 2>/dev/null || echo 0)"
    echo " All output in        : $OUTDIR"
    echo "------------------------------------------------------------"
}

# ---------- Main ----------
main() {
    enumerate_subdomains   # Phase 1
    probe_live_hosts       # Phase 2
    port_scan              # Phase 3 (only if -p passed)
    dir_bust               # Phase 4
    historical_urls        # Phase 5
    takeover_check         # Phase 6
    summarize
}

main
