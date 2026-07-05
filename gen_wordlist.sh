#!/usr/bin/env bash
#
# gen_wordlist.sh — Target-specific wordlist generator
#
# Instead of reusing SecLists (which every scanner/WAF already "knows" and
# every hunter already tries), this builds a wordlist FROM THE TARGET ITSELF:
#   - words scraped out of live HTML/JS responses
#   - path segments pulled from historical URLs (wayback/gau)
#   - JS variable/route/key names (common source of hidden API paths)
#   - the target's own naming conventions (company name, product name, domain
#     parts) run through mutation rules (case, separators, years, common
#     suffixes) to guess internal-style paths a generic list won't have
#
# Output: a deduped, sorted wordlist unique to the target, optionally merged
# with a SecLists baseline so you get both "generic" and "target-specific" hits.
#
# ⚠️  Only run against domains/URLs you are authorized to test.
#
# Requirements: curl, grep, sed, awk, sort (all standard). Optional: httpx, gau.
#
# Usage:
#   ./gen_wordlist.sh -d example.com -o custom_wordlist.txt
#   ./gen_wordlist.sh -d example.com -u urls_from_recon/all_urls.txt -o custom.txt
#   ./gen_wordlist.sh -d example.com --merge-seclists -o combined.txt
#
set -euo pipefail

DOMAIN=""
URLLIST=""
OUTFILE="custom_wordlist.txt"
MERGE_SECLISTS=false
WORKDIR=""
MIN_WORD_LEN=3
MAX_WORD_LEN=30

log()  { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
err()  { echo -e "\033[1;31m[-]\033[0m $*" >&2; }
require_cmd() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<EOF
Usage: $0 -d <domain> [options]

Options:
  -d <domain>        Target root domain (required), e.g. example.com
  -u <urls_file>      Existing list of URLs (from gau/wayback/recon.sh) to mine paths+words from
  -o <outfile>        Output wordlist path (default: $OUTFILE)
  --merge-seclists     Also fetch SecLists raft-medium-directories.txt and merge it in
  -h                  Show this help

Example:
  $0 -d example.com -u recon_example.com/urls/all_urls.txt --merge-seclists -o final.txt
EOF
    exit 1
}

# ---------- Parse args ----------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d) DOMAIN="$2"; shift 2 ;;
        -u) URLLIST="$2"; shift 2 ;;
        -o) OUTFILE="$2"; shift 2 ;;
        --merge-seclists) MERGE_SECLISTS=true; shift ;;
        -h) usage ;;
        *) err "Unknown option: $1"; usage ;;
    esac
done

[[ -z "$DOMAIN" ]] && { err "Domain is required (-d example.com)"; usage; }

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

log "Target: $DOMAIN"
log "Workdir: $WORKDIR"

# ---------- Source 1: live page content (HTML + inline text) ----------
scrape_live_content() {
    log "Source 1: scraping live HTML/JS content for word tokens"
    local body_dir="$WORKDIR/bodies"
    mkdir -p "$body_dir"

    local hosts=("$DOMAIN" "www.$DOMAIN")
    for h in "${hosts[@]}"; do
        for scheme in https http; do
            local url="${scheme}://${h}"
            log "  -> fetching $url"
            curl -s -m 10 -L "$url" -o "$body_dir/$(echo "$h" | tr '/' '_').html" 2>/dev/null || true
        done
    done

    # If httpx is available and we have a subdomain list nearby, grab a few more bodies
    if require_cmd httpx && [[ -f "recon_${DOMAIN}"*/all_subdomains.txt ]] 2>/dev/null; then
        : # left as an integration point — pipe subdomains through httpx -sr to save bodies if desired
    fi

    # Extract candidate words:
    #  - alnum tokens from HTML text, attribute values, and inline JS
    #  - camelCase / snake_case / kebab-case identifiers (common in JS)
    cat "$body_dir"/*.html 2>/dev/null \
        | grep -oE '[A-Za-z][A-Za-z0-9_-]{2,29}' \
        | sort -u > "$WORKDIR/from_html.txt" || true

    local c
    c=$(wc -l < "$WORKDIR/from_html.txt" 2>/dev/null || echo 0)
    log "  Extracted $c raw tokens from live page content"
}

# ---------- Source 2: path segments from historical / provided URLs ----------
mine_urls() {
    log "Source 2: mining path segments from URL list"

    local urls_file="$WORKDIR/urls_input.txt"
    if [[ -n "$URLLIST" && -f "$URLLIST" ]]; then
        cp "$URLLIST" "$urls_file"
    elif require_cmd gau; then
        log "  -> no URL file given, pulling fresh with gau..."
        gau --subs "$DOMAIN" > "$urls_file" 2>/dev/null || true
    else
        warn "  No URL list and gau not available — falling back to Wayback CDX API"
        curl -s "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey" \
            > "$urls_file" || true
    fi

    if [[ ! -s "$urls_file" ]]; then
        warn "  No URLs collected — skipping this source"
        : > "$WORKDIR/from_urls.txt"
        return
    fi

    # Break each URL into path segments, filenames, and query param names/values
    {
        # path segments (split on / ? & = . -)
        sed -E 's#https?://[^/]+##' "$urls_file" \
            | tr '/?&=._-' '\n' \
            | grep -E '^[A-Za-z][A-Za-z0-9]{2,29}$'
        # query parameter names specifically (often reveal internal terminology)
        grep -oE '[?&][A-Za-z_][A-Za-z0-9_]{1,29}=' "$urls_file" \
            | sed -E 's/^[?&]//; s/=$//'
    } | sort -u > "$WORKDIR/from_urls.txt"

    local c
    c=$(wc -l < "$WORKDIR/from_urls.txt" 2>/dev/null || echo 0)
    log "  Extracted $c unique path/param tokens from URLs"
}

# ---------- Source 3: mutate the domain/brand name itself ----------
mutate_brand() {
    log "Source 3: generating brand-based mutations"
    local base
    base=$(echo "$DOMAIN" | sed -E 's/\.(com|net|org|io|co|dev|app|in)$//' | awk -F. '{print $1}')

    local variants=()
    variants+=("$base")
    variants+=("${base}-api" "${base}_api" "api-${base}" "api_${base}")
    variants+=("${base}-admin" "${base}_admin" "${base}admin")
    variants+=("${base}-dev" "${base}-staging" "${base}-test" "${base}-prod")
    variants+=("${base}-backup" "${base}_backup" "${base}.bak" "${base}.old")
    variants+=("${base}-internal" "${base}-portal" "${base}-app")
    variants+=("${base}v1" "${base}v2" "${base}-v1" "${base}-v2")

    # Year-based guesses (deploy folders, backup dumps, changelogs)
    local this_year
    this_year=$(date +%Y)
    for y in $((this_year-2)) $((this_year-1)) "$this_year"; do
        variants+=("${base}-${y}" "${base}_${y}" "backup-${y}" "backup_${y}" "${y}-backup")
    done

    printf "%s\n" "${variants[@]}" | sort -u > "$WORKDIR/from_brand.txt"
    log "  Generated $(wc -l < "$WORKDIR/from_brand.txt") brand-based mutations"
}

# ---------- Merge everything, clean, dedupe ----------
build_final_list() {
    log "Merging sources, cleaning, and deduping"

    cat "$WORKDIR"/from_html.txt "$WORKDIR"/from_urls.txt "$WORKDIR"/from_brand.txt 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' \
        | awk -v min="$MIN_WORD_LEN" -v max="$MAX_WORD_LEN" 'length($0) >= min && length($0) <= max' \
        | grep -Ev '^(the|and|for|with|this|that|from|http|https|www|com|net|org)$' \
        | sort -u > "$WORKDIR/merged_unique.txt"

    local unique_count
    unique_count=$(wc -l < "$WORKDIR/merged_unique.txt")
    log "  $unique_count unique target-specific words generated"

    if [[ "$MERGE_SECLISTS" == true ]]; then
        log "  --merge-seclists set: fetching SecLists raft-medium-directories.txt to combine"
        local sec="$WORKDIR/seclists.txt"
        if curl -s -f -o "$sec" \
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"; then
            cat "$WORKDIR/merged_unique.txt" "$sec" | tr '[:upper:]' '[:lower:]' | sort -u > "$OUTFILE"
            log "  Combined list written (target-specific + SecLists baseline)"
        else
            warn "  Could not fetch SecLists — writing target-specific list only"
            cp "$WORKDIR/merged_unique.txt" "$OUTFILE"
        fi
    else
        cp "$WORKDIR/merged_unique.txt" "$OUTFILE"
    fi

    local final_count
    final_count=$(wc -l < "$OUTFILE")
    log "Final wordlist: $final_count entries -> $OUTFILE"
}

main() {
    scrape_live_content
    mine_urls
    mutate_brand
    build_final_list
    echo "------------------------------------------------------------"
    echo " Target-specific wordlist ready: $OUTFILE"
    echo " Use it directly with ffuf/gobuster, e.g.:"
    echo "   ffuf -u https://${DOMAIN}/FUZZ -w $OUTFILE -mc 200,301,302,403"
    echo "------------------------------------------------------------"
}

main
