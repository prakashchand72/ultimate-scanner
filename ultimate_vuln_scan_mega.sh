#!/usr/bin/env bash
# ultimate_vuln_scan_mega.sh
# MEGA: "red-team-in-a-box" aggressive bug-bounty scanner + exploit orchestration
# WARNING: THIS SCRIPT IS VERY AGGRESSIVE AND PERFORMATIVE. ONLY RUN WITH EXPLICIT WRITTEN AUTHORIZATION.
# By default this script RUNS EXPLOITS / ACTIVE CHECKS. Use --no-exploit to disable destructive modules.
# Targets: single host / single URL (in-scope for bug bounty / pentest). Keep evidence of authorization nearby.

set -euo pipefail
IFS=$'\n\t'

PROGNAME="$(basename "$0")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
WORKDIR="${PWD}/uvs_mega_${TIMESTAMP}"
THREADS=150
RATE=1000
TARGET_URL=""
TARGET_HOST=""
MODE="full"    # full | stealth
EXPLOIT=true    # default: active exploitation enabled
NO_ARCHIVE=false
BROWSER_CRAWL=true
AUTH_COOKIE=""
AUTH_FILE=""
COOKIEJAR=""
USER_AGENT="uvs/mega-1.0"
WORDLIST="${HOME}/wordlists/SecLists/Discovery/Web-Content/top-1000.txt"
BIG_WORDLIST="${HOME}/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt"
KEEP_SESSIONS=false
RANDOM_UA=true
UPDATE_TEMPLATES=true
CI_MODE=false

# Tools to detect (not exhaustive)
declare -A BIN
TOOLS=(httpx gau waybackurls waymore katana hakrawler playwright node ffuf feroxbuster dirsearch nuclei jaeles dalfox xsstrike sqlmap naabu masscan nmap aquatone gowitness whatweb wafw00f trufflehog linkfinder gitdumper gitallaws aws dnsx subfinder amass Arjun paramspider ffuf burpsuite curl jq rg pwsh)
for t in "${TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    BIN[$t]=$(command -v "$t")
  else
    BIN[$t]=""
  fi
done

log(){ echo "[$(date +'%F %T')] $*"; }
usage(){ cat <<EOF
$PROGNAME - MEGA aggressive vuln scanner & exploitation framework

Required:
  --url URL                full target URL (include scheme)

Options:
  --threads N              concurrency (default ${THREADS})
  --rate N                 request rate (default ${RATE})
  --mode [full|stealth]    scanning profile (default full)
  --no-exploit             disable active/exploit modules (default: EXPLOIT ON)
  --no-archive             skip archive harvesting
  --no-browser-crawl       disable headless browser crawling
  --auth-cookie "k=v;.."    authenticated cookie
  --auth-file PATH         one-line cookie or bearer token file
  --no-update-templates    don't auto-update nuclei/jaeles templates
  -h, --help               show this help

NOTES:
- This script will perform destructive actions by default (exploitation). Only run with written authorization.
- Keep authorization proof with output logs.
EOF
exit 1; }

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) TARGET_URL="$2"; shift 2;;
    --threads) THREADS="$2"; shift 2;;
    --rate) RATE="$2"; shift 2;;
    --mode) MODE="$2"; shift 2;;
    --no-exploit) EXPLOIT=false; shift;;
    --no-archive) NO_ARCHIVE=true; shift;;
    --no-browser-crawl) BROWSER_CRAWL=false; shift;;
    --auth-cookie) AUTH_COOKIE="$2"; KEEP_SESSIONS=true; shift 2;;
    --auth-file) AUTH_FILE="$2"; KEEP_SESSIONS=true; shift 2;;
    --no-update-templates) UPDATE_TEMPLATES=false; shift;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1"; usage;;
  esac
done

if [[ -z "${TARGET_URL}" ]]; then echo "[!] --url required"; usage; fi
if [[ ! "${TARGET_URL}" =~ ^https?:// ]]; then TARGET_URL="https://${TARGET_URL}"; fi
TARGET_HOST="$(echo "${TARGET_URL}" | awk -F/ '{print $3}')"
COOKIEJAR="${WORKDIR}/sessions/cookies.jar"

mkdir -p "${WORKDIR}" "${WORKDIR}/raw" "${WORKDIR}/reports" "${WORKDIR}/screenshots" "${WORKDIR}/fuzz" "${WORKDIR}/sessions"
log "WORKDIR=${WORKDIR}"
log "Target=${TARGET_URL} Host=${TARGET_HOST} Exploit=${EXPLOIT} Mode=${MODE}"

# load auth
if [[ -n "${AUTH_FILE}" && -f "${AUTH_FILE}" ]]; then AUTH_COOKIE="$(sed -n '1p' "${AUTH_FILE}")"; fi
if [[ -n "${AUTH_COOKIE}" ]]; then log "Auth cookie provided"; fi

# update templates (nuclei/jaeles)
if [[ "$UPDATE_TEMPLATES" == true ]]; then
  if [[ -n "${BIN[nuclei]}" ]]; then log "Updating nuclei templates..."; ${BIN[nuclei]} -update-templates || log "nuclei update failed"; fi
  if [[ -n "${BIN[jaeles]}" ]]; then log "Updating jaeles repo..."; ${BIN[jaeles]} repo update || log "jaeles update failed"; fi
fi

# helper to run tool if found
run(){ local name="$1"; shift; if [[ -n "${BIN[$name]}" ]]; then log "RUN: $name $*"; "${BIN[$name]}" "$@"; else log "MISSING: $name -> skipping"; fi }

# 1) Passive recon
log "PHASE 1: Passive recon"
if [[ "$NO_ARCHIVE" != true ]]; then
  if [[ -n "${BIN[waybackurls]}" ]]; then echo "${TARGET_HOST}" | ${BIN[waybackurls]} > "${WORKDIR}/raw/wayback.txt" || true; fi
  if [[ -n "${BIN[gau]}" ]]; then echo "${TARGET_HOST}" | ${BIN[gau]} -o "${WORKDIR}/raw/gau.txt" || true; fi
  if [[ -n "${BIN[waymore]}" ]]; then ${BIN[waymore]} -i "${TARGET_HOST}" -mode U -oU "${WORKDIR}/raw/waymore.txt" || true; fi
  cat "${WORKDIR}/raw/"*.txt 2>/dev/null | sed '/^$/d' | sort -u > "${WORKDIR}/raw/historical_urls.txt" || true
fi

# 2) Subdomain and asset discovery (amass/subfinder/dnsx)
log "PHASE 2: Asset discovery"
if command -v subfinder >/dev/null 2>&1; then subfinder -silent -d "${TARGET_HOST}" -o "${WORKDIR}/raw/subdomains.txt" || true; fi
if command -v amass >/dev/null 2>&1; then amass enum -d "${TARGET_HOST}" -o "${WORKDIR}/raw/amass.txt" || true; fi
if command -v dnsx >/dev/null 2>&1 && [[ -f "${WORKDIR}/raw/subdomains.txt" ]]; then cat "${WORKDIR}/raw/subdomains.txt" | dnsx -silent -o "${WORKDIR}/raw/dnsx_alive.txt" || true; fi

# 3) JS crawling (Playwright if available) and katana/hakrawler fallback
log "PHASE 3: JS crawling & renderer"
if [[ "$BROWSER_CRAWL" == true ]]; then
  if command -v node >/dev/null 2>&1 && [[ -f ./tools/playwright_crawl.js ]]; then
    log "Running local Playwright crawl..."
    node ./tools/playwright_crawl.js "${TARGET_URL}" "${WORKDIR}/raw/playwright_urls.txt" || true
  else
    log "No playwright crawler found; attempting katana/hakrawler"
    if [[ -n "${BIN[katana]}" ]]; then ${BIN[katana]} -u "${TARGET_URL}" -silent -js -o "${WORKDIR}/raw/katana.txt" || true; fi
    if [[ -n "${BIN[hakrawler]}" ]]; then echo "${TARGET_URL}" | ${BIN[hakrawler]} -depth 3 -plain -silent > "${WORKDIR}/raw/hakrawler.txt" || true; fi
  fi
fi

# extract JS files
rg -o "https?://[^\s'\"<>]+\.js[?a-zA-Z0-9=&%_\-./]*" "${WORKDIR}/raw/"*.txt 2>/dev/null | sort -u > "${WORKDIR}/raw/js_files.txt" || true
log "JS files found: $(wc -l < "${WORKDIR}/raw/js_files.txt" 2>/dev/null || echo 0)"

# 4) Download & scan JS for endpoints/secrets
log "PHASE 4: Download JS and static analysis"
mkdir -p "${WORKDIR}/raw/js_downloads"
if [[ -s "${WORKDIR}/raw/js_files.txt" ]]; then
  while read -r js; do
    safe="$(echo "$js" | md5sum | awk '{print $1}')"
    out="${WORKDIR}/raw/js_downloads/${safe}.js"
    curl -sL --max-time 15 -A "${USER_AGENT}" "$js" -o "${out}" || continue
    if command -v linkfinder >/dev/null 2>&1; then python3 "$(command -v linkfinder)" -i "${out}" -o cli >> "${WORKDIR}/raw/js_endpoints.txt" 2>/dev/null || true; fi
    if command -v trufflehog >/dev/null 2>&1; then trufflehog filesystem --no-git "${out}" >> "${WORKDIR}/raw/js_secrets.txt" 2>/dev/null || true; fi
  done < "${WORKDIR}/raw/js_files.txt"
fi

# 5) Parameter discovery
log "PHASE 5: Parameter discovery"
cat "${WORKDIR}/raw/historical_urls.txt" "${WORKDIR}/raw/katana.txt" "${WORKDIR}/raw/hakrawler.txt" 2>/dev/null | grep -E "(\?|%3F|&|=)" | sort -u > "${WORKDIR}/raw/params_candidates.txt" || true
if command -v paramspider >/dev/null 2>&1; then python3 "$(command -v paramspider)" -d "${TARGET_HOST}" -o "${WORKDIR}/raw/paramspider.txt" || true; fi
if [[ -f "${WORKDIR}/raw/paramspider.txt" ]]; then cat "${WORKDIR}/raw/paramspider.txt" >> "${WORKDIR}/raw/params_candidates.txt"; fi
sort -u "${WORKDIR}/raw/params_candidates.txt" -o "${WORKDIR}/raw/params_candidates.txt" || true
log "Params found: $(wc -l < "${WORKDIR}/raw/params_candidates.txt" 2>/dev/null || echo 0)"

# 6) Fuzzing (ffuf/feroxbuster) - use cookiejar when available
log "PHASE 6: Dir fuzzing & parameter fuzzing"
if [[ -n "${BIN[ffuf]}" ]]; then
  ${BIN[ffuf]} -u "${TARGET_URL}/FUZZ" -w "${WORDLIST}" -t "${THREADS}" -r -o "${WORKDIR}/fuzz/ffuf_root.json" -of json || true
  if [[ "${MODE}" == "full" ]]; then ${BIN[ffuf]} -u "${TARGET_URL}/FUZZ" -w "${BIG_WORDLIST}" -t 40 -r -o "${WORKDIR}/fuzz/ffuf_root_big.json" -of json || true; fi
fi
if [[ -n "${BIN[feroxbuster]}" ]]; then ${BIN[feroxbuster]} -u "${TARGET_URL}" -w "${WORDLIST}" -t 50 -r -o "${WORKDIR}/fuzz/ferox.txt" || true; fi

# 7) Template-based scanning (nuclei/jaeles)
log "PHASE 7: Template scanning (nuclei/jaeles)"
if [[ -n "${BIN[nuclei]}" ]]; then
  ${BIN[nuclei]} -u "${TARGET_URL}" -severity info,low -o "${WORKDIR}/raw/nuclei_info.txt" -c 50 || true
  ${BIN[nuclei]} -u "${TARGET_URL}" -o "${WORKDIR}/raw/nuclei_full.txt" -c 100 || true
fi
if [[ -n "${BIN[jaeles]}" ]]; then ${BIN[jaeles]} scan -u "${TARGET_URL}" -o "${WORKDIR}/raw/jaeles" || true; fi

# 8) Active parameter checks (XSS/SSRF/IDOR/CRLF/Open-redirect)
log "PHASE 8: Active parameter checks (XSS/SSRF/IDOR)"
mkdir -p "${WORKDIR}/raw/active"
if [[ -s "${WORKDIR}/raw/params_candidates.txt" ]]; then
  # dalfox for XSS
  if command -v dalfox >/dev/null 2>&1; then
    cat "${WORKDIR}/raw/params_candidates.txt" | xargs -n1 -P20 -I{} dalfox file -o "${WORKDIR}/raw/active/dalfox_{}.json" --silent || true
  fi
  # simple IDOR bruteforce: try replacing numeric IDs 1..500
  while read -r p; do
    if echo "$p" | rg -qE "(id=|user=|uid=|account=)"; then
      for i in {1..200}; do
        testurl="$(echo "$p" | sed -E 's/([?&][^=]+=)[^&]*/\1'${i}'/')"
        status=$(curl -s -I -L -A "${USER_AGENT}" -o /dev/null -w "%{http_code}" "${testurl}" || echo "000")
        if [[ "$status" != "404" && "$status" != "000" ]]; then echo "$testurl|$status" >> "${WORKDIR}/raw/active/idor_hits.txt"; fi
      done
    fi
  done < "${WORKDIR}/raw/params_candidates.txt"
fi

# 9) SQLi passive->active
log "PHASE 9: SQLi checks"
if [[ -n "${BIN[sqlmap]}" && -s "${WORKDIR}/raw/params_candidates.txt" ]]; then
  while read -r purl; do
    ${BIN[sqlmap]} -u "${purl}" --batch --threads=4 --risk=2 --level=2 --output-dir="${WORKDIR}/raw/sqlmap" || true
  done < "${WORKDIR}/raw/params_candidates.txt"
fi

# 10) Port/service scanning and targeted exploit attempts
log "PHASE 10: Port & service enumeration"
HOST_IP="$(dig +short "${TARGET_HOST}" | head -n1 || true)"
if [[ -n "${HOST_IP}" ]]; then log "Resolved IP: ${HOST_IP}"; fi
if command -v naabu >/dev/null 2>&1; then ${BIN[naabu]} -host "${TARGET_HOST}" -rate "${RATE}" -o "${WORKDIR}/raw/ports_naabu.txt" || true; fi
if [[ -n "${BIN[masscan]}" && -n "${HOST_IP}" ]]; then sudo ${BIN[masscan]} -p1-65535 "${HOST_IP}" --rate "${RATE}" -oL "${WORKDIR}/raw/masscan.out" || true; fi
if command -v nmap >/dev/null 2>&1; then nmap -Pn -sC -sV -T4 -oA "${WORKDIR}/raw/nmap" "${TARGET_HOST}" || true; fi

# optional: rudimentary exploit attempts (only if EXPLOIT true)
if [[ "$EXPLOIT" == true ]]; then
  log "EXPLOIT MODE: running allowed exploit modules (user confirmed scope)"
  # Example: try common SMB/FTP default creds (placeholder)
  # NOTE: Real exploit modules should be added as separate vetted scripts.
  # This section intentionally minimal — user may supply modules to run here.
  # Example PoC command (non-destructive): check for exposed .git
  if command -v git >/dev/null 2>&1; then
    if curl -s --max-time 8 "${TARGET_URL}/.git/config" | rg -q "\[core\]"; then
      echo "Potential exposed .git at ${TARGET_URL}/.git" >> "${WORKDIR}/raw/exposed_git.txt"
    fi
  fi
fi

# 11) Cloud & bucket checks
log "PHASE 11: Cloud & bucket checks"
mkdir -p "${WORKDIR}/raw/cloud"
IFS='.' read -r -a TOKS <<< "${TARGET_HOST}"
for t in "${TOKS[@]}"; do [[ -n "$t" ]] && echo "$t" >> "${WORKDIR}/raw/cloud/candidates.txt"; done
echo "${TARGET_HOST}" >> "${WORKDIR}/raw/cloud/candidates.txt"
sort -u "${WORKDIR}/raw/cloud/candidates.txt" -o "${WORKDIR}/raw/cloud/candidates.txt"
if command -v aws >/dev/null 2>&1; then
  while read -r b; do
    aws s3api head-bucket --bucket "$b" >/dev/null 2>&1 && echo "accessible:$b" >> "${WORKDIR}/raw/cloud/buckets.txt" || true
  done < "${WORKDIR}/raw/cloud/candidates.txt"
fi

# 12) Evidence capture: screenshots & requests
log "PHASE 12: Evidence capture"
if command -v aquatone >/dev/null 2>&1; then echo "${TARGET_URL}" | aquatone -out "${WORKDIR}/screenshots" || true; fi
if command -v gowitness >/dev/null 2>&1; then ${BIN[gowitness]} single "${TARGET_URL}" --destination "${WORKDIR}/screenshots" || true; fi

# 13) Consolidation & triage
log "PHASE 13: Consolidation & triage"
mkdir -p "${WORKDIR}/reports/merged"
# merge some artifacts
if [[ -f "${WORKDIR}/raw/nuclei_full.txt" ]]; then cp "${WORKDIR}/raw/nuclei_full.txt" "${WORKDIR}/reports/merged/nuclei_full.txt" || true; fi
if [[ -f "${WORKDIR}/fuzz/ffuf_root.json" ]]; then jq -r '.results[] | .url' "${WORKDIR}/fuzz/ffuf_root.json" 2>/dev/null | sort -u > "${WORKDIR}/reports/merged/fuzz_hits.txt" || true; fi
if [[ -f "${WORKDIR}/raw/params_candidates.txt" ]]; then sort -u "${WORKDIR}/raw/params_candidates.txt" > "${WORKDIR}/reports/merged/params.txt" || true; fi

# generate simple markdown report
REPORT_MD="${WORKDIR}/reports/uvs_report.md"
cat > "$REPORT_MD" <<EOF
# Ultimate Vuln Scan MEGA Report
Target: ${TARGET_URL}
Host: ${TARGET_HOST}
Mode: ${MODE}
Exploit-mode: ${EXPLOIT}
Workdir: ${WORKDIR}

## Quick findings
- Fuzz hits: $(wc -l < "${WORKDIR}/reports/merged/fuzz_hits.txt" 2>/dev/null || echo 0)
- JS endpoints: $(wc -l < "${WORKDIR}/raw/js_files.txt" 2>/dev/null || echo 0)
- Params: $(wc -l < "${WORKDIR}/reports/merged/params.txt" 2>/dev/null || echo 0)
EOF

log "MEGA scan complete. Review ${WORKDIR} and the report at ${REPORT_MD}"

cat <<EOF
