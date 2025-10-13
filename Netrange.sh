#!/usr/bin/env bash
# Netrange — Cross-platform Network surface extractor & scanner-suggester (advanced)
# Author: Vishal ❤️ Subhi
# No logo. Fully automated. "Ultra Sonic" features: parallel resolution, JSON output,
# cross-platform helpers (Linux/macOS/WSL/Windows PowerShell fallback), dependency checks,
# improved scan recommendations, and safe defaults.
# WARNING: Use only on authorized targets. Written permission required.

set -euo pipefail
IFS=$'\n\t'

# -------------------------
# Color handling (portable)
# -------------------------
FORCE_COLOR=${FORCE_COLOR:-0}
# Detect if stdout is a terminal
if [ "$FORCE_COLOR" -eq 1 ] || [ -t 1 ]; then
  # Use tput if available to be more portable
  if command -v tput >/dev/null 2>&1; then
    GREEN="$(tput setaf 2)"
    YELLOW="$(tput setaf 3)"
    NC="$(tput sgr0)"
  else
    GREEN='[0;32m'
    YELLOW='[1;33m'
    NC='[0m'
  fi
else
  # No colors
  GREEN=''
  YELLOW=''
  NC=''
fi

# -------------------------
# Config
# -------------------------
INPUT_FILE="${1:-}"
OUTDIR_BASE="netrange_output"
PARALLEL_RESOLVE=${PARALLEL_RESOLVE:-20}   # default parallel resolution
AGGRESSIVE=${AGGRESSIVE:-0}                # set 1 for aggressive (faster, noisier) scans
JSON_OUTPUT=1                               # produce JSON summary

usage(){
  cat <<EOF
${GREEN}Usage: $(basename "$0") <input_file>${NC}

${GREEN}Advanced Netrange - cross-platform network surface extractor${NC}
Author: Vishal ❤️ Subhi

Environment variables:
  PARALLEL_RESOLVE - number of concurrent DNS resolves (default: $PARALLEL_RESOLVE)
  AGGRESSIVE       - 1 for aggressive scan suggestions (use with caution)
  FORCE_COLOR      - set to 1 to force colored output even when stdout is not a TTY

Example:
  ${GREEN}PARALLEL_RESOLVE=50 AGGRESSIVE=1 ./$(basename "$0") allsubs.txt${NC}

EOF
}

if [ -z "$INPUT_FILE" ]; then
  usage
  exit 1
fi
if [ ! -f "$INPUT_FILE" ]; then
  echo -e "${YELLOW}[!] Input file not found: $INPUT_FILE${NC}"
  exit 2
fi

TS=$(date +%Y%m%d_%H%M%S)
OUTDIR="${OUTDIR_BASE}_${TS}"
mkdir -p "$OUTDIR"

RAW_IPS="$OUTDIR/_raw_ips.txt"
UNIQ_IPS="$OUTDIR/ips.txt"
CIDRS="$OUTDIR/cidrs.txt"
WHOIS_OUT="$OUTDIR/whois_summary.txt"
SUGGESTIONS_TXT="$OUTDIR/scan_suggestions.txt"
SUGGESTIONS_JSON="$OUTDIR/suggestions.json"

>"$RAW_IPS"

# -------------------------
# Detect platform & helpers
# -------------------------
OS_NAME=$(uname -s 2>/dev/null || echo "Windows_NT")
IS_MAC=0; IS_LINUX=0; IS_WINDOWS=0
case "$OS_NAME" in
  Darwin*) IS_MAC=1 ;;
  Linux*) IS_LINUX=1 ;;
  *CYGWIN*|*MINGW*|*MSYS*|Windows_NT) IS_WINDOWS=1 ;;
esac

cmd_exists(){ command -v "$1" >/dev/null 2>&1; }

# Cross-platform resolve function: returns IPv4 addresses (one per line)
resolve_token(){
  local token="$1"
  # if already IP
  if [[ "$token" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$token"
    return
  fi

  if [ "$IS_WINDOWS" -eq 1 ]; then
    if cmd_exists pwsh; then
      pwsh -NoProfile -Command "try{(Resolve-DnsName -Name '$token' -ErrorAction Stop | Where-Object { \\$_.IPAddress -match '^[0-9]'}).IPAddress }catch{}" 2>/dev/null || true
      return
    fi
    nslookup "$token" 2>/dev/null | awk '/^Address: /{print $2}' || true
    return
  fi

  if cmd_exists dig; then
    dig +short A "$token" 2>/dev/null || true
    return
  fi
  if cmd_exists getent; then
    getent ahosts "$token" 2>/dev/null | awk '{print $1}' | uniq || true
    return
  fi
  if cmd_exists host; then
    host "$token" 2>/dev/null | awk '/has address/ {print $4}' || true
    return
  fi
}

# Export the resolve function so subshells/xargs can use it
export -f resolve_token 2>/dev/null || true

# Parallel resolver using xargs or background jobs
parallel_resolve_file(){
  local infile="$1"; local outfile="$2"; local threads=$3
  >"$outfile"
  if cmd_exists xargs && cmd_exists bash; then
    # Use xargs to run bash -c so resolve_token is available
    cat "$infile" | sed '/^$/d' | awk '{print $1}' | sort -u | xargs -n1 -P${threads} -I{} bash -lc 'resolve_token "{}"' >>"$outfile" 2>/dev/null || true
  else
    while IFS= read -r t || [ -n "$t" ]; do
      ( resolve_token "$t" >>"$outfile" ) &
      while [ $(jobs -r | wc -l) -ge $threads ]; do sleep 0.05; done
    done < <(sort -u "$infile")
    wait
  fi
}

# -------------------------
# Pre-check dependencies
# -------------------------
echo -e "${GREEN}[+] Netrange (Ultra) starting...${NC}"
echo -e "${GREEN}[+] Platform: $OS_NAME${NC}"

MISSING=()
for dep in python3 sed awk sort whois; do
  if ! cmd_exists $dep; then MISSING+=("$dep"); fi
done

if [ ${#MISSING[@]} -ne 0 ]; then
  echo -e "${YELLOW}[!] Missing required commands: ${MISSING[*]}. The script may fail without them.${NC}"
fi

# -------------------------
# 1) Prepare tokens (trim, remove comments)
# -------------------------
TMP_TOKENS="$OUTDIR/_tokens.txt"
awk '{gsub(/\r/,"",$0); if($0~/^#/||$0~/^\/\//) next; if($0=="") next; print $1}' "$INPUT_FILE" | sort -u > "$TMP_TOKENS"

# -------------------------
# 2) Resolve tokens in parallel
# -------------------------
echo -e "${GREEN}[+] Resolving tokens (parallel=$PARALLEL_RESOLVE)...${NC}"
parallel_resolve_file "$TMP_TOKENS" "$RAW_IPS" "$PARALLEL_RESOLVE"

# Deduplicate and normalize IPv4 only
python3 - <<PY > "$UNIQ_IPS"
import ipaddress
ips=set()
for l in open('$RAW_IPS'):
    l=l.strip()
    if not l: continue
    try:
        ip=ipaddress.ip_address(l)
        if ip.version==4:
            ips.add(str(ip))
    except:
        continue
for ip in sorted(ips, key=lambda s: tuple(int(x) for x in s.split('.'))):
    print(ip)
PY

echo -e "${GREEN}[+] Collected $(wc -l < "$UNIQ_IPS") unique IPv4 addresses.${NC}"

# -------------------------
# 3) Collapse into CIDRs (python)
# -------------------------
python3 - <<PY > "$CIDRS"
import ipaddress
nets=[]
for l in open('$UNIQ_IPS'):
    l=l.strip()
    if not l: continue
    try:
        ip=ipaddress.ip_address(l)
        if ip.version==4:
            nets.append(ipaddress.ip_network(l + '/32', strict=False))
    except:
        pass
for net in ipaddress.collapse_addresses(nets):
    print(str(net))
PY

# -------------------------
# 4) Whois lookups (parallel-friendly)
# -------------------------
echo -e "${GREEN}[+] Running whois lookups...${NC}"
>"$WHOIS_OUT"
if cmd_exists whois; then
  while IFS= read -r net || [ -n "$net" ]; do
    ip=$(echo "$net" | cut -d'/' -f1)
    echo "--- $net ---" >> "$WHOIS_OUT"
    whois "$ip" | egrep -i '(^route|^route6|^cidr:|^inetnum:|^netrange:|^origin:|^descr:|^netname:)' -m 20 >> "$WHOIS_OUT" 2>/dev/null || true
    echo >> "$WHOIS_OUT"
  done < "$CIDRS"
else
  echo -e "${YELLOW}[!] whois not found; skipping whois lookups.${NC}"
fi

# -------------------------
# 5) Generate scan suggestions (text + JSON)
# -------------------------
>"$SUGGESTIONS_TXT"
python3 - <<PY > "$SUGGESTIONS_JSON"
import ipaddress, json
out=[]
for l in open('$CIDRS'):
    net=ipaddress.ip_network(l.strip(), strict=False)
    size=net.num_addresses
    recs=[]
    if size<=256:
        recs.append({'type':'nmap_full','cmd':f"nmap -sV -p 1-65535 -T4 -oA nmap_{str(net).replace('/','_')} {net.with_prefixlen}"})
    elif size<=4096:
        recs.append({'type':'masscan_then_nmap','cmd':f"masscan {net.with_prefixlen} -p1-65535 --rate=10000 -oL masscan_{str(net).replace('/','_')}.out"})
        recs.append({'type':'nmap_followup','cmd':'nmap -sV -p 1-65535 -iL <hosts_from_masscan> -oA nmap_followup'})
    else:
        recs.append({'type':'masscan_top','cmd':f"masscan {net.with_prefixlen} -p80,443,22,445,3389 --rate=50000 -oL masscan_top_{str(net).replace('/','_')}.out"})
    recs.append({'type':'quick_checks','cmd':'fping -a -g '+net.with_prefixlen})
    out.append({'network':str(net),'size':size,'recommendations':recs})
print(json.dumps(out,indent=2))
PY

# Write plain text suggestions
python3 - <<PY > "$SUGGESTIONS_TXT"
import json
j=json.load(open('$SUGGESTIONS_JSON'))
for n in j:
    print('Network:',n['network'])
    print('  Size:',n['size'])
    for r in n['recommendations']:
        print('  -',r['type']+':',r['cmd'])
    print()
PY

# -------------------------
# 6) Final summary + outputs
# -------------------------
echo -e "${GREEN}[+] Done. Outputs in: $OUTDIR${NC}"
ls -1 "$OUTDIR" || true

echo -e "${GREEN}Files:\n  - $UNIQ_IPS\n  - $CIDRS\n  - $WHOIS_OUT\n  - $SUGGESTIONS_TXT\n  - $SUGGESTIONS_JSON${NC}"

echo -e "${GREEN}Tips:${NC}"
echo "  - Review scan suggestions before running; adjust masscan --rate and nmap -T according to authorization."
echo "  - On Windows, run within WSL or install pwsh for DNS helpers."

echo -e "${GREEN}Netrange (Ultra) complete. Stay safe and authorized. — Vishal ❤️ Subhi${NC}"

exit 0

