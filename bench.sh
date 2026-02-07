#!/bin/bash
# Benchmark: parallel VT scans with multiple proxies

FILES_COUNT=${1:-10}
WORKERS=${2:-5}

echo "=== VT Scraper Benchmark ==="
echo "Files: $FILES_COUNT, Workers: $WORKERS"
echo ""

# Parse proxies from CSV
PROXIES=()
while IFS=',' read -r id valid inuse country score profile history groups owner proto host port login pass rest; do
    # Skip header and invalid
    [[ "$id" == '"Id"' ]] && continue
    [[ "$valid" != '"true"' ]] && continue

    # Clean quotes
    proto="${proto//\"/}"
    host="${host//\"/}"
    port="${port//\"/}"
    login="${login//\"/}"
    pass="${pass//\"/}"

    if [[ -n "$host" && -n "$port" && -n "$login" && -n "$pass" ]]; then
        PROXIES+=("socks://${login}:${pass}@${host}:${port}")
    fi
done < proxies.csv

PROXY_COUNT=${#PROXIES[@]}
echo "Loaded $PROXY_COUNT proxies"
echo ""

# Create test files
BENCH_DIR="$(pwd)/bench_data"
mkdir -p "$BENCH_DIR"
rm -f "$BENCH_DIR"/*.bin
for i in $(seq 1 $FILES_COUNT); do
    echo "bench_${i}_$(date +%s%N)" > "$BENCH_DIR/test_$i.bin"
done

echo "Created $FILES_COUNT test files"
echo ""

# Export proxies for xargs
export PROXIES_STR="${PROXIES[*]}"
export PROXY_COUNT

# Run benchmark
START=$(date +%s)

seq 1 $FILES_COUNT | xargs -P $WORKERS -I {} bash -c '
    read -ra PROXIES <<< "$PROXIES_STR"
    PROXY_IDX=$(( ({} - 1) % PROXY_COUNT ))
    PROXY="${PROXIES[$PROXY_IDX]}"
    FILE="test_{}.bin"

    echo "[{}] $FILE -> proxy #$((PROXY_IDX + 1))"
    docker run --rm --shm-size=2gb \
        -v "$(pwd)/json:/app/json" \
        -v "$(pwd)/bench_data:/data" \
        -v "$(pwd)/proxies.csv:/app/proxies.csv" \
        virustotal-scraper:latest "/data/$FILE" -p "$PROXY" -r 5 2>&1
' | tee bench.log

END=$(date +%s)
DURATION=$((END - START))

echo ""
echo "=== Results ==="
echo "Total time: ${DURATION}s"
echo "Success: $(grep -c 'OK (' bench.log 2>/dev/null || echo 0)/$FILES_COUNT"
echo "Timeouts: $(grep -c '"timeout"' bench.log 2>/dev/null || echo 0)"
echo "Upload errors: $(grep -c 'upload timeout' bench.log 2>/dev/null || echo 0)"
echo "Fetch errors: $(grep -c 'Failed to fetch' bench.log 2>/dev/null || echo 0)"
if [ $DURATION -gt 0 ]; then
    echo "Throughput: $(echo "scale=2; $FILES_COUNT / $DURATION * 60" | bc) files/min"
fi
