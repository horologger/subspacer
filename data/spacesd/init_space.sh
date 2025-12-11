#!/usr/bin/env bash

set -euo pipefail

#!/usr/bin/env bash

is_sourced() { [[ "${BASH_SOURCE[0]}" != "$0" ]]; }

# Enable optional command tracing with timestamps for progress visibility (via --verbose)
export PS4='+ [$(date "+%Y-%m-%d %H:%M:%S")] '

verify_only=true
compress=false
verbose=false

# Simple flags parsing for up to two flags
if [[ ${1:-} == "--compress" ]]; then
  compress=true
  shift
elif [[ ${1:-} == "--verbose" ]]; then
  verbose=true
  shift
fi

if [[ ${1:-} == "--compress" ]]; then
  compress=true
  shift
elif [[ ${1:-} == "--verbose" ]]; then
  verbose=true
  shift
fi

die() {
  local code=${1:-1}
  if is_sourced; then return "$code"; else exit "$code"; fi
}

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 [--compress] [--verbose] <space_name_without_at>" >&2
  die 1
fi

SPACE_NAME="$1"
SPACE_DIR="${SPACE_NAME}"

# Create the space directory if it doesn't exist
mkdir -p "$SPACE_DIR"

pushd "$SPACE_DIR" >/dev/null

# Timers
script_start_ts=$(date +%s)
last_ts=$script_start_ts
prove_secs=0
compress_secs=0

# Simple ASCII progress bar using an estimated duration (in seconds)
progress_bar() {
  local label="$1"; shift
  local est="$1"; shift
  local pid="$1"; shift
  local width=30
  local start_ts
  start_ts=$(date +%s)
  # Temporarily silence xtrace for clean progress output
  local xtrace_was_on=0
  case "$-" in
    *x*) xtrace_was_on=1; set +x ;;
  esac
  while kill -0 "$pid" 2>/dev/null; do
    local now elapsed filled i
    now=$(date +%s)
    elapsed=$(( now - start_ts ))
    if [[ "$est" -gt 0 ]]; then
      filled=$(( elapsed * width / est ))
      if [[ $filled -gt $width ]]; then filled=$width; fi
    else
      filled=$(( (elapsed % (width+1)) ))
    fi
    printf "\r[%s] [" "$label"
    for ((i=0;i<filled;i++)); do printf "#"; done
    for ((i=filled;i<width;i++)); do printf "-"; done
    printf "] %2ds/%2ds" "$elapsed" "$est"
    sleep 0.2
  done
  printf "\n"
  # Restore xtrace if it was on
  if [[ $xtrace_was_on -eq 1 ]]; then
    set -x
  fi
}

# Optionally enable xtrace
if [[ "$verbose" == true ]]; then
  set -x
fi

if [[ "$verify_only" == false ]]; then
  echo "[info] skipping request step due to --verify-only"
  echo "[info] skipping add step due to --verify-only"
  echo "[info] skipping commit step due to --verify-only"
  echo "[info] skipping user request step due to --verify-only"
  echo "[info] skipping add stage 2 step due to --verify-only"
  echo "[info] skipping commit 2 step due to --verify-only"
  echo "[info] skipping prove step due to --verify-only"
  echo "[info] skipping compress step due to --verify-only"
else

# Step 1: Create admin request
subs request "admin@${SPACE_NAME}" || true
now=$(date +%s); [[ "$verbose" == true ]] && echo "[timing] admin request: $((now - last_ts))s"; last_ts=$now

# Step 2: Stage requests in current directory
subs add .
now=$(date +%s); [[ "$verbose" == true ]] && echo "[timing] add stage 1: $((now - last_ts))s"; last_ts=$now

# Step 3: Commit batch
subs commit
now=$(date +%s); [[ "$verbose" == true ]] && echo "[timing] commit 1: $((now - last_ts))s"; last_ts=$now

# Step 4: Create user request
subs request "user@${SPACE_NAME}" || true
now=$(date +%s); [[ "$verbose" == true ]] && echo "[timing] user request: $((now - last_ts))s"; last_ts=$now

# Step 5: Stage new requests
subs add .
now=$(date +%s); [[ "$verbose" == true ]] && echo "[timing] add stage 2: $((now - last_ts))s"; last_ts=$now

# Step 6: Commit second batch (enables subtree proofs)
subs commit
now=$(date +%s); [[ "$verbose" == true ]] && echo "[timing] commit 2: $((now - last_ts))s"; last_ts=$now

# Step 7: Prove steps and fold aggregate
prove_start=$(date +%s)
EST_PROVE_SECS=${PREV_PROVE_SECS:-30}
subs prove &
prove_pid=$!
progress_bar "prove" "$EST_PROVE_SECS" "$prove_pid"
wait "$prove_pid"
prove_end=$(date +%s); prove_secs=$((prove_end - prove_start)); last_ts=$prove_end
[[ "$verbose" == true ]] && echo "[timing] prove+fold: ${prove_secs}s"
sleep 2

# Step 8: Compress to generate root certificate (writes commitments/@<space>.cert.json)
if [[ "$compress" == true ]]; then
  compress_start=$(date +%s)
  EST_COMPRESS_SECS=${PREV_COMPRESS_SECS:-120}
  subs compress &
  compress_pid=$!
  progress_bar "compress" "$EST_COMPRESS_SECS" "$compress_pid"
  if ! wait "$compress_pid"; then
    echo "[warn] compress failed (Docker or environment)"
  fi
  compress_end=$(date +%s); compress_secs=$((compress_end - compress_start)); last_ts=$compress_end
  [[ "$verbose" == true ]] && echo "[timing] compress: ${compress_secs}s"
else
  echo "[info] skipping compress step (use --compress to enable)"
  compress_secs=0
fi


script_end_ts=$(date +%s)
total_secs=$((script_end_ts - script_start_ts))

echo "Initialized space '${SPACE_NAME}' in '${SPACE_DIR}'."
echo "[timing] total: ${total_secs}s | prove: ${prove_secs}s | compress: ${compress_secs}s"

if is_sourced; then
  export PREV_PROVE_SECS="${prove_secs}"
  export PREV_COMPRESS_SECS="${compress_secs}"
else
  echo "[hint] To enable progress bars next run, set: export PREV_PROVE_SECS=${prove_secs} PREV_COMPRESS_SECS=${compress_secs}"
fi

sleep 5

fi

# After compression, verify admin/user certs against the space root cert
ROOT_CERT_PATH="@${SPACE_NAME}.cert.json"
if [[ -f "$ROOT_CERT_PATH" ]]; then
  # Ensure per-handle certs exist
  [[ -f "admin@${SPACE_NAME}.cert.json" ]] || subs cert issue "admin@${SPACE_NAME}" || true
  [[ -f "user@${SPACE_NAME}.cert.json" ]] || subs cert issue "user@${SPACE_NAME}" || true

  # Verify
  subs cert verify "admin@${SPACE_NAME}.cert.json" --root "$ROOT_CERT_PATH" || echo "[warn] admin cert verify failed"
  subs cert verify "user@${SPACE_NAME}.cert.json" --root "$ROOT_CERT_PATH" || echo "[warn] user cert verify failed"
else
  echo "[warn] root certificate not found at $ROOT_CERT_PATH; skipping cert verification"
fi

popd >/dev/null

# Note: We do not persist timings. If you want progress bar estimates,
# export PREV_PROVE_SECS and PREV_COMPRESS_SECS in your shell before running.

