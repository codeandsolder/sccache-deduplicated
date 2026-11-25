#!/usr/bin/env bash
# Exercise SSR, WASM hydration and SSE against the real scheduler binary.
set -euo pipefail
if (( $# != 2 )); then
    echo "usage: $0 <sccache-dist binary> <dashboard assets directory>" >&2
    exit 2
fi
binary="$(realpath "$1")"
assets="$(realpath "$2")"
root="$(mktemp -d "$(dirname "$assets")/browser-test.XXXXXXXX")"
scheduler_pid=
driver_pid=
session=
driver=
cleanup() {
    status=$?
    if [[ -n "$session" ]]; then
        curl -fsS --max-time 5 -X DELETE "$driver/session/$session" >/dev/null || true
    fi
    for pid in "$scheduler_pid" "$driver_pid"; do
        if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    done
    if (( status != 0 )); then
        cat "$root/scheduler.log" "$root/driver.log" 2>/dev/null || true
    fi
    rm -rf "$root"
}
trap cleanup EXIT
jq -n --arg assets "$assets" --arg drain "$root/drain" --arg cluster "$root/cluster" '{
    public_addr: "127.0.0.1:0",
    cluster_directory: $cluster,
    maintenance_drain_file: $drain,
    job_slack: {static_jobs: 0, percent: 200.0},
    client_auth: {type: "token", token: "test-client"},
    server_auth: {type: "token", token: "test-worker"},
    dashboard: {bind_address: "127.0.0.2:0", assets: $assets}
}' > "$root/scheduler.json"
SCCACHE_NO_DAEMON=1 SCCACHE_LOG=info "$binary" scheduler --config "$root/scheduler.json" > "$root/scheduler.log" 2>&1 &
scheduler_pid=$!
chromedriver --port=0 --allowed-ips=127.0.0.1 > "$root/driver.log" 2>&1 &
driver_pid=$!
dashboard=
for ((i=0;i<100;i++)); do
    kill -0 "$scheduler_pid" "$driver_pid"
    dashboard="$(sed -n 's/.*Scheduler status dashboard listening on \(http:\/\/[^ ]*\).*/\1/p' "$root/scheduler.log" | tail -1)"
    port="$(sed -n 's/.*started successfully on port \([0-9]*\).*/\1/p' "$root/driver.log" | tail -1)"
    if [[ -n "$dashboard" && -n "$port" ]]; then driver="http://127.0.0.1:$port"; break; fi
    sleep .2
done
test -n "$driver"
curl --noproxy '*' -fsS --max-time 10 "$dashboard/" | rg 'Scheduler status' >/dev/null
chrome="$(command -v chromium || command -v google-chrome || command -v google-chrome-stable)"
caps="$(jq -n --arg chrome "$chrome" --arg profile "$root/chrome" '{
    capabilities: {alwaysMatch: {browserName: "chrome", "goog:chromeOptions": {
        binary: $chrome, args: ["--headless=new", "--disable-dev-shm-usage", "--no-sandbox", "--no-proxy-server", ("--user-data-dir=" + $profile)]
    }}}
}')"
session="$(curl -fsS --max-time 30 -H 'Content-Type: application/json' -d "$caps" "$driver/session" | jq -er '.value.sessionId')"
webdriver() {
    curl -fsS --max-time 30 -H 'Content-Type: application/json' -d "$2" "$driver/session/$session/$1"
}
js() {
    webdriver execute/sync "$(jq -n --arg script "$1" '{script: $script, args: []}')"
}
await_js() {
    for ((i=0;i<100;i++)); do
        if js "$1" | jq -e '.value == true' >/dev/null; then return 0; fi
        sleep .2
    done
    echo "browser assertion timed out: $1" >&2
    js 'return document.body.innerText' >&2
    return 1
}
webdriver url "$(jq -n --arg url "$dashboard/" '{url: $url}')" >/dev/null
await_js 'return [...document.querySelectorAll("[role=status]")].length === 2 && [...document.querySelectorAll("[role=status]")].every(x => x.textContent.trim() === "Live")'
await_js 'return document.body.innerText.includes("NO WORKERS")'
await_js 'return document.querySelector("#topology svg") !== null && document.querySelector("#topology").innerText.includes("1 identities")'
js 'const e=document.querySelector("#topology select"); e.selectedIndex=1; e.dispatchEvent(new Event("change",{bubbles:true})); return true' >/dev/null
await_js 'return document.querySelector("#topology article")?.innerText.includes("Scheduler") === true'
# Enroll a real authenticated client after hydration; membership must arrive via SSE.
scheduler_endpoint="$(sed -n 's/.*Scheduler listening for clients on \([^ ]*\).*/\1/p' "$root/scheduler.log" | tail -1)"
test -n "$scheduler_endpoint"
scheduler_id="$("$binary" cluster-id --directory "$root/cluster")"
mkdir -p "$root/client"
jq -n --arg endpoint "https://$scheduler_endpoint" --arg id "$scheduler_id" --arg root "$root" '{dist:{scheduler_url:$endpoint,auth:{type:"token",token:"test-client"},cluster:{directory:($root+"/client"),ca_certificate:($root+"/cluster/ca.pem"),scheduler_id:$id}}}' > "$root/client.json"
"$binary" cluster-status --client-config "$root/client.json" >/dev/null
await_js 'return document.querySelector("#topology").innerText.includes("2 identities") && [...document.querySelectorAll("#topology select option")].some(x => x.textContent.includes("Client"))'
# The browser sees actual maintenance state changes without page reload.
touch "$root/drain"
await_js 'return document.body.innerText.includes("DRAINING")'
rm "$root/drain"
await_js 'return document.body.innerText.includes("NO WORKERS")'
js 'const e=document.querySelector("#metrics select"); e.value="six_hours"; e.dispatchEvent(new Event("change",{bubbles:true})); return true' >/dev/null
await_js 'return document.querySelector("#metrics").innerText.includes("60 s resolution") && document.querySelector("#metrics [role=status]").textContent.trim() === "Live"'
js 'document.querySelector("main button").click(); return true' >/dev/null
await_js 'return document.querySelector("main [role=status]").textContent.trim() === "Live"'
# All updates came through SSE, not repeated snapshot RPCs.
await_js 'return performance.getEntriesByType("resource").filter(x => x.name.includes("/api/snapshot")).length <= 1'
echo "Scheduler dashboard browser smoke test passed."
