#!/usr/bin/env bash
# Exercise SSR, WASM hydration and SSE against the real scheduler binary.
set -euo pipefail
if (( $# != 3 )); then
    echo "usage: $0 <sccache-dist binary | --fixture-only> <dashboard assets directory> <populated fixture binary>" >&2
    exit 2
fi
binary=
if [[ "$1" != --fixture-only ]]; then binary="$(realpath "$1")"; fi
assets="$(realpath "$2")"
fixture="$(realpath "$3")"
root="$(mktemp -d "$(dirname "$assets")/browser-test.XXXXXXXX")"
scheduler_pid=
fixture_pid=
driver_pid=
session=
driver=
cleanup() {
    status=$?
    if [[ -n "$session" ]]; then
        curl --noproxy '*' -fsS --max-time 5 -X DELETE "$driver/session/$session" >/dev/null || true
    fi
    for pid in "$scheduler_pid" "$fixture_pid" "$driver_pid"; do
        if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    done
    if (( status != 0 )); then
        cat "$root/scheduler.log" "$root/fixture.log" "$root/driver.log" 2>/dev/null || true
    fi
    rm -rf "$root"
}
trap cleanup EXIT
if [[ -n "$binary" ]]; then
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
fi
chromedriver --verbose --port=0 --allowed-ips=127.0.0.1 > "$root/driver.log" 2>&1 &
driver_pid=$!
dashboard=
for ((i=0;i<100;i++)); do
    kill -0 "$driver_pid"
    if [[ -n "$scheduler_pid" ]]; then
        kill -0 "$scheduler_pid"
        dashboard="$(sed -n 's/.*Scheduler status dashboard listening on \(http:\/\/[^ ]*\).*/\1/p' "$root/scheduler.log" | tail -1)"
    fi
    port="$(sed -n 's/.*started successfully on port \([0-9]*\).*/\1/p' "$root/driver.log" | tail -1)"
    if [[ ( -z "$binary" || -n "$dashboard" ) && -n "$port" ]]; then driver="http://127.0.0.1:$port"; break; fi
    sleep .2
done
test -n "$driver"
if [[ -n "$binary" ]]; then
    "$(dirname "$0")/../contrib/codeandsolder/host-native-metadata" dashboard-ready "$binary" "$assets" "$dashboard"
fi
chrome="$(command -v chromium || command -v google-chrome || command -v google-chrome-stable)"
caps="$(jq -n --arg chrome "$chrome" --arg profile "$root/chrome" '{
    capabilities: {alwaysMatch: {browserName: "chrome", pageLoadStrategy: "eager", timeouts: {pageLoad: 20000, script: 20000}, "goog:chromeOptions": {
        binary: $chrome, args: ["--headless=new", "--disable-dev-shm-usage", "--no-sandbox", "--no-proxy-server", "--remote-debugging-pipe", "--no-first-run", ("--user-data-dir=" + $profile)]
    }}}
}')"
echo "Creating headless Chrome session via $driver"
if ! curl --noproxy '*' --fail-with-body --show-error --silent --max-time 60 \
    -H 'Content-Type: application/json' -d "$caps" "$driver/session" > "$root/session.json"; then
    echo "Chrome session creation failed" >&2
    cat "$root/session.json" >&2
    exit 1
fi
session="$(jq -er '.value.sessionId' "$root/session.json")"
echo "Chrome session established; loading $dashboard"
webdriver() {
    curl --noproxy '*' -fsS --max-time 30 -H 'Content-Type: application/json' -d "$2" "$driver/session/$session/$1"
}
js() {
    webdriver execute/sync "$(jq -n --arg script "$1" '{script: $script, args: []}')"
}
await_js() {
    for ((i=0;i<200;i++)); do
        if js "$1" | jq -e '.value == true' >/dev/null; then return 0; fi
        sleep .2
    done
    echo "browser assertion timed out: $1" >&2
    js 'return document.body.innerText' >&2
    return 1
}
select_tab() {
    js "const tab=[...document.querySelectorAll('nav button')].find(x=>x.textContent.trim()==='$1'); tab.click(); return true" >/dev/null
}
if [[ -n "$binary" ]]; then
webdriver url "$(jq -n --arg url "$dashboard/" '{url: $url}')" >/dev/null
await_js 'return document.querySelectorAll("[role=status]").length === 1 && document.querySelector("[role=status]").textContent.trim() === "Live"'
await_js 'return document.body.innerText.includes("NO WORKERS")'
await_js 'return document.querySelector("nav button[aria-pressed=true]").textContent.trim() === "Overview" && document.querySelector("#topology") === null'

# Updates while the same tab is active retain the chart's actual DOM nodes.
await_js 'return document.querySelector("main svg path[stroke-linecap]") !== null'
js 'window.activityChart=document.querySelector("main svg"); window.activityPath=document.querySelector("main svg path[stroke-linecap]"); window.oldPath=activityPath.getAttribute("d"); return true' >/dev/null
await_js 'return activityPath.getAttribute("d") !== oldPath && document.querySelector("main svg") === activityChart && document.querySelector("main svg path[stroke-linecap]") === activityPath'
select_tab Jobs
await_js 'return document.querySelector("#jobs") !== null && document.querySelector("#workers") === null'
js 'const jobFilter=document.querySelector("#jobs input"); jobFilter.value="rustc"; jobFilter.dispatchEvent(new Event("input",{bubbles:true})); return true' >/dev/null
js 'const sort=document.querySelectorAll("#jobs select")[1]; sort.value="input"; sort.dispatchEvent(new Event("change",{bubbles:true})); return true' >/dev/null
select_tab "Cache hits"
await_js 'return document.querySelector("#admission") !== null && document.querySelector("#jobs") === null'
select_tab Jobs
await_js 'return document.querySelector("#jobs input")?.value === "rustc" && document.querySelectorAll("#jobs select")[1]?.value === "input" && document.querySelector("#jobs table") !== null'
select_tab Topology
await_js 'return document.querySelector("#topology svg") !== null && document.querySelector("#topology").innerText.includes("1 identities")'
js 'const e=document.querySelector("#topology select"); e.selectedIndex=1; e.dispatchEvent(new Event("change",{bubbles:true})); return true' >/dev/null
await_js 'return document.querySelector("#topology article")?.innerText.includes("Scheduler") === true'
select_tab "Cache storage"
await_js 'return document.querySelector("#cache-analytics") !== null && document.querySelector("#metrics h2")?.textContent.trim() === "Historical cache storage"'
select_tab Topology
await_js 'return document.querySelector("#topology article")?.innerText.includes("Scheduler") === true && document.querySelector("#metrics") === null'
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
select_tab "Fleet metrics"
await_js 'return document.querySelector("#metrics [role=status]")?.textContent.trim() === "Live"'
js 'const e=document.querySelector("#metrics select"); e.value="six_hours"; e.dispatchEvent(new Event("change",{bubbles:true})); return true' >/dev/null
await_js 'return document.querySelector("#metrics").innerText.includes("60 s resolution") && document.querySelector("#metrics [role=status]").textContent.trim() === "Live"'
js 'document.querySelector("main button").click(); return true' >/dev/null
await_js 'return document.querySelector("main [role=status]").textContent.trim() === "Live"'
# All updates came through SSE, not repeated snapshot RPCs.
await_js 'return performance.getEntriesByType("resource").filter(x => x.name.includes("/api/snapshot")).length <= 1'
echo "Real scheduler browser smoke test passed."
fi

# Use the production SSR/SSE router and optimized WASM with controlled,
# populated projections and a real HTTP Prometheus-compatible fixture.
"$fixture" "$assets" > "$root/fixture.log" 2>&1 &
fixture_pid=$!
fixture_dashboard=
fixture_metrics=
for ((i=0;i<100;i++)); do
    kill -0 "$fixture_pid"
    fixture_dashboard="$(sed -n 's/^FIXTURE_DASHBOARD=//p' "$root/fixture.log" | tail -1)"
    fixture_metrics="$(sed -n 's/^FIXTURE_METRICS=//p' "$root/fixture.log" | tail -1)"
    if [[ -n "$fixture_dashboard" && -n "$fixture_metrics" ]]; then break; fi
    sleep .2
done
test -n "$fixture_dashboard"
test -n "$fixture_metrics"
control() { curl --noproxy '*' -fsS --max-time 5 -X POST "$fixture_metrics/fixture/$1/$2"; }
request_count() { curl --noproxy '*' -fsS --max-time 5 "$fixture_metrics/fixture/count"; }

# Instrument actual EventSource instances without changing production code.
# The tests can simulate a stalled transport and a corrupt revision.
webdriver goog/cdp/execute "$(jq -n --arg script 'window.dashboardSources=[]; window.EventSource=class extends EventSource {constructor(...args){super(...args); dashboardSources.push(this);}}; window.nativeSource=()=>dashboardSources.filter(s=>new URL(s.url).pathname==="/api/events").at(-1); window.metricSource=()=>dashboardSources.filter(s=>new URL(s.url).pathname==="/api/metrics/events").at(-1);' '{cmd:"Page.addScriptToEvaluateOnNewDocument",params:{source:$script}}')" >/dev/null
webdriver url "$(jq -n --arg url "$fixture_dashboard/" '{url:$url}')" >/dev/null
await_js 'return document.querySelector("main [role=status]")?.textContent.trim()==="Live" && document.body.innerText.includes("ACCEPTING WORK")'
await_js 'return performance.getEntriesByType("resource").some(x=>x.name.includes("/pkg/sccache-dashboard-generation-v1:")&&x.name.endsWith(".wasm"))'

select_tab Jobs
await_js 'return document.querySelectorAll("#jobs tbody tr").length===3 && document.querySelector("#jobs").innerText.includes("Queued") && document.querySelector("#jobs").innerText.includes("Staging inputs") && document.querySelector("#jobs").innerText.includes("Compiling")'
js 'window.jobRow=[...document.querySelectorAll("#jobs tbody tr")].find(r=>r.innerText.includes("fixture-crate-0")); window.jobCell=jobRow.cells[3]; window.jobProgress=jobRow.querySelector("progress"); window.jobGeometry=jobRow.getBoundingClientRect(); return !!jobProgress' | jq -e '.value==true' >/dev/null
control phase 1
await_js 'return jobRow.isConnected && jobCell===jobRow.cells[3] && jobCell.innerText.includes("Staging inputs") && jobProgress===jobRow.querySelector("progress") && jobProgress.value===50 && jobRow.getBoundingClientRect().width===jobGeometry.width && jobRow.getBoundingClientRect().height===jobGeometry.height'
control phase 2
await_js 'return jobRow.isConnected && jobCell.innerText.includes("Compiling") && jobProgress.value===100'
control phase 3
await_js 'return jobRow.isConnected && jobCell.innerText.includes("Finished") && jobProgress.hidden'
select_tab Workers
await_js 'return document.querySelector("#workers tbody tr")?.innerText.includes("fixture-worker")'
js 'window.workerRow=document.querySelector("#workers tbody tr"); window.workerCell=workerRow.cells[3]; window.workerGeometry=workerRow.getBoundingClientRect(); return true' >/dev/null
control phase 4
await_js 'return workerRow===document.querySelector("#workers tbody tr") && workerCell.innerText.startsWith("2") && workerRow.getBoundingClientRect().height===workerGeometry.height'
select_tab Jobs
await_js 'return document.querySelectorAll("#jobs tbody tr").length===2 && !document.querySelector("#jobs").innerText.includes("fixture-crate-0")'
select_tab CAS
await_js 'return document.querySelector("#cas")?.innerText.includes("12.0 KiB") && document.querySelector("#cas").innerText.includes("Filesystem free")'
select_tab Network
await_js 'return document.querySelector("#network")?.innerText.includes("fixture-worker") && document.querySelector("#network").innerText.includes("50.0%")'
select_tab Topology
await_js 'return document.querySelector("#topology")?.innerText.includes("3 identities") && document.querySelector("#topology tbody tr")?.innerText.includes("Transferring")'
js 'window.routeRow=document.querySelector("#topology tbody tr"); window.routeCell=routeRow.cells[3]; window.routePath=document.querySelector("#topology svg path[marker-end]"); window.oldRoute=routeCell.innerText; return true' >/dev/null
control phase 6
await_js 'return routeRow===document.querySelector("#topology tbody tr") && routeCell===routeRow.cells[3] && routePath===document.querySelector("#topology svg path[marker-end]") && routeCell.innerText!==oldRoute'

select_tab Traces
trace_tab() {
    js "const tab=[...document.querySelectorAll('#traces [aria-label=\"Trace views\"] button')].find(x=>x.textContent.trim()==='$1'); tab.click(); return true" >/dev/null
}
await_js 'return document.querySelector("#trace-completed:not([hidden]) tbody tr")?.innerText.includes("fixture-traced-crate") && document.querySelector("#trace-active-requests").hidden && document.querySelector("#trace-active-jobs").hidden'
js 'window.historyPane=document.querySelector("#trace-completed"); window.historyRow=historyPane.querySelector("tbody tr"); window.scrollTo(0,0); historyPane.scrollTop=180; window.historyScroll=historyPane.scrollTop; window.historyBox=historyPane.getBoundingClientRect(); window.historyRowBox=historyRow.getBoundingClientRect(); window.historyFilter=[...document.querySelectorAll("#traces label")].find(l=>l.textContent.includes("Revision (full SHA)")).querySelector("input"); historyFilter.focus({preventScroll:true}); historyFilter.value="partial-filter"; historyFilter.dispatchEvent(new Event("input",{bubbles:true})); window.historyStable=()=>historyScroll>0&&historyPane.scrollTop===historyScroll&&historyPane===document.querySelector("#trace-completed")&&historyRow===historyPane.querySelector("tbody tr")&&historyPane.getBoundingClientRect().y===historyBox.y&&historyPane.getBoundingClientRect().height===historyBox.height&&historyRow.getBoundingClientRect().y===historyRowBox.y&&historyFilter.value==="partial-filter"; return historyStable()' | jq -e '.value==true' >/dev/null
control phase 8
await_js 'return document.querySelectorAll("#trace-active-requests tbody tr").length===48 && document.querySelectorAll("#trace-active-jobs tbody tr").length===11 && historyStable() && document.activeElement===historyFilter'
control phase 9
await_js 'return document.querySelectorAll("#trace-active-requests tbody tr").length===0 && document.querySelectorAll("#trace-active-jobs tbody tr").length===2 && historyStable() && document.activeElement===historyFilter'
control phase 6
trace_tab "Active requests"
await_js 'return document.querySelector("#trace-active-requests:not([hidden])")?.innerText.includes("1 reported active") && document.querySelector("#trace-completed").hidden'
js 'window.traceRow=document.querySelector("#trace-active-requests tbody tr"); window.tracePhase=traceRow.cells[2]; window.livePane=document.querySelector("#trace-active-requests"); window.liveBox=livePane.getBoundingClientRect(); return tracePhase.innerText==="hash_inputs"' | jq -e '.value==true' >/dev/null
control phase 8
await_js 'return document.querySelectorAll("#trace-active-requests tbody tr").length===48 && traceRow===document.querySelector("#trace-active-requests tbody tr") && livePane.getBoundingClientRect().height===liveBox.height && livePane.getBoundingClientRect().y===liveBox.y && livePane.scrollHeight>livePane.clientHeight'
control phase 7
await_js 'return traceRow===document.querySelector("#trace-active-requests tbody tr") && tracePhase===traceRow.cells[2] && tracePhase.innerText==="wait_for_producer" && livePane.getBoundingClientRect().height===liveBox.height'
js 'traceRow.querySelector("a").click(); return true' >/dev/null
await_js 'const detail=document.querySelector("#trace-detail:not([hidden])"); return detail?.innerText.includes("fixture-traced-crate") && detail.innerText.includes("Action key:") && detail.innerText.includes("Latency attribution") && [...detail.querySelectorAll(".trace-breakdown tbody tr")].some(row=>row.innerText.includes("wait_for_producer")&&row.innerText.includes("60.000 ms")&&row.innerText.includes("60.0%")) && [...detail.querySelectorAll(".trace-breakdown tbody tr")].some(row=>row.innerText.includes("Unobserved")&&row.innerText.includes("10.000 ms")) && detail.querySelectorAll(".trace-waterfall tbody tr").length===4'
js 'window.detailPane=document.querySelector("#trace-detail"); window.detailRow=detailPane.querySelector(".trace-waterfall tbody tr"); window.detailBox=detailPane.getBoundingClientRect(); return true' >/dev/null
control phase 8
await_js 'return document.querySelectorAll("#trace-active-requests tbody tr").length===48 && detailRow===detailPane.querySelector(".trace-waterfall tbody tr") && detailPane.getBoundingClientRect().y===detailBox.y && detailPane.getBoundingClientRect().height===detailBox.height'
js 'document.querySelector("#trace-detail .trace-waterfall a").click(); return true' >/dev/null
await_js 'const detail=document.querySelector("#trace-detail:not([hidden])"); return detail?.innerText.includes("fixture-producer") && detail.innerText.includes("clock skew or asynchronous completion") && detail.querySelectorAll(".trace-breakdown").length===2 && [...detail.querySelectorAll(".trace-breakdown tbody tr")].some(row=>row.innerText.includes("compiler_process")&&row.innerText.includes("50.000 ms")&&row.innerText.includes("62.5%"))'
js '[...document.querySelectorAll("#traces button")].find(b=>b.textContent==="Back to list").click(); return true' >/dev/null
await_js 'return !document.querySelector("#trace-active-requests").hidden && document.querySelector("#trace-detail").hidden'
trace_tab "Active jobs"
await_js 'return !document.querySelector("#trace-active-jobs").hidden && document.querySelectorAll("#trace-active-jobs tbody tr").length===11'
js 'window.jobsPane=document.querySelector("#trace-active-jobs"); window.jobsBox=jobsPane.getBoundingClientRect(); return true' >/dev/null
control phase 9
await_js 'return document.querySelectorAll("#trace-active-jobs tbody tr").length===2 && jobsPane.getBoundingClientRect().height===jobsBox.height && jobsPane.getBoundingClientRect().y===jobsBox.y'
trace_tab "Completed requests"
js 'window.scrollTo(0,0); return true' >/dev/null
await_js 'return historyStable() && !historyPane.hidden'
js 'historyFilter.value="wrong-revision"; historyFilter.dispatchEvent(new Event("input",{bubbles:true})); [...document.querySelectorAll("#traces button")].find(b=>b.textContent.includes("Search / refresh")).click(); return true' >/dev/null
await_js 'return !document.querySelector("#trace-completed tbody tr")'
trace_tab "Phase latency"
await_js 'return document.querySelector("#trace-phases:not([hidden])")?.innerText.includes("Fleet-wide phase latency") && document.querySelector("#trace-completed").hidden'
trace_tab "Completed requests"
js 'historyFilter.value="0123456789abcdef0123456789abcdef01234567"; historyFilter.dispatchEvent(new Event("input",{bubbles:true})); [...document.querySelectorAll("#traces button")].find(b=>b.textContent.includes("Search / refresh")).click(); return true' >/dev/null
await_js 'return document.querySelector("#trace-completed:not([hidden]) tbody tr")?.innerText.includes("fixture-traced-crate")'

control phase 6
select_tab "Cache hits"
await_js 'return document.querySelector("#admission")?.innerText.includes("80.0%") && document.querySelectorAll("#metrics article").length===20 && [...document.querySelectorAll("#metrics article")].some(a=>a.querySelector("h3").textContent==="Cache hit rate (rolling)"&&a.innerText.includes("80.0%"))'
await_js 'return [...document.querySelectorAll("#metrics select")[1].options].some(o=>o.value==="fixture-client")'
js 'const e=document.querySelectorAll("#metrics select")[1]; e.value="fixture-client"; e.dispatchEvent(new Event("change",{bubbles:true})); return true' >/dev/null
await_js 'return document.querySelectorAll("#metrics article").length===20 && document.querySelectorAll("#metrics select")[1].value==="fixture-client" && document.querySelector("#metrics [role=status]").textContent.trim()==="Live"'
test "$(curl --noproxy '*' -fsS --max-time 5 "$fixture_metrics/fixture/selected")" -gt 0
js 'window.metricCard=(title)=>[...document.querySelectorAll("#metrics article")].find(a=>a.querySelector("h3")?.textContent===title); window.statCard=metricCard("Cache hit rate (rolling)"); window.statValue=statCard.querySelector("strong"); window.metricHistory=metricCard("Completed cache hit rate · client history"); window.metricPath=metricHistory.querySelector("svg path[stroke-linecap]"); window.oldMetricPath=metricPath.getAttribute("d"); return !!statValue' | jq -e '.value==true' >/dev/null
control mode 1
await_js 'return statCard===metricCard("Cache hit rate (rolling)") && statValue===statCard.querySelector("strong") && statValue.textContent==="90.0%" && metricPath===metricHistory.querySelector("svg path[stroke-linecap]") && metricPath.getAttribute("d")!==oldMetricPath && document.querySelectorAll("#metrics select")[1].value==="fixture-client" && document.querySelectorAll("#metrics select")[1].selectedOptions[0].textContent.includes("not observed in range")'
control mode 2
await_js 'return statCard.innerText.includes("queries failed") && statCard.innerText.includes("Last observed") && statValue.textContent==="90.0%"'
control mode 3
await_js 'return statCard.innerText.includes("No samples") && statCard.querySelector("strong")===null'
control mode 0

select_tab "Cache storage"
await_js 'return document.querySelector("#cache-analytics")?.innerText.includes("fixture-worker") && document.querySelector("#cache-analytics").innerText.includes("Distinct live blobs") && document.querySelectorAll("#metrics article").length===10 && [...document.querySelectorAll("#metrics article")].some(a=>a.querySelector("meter"))'
select_tab "Fleet metrics"
await_js 'return document.querySelectorAll("#metrics article").length===20 && [...document.querySelectorAll("#metrics article")].some(a=>a.querySelector("h3")?.textContent==="Versions"&&a.querySelector("tbody tr"))'
select_tab Overview
await_js 'return document.querySelector("#metrics")===null && metricSource().readyState===EventSource.CLOSED'
# Allow an already-dispatched HTTP query to complete, then verify the
# backend no longer receives refreshes for an inactive metrics view.
sleep 2
before="$(request_count)"
sleep 18
test "$(request_count)" = "$before"

# Corrupt revision: no partial application, reconnect with a full reset.
js 'window.oldNative=nativeSource(); oldNative.dispatchEvent(new MessageEvent("message",{data:JSON.stringify({Patch:{revision:999999999,sampled_at:null,sample:null,error:null,totals:null,workers:{upsert:[],remove:[]},jobs:{upsert:[],remove:[]},hosts:{upsert:[],remove:[]},links:{upsert:[],remove:[]},telemetry:null}})})); return true' >/dev/null
await_js 'return nativeSource()!==oldNative && oldNative.readyState===EventSource.CLOSED && document.querySelector("main [role=status]").textContent.trim()==="Live"'
# Closing EventSource explicitly emits no browser error event. The native
# watchdog must detect the absence of valid data, independently of transport.
js 'nativeSource().close(); return true' >/dev/null
await_js 'return document.querySelector("main [role=status]").textContent.trim()==="No recent samples"'
js 'document.querySelector("main button").click(); return true' >/dev/null
await_js 'return document.querySelector("main [role=status]").textContent.trim()==="Live" && document.body.innerText.includes("ACCEPTING WORK")'
echo "Populated scheduler dashboard browser integration passed."
