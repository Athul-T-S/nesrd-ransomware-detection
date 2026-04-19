"""
NESRD Dashboard Server
Real-time web dashboard for the NESRD ransomware detection system.
Run alongside grpc_server.py to get live visibility into detections.

Usage:
    python dashboard_server.py
    Open http://localhost:5000
"""

import os
import json
import time
import threading
from datetime import datetime
from flask import Flask, render_template_string, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config["SECRET_KEY"] = "nesrd-dashboard-2026"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
ALERTS_FILE = os.path.join(BASE_DIR, "logs", "nesrd_alerts.json")
LOG_FILE    = os.path.join(BASE_DIR, "logs", "nesrd.log")

# ── In-memory state ────────────────────────────────────────────────────────
state = {
    "agents":   {},
    "alerts":   [],
    "stats": {
        "total_alerts":      0,
        "total_isolations":  0,
        "total_alerts_only": 0,
        "uptime_start":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "live_feed": [],
}
state_lock = threading.Lock()

# ── Alert file watcher ─────────────────────────────────────────────────────
_last_alerts_mtime = 0
_last_alerts_count = 0


def _parse_alerts_file():
    """
    Parse the alerts file which is newline-delimited JSON.
    Skips blank lines and bare '[' or ']' characters.
    Returns list of alert dicts, oldest first.
    """
    alerts = []
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass
    return alerts


def watch_alerts():
    """Watch the alerts file for changes and push new alerts to clients."""
    global _last_alerts_mtime, _last_alerts_count

    while True:
        try:
            if os.path.exists(ALERTS_FILE):
                mtime = os.path.getmtime(ALERTS_FILE)
                if mtime != _last_alerts_mtime:
                    _last_alerts_mtime = mtime
                    alerts = _parse_alerts_file()

                    total      = len(alerts)
                    isolations = sum(1 for a in alerts if a.get("decision") == "ISOLATE")
                    alert_only = sum(1 for a in alerts if a.get("decision") == "ALERT")

                    new_alerts = []
                    with state_lock:
                        state["alerts"]                     = list(reversed(alerts))[:200]
                        state["stats"]["total_alerts"]      = total
                        state["stats"]["total_isolations"]  = isolations
                        state["stats"]["total_alerts_only"] = alert_only
                        if total > _last_alerts_count:
                            new_alerts         = alerts[_last_alerts_count:]
                            _last_alerts_count = total

                    # Emit outside lock to avoid deadlock
                    for alert in new_alerts:
                        socketio.emit("new_alert", alert)

        except Exception:
            pass

        time.sleep(1)


# ── Log file watcher ───────────────────────────────────────────────────────
_log_position = 0


def _extract(text, start, end):
    """Extract substring between start and end markers."""
    try:
        i = text.index(start) + len(start)
        if end is None:
            return text[i:].split()[0].strip()
        j = text.index(end, i)
        return text[i:j].strip()
    except (ValueError, IndexError):
        return ""


def watch_log():
    """Tail the manager log and parse decisions, heartbeats, connections."""
    global _log_position

    # FIX: On startup seek to end of log so we only tail NEW entries.
    # Without this, every dashboard restart replays the entire log
    # history into live_feed, flooding it with stale data.
    if os.path.exists(LOG_FILE):
        try:
            _log_position = os.path.getsize(LOG_FILE)
        except Exception:
            pass

    while True:
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(_log_position)
                    new_lines = f.readlines()
                    _log_position = f.tell()

                for raw in new_lines:
                    line = raw.strip()
                    if not line:
                        continue

                    # ── Decision line ──────────────────────────────────
                    if "Decision=" in line and "Confidence=" in line:
                        try:
                            decision   = _extract(line, "Decision=", " ")
                            confidence = _extract(line, "Confidence=", " ")
                            reason     = _extract(line, "Reason=", " | PID")
                            pid        = _extract(line, "PID=", None)
                            agent      = _extract(line, "[", "]")
                            ts         = line[:23]

                            if decision not in ("LOG", "ALERT", "ISOLATE"):
                                continue

                            entry = {
                                "time":       ts,
                                "agent":      agent,
                                "decision":   decision,
                                "confidence": round(float(confidence), 3) if confidence else 0.0,
                                "reason":     reason,
                                "pid":        pid,
                            }

                            with state_lock:
                                state["live_feed"].insert(0, entry)
                                state["live_feed"] = state["live_feed"][:50]

                                if agent:
                                    if agent not in state["agents"]:
                                        state["agents"][agent] = {
                                            "id":        agent,
                                            "ip":        "",
                                            "last_seen": ts,
                                            "status":    "active",
                                            "decisions": 0,
                                        }
                                    state["agents"][agent]["last_seen"] = ts
                                    state["agents"][agent]["decisions"] += 1
                                    if decision == "ISOLATE":
                                        state["agents"][agent]["status"] = "isolated"

                            socketio.emit("live_decision", entry)

                        except Exception:
                            pass

                    # ── Heartbeat line ─────────────────────────────────
                    elif "Heartbeat from" in line:
                        try:
                            agent_id = _extract(line, "Heartbeat from ", " at")
                            agent_ip = _extract(line, " at ", None)
                            ts       = line[:23]

                            if not agent_id:
                                continue

                            with state_lock:
                                if agent_id not in state["agents"]:
                                    state["agents"][agent_id] = {
                                        "id":        agent_id,
                                        "ip":        agent_ip or "",
                                        "last_seen": ts,
                                        "status":    "active",
                                        "decisions": 0,
                                    }
                                else:
                                    state["agents"][agent_id]["last_seen"] = ts
                                    if agent_ip:
                                        state["agents"][agent_id]["ip"] = agent_ip
                                    if state["agents"][agent_id]["status"] != "isolated":
                                        state["agents"][agent_id]["status"] = "active"

                            socketio.emit("agent_heartbeat", {
                                "agent_id": agent_id,
                                "agent_ip": agent_ip,
                                "time":     ts,
                            })

                        except Exception:
                            pass

                    # ── Agent connected ────────────────────────────────
                    elif "Agent connected:" in line:
                        try:
                            peer = line.split("Agent connected:")[1].strip()
                            socketio.emit("agent_event", {
                                "type": "connected",
                                "peer": peer,
                                "time": datetime.now().isoformat(),
                            })
                        except Exception:
                            pass

        except Exception:
            pass

        time.sleep(0.5)


# ── Flask routes ───────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/state")
def api_state():
    with state_lock:
        return jsonify({
            "agents":    list(state["agents"].values()),
            "alerts":    state["alerts"][:50],
            "stats":     state["stats"],
            "live_feed": state["live_feed"][:30],
        })


# ── SocketIO events ────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    # Build payload inside lock, emit outside to avoid deadlock
    with state_lock:
        payload = {
            "agents":    list(state["agents"].values()),
            "alerts":    state["alerts"][:50],
            "stats":     state["stats"],
            "live_feed": state["live_feed"][:30],
        }
    emit("init", payload)


# ── Dashboard HTML ─────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NESRD — Ransomware Detection Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:     #040810;
    --bg2:    #080f1a;
    --bg3:    #0d1829;
    --border: #1a2d4a;
    --accent: #00d4ff;
    --accent2:#0066ff;
    --green:  #00ff88;
    --yellow: #ffcc00;
    --red:    #ff3355;
    --text:   #c8d8e8;
    --text2:  #6888a8;
    --mono:   'Share Tech Mono', monospace;
    --sans:   'Rajdhani', sans-serif;
  }

  * { margin:0; padding:0; box-sizing:border-box; }

  html { background: var(--bg); min-height: 100%; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    min-height: 100vh;
    overflow-x: hidden;
    background-attachment: fixed;
  }

  body::before {
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg, transparent, transparent 2px,
      rgba(0,212,255,0.012) 2px, rgba(0,212,255,0.012) 4px
    );
    pointer-events: none; z-index: 9999;
  }

  header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 28px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(90deg, #000408 0%, #040e1c 50%, #000408 100%);
    position: sticky; top: 0; z-index: 100;
  }

  .logo { display:flex; align-items:center; gap:14px; }

  .logo-icon {
    width:36px; height:36px;
    border:2px solid var(--accent); border-radius:4px;
    display:flex; align-items:center; justify-content:center;
    font-family:var(--mono); font-size:14px; color:var(--accent);
    background:rgba(0,212,255,0.05);
    animation:pulse-border 3s ease infinite;
  }

  @keyframes pulse-border {
    0%,100% { box-shadow:0 0 10px rgba(0,212,255,0.3); }
    50%      { box-shadow:0 0 22px rgba(0,212,255,0.6); }
  }

  .logo h1 {
    font-size:22px; font-weight:700; letter-spacing:3px;
    color:var(--accent); text-shadow:0 0 20px rgba(0,212,255,0.5);
  }

  .logo p {
    font-size:10px; color:var(--text2);
    letter-spacing:2px; font-family:var(--mono); text-transform:uppercase;
  }

  .header-right { display:flex; align-items:center; gap:24px; }

  .status-dot {
    display:flex; align-items:center; gap:8px;
    font-family:var(--mono); font-size:12px; color:var(--green);
  }

  .dot {
    width:8px; height:8px; border-radius:50%;
    background:var(--green); box-shadow:0 0 8px var(--green);
    animation:blink 2s ease infinite;
  }

  @keyframes blink { 0%,100%{opacity:1;} 50%{opacity:0.3;} }

  #clock { font-family:var(--mono); font-size:13px; color:var(--text2); }

  .threat-bar {
    display:flex; align-items:center; gap:12px;
    padding:6px 28px; background:var(--bg3); border-bottom:1px solid var(--border);
  }

  .threat-label {
    font-size:10px; font-family:var(--mono);
    color:var(--text2); letter-spacing:1px; flex-shrink:0;
  }

  .threat-track { flex:1; height:4px; background:var(--border); border-radius:2px; overflow:hidden; }

  .threat-fill { height:100%; border-radius:2px; transition:width 0.8s ease, background 0.5s ease; }

  .threat-value {
    font-family:var(--mono); font-size:11px; color:var(--accent);
    flex-shrink:0; min-width:36px; text-align:right;
  }

  .container {
    padding:20px 28px;
    display:grid;
    grid-template-columns:1fr 1fr 1fr 1fr;
    gap:16px;
  }

  .stats-row { grid-column:1/-1; display:grid; grid-template-columns:repeat(4,1fr); gap:16px; }

  .stat-card {
    background:var(--bg2); border:1px solid var(--border);
    border-radius:6px; padding:20px; position:relative; overflow:hidden;
  }

  .stat-card::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; }
  .stat-card.blue::before   { background:linear-gradient(90deg,transparent,var(--accent),transparent); }
  .stat-card.green::before  { background:linear-gradient(90deg,transparent,var(--green),transparent); }
  .stat-card.yellow::before { background:linear-gradient(90deg,transparent,var(--yellow),transparent); }
  .stat-card.red::before    { background:linear-gradient(90deg,transparent,var(--red),transparent); }

  .stat-label {
    font-size:10px; letter-spacing:2px; text-transform:uppercase;
    color:var(--text2); font-family:var(--mono); margin-bottom:8px;
  }

  .stat-value { font-size:42px; font-weight:700; line-height:1; font-family:var(--mono); }

  .stat-card.blue   .stat-value { color:var(--accent); text-shadow:0 0 20px rgba(0,212,255,0.4); }
  .stat-card.green  .stat-value { color:var(--green);  text-shadow:0 0 20px rgba(0,255,136,0.4); }
  .stat-card.yellow .stat-value { color:var(--yellow); text-shadow:0 0 20px rgba(255,204,0,0.4); }
  .stat-card.red    .stat-value { color:var(--red);    text-shadow:0 0 20px rgba(255,51,85,0.4); }

  .stat-sub { font-size:11px; color:var(--text2); margin-top:6px; font-family:var(--mono); }

  .panel { background:var(--bg2); border:1px solid var(--border); border-radius:6px; overflow:hidden; }

  .panel-header {
    padding:12px 16px; border-bottom:1px solid var(--border);
    display:flex; align-items:center; justify-content:space-between;
    background:rgba(0,212,255,0.03);
  }

  .panel-title {
    font-size:11px; letter-spacing:2px; text-transform:uppercase;
    color:var(--accent); font-family:var(--mono);
    display:flex; align-items:center; gap:8px;
  }
  .panel-title::before { content:'//'; color:var(--text2); }

  .panel-body { padding:12px; }

  .agents-panel { grid-column:1/3; }

  .agent-row {
    display:flex; align-items:center; gap:12px;
    padding:10px 12px; border-bottom:1px solid rgba(26,45,74,0.5);
    transition:background 0.2s;
  }
  .agent-row:hover { background:rgba(0,212,255,0.04); }
  .agent-row:last-child { border-bottom:none; }

  .agent-dot { width:10px; height:10px; border-radius:50%; flex-shrink:0; }
  .agent-dot.active   { background:var(--green); box-shadow:0 0 8px var(--green); animation:blink 2s ease infinite; }
  .agent-dot.isolated { background:var(--red);   box-shadow:0 0 8px var(--red); }
  .agent-dot.offline  { background:var(--text2); }

  .agent-info { flex:1; }
  .agent-id   { font-family:var(--mono); font-size:13px; color:var(--text); }
  .agent-meta { font-size:11px; color:var(--text2); font-family:var(--mono); margin-top:2px; }

  .agent-badge {
    font-size:10px; font-family:var(--mono);
    letter-spacing:1px; padding:3px 8px;
    border-radius:2px; text-transform:uppercase;
  }
  .agent-badge.active   { background:rgba(0,255,136,0.1);  color:var(--green); border:1px solid rgba(0,255,136,0.3); }
  .agent-badge.isolated { background:rgba(255,51,85,0.1);  color:var(--red);   border:1px solid rgba(255,51,85,0.3); }
  .agent-badge.offline  { background:rgba(104,136,168,0.1);color:var(--text2); border:1px solid var(--border); }

  .feed-panel { grid-column:3/-1; }

  .feed-row {
    display:flex; align-items:flex-start; gap:10px;
    padding:8px 12px; border-bottom:1px solid rgba(26,45,74,0.4);
    font-family:var(--mono); font-size:12px;
    animation:slide-in 0.25s ease;
  }
  .feed-row:last-child { border-bottom:none; }

  @keyframes slide-in { from{opacity:0;transform:translateX(8px);} to{opacity:1;transform:translateX(0);} }

  .feed-badge {
    font-size:10px; letter-spacing:1px;
    padding:2px 6px; border-radius:2px; flex-shrink:0; margin-top:1px;
  }
  .feed-badge.LOG     { background:rgba(104,136,168,0.15); color:var(--text2); }
  .feed-badge.ALERT   { background:rgba(255,204,0,0.15);   color:var(--yellow); border:1px solid rgba(255,204,0,0.3); }
  .feed-badge.ISOLATE { background:rgba(255,51,85,0.15);   color:var(--red);    border:1px solid rgba(255,51,85,0.4); }

  .feed-content { flex:1; }
  .feed-agent { color:var(--accent2); }
  .feed-conf  { color:var(--text2); }
  .feed-time  { color:var(--text2); font-size:10px; flex-shrink:0; }

  .alerts-panel { grid-column:1/3; }

  .alert-row {
    display:flex; align-items:flex-start; gap:12px;
    padding:10px 12px; border-bottom:1px solid rgba(26,45,74,0.4);
    animation:slide-in 0.25s ease;
  }
  .alert-row:last-child { border-bottom:none; }

  .alert-icon { font-size:16px; flex-shrink:0; margin-top:2px; }
  .alert-body { flex:1; }
  .alert-top  { display:flex; align-items:center; gap:8px; margin-bottom:3px; }

  .alert-decision { font-size:11px; letter-spacing:1px; font-family:var(--mono); font-weight:700; }
  .alert-decision.ISOLATE { color:var(--red); }
  .alert-decision.ALERT   { color:var(--yellow); }
  .alert-decision.LOG     { color:var(--text2); }

  .alert-agent  { font-size:11px; color:var(--text2); font-family:var(--mono); }
  .alert-conf   { font-size:11px; font-family:var(--mono); margin-left:auto; }
  .alert-reason { font-size:12px; color:var(--text); font-family:var(--mono); }
  .alert-time   { font-size:10px; color:var(--text2); font-family:var(--mono); margin-top:2px; }

  .chart-panel { grid-column:3/-1; }
  canvas { max-height:200px; }

  .scrollable {
    max-height:280px; overflow-y:auto;
    scrollbar-width:thin; scrollbar-color:var(--border) transparent;
  }
  .scrollable::-webkit-scrollbar       { width:4px; }
  .scrollable::-webkit-scrollbar-track { background:transparent; }
  .scrollable::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }

  .empty-state {
    padding:32px; text-align:center;
    color:var(--text2); font-family:var(--mono); font-size:12px;
  }

  @keyframes flash-red    { 0%{background:rgba(255,51,85,0.18);}  100%{background:transparent;} }
  @keyframes flash-yellow { 0%{background:rgba(255,204,0,0.12);}  100%{background:transparent;} }
  .flash-red    { animation:flash-red    0.6s ease forwards; }
  .flash-yellow { animation:flash-yellow 0.6s ease forwards; }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">N</div>
    <div>
      <h1>NESRD</h1>
      <p>Network Early-Stage Ransomware Detector</p>
    </div>
  </div>
  <div class="header-right">
    <div class="status-dot"><div class="dot"></div><span>SYSTEM ACTIVE</span></div>
    <div id="clock">--:--:--</div>
  </div>
</header>

<div class="threat-bar">
  <span class="threat-label">THREAT LEVEL</span>
  <div class="threat-track">
    <div class="threat-fill" id="threat-fill" style="width:0%;background:var(--green)"></div>
  </div>
  <span class="threat-value" id="threat-value">0%</span>
</div>

<div class="container">

  <div class="stats-row">
    <div class="stat-card blue">
      <div class="stat-label">Agents Connected</div>
      <div class="stat-value" id="stat-agents">0</div>
      <div class="stat-sub">monitoring endpoints</div>
    </div>
    <div class="stat-card green">
      <div class="stat-label">Total Detections</div>
      <div class="stat-value" id="stat-total">0</div>
      <div class="stat-sub">alerts + isolations</div>
    </div>
    <div class="stat-card yellow">
      <div class="stat-label">Alerts Raised</div>
      <div class="stat-value" id="stat-alerts">0</div>
      <div class="stat-sub">confidence &gt; threshold</div>
    </div>
    <div class="stat-card red">
      <div class="stat-label">Endpoints Isolated</div>
      <div class="stat-value" id="stat-isolated">0</div>
      <div class="stat-sub">ransomware blocked</div>
    </div>
  </div>

  <div class="panel agents-panel">
    <div class="panel-header">
      <span class="panel-title">Agent Status</span>
      <span id="agent-count" style="font-size:11px;color:var(--text2);font-family:var(--mono)">0 agents</span>
    </div>
    <div class="scrollable" id="agents-list">
      <div class="empty-state">Waiting for agent connections...</div>
    </div>
  </div>

  <div class="panel feed-panel">
    <div class="panel-header">
      <span class="panel-title">Live Decision Feed</span>
      <span style="font-size:10px;color:var(--green);font-family:var(--mono)">&#9679; LIVE</span>
    </div>
    <div class="scrollable" id="live-feed">
      <div class="empty-state">No decisions yet...</div>
    </div>
  </div>

  <div class="panel alerts-panel">
    <div class="panel-header">
      <span class="panel-title">Alert History</span>
      <span id="alert-count" style="font-size:11px;color:var(--text2);font-family:var(--mono)">0 alerts</span>
    </div>
    <div class="scrollable" id="alerts-list">
      <div class="empty-state">No alerts recorded yet...</div>
    </div>
  </div>

  <div class="panel chart-panel">
    <div class="panel-header">
      <span class="panel-title">Decision Timeline</span>
    </div>
    <div class="panel-body">
      <canvas id="timeline-chart"></canvas>
    </div>
  </div>

</div>

<script>
const socket = io();
let agents   = {};
let alerts   = [];
let liveFeed = [];
let stats    = { total_alerts:0, total_isolations:0, total_alerts_only:0 };

// ── Clock ──────────────────────────────────────────────────────────────────
setInterval(() => {
  document.getElementById('clock').textContent =
    new Date().toLocaleTimeString('en-GB');
}, 1000);

// ── Chart ──────────────────────────────────────────────────────────────────
const ctx = document.getElementById('timeline-chart').getContext('2d');
const chart = new Chart(ctx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      { label:'LOG',     data:[], borderColor:'#6888a8', backgroundColor:'rgba(104,136,168,0.08)', tension:0.4, fill:true, borderWidth:1.5, pointRadius:0 },
      { label:'ALERT',   data:[], borderColor:'#ffcc00', backgroundColor:'rgba(255,204,0,0.08)',   tension:0.4, fill:true, borderWidth:1.5, pointRadius:0 },
      { label:'ISOLATE', data:[], borderColor:'#ff3355', backgroundColor:'rgba(255,51,85,0.12)',   tension:0.4, fill:true, borderWidth:2,   pointRadius:0 },
    ],
  },
  options: {
    responsive:true, maintainAspectRatio:true,
    animation:{ duration:200 },
    plugins:{ legend:{ labels:{ color:'#6888a8', font:{ family:'Share Tech Mono', size:11 } } } },
    scales:{
      x:{ ticks:{ color:'#6888a8', font:{ family:'Share Tech Mono', size:10 }, maxTicksLimit:10 }, grid:{ color:'rgba(26,45,74,0.5)' } },
      y:{ ticks:{ color:'#6888a8', font:{ family:'Share Tech Mono', size:10 } }, grid:{ color:'rgba(26,45,74,0.5)' }, beginAtZero:true },
    },
  },
});

let cLog = 0, cAlert = 0, cIsolate = 0;

// FIX: Accept optional timeLabel so historical replay uses real timestamps
// instead of current time, keeping chart accurate after page refresh.
function pushChart(decision, timeLabel) {
  const label = timeLabel || new Date().toLocaleTimeString('en-GB');
  if (decision === 'LOG')     cLog++;
  if (decision === 'ALERT')   cAlert++;
  if (decision === 'ISOLATE') cIsolate++;

  const labels = chart.data.labels;
  if (labels.length === 0 || labels[labels.length - 1] !== label) {
    labels.push(label);
    chart.data.datasets[0].data.push(cLog);
    chart.data.datasets[1].data.push(cAlert);
    chart.data.datasets[2].data.push(cIsolate);
    if (labels.length > 40) {
      labels.shift();
      chart.data.datasets.forEach(d => d.data.shift());
    }
  } else {
    const i = labels.length - 1;
    chart.data.datasets[0].data[i] = cLog;
    chart.data.datasets[1].data[i] = cAlert;
    chart.data.datasets[2].data[i] = cIsolate;
  }
  chart.update('none');
}

// ── Renderers ──────────────────────────────────────────────────────────────
function renderAgents() {
  const arr = Object.values(agents);
  document.getElementById('stat-agents').textContent = arr.length;
  document.getElementById('agent-count').textContent =
    arr.length + ' agent' + (arr.length !== 1 ? 's' : '');

  const el = document.getElementById('agents-list');
  if (arr.length === 0) {
    el.innerHTML = '<div class="empty-state">Waiting for agent connections...</div>';
    return;
  }

  el.innerHTML = arr.map(a => {
    const status = a.status || 'active';
    return '<div class="agent-row">'
      + '<div class="agent-dot ' + status + '"></div>'
      + '<div class="agent-info">'
      + '<div class="agent-id">' + a.id + '</div>'
      + '<div class="agent-meta">'
      + (a.ip || '&mdash;') + ' &nbsp;&middot;&nbsp; '
      + 'last seen ' + ((a.last_seen || '').substring(11,19) || '&mdash;') + ' &nbsp;&middot;&nbsp; '
      + (a.decisions || 0) + ' decisions'
      + '</div></div>'
      + '<span class="agent-badge ' + status + '">' + status + '</span>'
      + '</div>';
  }).join('');
}

function renderFeed() {
  const el = document.getElementById('live-feed');
  if (liveFeed.length === 0) {
    el.innerHTML = '<div class="empty-state">No decisions yet...</div>';
    return;
  }
  el.innerHTML = liveFeed.slice(0, 30).map(e => {
    const conf = ((e.confidence || 0) * 100).toFixed(0);
    const pid  = (e.pid && e.pid !== '0') ? ' &middot; pid:' + e.pid : '';
    return '<div class="feed-row">'
      + '<span class="feed-badge ' + e.decision + '">' + e.decision + '</span>'
      + '<div class="feed-content">'
      + '<span class="feed-agent">' + (e.agent || '&mdash;') + '</span>'
      + '<span class="feed-conf"> &middot; ' + conf + '%' + pid + '</span>'
      + '</div>'
      + '<span class="feed-time">' + (e.time || '').substring(11,19) + '</span>'
      + '</div>';
  }).join('');
}

function renderAlerts() {
  const el = document.getElementById('alerts-list');
  document.getElementById('alert-count').textContent =
    alerts.length + ' alert' + (alerts.length !== 1 ? 's' : '');

  if (alerts.length === 0) {
    el.innerHTML = '<div class="empty-state">No alerts recorded yet...</div>';
    return;
  }

  el.innerHTML = alerts.slice(0, 50).map(a => {
    const icon      = a.decision === 'ISOLATE' ? '&#128308;' : a.decision === 'ALERT' ? '&#128993;' : '&#9898;';
    const conf      = a.confidence != null ? (a.confidence * 100).toFixed(0) + '%' : '&mdash;';
    const confColor = a.decision === 'ISOLATE' ? 'var(--red)' : a.decision === 'ALERT' ? 'var(--yellow)' : 'var(--text2)';
    return '<div class="alert-row">'
      + '<span class="alert-icon">' + icon + '</span>'
      + '<div class="alert-body">'
      + '<div class="alert-top">'
      + '<span class="alert-decision ' + a.decision + '">' + a.decision + '</span>'
      + '<span class="alert-agent">' + (a.agent_id || '&mdash;') + '</span>'
      + '<span class="alert-conf" style="color:' + confColor + '">' + conf + '</span>'
      + '</div>'
      + '<div class="alert-reason">' + (a.reason || '&mdash;') + '</div>'
      + (a.process_name ? '<div class="alert-time" style="color:var(--accent2)">&#9654; '
          + a.process_name + ' (PID ' + a.process_pid + ')'
          + ' &nbsp;&middot;&nbsp; ' + (a.detection_time_ms || 0) + 'ms response'
          + '</div>' : '')
      + '<div class="alert-time">' + (a.timestamp || '') + '</div>'
      + '</div></div>';
  }).join('');
}

function renderStats() {
  const total     = stats.total_alerts      || 0;
  const isolated  = stats.total_isolations  || 0;
  const alertOnly = stats.total_alerts_only || 0;

  document.getElementById('stat-total').textContent    = total;
  document.getElementById('stat-alerts').textContent   = alertOnly;
  document.getElementById('stat-isolated').textContent = isolated;

  const level = Math.min(100, isolated * 20 + alertOnly * 5);
  const fill  = document.getElementById('threat-fill');
  fill.style.width      = level + '%';
  fill.style.background = level >= 60 ? 'var(--red)' : level >= 30 ? 'var(--yellow)' : 'var(--green)';
  document.getElementById('threat-value').textContent = level + '%';
}

function flash(decision) {
  document.body.classList.remove('flash-red', 'flash-yellow');
  void document.body.offsetWidth; // force reflow to restart animation
  if (decision === 'ISOLATE')    document.body.classList.add('flash-red');
  else if (decision === 'ALERT') document.body.classList.add('flash-yellow');
}

// ── Socket events ──────────────────────────────────────────────────────────
socket.on('init', data => {
  agents   = {};
  (data.agents || []).forEach(a => { agents[a.id] = a; });
  alerts   = data.alerts    || [];
  liveFeed = data.live_feed || [];
  stats    = data.stats     || stats;
  renderAgents(); renderFeed(); renderAlerts(); renderStats();

  // FIX: Pre-populate chart from history using real timestamps
  // so the graph survives page refresh correctly
  const reversed = [...liveFeed].reverse();
  reversed.forEach(e => pushChart(e.decision, (e.time || '').substring(11,19)));
});

socket.on('live_decision', entry => {
  liveFeed.unshift(entry);
  if (liveFeed.length > 50) liveFeed.pop();
  if (entry.agent) {
    if (!agents[entry.agent])
      agents[entry.agent] = { id:entry.agent, ip:'', last_seen:'', status:'active', decisions:0 };
    agents[entry.agent].last_seen = entry.time;
    agents[entry.agent].decisions = (agents[entry.agent].decisions || 0) + 1;
    if (entry.decision === 'ISOLATE') agents[entry.agent].status = 'isolated';
  }
  renderFeed(); renderAgents();
  // Pass real timestamp to chart
  pushChart(entry.decision, (entry.time || '').substring(11,19));
});

socket.on('new_alert', alert => {
  alerts.unshift(alert);
  if (alerts.length > 200) alerts.pop();
  // Recompute stats from source of truth
  stats.total_alerts      = alerts.length;
  stats.total_isolations  = alerts.filter(a => a.decision === 'ISOLATE').length;
  stats.total_alerts_only = alerts.filter(a => a.decision === 'ALERT').length;
  renderAlerts(); renderStats(); flash(alert.decision);
});

socket.on('agent_heartbeat', data => {
  if (!data.agent_id) return;
  const id = data.agent_id;
  if (!agents[id])
    agents[id] = { id, ip:data.agent_ip||'', last_seen:data.time, status:'active', decisions:0 };
  else {
    agents[id].last_seen = data.time;
    if (data.agent_ip) agents[id].ip = data.agent_ip;
    if (agents[id].status !== 'isolated') agents[id].status = 'active';
  }
  renderAgents();
});

socket.on('disconnect', () => {
  document.querySelector('.status-dot span').textContent = 'DISCONNECTED';
  document.querySelector('.dot').style.background = 'var(--red)';
  document.querySelector('.dot').style.boxShadow  = '0 0 8px var(--red)';
});

socket.on('connect', () => {
  document.querySelector('.status-dot span').textContent = 'SYSTEM ACTIVE';
  document.querySelector('.dot').style.background = 'var(--green)';
  document.querySelector('.dot').style.boxShadow  = '0 0 8px var(--green)';
});
</script>
</body>
</html>
"""

# ── Main ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)

    threading.Thread(target=watch_alerts, daemon=True, name="AlertWatcher").start()
    threading.Thread(target=watch_log,    daemon=True, name="LogWatcher").start()

    print("=" * 50)
    print("  NESRD Dashboard")
    print("  http://localhost:5000")
    print("=" * 50)

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        allow_unsafe_werkzeug=True
    )