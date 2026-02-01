import os
import threading
from datetime import datetime
import networkx as nx
import matplotlib.pyplot as plt
import nmap
from flask import Flask, send_file, redirect

# -----------
# Config
# -----------
TARGET_SUBNET = "192.168.1.0/24"
PORT_RANGE = "1-1024"

OUTPUT_DIR = "static"
OUTPUT_IMAGE = os.path.join(OUTPUT_DIR, "network.png")
OUTPUT_HTML = os.path.join(OUTPUT_DIR, "index.html")
OUTPUT_REPORT = os.path.join(OUTPUT_DIR, "report.html")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

app = Flask(__name__)

SCAN_STATE = {
    "last_scan": None,
    "status": "idle",            # idle | scanning | done
    "hosts": [],
    "host_details": {},
    "open_ports_total": 0,
}

LOCK = threading.Lock()

# -----------------------------
# Helpers: Nmap path
# -----------------------------
def find_nmap_path() -> str:
    candidates = [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return "nmap"  # fallback if in PATH


# -----------------------------
# Risk model (safe heuristic)
# -----------------------------

PORT_INFO = {
    21:  ("FTP", "File transfer (often weak creds)", 3),
    22:  ("SSH", "Remote login (exposed admin access)", 2),
    23:  ("TELNET", "Unencrypted remote login (high risk)", 5),
    25:  ("SMTP", "Mail service (can be abused if open)", 2),
    53:  ("DNS", "Name service (check if intended)", 2),
    80:  ("HTTP", "Web service (check for weak pages)", 1),
    110: ("POP3", "Email retrieval (check security)", 2),
    135: ("MS RPC", "Windows RPC (common attack surface)", 4),
    139: ("NetBIOS", "Windows file sharing (legacy surface)", 4),
    143: ("IMAP", "Email retrieval (check security)", 2),
    443: ("HTTPS", "Secure web service (still check app security)", 1),
    445: ("SMB", "Windows file sharing (high-value target)", 5),
    512: ("rexec", "Legacy remote exec (risky)", 5),
    513: ("rlogin", "Legacy remote login (risky)", 5),
    514: ("rsh", "Legacy remote shell (risky)", 5),
    631: ("IPP", "Printing service (check exposure)", 2),
    3306: ("MySQL", "DB service (usually should not be open)", 5),
    5432: ("PostgreSQL", "DB service (usually should not be open)", 5),
}

def port_summary(proto: str, port: int) -> dict:
    svc, note, weight = PORT_INFO.get(port, ("Unknown", "No common profile", 1))
    return {
        "proto": proto.upper(),
        "port": port,
        "service": svc,
        "note": note,
        "risk_points": weight,
        "label": f"{proto.upper()}:{port} ({svc})"
    }

def host_risk(ports: list[dict]) -> dict:
    if not ports:
        return {
            "score": 0,
            "level": "LOW",
            "tag": "LIKELY NORMAL",
            "summary": "No open ports detected in scan range.",
            "top_exposures": "None"
        }

    score = sum(p["risk_points"] for p in ports)
    risky = [p for p in ports if p["risk_points"] >= 4]

    if score >= 12 or len(risky) >= 2:
        level = "HIGH"
        tag = "NEEDS REVIEW"
        summary = "Multiple risky services exposed. Confirm this host is expected."
    elif score >= 6 or len(risky) == 1:
        level = "MEDIUM"
        tag = "CHECK"
        summary = "Some exposed services found. Confirm they are expected."
    else:
        level = "LOW"
        tag = "LIKELY NORMAL"
        summary = "Only low-risk services found (based on open ports)."

    top_ports = sorted(ports, key=lambda x: x["risk_points"], reverse=True)[:3]
    top_text = ", ".join([p["label"] for p in top_ports]) if top_ports else "None"

    return {
        "score": score,
        "level": level,
        "tag": tag,
        "summary": summary,
        "top_exposures": top_text
    }


# -----------------------------
# Scanning
# -----------------------------
def scan_hosts(nm: nmap.PortScanner) -> list[str]:
    nm.scan(hosts=TARGET_SUBNET, arguments="-sn")
    return nm.all_hosts()

def scan_ports_for_host(host: str, nm_path: str) -> tuple[str, list[dict]]:
    nm = nmap.PortScanner(nmap_search_path=[nm_path] if nm_path.endswith(".exe") else None)
    nm.scan(host, PORT_RANGE)

    if host not in nm.all_hosts():
        return host, []

    found = []
    for proto in nm[host].all_protocols():
        for port in nm[host][proto].keys():
            if nm[host][proto][port]["state"] == "open":
                found.append(port_summary(proto, int(port)))

    found.sort(key=lambda x: (x["proto"], x["port"]))
    return host, found


# -----------------------------
# Graph generation (dark/neon)
# -----------------------------
def build_graph_image(hosts: list[str], host_details: dict):
    G = nx.Graph()

    for ip in hosts:
        risk_level = host_details.get(ip, {}).get("risk", {}).get("level", "LOW")
        G.add_node(ip, kind="host", risk=risk_level)

    for ip, details in host_details.items():
        for p in details.get("ports", []):
            port_node = f'{p["proto"]}:{p["port"]}'
            G.add_node(port_node, kind="port")
            G.add_edge(ip, port_node)

    pos = nx.spring_layout(G, k=0.8, iterations=90, seed=7)

    host_nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == "host"]
    port_nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == "port"]

    def host_color(node):
        level = G.nodes[node].get("risk", "LOW")
        if level == "HIGH":
            return "#ff4d4d"
        if level == "MEDIUM":
            return "#ffd166"
        return "#00ff88"

    host_colors = [host_color(n) for n in host_nodes]
    port_colors = ["#00b3ff" for _ in port_nodes]

    plt.figure(figsize=(14, 8), facecolor="#05070a")
    ax = plt.gca()
    ax.set_facecolor("#05070a")
    plt.axis("off")

    nx.draw_networkx_edges(G, pos, width=1.2, alpha=0.25, edge_color="#66ffcc")

    nx.draw_networkx_nodes(
        G, pos,
        nodelist=host_nodes,
        node_size=1900,
        node_color=host_colors,
        linewidths=1.2,
        edgecolors="#001b12",
        alpha=0.95
    )

    nx.draw_networkx_nodes(
        G, pos,
        nodelist=port_nodes,
        node_size=900,
        node_color=port_colors,
        linewidths=1.0,
        edgecolors="#00121b",
        alpha=0.9
    )

    nx.draw_networkx_labels(G, pos, labels={h: h for h in host_nodes}, font_size=9, font_color="#e6fff5")
    nx.draw_networkx_labels(G, pos, labels={p: p for p in port_nodes}, font_size=8, font_color="#d6f0ff")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    plt.title(
        f"Network Visualizer — {TARGET_SUBNET}\nScan time: {now} | Hosts: {len(host_nodes)}",
        fontsize=14,
        fontweight="bold",
        color="#b7ffe6",
        pad=18
    )

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    plt.savefig(OUTPUT_IMAGE, dpi=240, bbox_inches="tight", facecolor="#05070a")
    plt.close()


# -----------------------------
# HTML generators
# -----------------------------
def generate_report_page():
    last = SCAN_STATE["last_scan"] or "Not scanned yet"
    status = SCAN_STATE["status"]
    hosts = SCAN_STATE["hosts"]
    host_details = SCAN_STATE["host_details"]
    ports_total = SCAN_STATE["open_ports_total"]

    rows = []
    for ip in hosts:
        r = host_details.get(ip, {}).get("risk", {})
        rows.append(f"""
        <tr>
          <td><code>{ip}</code></td>
          <td>{r.get("level","LOW")}</td>
          <td><code>{r.get("score",0)}</code></td>
          <td class="muted">{r.get("top_exposures","None")}</td>
          <td class="muted">{r.get("summary","")}</td>
        </tr>
        """)

    rows_html = "\n".join(rows) if rows else '<tr><td colspan="5" class="muted">No results yet.</td></tr>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Scan Report</title>
  <style>
    body {{
      margin:0;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      background: #05070a;
      color: #d8ffe9;
      padding: 16px;
    }}
    .card {{
      background: rgba(11,17,22,0.85);
      border: 1px solid rgba(0,255,136,0.18);
      border-radius: 14px;
      padding: 14px;
      max-width: 1100px;
      margin: 0 auto;
    }}
    h1 {{ margin: 0 0 10px 0; font-size: 18px; }}
    .muted {{ color: rgba(216,255,233,0.65); }}
    table {{ width:100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }}
    th, td {{ padding: 10px; border-bottom: 1px solid rgba(0,255,136,0.10); vertical-align: top; }}
    th {{ text-align:left; color: #00ff88; }}
    code {{
      background: rgba(0,255,136,0.10);
      color: #00ff88;
      border: 1px solid rgba(0,255,136,0.12);
      padding: 2px 6px;
      border-radius: 8px;
    }}
    a {{ color: #00b3ff; text-decoration:none; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Network Scan Report</h1>
    <div class="muted">Status: <b>{status}</b> • Last Scan: <b>{last}</b> • Hosts: <b>{len(hosts)}</b> • Open Ports: <b>{ports_total}</b></div>

    <table>
      <thead>
        <tr>
          <th>IP</th>
          <th>Risk</th>
          <th>Score</th>
          <th>Top Exposures</th>
          <th>Summary</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>

    <p class="muted" style="margin-top:12px;">
      Back to <a href="/">Dashboard</a>
    </p>
  </div>
</body>
</html>
"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_REPORT, "w", encoding="utf-8") as f:
        f.write(html)


def generate_html_page():
    last = SCAN_STATE["last_scan"] or "Not scanned yet"
    status = SCAN_STATE["status"]
    hosts = SCAN_STATE["hosts"]
    host_details = SCAN_STATE["host_details"]
    ports_total = SCAN_STATE["open_ports_total"]

    high = sum(1 for ip in hosts if host_details.get(ip, {}).get("risk", {}).get("level") == "HIGH")
    med  = sum(1 for ip in hosts if host_details.get(ip, {}).get("risk", {}).get("level") == "MEDIUM")
    low  = sum(1 for ip in hosts if host_details.get(ip, {}).get("risk", {}).get("level") == "LOW")

    # Cache-bust image (so you always see newest graph after scan)
    img_v = int(datetime.now().timestamp())

    # Simple IP list like before
    ip_list_html = "".join(f"<li><code>{ip}</code></li>" for ip in hosts) if hosts else "<li class='muted'>No hosts yet</li>"

    def badge(level: str) -> str:
        if level == "HIGH":
            return '<span class="pill high">HIGH</span>'
        if level == "MEDIUM":
            return '<span class="pill med">MED</span>'
        return '<span class="pill low">LOW</span>'

    host_cards = []
    for ip in hosts:
        details = host_details.get(ip, {})
        ports = details.get("ports", [])
        risk = details.get("risk", {})
        level = risk.get("level", "LOW")
        summary = risk.get("summary", "")
        top = risk.get("top_exposures", "None")

        ports_html = ""
        if ports:
            for p in ports:
                ports_html += f"""
                <tr>
                  <td><code>{p['proto']}</code></td>
                  <td><code>{p['port']}</code></td>
                  <td>{p['service']}</td>
                  <td class="muted">{p['note']}</td>
                  <td><code>{p['risk_points']}</code></td>
                </tr>
                """
        else:
            ports_html = """
            <tr><td colspan="5" class="muted">No open ports found in scan range.</td></tr>
            """

        host_cards.append(f"""
        <details class="host">
          <summary>
            <div class="row">
              <div class="ip">{ip}</div>
              <div class="meta">
                {badge(level)}
                <span class="muted">Score: <b>{risk.get('score', 0)}</b></span>
                <span class="muted">Top: {top}</span>
              </div>
            </div>
            <div class="muted summary">{summary}</div>
          </summary>

          <div class="panel">
            <table>
              <thead>
                <tr>
                  <th>Proto</th>
                  <th>Port</th>
                  <th>Service</th>
                  <th>Why it matters</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {ports_html}
              </tbody>
            </table>
          </div>
        </details>
        """)

    host_cards_html = "\n".join(host_cards) if host_cards else '<div class="muted">No scan results yet.</div>'

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Network Visualizer</title>
  <style>
    :root {{
      --bg: #05070a;
      --border: rgba(0,255,136,0.18);
      --text: #d8ffe9;
      --muted: rgba(216,255,233,0.65);
      --green: #00ff88;
      --cyan: #00b3ff;
      --red: #ff4d4d;
      --yellow: #ffd166;
    }}
    body {{
      margin:0;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      background: radial-gradient(1200px 700px at 20% 0%, rgba(0,255,136,0.12), transparent 55%),
                  radial-gradient(900px 600px at 90% 10%, rgba(0,179,255,0.12), transparent 60%),
                  var(--bg);
      color: var(--text);
    }}
    header {{
      padding: 18px 18px;
      border-bottom: 1px solid var(--border);
      background: rgba(5,7,10,0.7);
      backdrop-filter: blur(8px);
    }}
    header .title {{
      display:flex;
      align-items:center;
      gap:10px;
      font-size: 18px;
      letter-spacing: 1px;
    }}
    .dot {{
      width:10px; height:10px; border-radius:50%;
      background: var(--green);
      box-shadow: 0 0 12px rgba(0,255,136,0.8);
    }}
    header .sub {{
      margin-top: 8px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.4;
    }}
    .wrap {{
      max-width: 1150px;
      margin: 16px auto;
      padding: 0 14px;
    }}
    .card {{
      background: rgba(11,17,22,0.85);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 14px;
      box-shadow: 0 10px 24px rgba(0,0,0,0.45);
      margin-bottom: 14px;
    }}
    .topbar {{
      display:flex;
      flex-wrap:wrap;
      gap: 10px;
      align-items:center;
      justify-content: space-between;
    }}
    .badges {{
      display:flex;
      gap:8px;
      flex-wrap:wrap;
      align-items:center;
    }}
    .badge {{
      border:1px solid var(--border);
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 12px;
      color: var(--muted);
      background: rgba(0,0,0,0.2);
    }}
    .badge b {{ color: var(--text); }}
    .actions {{
      display:flex;
      gap:10px;
      flex-wrap:wrap;
    }}
    .btn {{
      text-decoration:none;
      border:1px solid var(--border);
      padding: 10px 12px;
      border-radius: 12px;
      color: var(--text);
      background: rgba(0,255,136,0.07);
      transition: 0.15s;
      font-weight: 700;
      letter-spacing: 0.5px;
    }}
    .btn:hover {{
      transform: translateY(-1px);
      box-shadow: 0 0 18px rgba(0,255,136,0.12);
      border-color: rgba(0,255,136,0.35);
    }}
    .grid {{
      display:grid;
      grid-template-columns: 2fr 1fr;
      gap: 14px;
    }}
    img {{
      width: 100%;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: black;
    }}
    .muted {{ color: var(--muted); }}
    .pill {{
      font-size: 11px;
      padding: 5px 10px;
      border-radius: 999px;
      font-weight: 800;
      letter-spacing: 0.5px;
      border: 1px solid rgba(255,255,255,0.08);
    }}
    .pill.low {{
      background: rgba(0,255,136,0.14);
      color: var(--green);
      border-color: rgba(0,255,136,0.25);
    }}
    .pill.med {{
      background: rgba(255,209,102,0.14);
      color: var(--yellow);
      border-color: rgba(255,209,102,0.25);
    }}
    .pill.high {{
      background: rgba(255,77,77,0.14);
      color: var(--red);
      border-color: rgba(255,77,77,0.25);
    }}
    details.host {{
      border: 1px solid rgba(0,255,136,0.14);
      border-radius: 12px;
      background: rgba(0,0,0,0.18);
      margin-bottom: 10px;
      overflow:hidden;
    }}
    details.host summary {{
      cursor:pointer;
      list-style:none;
      padding: 12px;
      outline:none;
    }}
    details.host summary::-webkit-details-marker {{ display:none; }}
    .row {{
      display:flex;
      gap: 10px;
      align-items:center;
      justify-content: space-between;
      flex-wrap: wrap;
    }}
    .ip {{
      font-weight: 900;
      color: var(--text);
      font-size: 14px;
    }}
    .meta {{
      display:flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items:center;
      font-size: 12px;
    }}
    .summary {{
      margin-top: 6px;
      font-size: 12px;
    }}
    .panel {{
      padding: 0 12px 12px 12px;
    }}
    table {{
      width:100%;
      border-collapse: collapse;
      margin-top: 8px;
      font-size: 12px;
    }}
    th, td {{
      padding: 8px 8px;
      border-bottom: 1px solid rgba(0,255,136,0.10);
      vertical-align: top;
    }}
    th {{
      color: var(--green);
      text-align:left;
      font-size: 12px;
      letter-spacing: 0.5px;
    }}
    code {{
      background: rgba(0,255,136,0.10);
      color: var(--green);
      border: 1px solid rgba(0,255,136,0.12);
      padding: 2px 6px;
      border-radius: 8px;
    }}
    .note {{
      margin-top: 10px;
      font-size: 12px;
      color: var(--muted);
    }}

    /* Loading overlay */
    .overlay {{
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(0,0,0,0.65);
      z-index: 9999;
      backdrop-filter: blur(6px);
    }}
    .overlay .box {{
      border: 1px solid rgba(0,255,136,0.25);
      border-radius: 14px;
      padding: 18px 18px;
      background: rgba(11,17,22,0.95);
      width: 340px;
      text-align: center;
      box-shadow: 0 10px 24px rgba(0,0,0,0.55);
    }}
    .spinner {{
      width: 40px;
      height: 40px;
      border-radius: 50%;
      border: 4px solid rgba(0,255,136,0.20);
      border-top-color: rgba(0,255,136,0.95);
      margin: 0 auto 12px auto;
      animation: spin 0.9s linear infinite;
    }}
    @keyframes spin {{
      to {{ transform: rotate(360deg); }}
    }}
  </style>
</head>
<body>

  <div class="overlay" id="overlay">
    <div class="box">
      <div class="spinner"></div>
      <div style="font-weight:800; letter-spacing:0.5px;">SCANNING…</div>
      <div class="muted" style="margin-top:8px; font-size:12px;">
        Discovering hosts and checking open ports…
      </div>
    </div>
  </div>

  <header>
    <div class="title"><span class="dot"></span> Network Visualizer</div>
    <div class="sub">
      Active hosts + open ports map (Nmap + NetworkX + Flask) • Risk tags are based on exposed services (not malware detection).
    </div>
  </header>

  <div class="wrap">
    <div class="card">
      <div class="topbar">
        <div class="badges">
          <div class="badge">Status: <b id="statusText">{status}</b></div>
          <div class="badge">Last Scan: <b>{last}</b></div>
          <div class="badge">Hosts: <b>{len(hosts)}</b></div>
          <div class="badge">Open Ports: <b>{ports_total}</b></div>
          <div class="badge">LOW: <b>{low}</b></div>
          <div class="badge">MED: <b>{med}</b></div>
          <div class="badge">HIGH: <b>{high}</b></div>
        </div>

        <div class="actions">
          <a class="btn" href="/scan">RUN SCAN</a>
          <a class="btn" href="/image">DOWNLOAD GRAPH</a>
          <a class="btn" href="/report">VIEW REPORT</a>
        </div>
      </div>

      <div class="note">
        ⚠️ Scan only networks you own or have permission to test.
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="muted" style="margin-bottom:10px;">Topology Graph</div>
        <img src="/static/network.png?v={img_v}" alt="Network graph image" />
      </div>

      <div class="card">
        <div class="muted" style="margin-bottom:10px;">Detected IPs</div>
        <ul style="margin-top:0;">{ip_list_html}</ul>

        <div class="muted" style="margin:14px 0 10px 0;">Host Exposure Summary</div>
        {host_cards_html}
      </div>
    </div>
  </div>

<script>
  const overlay = document.getElementById("overlay");
  const statusText = document.getElementById("statusText");

  let wasScanning = false;

  async function pollStatus() {{
    try {{
      const r = await fetch("/status?ts=" + Date.now(), {{ cache: "no-store" }});
      const st = (await r.text()).trim();
      statusText.textContent = st;

      if (st === "scanning") {{
        wasScanning = true;
        overlay.style.display = "flex";
        setTimeout(pollStatus, 1200);
        return;
      }}

      // done or idle
      overlay.style.display = "none";

      // if we were scanning and now finished -> refresh to show results automatically
      if (wasScanning && st === "done") {{
        window.location.reload();
        return;
      }}

      setTimeout(pollStatus, 2000);
    }} catch (e) {{
      // if error, try again
      setTimeout(pollStatus, 2000);
    }}
  }}

  // start polling on page load
  pollStatus();
</script>

</body>
</html>
"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)


# -----------------------------
# Scan runner
# -----------------------------
def perform_scan():
    with LOCK:
        SCAN_STATE["status"] = "scanning"
        SCAN_STATE["hosts"] = []
        SCAN_STATE["host_details"] = {}
        SCAN_STATE["open_ports_total"] = 0

    generate_html_page()
    generate_report_page()

    nm_path = find_nmap_path()

    nm_discovery = nmap.PortScanner(nmap_search_path=[nm_path] if nm_path.endswith(".exe") else None)
    hosts = scan_hosts(nm_discovery)

    results = {}
    threads = []

    def worker(ip: str):
        host_ip, ports = scan_ports_for_host(ip, nm_path)
        with LOCK:
            results[host_ip] = ports

    for ip in hosts:
        t = threading.Thread(target=worker, args=(ip,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    host_details = {}
    open_ports_total = 0
    for ip in hosts:
        ports = results.get(ip, [])
        open_ports_total += len(ports)
        risk = host_risk(ports)
        host_details[ip] = {"ports": ports, "risk": risk}

    build_graph_image(hosts, host_details)

    with LOCK:
        SCAN_STATE["hosts"] = hosts
        SCAN_STATE["host_details"] = host_details
        SCAN_STATE["open_ports_total"] = open_ports_total
        SCAN_STATE["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        SCAN_STATE["status"] = "done"

    generate_html_page()
    generate_report_page()


# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def home():
    if not os.path.exists(OUTPUT_HTML):
        generate_html_page()
    return send_file(OUTPUT_HTML)

@app.route("/scan")
def scan():
    threading.Thread(target=perform_scan, daemon=True).start()
    return redirect("/")

@app.route("/image")
def image():
    return send_file(OUTPUT_IMAGE, mimetype="image/png")

@app.route("/report")
def report():
    if not os.path.exists(OUTPUT_REPORT):
        generate_report_page()
    return send_file(OUTPUT_REPORT)

@app.route("/status")
def status():
    # plain text (not JSON)
    return SCAN_STATE["status"]


if __name__ == "__main__":
    generate_html_page()
    generate_report_page()
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False, threaded=True)
