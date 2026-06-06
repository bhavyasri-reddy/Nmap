from flask import Flask, render_template, request, redirect, session, url_for, send_file
import io
import os
import sqlite3
import datetime

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
except ModuleNotFoundError:
    letter = None
    canvas = None
    inch = None

app = Flask(__name__)
app.secret_key = "secret123"
DB_PATH = os.path.join(app.root_path, "database.db")

# ---------------- DATABASE ----------------
def get_db_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY, username TEXT, target TEXT, result TEXT, date TEXT)''')

    conn.commit()
    conn.close()

init_db()

# ---------------- PDF GENERATION ----------------

def generate_scan_pdf(target, findings, username, scan_date):
    if canvas is None or letter is None or inch is None:
        raise RuntimeError("Reportlab is required to generate PDF reports. Install reportlab and restart the app.")

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    c.setTitle(f"ScanResult_{target}")

    c.setFont("Helvetica-Bold", 18)
    c.drawString(1 * inch, height - 1 * inch, "Nmap AI Scan Result")

    c.setFont("Helvetica", 12)
    c.drawString(1 * inch, height - 1.4 * inch, f"Target: {target}")
    c.drawString(1 * inch, height - 1.7 * inch, f"User: {username}")
    c.drawString(1 * inch, height - 2.0 * inch, f"Date: {scan_date}")

    c.setFont("Helvetica-Bold", 14)
    c.drawString(1 * inch, height - 2.5 * inch, "Security Findings:")

    c.setFont("Helvetica", 12)
    y = height - 2.9 * inch
    if findings:
        for index, finding in enumerate(findings, start=1):
            if y < 1 * inch:
                c.showPage()
                y = height - 1 * inch
                c.setFont("Helvetica", 12)
            c.drawString(1.1 * inch, y, f"{index}. {finding}")
            y -= 0.3 * inch
    else:
        c.drawString(1.1 * inch, y, "No findings detected.")

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer

# ---------------- AI ANALYSIS ----------------
def ai_analysis(scan_data):
    insights = []
    
    for host in scan_data.all_hosts():
        for proto in scan_data[host].all_protocols():
            ports = scan_data[host][proto].keys()
            
            for port in ports:
                state = scan_data[host][proto][port]['state']
                
                if port == 22 and state == "open":
                    insights.append("⚠️ SSH open → Possible brute-force target")
                if port == 80:
                    insights.append("🌐 Web server detected")
                if port == 443:
                    insights.append("🔐 HTTPS service running")
                if state == "open":
                    insights.append(f"Open Port: {port}")
    
    return list(set(insights))


# ---------------- ROUTES ----------------

@app.route("/")
def home():
    return redirect(url_for('login'))


@app.route("/login", methods=["GET", "POST"])
@app.route("/login/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = request.form.get('username', '').strip()
        pwd = request.form.get('password', '').strip()

        if not user or not pwd:
            error = "Please enter both username and password."
        else:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=? AND password=?", (user, pwd))
            result = c.fetchone()
            conn.close()

            if result:
                session['user'] = user
                return redirect(url_for('dashboard'))
            error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
@app.route("/register/", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        user = request.form.get('username', '').strip()
        pwd = request.form.get('password', '').strip()

        if not user or not pwd:
            error = "Please enter both username and password."
        else:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE username=?", (user,))
            if c.fetchone():
                error = "Username already exists. Choose another one."
            else:
                c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user, pwd))
                conn.commit()
                conn.close()
                return redirect(url_for('login'))
            conn.close()

    return render_template("register.html", error=error)


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if 'user' not in session:
        return redirect("/")

    error = None
    if request.method == "POST":
        target = request.form['target']
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(target, '1-1024')
            ai_result = ai_analysis(nm)
        except ModuleNotFoundError:
            error = "Nmap Python package is not installed. Install python-nmap and restart the app."
        except Exception as exc:
            error = f"Scan failed: {exc}"
        else:
            scan_date = str(datetime.datetime.now())
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("INSERT INTO scans VALUES (NULL, ?, ?, ?, ?)",
                      (session['user'], target, str(ai_result), scan_date))
            scan_id = c.lastrowid
            conn.commit()
            conn.close()
            return render_template("result.html", result=ai_result, scan_id=scan_id, target=target, scan_date=scan_date)

    return render_template("dashboard.html", error=error)


@app.route("/download_scan/<int:scan_id>")
def download_scan(scan_id):
    if 'user' not in session:
        return redirect("/")

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username, target, result, date FROM scans WHERE id=?", (scan_id,))
    row = c.fetchone()
    conn.close()

    if not row or row[0] != session['user']:
        return redirect(url_for('history'))

    username, target, result_text, scan_date = row
    import ast
    try:
        findings = ast.literal_eval(result_text) if result_text else []
    except Exception:
        findings = []

    try:
        pdf_buffer = generate_scan_pdf(target, findings, username, scan_date)
    except RuntimeError as exc:
        return render_template("result.html", result=findings, scan_id=scan_id, target=target, scan_date=scan_date, download_error=str(exc))

    return send_file(
        pdf_buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'scan_result_{target}_{scan_id}.pdf',
        conditional=False
    )

@app.route("/history")
def history():
    if 'user' not in session:
        return redirect("/")

    # Fetch history
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM scans WHERE username=?", (session['user'],))
    scans = c.fetchall()
    conn.close()

    # Parse scan results for display
    processed_scans = []
    for scan in scans:
        try:
            # Parse the string representation of the list
            import ast
            findings = ast.literal_eval(scan[3]) if scan[3] else []
        except:
            findings = []
        
        processed_scans.append({
            'id': scan[0],
            'username': scan[1],
            'target': scan[2],
            'findings': findings,
            'date': scan[4]
        })
    
    return render_template("history.html", scans=processed_scans)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    # Use a different port if another local service is already occupying 5000
    app.run(debug=True, port=5001)