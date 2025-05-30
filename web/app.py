import os
import psutil
import joblib
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename
from mluser_file.extract_suricata_alerts import extract_alerts, featurize
from tplink import inspect_router as inspect_tplink  # 공유기 점검 함수

app = Flask(__name__)
app.secret_key = 'CHANGE_THIS_TO_SOMETHING_SECURE'

VALID_USERNAME = 'admin'
VALID_PASSWORD = 'password123'

BASE_DIR = os.path.dirname(__file__)
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

MODEL_PATH = os.path.join(BASE_DIR, 'mluser_file', 'rf_model.joblib')
DEFAULT_LOG_PATH = '/var/log/suricata/eve.json'

# 모델 로드
try:
    MODEL = joblib.load(MODEL_PATH)
    print(f"✅ 모델 로드 완료: {MODEL_PATH}")
except Exception as e:
    print(f"❌ 모델 로드 실패: {e}")
    MODEL = None


def fetch_system_info():
    cpu = psutil.cpu_percent(percpu=True)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net = psutil.net_io_counters()
    try:
        from gpiozero import CPUTemperature
        temp = CPUTemperature().temperature
    except:
        temp = None
    return {
        'cpu': cpu,
        'memory_used': mem.used,
        'memory_available': mem.available,
        'disk_used': disk.used,
        'disk_available': disk.free,
        'disk_total': disk.total,
        'network': {
            'bytes_sent': net.bytes_sent,
            'bytes_recv': net.bytes_recv
        },
        'temperature': temp
    }


@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    info = fetch_system_info()
    return render_template('index.html',
                           system_info=info,
                           active_tab='dashboard')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        if u == VALID_USERNAME and p == VALID_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        return render_template('login.html', error='아이디 또는 비밀번호가 잘못되었습니다.')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


@app.route('/inspect', methods=['POST'])
def inspect():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    router_type = request.form.get('router_type', 'tplink')
    ip = request.form.get('router_ip', '')
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    try:
        raw = inspect_tplink(ip, username, password)
        msgs = [msg for (_lvl, msg) in raw]
        result = '\n'.join(msgs)
    except Exception as e:
        result = f'점검 중 오류 발생: {e}'

    info = fetch_system_info()
    return render_template('index.html',
                           system_info=info,
                           inspect_result=result,
                           active_tab='inspect')


@app.route('/detect', methods=['POST'])
def detect():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    file = request.files.get('log_file')
    if file:
        filename = secure_filename(file.filename)
        log_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(log_path)
    else:
        log_path = DEFAULT_LOG_PATH

    try:
        df_alerts = extract_alerts(log_path)
        X = featurize(df_alerts)
        if MODEL:
            preds = MODEL.predict(X)
            df_alerts['anomaly'] = preds
            total = len(df_alerts)
            anomalies = int(df_alerts['anomaly'].sum())
            summary = f'총 이벤트: {total}건, 이상 이벤트: {anomalies}건'
            table_html = df_alerts.tail(20).to_html(classes='table table-bordered', index=False)
        else:
            summary = '모델이 로드되지 않았습니다.'
            table_html = ''
    except Exception as e:
        summary = f'오류 발생: {e}'
        table_html = ''

    info = fetch_system_info()
    return render_template('index.html',
                           system_info=info,
                           detect_result=summary,
                           detect_table=table_html,
                           active_tab='detect')


@app.route('/system_info')
def system_info():
    if not session.get('logged_in'):
        return jsonify({'error': '로그인이 필요합니다.'}), 401
    return jsonify(fetch_system_info())


@app.route('/anomaly_stats')
def anomaly_stats():
    try:
        df = extract_alerts(DEFAULT_LOG_PATH)
        X = featurize(df)
        preds = MODEL.predict(X) if MODEL else []
        df['anomaly'] = preds
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    df['time'] = pd.to_datetime(df['timestamp'], errors='coerce').dt.strftime('%H:%M')
    grouped = df.groupby('time').agg(
        total=('anomaly', 'count'),
        abnormal=('anomaly', 'sum')
    ).reset_index()
    grouped['ratio'] = (grouped['abnormal'] / grouped['total'] * 100).round(2)

    return jsonify({
        'timestamps': grouped['time'].tolist(),
        'ratio': grouped['ratio'].tolist()
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
