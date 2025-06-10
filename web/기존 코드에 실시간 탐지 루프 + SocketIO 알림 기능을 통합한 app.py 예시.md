### 주요 변경점
- Flask 대신 Flask-SocketIO 사용 (비동기 알림 가능)
- 별도 백그라운드 쓰레드로 eve.json 파일 변경 감지 및 탐지 실행
- 이상 트래픽 탐지 시 웹소켓으로 클라이언트에게 알림 전송(intrusion_alert 이벤트)
- 기본 웹 라우트 유지하면서 SocketIO 서버 실행

### 전체 코드(변경/추가된 부분 주석 처리함)
...
import os
import psutil
import joblib
import pandas as pd
import threading
import time
import json
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename
from mluser_file.extract_suricata_alerts import extract_alerts, featurize
from tplink import inspect_router as inspect_tplink  # 공유기 점검 함수

from flask_socketio import SocketIO

app = Flask(__name__)
app.secret_key = 'CHANGE_THIS_TO_SOMETHING_SECURE'

# SocketIO 인스턴스 생성 (eventlet/gevent 설치시 async_mode 변경 가능)
socketio = SocketIO(app)

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
    if 'logged_in' in session and session['logged_in'] is True:
        cpu_usage = psutil.cpu_percent(interval=0.5)
        mem_info = psutil.virtual_memory()
        disk_info = psutil.disk_usage('/')
        net_info = psutil.net_io_counters()

        cpu_temp = 0
        try:
            cpu_temp = float(os.popen("vcgencmd measure_temp").readline().replace("temp=", "").replace("'C", "").strip())
        except:
            pass
        data = {
            'cpu': {
                'per_core_percent': psutil.cpu_percent(interval=0.5, percpu=True),
            },
            'memory': {
                'used': mem_info.used,
                'available': mem_info.available,
            },
            'disk': {
                'used': disk_info.used,
                'total': disk_info.total,
            },
            'network': {
                'bytes_sent': net_info.bytes_sent,
                'bytes_received': net_info.bytes_recv,
            },
            'security': {
                'active_connections': len(psutil.net_connections(kind='inet')),
                'failed_login_attempts': 3,
                'active_admin_accounts': 1,
            },
            'hardware': {
                'cpu_temperature': cpu_temp
            },
        }
        return jsonify(data)
    else:
        return jsonify({'error': '로그인이 필요합니다.'}), 401

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


# --------------------
# 백그라운드 탐지 루프 추가 (실시간 eve.json 감시)
# --------------------

def detection_loop():
    last_mtime = None
    while True:
        try:
            if not os.path.exists(DEFAULT_LOG_PATH):
                time.sleep(3)
                continue

            mtime = os.path.getmtime(DEFAULT_LOG_PATH)
            if last_mtime is None:
                last_mtime = mtime

            if mtime != last_mtime:
                print("🔍 [실시간 탐지] 로그 변경 감지, 분석 시작...")
                try:
                    df = extract_alerts(DEFAULT_LOG_PATH)
                    if len(df) == 0:
                        print("⚠️ 이벤트 없음")
                        last_mtime = mtime
                        time.sleep(3)
                        continue
                    X = featurize(df)
                    preds = MODEL.predict(X) if MODEL else []
                    df['anomaly'] = preds
                    anomalies = df[df['anomaly'] == 1]
                    if len(anomalies) > 0:
                        for _, row in anomalies.iterrows():
                            alert_msg = f"이상 트래픽 탐지: {row.get('src_ip', 'N/A')} → {row.get('dest_ip', 'N/A')}"
                            print(f"🚨 {alert_msg}")
                            # SocketIO로 클라이언트에 알림 전송
                            socketio.emit('intrusion_alert', {
                                'msg': alert_msg,
                                'src': row.get('src_ip', 'N/A'),
                                'dest': row.get('dest_ip', 'N/A')
                            })
                    else:
                        print("✅ 이상 없음")

                    last_mtime = mtime
                except Exception as e:
                    print(f"❌ 탐지 중 오류 발생: {e}")

            time.sleep(3)

        except Exception as e:
            print(f"❌ 감시 루프 오류: {e}")
            time.sleep(3)

# 서버 시작 시 백그라운드 탐지 쓰레드 실행
def start_background_thread():
    thread = threading.Thread(target=detection_loop)
    thread.daemon = True
    thread.start()

if __name__ == '__main__':
    start_background_thread()
    # Flask 대신 SocketIO 앱 실행
    socketio.run(app, host='0.0.0.0', port=5000)
...
