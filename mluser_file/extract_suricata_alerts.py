# mluser_file/extract_suricata_alerts.py

import os
import json
import shutil
import datetime
import pandas as pd

# 기본 로그 경로와 CSV 저장 경로
DEFAULT_LOG_PATH    = '/var/log/suricata/eve.json'
CSV_OUTPUT_PATH     = os.path.join(os.path.dirname(__file__), 'suricata_alerts.csv')
BACKUP_DIR          = os.path.join(os.path.dirname(__file__), 'backups')

# 백업 디렉토리 생성
os.makedirs(BACKUP_DIR, exist_ok=True)

def extract_alerts(log_path: str = DEFAULT_LOG_PATH) -> pd.DataFrame:
    """
    1) JSON-lines 로그에서 event_type=='alert' 만 필터링
    2) 주요 필드(timestamp, src/dst IP·Port, proto, signature, severity, flow pkts) 추출
    3) 기존 CSV는 backups/alerts_YYYYMMDD_HHMMSS.csv 로 이동해 백업
    4) 새 DataFrame을 suricata_alerts.csv 로 저장 및 반환
    """
    # 1. 기존 CSV 백업
    if os.path.exists(CSV_OUTPUT_PATH):
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f'alerts_{ts}.csv'
        shutil.move(CSV_OUTPUT_PATH, os.path.join(BACKUP_DIR, backup_name))

    records = []
    # 2. 로그 파일 파싱
    with open(log_path, 'r') as f:
        for line in f:
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            if evt.get('event_type') != 'alert':
                continue

            # 필드 추출
            alert = evt.get('alert', {})
            flow  = evt.get('flow', {})
            rec = {
                'timestamp'        : evt.get('timestamp', ''),
                'src_ip'           : evt.get('src_ip', ''),
                'src_port'         : evt.get('src_port', ''),
                'dest_ip'          : evt.get('dest_ip', ''),
                'dest_port'        : evt.get('dest_port', ''),
                'proto'            : evt.get('proto', ''),
                'alert_signature'  : alert.get('signature', ''),
                'severity'         : alert.get('severity', 0),
                'flow_pkts_toserver'  : flow.get('pkts_toserver', 0),
                'flow_pkts_toclient'  : flow.get('pkts_toclient', 0),
            }
            records.append(rec)

    # 3. DataFrame 생성 및 CSV 저장
    df = pd.DataFrame(records)
    df.to_csv(CSV_OUTPUT_PATH, index=False)
    return df

def featurize(df: pd.DataFrame) -> pd.DataFrame:
    """
    ML 입력용 피처 생성
    - timestamp → hour (0–23)
    - alert_signature → sig_code (factorize)
    - severity, flow_pkts_toserver, flow_pkts_toclient 그대로
    """
    df = df.copy()
    # 시간(hour) 추출
    df['hour'] = pd.to_datetime(df['timestamp'], errors='coerce').dt.hour.fillna(0).astype(int)
    # 시그니처를 숫자 인덱스로 변환
    df['sig_code'] = pd.factorize(df['alert_signature'])[0]

    # 사용할 피처 리스트
    feature_cols = ['hour', 'severity', 'flow_pkts_toserver', 'flow_pkts_toclient', 'sig_code']
    return df[feature_cols]

if __name__ == '__main__':
    # 단독 실행 시 테스트
    print("Extracting alerts from default path...")
    df_alerts = extract_alerts()
    print(f"Extracted {len(df_alerts)} alerts, saved to {CSV_OUTPUT_PATH}")

    print("Featurizing data...")
    X = featurize(df_alerts)
    print("Feature sample:")
    print(X.head())
