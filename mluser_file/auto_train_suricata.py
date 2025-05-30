import os
import time
import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

EVE_JSON_PATH = "/var/log/suricata/eve.json"
CSV_PATH = "suricata_logs.csv"

def convert_eve_to_csv():
    print("🔄 eve.json → suricata_logs.csv 변환 중...")
    with open(EVE_JSON_PATH, "r") as f:
        lines = f.readlines()

    data = []
    for line in lines:
        try:
            event = json.loads(line)
            if event.get("event_type") == "alert":
                row = {
                    "src_port": event.get("src_port", 0),
                    "dest_port": event.get("dest_port", 0),
                    "proto": event.get("proto", ""),
                    "flow_pkts_toserver": event.get("flow", {}).get("pkts_toserver", 0),
                    "flow_pkts_toclient": event.get("flow", {}).get("pkts_toclient", 0),
                    "alert": event.get("alert", {}).get("signature", "")
                }
                data.append(row)
        except json.JSONDecodeError:
            continue

    df = pd.DataFrame(data)
    df.to_csv(CSV_PATH, index=False)
    print("✅ CSV 저장 완료")


def preprocess_data():
    df = pd.read_csv(CSV_PATH)

    # 라벨: alert 값이 있으면 1 (이상), 없으면 0 (정상)
    df['label'] = df['alert'].notnull().astype(int)

    # 필요 없는 열 제거
    df = df.drop(columns=['alert'])

    # 범주형 데이터 처리
    df = pd.get_dummies(df, columns=['proto'])

    X = df.drop(columns=['label'])
    y = df['label']

    return train_test_split(X, y, test_size=0.2, random_state=42)


def train_model():
    X_train, X_test, y_train, y_test = preprocess_data()

    model = RandomForestClassifier()
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    acc = accuracy_score(y_test, predictions)
    report = classification_report(y_test, predictions)

    print("✅ 모델 학습 완료")
    print(f"🎯 정확도: {acc}")
    print("📊 분류 리포트:\n", report)


def watch_and_train():
    print("👀 Suricata 로그 변경 감지 중... (중지하려면 Ctrl+C)")
    last_mtime = None

    while True:
        try:
            mtime = os.path.getmtime(EVE_JSON_PATH)
            if last_mtime is None:
                last_mtime = mtime

            if mtime != last_mtime:
                print("🔁 로그 변경 감지! 학습 시작...")
                convert_eve_to_csv()
                train_model()
                last_mtime = mtime

            time.sleep(5)

        except KeyboardInterrupt:
            print("🛑 사용자에 의해 종료되었습니다.")
            break
        except FileNotFoundError:
            print("🚫 eve.json 파일을 찾을 수 없습니다.")
            time.sleep(5)


if __name__ == "__main__":
    watch_and_train()
