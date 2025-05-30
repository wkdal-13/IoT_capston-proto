#!/usr/bin/env python3
# mluser_file/train_model.py

import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# 같은 폴더의 extract_suricata_alerts 모듈에서 featurize 가져오기
from mluser_file.extract_suricata_alerts import featurize

# 경로 설정
BASE_DIR       = os.path.dirname(__file__)
CSV_PATH       = os.path.join(BASE_DIR, 'suricata_alerts.csv')
MODEL_OUTPUT   = os.path.join(BASE_DIR, 'rf_model.joblib')
TEST_SIZE      = 0.2           # 테스트 데이터 비율
RANDOM_STATE   = 42            # 재현성을 위한 시드
N_ESTIMATORS   = 100           # RandomForest 트리 개수

def load_data(csv_path: str) -> pd.DataFrame:
    """
    CSV에서 DataFrame 로드, 'label' 컬럼 확인
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV 파일이 없습니다: {csv_path}")
    df = pd.read_csv(csv_path)
    if 'label' not in df.columns:
        raise KeyError("CSV에 'label' 컬럼이 없습니다. 0=정상, 1=이상 레이블이 필요합니다.")
    return df

def train_model():
    # 1) 데이터 불러오기
    df = load_data(CSV_PATH)
    print(f"총 샘플: {len(df)}, 이상 이벤트: {df['label'].sum()}, 정상 이벤트: {len(df)-df['label'].sum()}")

    # 2) 피처 생성
    X = featurize(df)
    y = df['label']
    print("피처(shape):", X.shape)

    # 3) Train/Test 분할
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"학습 샘플: {len(X_train)}, 테스트 샘플: {len(X_test)}")

    # 4) 모델 학습
    clf = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)
    print("모델 학습 완료")

    # 5) 성능 평가
    train_acc = clf.score(X_train, y_train)
    test_acc  = clf.score(X_test, y_test)
    print(f"Train Accuracy: {train_acc:.4f}")
    print(f"Test  Accuracy: {test_acc:.4f}")

    # 6) 모델 저장
    joblib.dump(clf, MODEL_OUTPUT)
    print(f"모델 저장: {MODEL_OUTPUT}")

if __name__ == '__main__':
    train_model()
