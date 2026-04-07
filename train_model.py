import pandas as pd
import pickle
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

def train_model():
    print("Loading dataset...")
    try:
        df = pd.read_csv('iot23_sample.csv', keep_default_na=False)
    except FileNotFoundError:
        print("Please run generate_dataset.py first!")
        return

    # Drop detailed label as we're doing binary classification for the main model, or predicting the attack type
    # Let's actually predict the detailed label because it's more impressive!
    df = df.drop(columns=['label']) # Drop binary label
    y = df['detailed_label'].fillna('None').astype(str)
    X = df.drop(columns=['detailed_label', 'src_ip', 'dst_ip'], errors='ignore')

    # Convert categorical to numerical
    print("Preprocessing data...")
    categorical_cols = ['proto', 'service', 'conn_state']
    X = pd.get_dummies(X, columns=categorical_cols, drop_first=True)

    # Need to keep the exact columns expected by the model during inference
    model_columns = list(X.columns)
    with open('model_columns.pkl', 'wb') as f:
        pickle.dump(model_columns, f)

    # Scale numerical features
    numerical_cols = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'orig_p', 'resp_p']
    scaler = StandardScaler()
    X[numerical_cols] = scaler.fit_transform(X[numerical_cols])
    
    with open('scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)

    # Encode target
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    with open('label_encoder.pkl', 'wb') as f:
        pickle.dump(le, f)

    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)

    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    print("Evaluating Model...")
    y_pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    
    # We want to print report with actual string names
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=[str(c) for c in le.classes_]))

    print("Saving model artifacts...")
    with open('model.pkl', 'wb') as f:
        pickle.dump(model, f)
        
    print("Training complete! Model ready for the Streamlit app.")

if __name__ == "__main__":
    train_model()
