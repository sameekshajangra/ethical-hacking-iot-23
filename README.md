# IoT-23 Network Sentinel 🛡️

An AI-Powered Intrusion Detection System (IDS) designed to protect Internet of Things (IoT) devices from botnet attacks, leveraging the **IoT-23 Dataset**.

## 🚀 Overview

IoT devices are frequently targeted to create malicious botnets (such as Mirai) to launch devastating DDoS attacks. This project utilizes a Machine Learning pipeline (Random Forest Classifier) to analyze network telemetry and instantly classify traffic into various categories:

*   ✅ **Benign** (Normal Traffic)
*   🔴 **Mirai** (Botnet Infection)
*   🔴 **C&C** (Command and Control Communication)
*   🔴 **DDoS** (Active Denial of Service Attack)
*   🟡 **Port Scan** (Reconnaissance)

## 🖥️ Streamlit Dashboard

The project features a premium, interactive web dashboard for real-time threat analysis, featuring:
* Glassmorphism Dark Mode UI
* 3D/Plotly Threat Distribution Charts
* Live AI Threat Classification Feed

### 🔗 Access the Dashboard

To view the dashboard, you must run the application locally. Make sure you have cloned this repository.

1. **Run the startup script** from your terminal:
   ```bash
   ./run.sh
   ```
2. **Open the Dashboard Link** in your browser:  
   👉 **[http://localhost:8501](http://localhost:8501)**

---
### 🛠️ Manual Installation (Without `run.sh`)

If you want to run the python scripts manually:
```bash
# 1. Create a virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Generate the synthetic dataset and train the AI
python generate_dataset.py
python train_model.py

# 3. Launch the Web Interface
streamlit run app.py
```
