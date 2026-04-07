import streamlit as st
import pandas as pd
import pickle
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import time

# Must be the first Streamlit command
st.set_page_config(page_title="IoT-23 Sentinel", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# Custom UI Injection for that "WOW" factor
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }
    
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    .stApp {
        background-color: #0d1117;
        background-image: radial-gradient(circle at 15% 50%, rgba(56, 189, 248, 0.05), transparent 25%), 
                          radial-gradient(circle at 85% 30%, rgba(168, 85, 247, 0.05), transparent 25%);
    }

    /* Glassmorphism Metrics */
    div[data-testid="metric-container"] {
        background: rgba(30, 41, 59, 0.7);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    div[data-testid="metric-container"]:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 25px rgba(56, 189, 248, 0.2);
        border: 1px solid rgba(56, 189, 248, 0.4);
    }
    
    /* Headers with glowing text */
    h1, h2, h3 {
        color: #f8fafc !important;
        font-weight: 600 !important;
    }
    .main-title {
        background: linear-gradient(to right, #38bdf8, #a855f7);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 3rem !important;
        font-weight: 800 !important;
        margin-bottom: 0rem;
        padding-bottom: 0rem;
    }
    
    /* Glowing status badges */
    .badge-mirai { background-color: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; padding: 4px 10px; border-radius: 20px; font-weight: bold;}
    .badge-ddos { background-color: rgba(249, 115, 22, 0.2); border: 1px solid #f97316; color: #fdba74; padding: 4px 10px; border-radius: 20px; font-weight: bold;}
    .badge-scan { background-color: rgba(234, 179, 8, 0.2); border: 1px solid #eab308; color: #fde047; padding: 4px 10px; border-radius: 20px; font-weight: bold;}
    .badge-benign { background-color: rgba(34, 197, 94, 0.2); border: 1px solid #22c55e; color: #86efac; padding: 4px 10px; border-radius: 20px; font-weight: bold;}
    
    /* Buttons */
    .stButton>button {
        background: linear-gradient(to right, #3b82f6, #8b5cf6);
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        padding: 0.5rem 2rem;
        transition: all 0.3s;
    }
    .stButton>button:hover {
        box-shadow: 0 0 15px rgba(139, 92, 246, 0.5);
        transform: scale(1.02);
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# Application Header
st.markdown('<h1 class="main-title">IoT-23 Network Sentinel <span style="font-size:1.5rem">🛡️</span></h1>', unsafe_allow_html=True)
st.markdown("<p style='color: #94a3b8; font-size: 1.1rem;'>Real-time AI-Powered Botnet Detection Dashboard based on the Aposemat IoT-23 Dataset.</p>", unsafe_allow_html=True)
st.divider()

# Load Models
@st.cache_resource
def load_models():
    try:
        with open('model.pkl', 'rb') as f:
            model = pickle.load(f)
        with open('scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
        with open('label_encoder.pkl', 'rb') as f:
            le = pickle.load(f)
        with open('model_columns.pkl', 'rb') as f:
            model_columns = pickle.load(f)
        return model, scaler, le, model_columns
    except FileNotFoundError:
        return None, None, None, None

model, scaler, le, model_columns = load_models()

# Sidebar
with st.sidebar:
    st.image('https://cdn-icons-png.flaticon.com/512/2885/2885408.png', width=80)
    st.markdown("## ⚙️ Control Panel")
    
    if model is None:
        st.error("Model not found! Run `train_model.py` first.")
    else:
        st.success("✅ AI Engine Online", icon="🤖")
        
    st.markdown("---")
    
    upload_file = st.file_uploader("Upload Network Traffic (CSV)", type=['csv'])
    if st.button("Load Sample Data"):
        st.session_state['use_sample'] = True
    else:
        if 'use_sample' not in st.session_state:
            st.session_state['use_sample'] = False
            
    st.markdown("---")
    st.markdown("<small>Designed for Ethical Hacking Grp Project</small>", unsafe_allow_html=True)

# Main Logic
demo_df = None

if upload_file is not None:
    demo_df = pd.read_csv(upload_file, keep_default_na=False)
elif st.session_state['use_sample']:
    try:
        demo_df = pd.read_csv('iot23_sample.csv', keep_default_na=False).sample(n=1000, random_state=np.random.randint(0,10000))
        st.info("Loaded 1,000 random network flows from the sample dataset.")
    except:
        st.warning("Sample dataset not found. Run generate_dataset.py first.")

if demo_df is not None and model is not None:
    
    # Simulate processing delay for effect
    with st.spinner('Analyzing network patterns via Random Forest...'):
        time.sleep(1)
        
    X_inference = demo_df.drop(columns=['label', 'detailed_label'], errors='ignore')
    
    # Preprocess
    categorical_cols = ['proto', 'service', 'conn_state']
    X_processed = pd.get_dummies(X_inference, columns=[col for col in categorical_cols if col in X_inference.columns])
    
    # Align columns
    for col in model_columns:
        if col not in X_processed.columns:
            X_processed[col] = 0
    X_processed = X_processed[model_columns]
    
    # Scale
    numerical_cols = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'orig_p', 'resp_p']
    X_processed[numerical_cols] = scaler.transform(X_processed[numerical_cols])
    
    # Predict
    preds = model.predict(X_processed)
    pred_labels = le.inverse_transform(preds)
    
    demo_df['AI_Detection'] = pred_labels
    
    # Metrics
    total_flows = len(demo_df)
    malicious = len(demo_df[demo_df['AI_Detection'] != 'None'])
    benign = total_flows - malicious
    mirai = len(demo_df[demo_df['AI_Detection'] == 'Mirai'])
    
    col1, col2, col3, col4 = st.columns(4)
    with col1: st.metric("Total Flows Analyzed", f"{total_flows:,}")
    with col2: st.metric("Malicious Flows Detected", f"{malicious:,}", delta=f"{malicious/total_flows*100:.1f}%", delta_color="inverse")
    with col3: st.metric("Mirai Botnet Traces", f"{mirai:,}")
    with col4: st.metric("Clean Flows", f"{benign:,}", delta="Safe", delta_color="normal")
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Charts
    chart_col1, chart_col2 = st.columns([1, 1])
    
    with chart_col1:
        st.markdown("### 📊 Threat Distribution")
        threat_counts = demo_df['AI_Detection'].value_counts().reset_index()
        threat_counts.columns = ['Threat', 'Count']
        
        # Determine colors based on threat
        color_map = {'None': '#22c55e', 'Mirai': '#ef4444', 'C&C': '#f97316', 'PartOfAHorizontalPortScan': '#eab308', 'DDoS': '#dc2626'}
        
        fig1 = px.pie(threat_counts, names='Threat', values='Count', hole=0.6, 
                     color='Threat', color_discrete_map=color_map)
        fig1.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', 
                          font_color='#f8fafc', showlegend=True, margin=dict(t=30, b=0, l=0, r=0))
        # Add glowing effect to pie
        fig1.update_traces(marker=dict(line=dict(color='#000000', width=2)))
        st.plotly_chart(fig1, use_container_width=True)
        
    with chart_col2:
        st.markdown("### 📡 Traffic Volume Features (Bytes)")
        # Plotly scatter for bytes
        fig2 = px.scatter(demo_df, x='orig_bytes', y='resp_bytes', color='AI_Detection', log_x=True, log_y=True,
                          hover_data=['proto', 'orig_p', 'resp_p'], color_discrete_map=color_map, opacity=0.7)
        fig2.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                           font_color='#f8fafc', margin=dict(t=30, b=0, l=0, r=0))
        st.plotly_chart(fig2, use_container_width=True)
        
    st.markdown("### 🚨 Threat Log (Live Feed)")
    
    # Aesthetic rendering for dataframe
    def color_threat(val):
        if val == 'None': return 'color: #4ade80' # green
        if val == 'Mirai': return 'color: #ef4444; font-weight: bold' # red
        return 'color: #f59e0b' # yellow
        
    display_cols = ['AI_Detection', 'proto', 'service', 'duration', 'orig_pkts', 'resp_pkts', 'orig_bytes', 'resp_bytes']
    st.dataframe(demo_df[display_cols].style.applymap(color_threat, subset=['AI_Detection']), use_container_width=True, height=300)

elif demo_df is None:
    # Empty State Dashboard
    st.markdown("""
    <div style='text-align: center; padding: 4rem; background: rgba(30, 41, 59, 0.4); border-radius: 20px; border: 1px dashed rgba(148, 163, 184, 0.3)'>
        <h2 style='color: #475569 !important'>System Standby</h2>
        <p style='color: #94a3b8'>Upload network logs from the sidebar or click "Load Sample Data" to begin threat analysis.</p>
    </div>
    """, unsafe_allow_html=True)
