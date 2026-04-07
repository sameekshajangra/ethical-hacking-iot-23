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
</style>
""", unsafe_allow_html=True)

# Application Header
st.markdown('<h1 class="main-title">IoT-23 Network Sentinel <span style="font-size:1.5rem">🛡️</span></h1>', unsafe_allow_html=True)
st.markdown("<p style='color: #94a3b8; font-size: 1.1rem;'>Enterprise SOC Dashboard: AI-Powered Botnet Detection and Topology Mapping.</p>", unsafe_allow_html=True)
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
            
    live_simulation = st.toggle("🔴 Enable Live Simulation Mode", value=False, help="Streams traffic onto the screen slowly.")
    
    st.markdown("---")
    st.markdown("<small>Designed for Ethical Hacking Grp Project</small>", unsafe_allow_html=True)

# Main Logic
full_df = None

if upload_file is not None:
    full_df = pd.read_csv(upload_file, keep_default_na=False)
elif st.session_state['use_sample']:
    try:
        full_df = pd.read_csv('iot23_sample.csv', keep_default_na=False).sample(n=200, random_state=np.random.randint(0,10000))
        st.info("Loaded random network flows from the sample dataset.")
    except:
        st.warning("Sample dataset not found. Run generate_dataset.py first.")

def render_dashboard(demo_df):
    
    X_inference = demo_df.drop(columns=['label', 'detailed_label', 'src_ip', 'dst_ip'], errors='ignore')
    
    # Preprocess
    categorical_cols = ['proto', 'service', 'conn_state']
    X_processed = pd.get_dummies(X_inference, columns=[col for col in categorical_cols if col in X_inference.columns])
    
    for col in model_columns:
        if col not in X_processed.columns:
            X_processed[col] = 0
    X_processed = X_processed[model_columns]
    
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
    with col2: st.metric("Threats Blocked", f"{malicious:,}", delta=f"{malicious/max(1, total_flows)*100:.1f}%", delta_color="inverse")
    with col3: st.metric("Mirai Botnet Traces", f"{mirai:,}")
    with col4: st.metric("Clean Flows", f"{benign:,}", delta="Safe", delta_color="normal")
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Topology and Visuals
    tab1, tab2, tab3 = st.tabs(["🌐 Threat Topology", "🧠 AI Explainability", "📊 Raw Visuals"])
    
    color_map = {'None': '#22c55e', 'Mirai': '#ef4444', 'C&C': '#f97316', 'PartOfAHorizontalPortScan': '#eab308', 'DDoS': '#dc2626'}

    with tab1:
        st.markdown("### 🕸️ Network Flow Map (Parallel Categories)")
        st.markdown("<small>Tracing connection sources through identified protocols to victim destinations.</small>", unsafe_allow_html=True)
        if 'src_ip' in demo_df.columns:
            # Drop very rare IPS just to keep the chart clean, keep top ones
            top_src = demo_df['src_ip'].value_counts().nlargest(10).index
            filtered = demo_df[demo_df['src_ip'].isin(top_src)]
            
            fig_sankey = px.parallel_categories(filtered[['src_ip', 'proto', 'AI_Detection', 'dst_ip']], 
                                          labels={'src_ip': 'Source IP', 'proto': 'Protocol', 'AI_Detection': 'AI Finding', 'dst_ip': 'Destination IP'},
                                          color=filtered['AI_Detection'].map({'None': 0, 'Mirai': 1, 'C&C': 1, 'PartOfAHorizontalPortScan': 1, 'DDoS': 1}),
                                          color_continuous_scale=[[0, '#22c55e'], [1, '#ef4444']])
            fig_sankey.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#f8fafc', margin=dict(t=30, b=0, l=0, r=0))
            fig_sankey.update_coloraxes(showscale=False)
            st.plotly_chart(fig_sankey, use_container_width=True, key=f"sankey_{len(demo_df)}")
        else:
            st.warning("Generate Dataset with IP tracking first.")
            
    with tab2:
        st.markdown("### 🤖 Model Decision Logic (Feature Importances)")
        st.markdown("<small>Which telemetry columns does the Random Forest weigh the heaviest to detect attacks?</small>", unsafe_allow_html=True)
        importances = model.feature_importances_
        indices = np.argsort(importances)[-10:] # Top 10
        imp_df = pd.DataFrame({'Feature': np.array(model_columns)[indices], 'Importance': importances[indices]})
        fig_imp = px.bar(imp_df, x='Importance', y='Feature', orientation='h', color='Importance', color_continuous_scale='Purpor')
        fig_imp.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#f8fafc', margin=dict(t=0, b=0, l=0, r=0))
        st.plotly_chart(fig_imp, use_container_width=True, key=f"imp_{len(demo_df)}")
        
    with tab3:
        chart_col1, chart_col2 = st.columns([1, 1])
        with chart_col1:
            threat_counts = demo_df['AI_Detection'].value_counts().reset_index()
            threat_counts.columns = ['Threat', 'Count']
            fig1 = px.pie(threat_counts, names='Threat', values='Count', hole=0.6, color='Threat', color_discrete_map=color_map)
            fig1.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#f8fafc', margin=dict(t=10, b=0, l=0, r=0))
            st.plotly_chart(fig1, use_container_width=True, key=f"pie_{len(demo_df)}")
        with chart_col2:
            fig2 = px.scatter(demo_df, x='orig_bytes', y='resp_bytes', color='AI_Detection', log_x=True, log_y=True, color_discrete_map=color_map, opacity=0.7)
            fig2.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#f8fafc', margin=dict(t=10, b=0, l=0, r=0))
            st.plotly_chart(fig2, use_container_width=True, key=f"scatter_{len(demo_df)}")
            
    st.markdown("### 🚨 Threat Log (Live Feed)")
    def color_threat(val):
        if val == 'None': return 'color: #4ade80'
        if val in ['Mirai', 'DDoS']: return 'color: #ef4444; font-weight: bold'
        return 'color: #f59e0b'
        
    display_cols = ['src_ip', 'dst_ip', 'AI_Detection', 'proto', 'service', 'duration', 'orig_pkts', 'orig_bytes']
    valid_cols = [c for c in display_cols if c in demo_df.columns]
    
    st.dataframe(demo_df[valid_cols].iloc[::-1].style.map(color_threat, subset=['AI_Detection']), use_container_width=True, height=250)


if full_df is not None and model is not None:
    if live_simulation:
        placeholder = st.empty()
        for i in range(10, len(full_df) + 1, 10):
            with placeholder.container():
                render_dashboard(full_df.iloc[:i].copy())
            time.sleep(0.5)
    else:
        render_dashboard(full_df)
elif full_df is None:
    st.markdown("""
    <div style='text-align: center; padding: 4rem; background: rgba(30, 41, 59, 0.4); border-radius: 20px; border: 1px dashed rgba(148, 163, 184, 0.3)'>
        <h2 style='color: #475569 !important'>System Standby</h2>
        <p style='color: #94a3b8'>Upload network logs from the sidebar or click "Load Sample Data" to begin SOC analysis.</p>
    </div>
    """, unsafe_allow_html=True)
