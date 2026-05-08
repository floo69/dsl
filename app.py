import streamlit as st
import pickle
import numpy as np
import warnings
warnings.filterwarnings('ignore')

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Syne', sans-serif;
}

.stApp {
    background: #0a0e1a;
    color: #e0e6f0;
}

.main-header {
    text-align: center;
    padding: 2.5rem 0 1.5rem 0;
}

.main-header h1 {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 3rem;
    letter-spacing: -1px;
    background: linear-gradient(135deg, #00d4ff, #7b61ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0.3rem;
}

.main-header p {
    color: #6b7a99;
    font-size: 1rem;
    font-family: 'Space Mono', monospace;
}

.model-badge {
    display: inline-block;
    background: linear-gradient(135deg, #1a2340, #0f1628);
    border: 1px solid #2a3a5c;
    border-radius: 8px;
    padding: 0.4rem 1rem;
    font-family: 'Space Mono', monospace;
    font-size: 0.75rem;
    color: #00d4ff;
    margin-bottom: 2rem;
}

.section-title {
    font-family: 'Syne', sans-serif;
    font-weight: 600;
    font-size: 0.7rem;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: #4a5a7a;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid #1a2340;
}

.feature-card {
    background: #0f1628;
    border: 1px solid #1a2340;
    border-radius: 10px;
    padding: 1.2rem;
    margin-bottom: 0.6rem;
    transition: border-color 0.2s;
}

.feature-card:hover {
    border-color: #2a3a6c;
}

.feature-label {
    font-family: 'Space Mono', monospace;
    font-size: 0.72rem;
    color: #6b7a99;
    margin-bottom: 0.3rem;
}

.result-safe {
    background: linear-gradient(135deg, #0a2a1a, #0d3520);
    border: 2px solid #00c853;
    border-radius: 16px;
    padding: 2.5rem;
    text-align: center;
    animation: pulse-green 2s infinite;
}

.result-phishing {
    background: linear-gradient(135deg, #2a0a0a, #350d0d);
    border: 2px solid #ff3d3d;
    border-radius: 16px;
    padding: 2.5rem;
    text-align: center;
    animation: pulse-red 2s infinite;
}

@keyframes pulse-green {
    0%, 100% { box-shadow: 0 0 20px rgba(0,200,83,0.15); }
    50% { box-shadow: 0 0 40px rgba(0,200,83,0.35); }
}

@keyframes pulse-red {
    0%, 100% { box-shadow: 0 0 20px rgba(255,61,61,0.15); }
    50% { box-shadow: 0 0 40px rgba(255,61,61,0.35); }
}

.result-emoji { font-size: 4rem; margin-bottom: 0.5rem; }

.result-label {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 2rem;
    margin-bottom: 0.5rem;
}

.result-safe .result-label { color: #00c853; }
.result-phishing .result-label { color: #ff3d3d; }

.result-sub {
    font-family: 'Space Mono', monospace;
    font-size: 0.8rem;
    color: #6b7a99;
}

.prob-bar-container {
    background: #0a0e1a;
    border-radius: 8px;
    height: 10px;
    margin: 1.2rem auto;
    width: 80%;
    overflow: hidden;
}

.prob-bar-fill-safe {
    height: 100%;
    border-radius: 8px;
    background: linear-gradient(90deg, #00c853, #69f0ae);
    transition: width 0.8s ease;
}

.prob-bar-fill-phish {
    height: 100%;
    border-radius: 8px;
    background: linear-gradient(90deg, #ff3d3d, #ff8a80);
    transition: width 0.8s ease;
}

.prob-text {
    font-family: 'Space Mono', monospace;
    font-size: 1.5rem;
    font-weight: 700;
    margin-top: 0.5rem;
}

.result-safe .prob-text { color: #00c853; }
.result-phishing .prob-text { color: #ff3d3d; }

.info-box {
    background: #0f1628;
    border-left: 3px solid #7b61ff;
    border-radius: 0 8px 8px 0;
    padding: 1rem 1.2rem;
    margin: 1rem 0;
    font-family: 'Space Mono', monospace;
    font-size: 0.75rem;
    color: #6b7a99;
    line-height: 1.7;
}

div[data-testid="stSelectbox"] label {
    font-family: 'Space Mono', monospace !important;
    font-size: 0.75rem !important;
    color: #6b7a99 !important;
}

div[data-testid="stSelectbox"] > div > div {
    background: #0f1628 !important;
    border: 1px solid #1a2340 !important;
    color: #e0e6f0 !important;
    border-radius: 8px !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 0.85rem !important;
}

div.stButton > button {
    width: 100%;
    background: linear-gradient(135deg, #00d4ff, #7b61ff);
    color: #0a0e1a;
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 1.1rem;
    letter-spacing: 1px;
    border: none;
    border-radius: 12px;
    padding: 0.9rem 2rem;
    margin-top: 1.5rem;
    cursor: pointer;
    transition: opacity 0.2s, transform 0.1s;
}

div.stButton > button:hover {
    opacity: 0.9;
    transform: translateY(-1px);
}

.stDivider { border-color: #1a2340 !important; }

footer { visibility: hidden; }
#MainMenu { visibility: hidden; }
header { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ── Load model ────────────────────────────────────────────────────────────────
@st.cache_resource
def load_model():
    with open('best_model.pkl', 'rb') as f:
        return pickle.load(f)

bundle    = load_model()
model     = bundle['model']
scaler    = bundle['scaler']
best_name = bundle['best_name']
features  = bundle['features']

# ── Feature metadata ──────────────────────────────────────────────────────────
FEATURE_INFO = {
    'having_IP_Address':           ('IP Address in URL',            {-1:'Has IP (-1)', 1:'No IP (+1)'}),
    'URL_Length':                  ('URL Length',                   {1:'Short (+1)', 0:'Medium (0)', -1:'Long (-1)'}),
    'Shortining_Service':          ('URL Shortening Service',       {1:'Not Used (+1)', -1:'Used (-1)'}),
    'having_At_Symbol':            ('@ Symbol in URL',              {1:'No @ (+1)', -1:'Has @ (-1)'}),
    'double_slash_redirecting':    ('Double Slash Redirect',        {1:'Normal (+1)', -1:'Redirecting (-1)'}),
    'Prefix_Suffix':               ('Prefix/Suffix in Domain',      {1:'No Dash (+1)', -1:'Has Dash (-1)'}),
    'having_Sub_Domain':           ('Subdomains',                   {1:'No Sub (+1)', 0:'One Sub (0)', -1:'Many Subs (-1)'}),
    'SSLfinal_State':              ('SSL Certificate',              {1:'Trusted HTTPS (+1)', 0:'Untrusted (0)', -1:'No SSL (-1)'}),
    'Domain_registeration_length': ('Domain Registration Length',  {1:'Long Reg (+1)', -1:'Short Reg (-1)'}),
    'Favicon':                     ('Favicon Source',               {1:'Same Domain (+1)', -1:'External (-1)'}),
    'port':                        ('Port',                         {1:'Standard (+1)', -1:'Non-standard (-1)'}),
    'HTTPS_token':                 ('HTTPS in Domain Name',         {1:'No HTTPS Token (+1)', -1:'Has HTTPS Token (-1)'}),
    'Request_URL':                 ('Request URL',                  {1:'Mostly Local (+1)', 0:'Mixed (0)', -1:'Mostly External (-1)'}),
    'URL_of_Anchor':               ('Anchor URL',                   {1:'Mostly Local (+1)', 0:'Mixed (0)', -1:'Mostly External (-1)'}),
    'Links_in_tags':               ('Links in Tags',                {1:'Mostly Local (+1)', 0:'Mixed (0)', -1:'Mostly External (-1)'}),
    'SFH':                         ('Server Form Handler',          {1:'Legit Handler (+1)', 0:'About Blank (0)', -1:'Empty/Ext (-1)'}),
    'Submitting_to_email':         ('Form Submits to Email',        {1:'No (-1→+1)', -1:'Yes (-1)'}),
    'Abnormal_URL':                ('Abnormal URL',                 {1:'Normal (+1)', -1:'Abnormal (-1)'}),
    'Redirect':                    ('Redirects',                    {1:'≤1 Redirect (+1)', -1:'>2 Redirects (-1)'}),
    'on_mouseover':                ('onMouseOver Changes Bar',      {1:'No Change (+1)', -1:'Changes (-1)'}),
    'RightClick':                  ('Right Click Disabled',         {1:'Enabled (+1)', -1:'Disabled (-1)'}),
    'popUpWidnow':                 ('Popup Window',                 {1:'No Popup (+1)', -1:'Has Popup (-1)'}),
    'Iframe':                      ('iFrame Usage',                 {1:'No iFrame (+1)', -1:'Has iFrame (-1)'}),
    'age_of_domain':               ('Age of Domain',               {1:'Old ≥6mo (+1)', -1:'Young (-1)'}),
    'DNSRecord':                   ('DNS Record',                   {1:'DNS Exists (+1)', -1:'No DNS (-1)'}),
    'web_traffic':                 ('Web Traffic Rank',             {1:'High Traffic (+1)', 0:'Medium (0)', -1:'Low/None (-1)'}),
    'Page_Rank':                   ('PageRank',                     {1:'High PR (+1)', -1:'Low PR (-1)'}),
    'Google_Index':                ('Google Indexed',               {1:'Indexed (+1)', -1:'Not Indexed (-1)'}),
    'Links_pointing_to_page':      ('Inbound Links',                {1:'Many (+1)', 0:'Some (0)', -1:'Few (-1)'}),
    'Statistical_report':          ('Statistical Report',           {1:'Clean (+1)', -1:'Flagged (-1)'}),
}

# Group features into categories
GROUPS = {
    "🔗 URL Structure": [
        'having_IP_Address','URL_Length','Shortining_Service',
        'having_At_Symbol','double_slash_redirecting','Prefix_Suffix',
        'having_Sub_Domain','HTTPS_token','Abnormal_URL','Redirect'
    ],
    "🔒 Security & SSL": [
        'SSLfinal_State','Domain_registeration_length','port',
        'Favicon','age_of_domain','DNSRecord'
    ],
    "📄 Page Content": [
        'Request_URL','URL_of_Anchor','Links_in_tags','SFH',
        'Submitting_to_email','on_mouseover','RightClick',
        'popUpWidnow','Iframe'
    ],
    "📊 Domain Reputation": [
        'web_traffic','Page_Rank','Google_Index',
        'Links_pointing_to_page','Statistical_report'
    ],
}

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1>🛡️ Phishing URL Detector</h1>
    <p>UCI ML Phishing Dataset · 30 Features · Binary Classification</p>
</div>
""", unsafe_allow_html=True)

col_badge, _, _ = st.columns([1,2,1])
with col_badge:
    st.markdown(f'<div class="model-badge" style="text-align:center">⚡ Model: {best_name} &nbsp;|&nbsp; 30 Features &nbsp;|&nbsp; Trained on 11,055 URLs</div>', unsafe_allow_html=True)

st.markdown("---")

# ── Prediction Display Function ───────────────────────────────────────────────
def display_prediction(inputs_dict):
    input_vector = np.array([[inputs_dict[f] for f in features]])
    input_scaled = scaler.transform(input_vector)
    prediction   = model.predict(input_scaled)[0]
    probability  = model.predict_proba(input_scaled)[0]

    # 0 = Phishing, 1 = Legitimate
    is_legit    = prediction == 1
    conf        = probability[1] if is_legit else probability[0]
    conf_pct    = f"{conf*100:.1f}%"
    bar_width   = f"{conf*100:.1f}%"

    st.markdown("---")
    st.markdown('<div class="section-title">Analysis Result</div>', unsafe_allow_html=True)

    r1, r2, r3 = st.columns([1, 2, 1])
    with r2:
        if is_legit:
            st.markdown(f"""
            <div class="result-safe">
                <div class="result-emoji">✅</div>
                <div class="result-label">LEGITIMATE</div>
                <div class="prob-bar-container">
                    <div class="prob-bar-fill-safe" style="width:{bar_width}"></div>
                </div>
                <div class="prob-text">{conf_pct} confidence</div>
                <div class="result-sub" style="margin-top:0.8rem">
                    Random Forest classified this URL as safe.<br>
                    Always verify independently before sharing credentials.
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="result-phishing">
                <div class="result-emoji">🚨</div>
                <div class="result-label">PHISHING</div>
                <div class="prob-bar-container">
                    <div class="prob-bar-fill-phish" style="width:{bar_width}"></div>
                </div>
                <div class="prob-text">{conf_pct} confidence</div>
                <div class="result-sub" style="margin-top:0.8rem">
                    Random Forest flagged this URL as malicious.<br>
                    Do NOT enter credentials or download files from this site.
                </div>
            </div>
            """, unsafe_allow_html=True)

    # Feature breakdown
    st.markdown("")
    with st.expander("📊 Feature values used for this prediction"):
        cols = st.columns(3)
        for i, feat in enumerate(features):
            label = FEATURE_INFO.get(feat, (feat, {}))[0]
            val   = inputs_dict[feat]
            color = "#00c853" if val == 1 else ("#ff3d3d" if val == -1 else "#f9a825")
            cols[i % 3].markdown(
                f'<div style="font-family:Space Mono,monospace;font-size:0.7rem;'
                f'padding:0.3rem 0;border-bottom:1px solid #1a2340;">'
                f'<span style="color:#4a5a7a">{label}</span><br>'
                f'<span style="color:{color};font-weight:700">{val:+d}</span></div>',
                unsafe_allow_html=True
            )

# ── Inputs & Predict ──────────────────────────────────────────────────────────

tab1, tab2 = st.tabs(["🔴 Live URL Analysis", "⚙️ Manual Feature Entry"])

with tab1:
    st.markdown('<div class="section-title">Analyze a Live URL</div>', unsafe_allow_html=True)
    url_input = st.text_input("Enter URL (e.g., https://example.com):")
    col_btn_1, col_btn_2, col_btn_3 = st.columns([1, 1, 1])
    with col_btn_2:
        live_analyze_btn = st.button("🚀 LIVE ANALYZE")

    if live_analyze_btn and url_input:
        if not url_input.startswith("http"):
            url_input = "http://" + url_input
        with st.spinner("Extracting 30 features from URL... This may take a few seconds."):
            try:
                from extractor import extract_features
                extracted_features = extract_features(url_input)
                display_prediction(extracted_features)
            except Exception as e:
                st.error(f"Error during feature extraction: {e}")

with tab2:
    st.markdown('<div class="section-title">Configure URL Features</div>', unsafe_allow_html=True)

    user_inputs = {}

    for group_name, group_features in GROUPS.items():
        st.markdown(f"**{group_name}**")
        cols = st.columns(3)
        for i, feat in enumerate(group_features):
            label, options_map = FEATURE_INFO.get(feat, (feat, {-1:'-1', 0:'0', 1:'+1'}))
            available_vals = sorted(options_map.keys())
            display_opts  = [options_map[v] for v in available_vals]
            with cols[i % 3]:
                chosen = st.selectbox(
                    label,
                    options=display_opts,
                    index=len(available_vals)-1,  # default to highest (safest)
                    key=feat
                )
                # Map back to numeric
                user_inputs[feat] = available_vals[display_opts.index(chosen)]
        st.markdown("")

    st.markdown("---")

    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        predict_btn = st.button("🔍  ANALYSE MANUAL FEATURES")

    if predict_btn:
        display_prediction(user_inputs)

# ── Footer info ───────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown("""
<div class="info-box">
    📌 &nbsp;<strong style="color:#e0e6f0">How to use:</strong> Set each feature based on the URL you want to analyse. 
    Features use the UCI ML encoding: <span style="color:#00c853">+1 = legitimate indicator</span>, 
    <span style="color:#f9a825">0 = neutral/suspicious</span>, 
    <span style="color:#ff3d3d">-1 = phishing indicator</span>. 
    Then click ANALYSE URL.
</div>
""", unsafe_allow_html=True)
