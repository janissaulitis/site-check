"""Site Check: a website security check, and the client dashboard it would feed. Run: streamlit run app.py"""
import importlib

import streamlit as st

import kit

importlib.reload(kit)  # Streamlit Cloud keeps old copies of imported files after an update

kit.page("Site Check", "A website security check that says what to fix, how, and how to retest", mark="lock", icon="🔒",
         theme="inspect", badge="Passive checks · free", meta="Second opinion from Mozilla HTTP Observatory")

nav = st.navigation([st.Page("check_page.py", title="Check a site", icon=":material/search:", default=True),
                     st.Page("dashboard_page.py", title="Client dashboard (demo)", icon=":material/space_dashboard:",
                             url_path="dashboard")], position="top")
nav.run()
