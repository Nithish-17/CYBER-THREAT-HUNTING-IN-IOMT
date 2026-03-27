import glob
import os
import subprocess
import time
from datetime import datetime

import pandas as pd
import psutil
import streamlit as st

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
ANOMALY_DIR = os.path.join(PROJECT_ROOT, "anomaly_results")
VENV_PYTHON = os.path.join(PROJECT_ROOT, "venv", "Scripts", "python.exe")
PRODUCER_SCRIPT = os.path.join(PROJECT_ROOT, "Kafka", "producer.py")
DETECTOR_SCRIPT = os.path.join(PROJECT_ROOT, "tools", "realtime_detector.py")

ATTACK_CATEGORY_ORDER = [
	"Normal (benign)",
	"DoS / DDoS",
	"Port Scan / Reconnaissance",
	"Brute Force / Login attacks",
	"Botnet traffic",
	"MITM / Spoofing",
	"Injection attacks (SQL/command)",
	"Malware / Ransomware traffic",
	"Data exfiltration / abnormal transfer",
	"Other attacks",
]


def map_attack_category(label: str) -> str:
	l = str(label).strip().upper()
	if l in {"BENIGN", "NORMAL"}:
		return "Normal (benign)"
	if "DDOS" in l or l.startswith("DOS"):
		return "DoS / DDoS"
	if "RECON" in l or "SCAN" in l or "VULNERABILITY" in l:
		return "Port Scan / Reconnaissance"
	if "BRUTE" in l or "LOGIN" in l or "PASSWORD" in l:
		return "Brute Force / Login attacks"
	if "MIRAI" in l or "BOTNET" in l:
		return "Botnet traffic"
	if "MITM" in l or "SPOOF" in l or "ARP" in l:
		return "MITM / Spoofing"
	if "SQL" in l or "INJECT" in l or "COMMAND" in l:
		return "Injection attacks (SQL/command)"
	if "MALWARE" in l or "RANSOM" in l or "TROJAN" in l:
		return "Malware / Ransomware traffic"
	if "EXFIL" in l or "DATA_THEFT" in l or "LEAK" in l:
		return "Data exfiltration / abnormal transfer"
	return "Other attacks"


def find_process_by_script(script_name: str) -> int | None:
	try:
		for proc in psutil.process_iter(["pid", "cmdline"]):
			try:
				cmdline = proc.info.get("cmdline") or []
				cmd_str = " ".join(cmdline).lower()
				if script_name.lower() in cmd_str and "python" in cmd_str:
					return proc.info["pid"]
			except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
				continue
	except Exception:
		pass
	return None


def is_running(pid: int | None) -> bool:
	if not pid:
		return False
	try:
		return psutil.Process(pid).is_running()
	except (psutil.NoSuchProcess, psutil.AccessDenied):
		return False


def start_process(script_path: str) -> None:
	if not os.path.exists(script_path):
		return
	creationflags = 0
	if os.name == "nt":
		creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
		if hasattr(subprocess, "DETACHED_PROCESS"):
			creationflags |= subprocess.DETACHED_PROCESS

	env = os.environ.copy()
	env["PYTHONPATH"] = PROJECT_ROOT
	script_cwd = os.path.dirname(script_path) if os.path.dirname(script_path) else PROJECT_ROOT
	subprocess.Popen(
		[VENV_PYTHON, script_path],
		cwd=script_cwd,
		stdin=subprocess.DEVNULL,
		stdout=subprocess.DEVNULL,
		stderr=subprocess.DEVNULL,
		close_fds=True,
		creationflags=creationflags,
		env=env,
	)


def stop_process(pid: int | None) -> None:
	if not pid:
		return
	try:
		p = psutil.Process(pid)
		p.terminate()
		p.wait(timeout=3)
	except Exception:
		try:
			psutil.Process(pid).kill()
		except Exception:
			pass


def init_state() -> None:
	if "file_rows" not in st.session_state:
		st.session_state.file_rows = {}
	if "total_rows" not in st.session_state:
		st.session_state.total_rows = 0
	if "last_refresh" not in st.session_state:
		st.session_state.last_refresh = datetime.now()


def _row_count_csv(file_path: str) -> int:
	try:
		with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
			# header excluded
			return max(sum(1 for _ in f) - 1, 0)
	except Exception:
		return 0


def update_counters() -> tuple[int, int]:
	files = sorted(glob.glob(os.path.join(ANOMALY_DIR, "anomalies_*.csv")))
	known = st.session_state.file_rows
	touched = 0

	for fp in files:
		key = f"{fp}|{os.path.getmtime(fp)}|{os.path.getsize(fp)}"
		if key in known:
			continue
		rows = _row_count_csv(fp)
		known[key] = rows
		st.session_state.total_rows += rows
		touched += 1

	return st.session_state.total_rows, touched


@st.cache_data(ttl=1)
def load_recent_rows(max_files: int = 8, max_rows: int = 200) -> pd.DataFrame:
	files = sorted(glob.glob(os.path.join(ANOMALY_DIR, "anomalies_*.csv")))
	if not files:
		return pd.DataFrame()
	dfs = []
	for fp in files[-max_files:]:
		try:
			df = pd.read_csv(fp)
			df["_source_file"] = os.path.basename(fp)
			dfs.append(df)
		except Exception:
			continue
	if not dfs:
		return pd.DataFrame()
	merged = pd.concat(dfs, ignore_index=True)
	if len(merged) > max_rows:
		merged = merged.tail(max_rows).reset_index(drop=True)
	return merged


@st.cache_data(ttl=1)
def load_all_anomalies() -> pd.DataFrame:
	"""Load ALL anomaly data for full threat analysis"""
	files = sorted(glob.glob(os.path.join(ANOMALY_DIR, "anomalies_*.csv")))
	if not files:
		return pd.DataFrame()
	dfs = []
	for fp in files:
		try:
			df = pd.read_csv(fp)
			df["_source_file"] = os.path.basename(fp)
			dfs.append(df)
		except Exception:
			continue
	if not dfs:
		return pd.DataFrame()
	return pd.concat(dfs, ignore_index=True)


def clear_all_data() -> int:
	files = glob.glob(os.path.join(ANOMALY_DIR, "anomalies_*.csv"))
	removed = 0
	for fp in files:
		try:
			os.remove(fp)
			removed += 1
		except Exception:
			continue
	st.session_state.file_rows = {}
	st.session_state.total_rows = 0
	st.cache_data.clear()
	return removed


st.set_page_config(page_title="IoMT Anomaly Detection", layout="wide")
init_state()

producer_pid = find_process_by_script("producer.py")
detector_pid = find_process_by_script("realtime_detector.py")
producer_running = is_running(producer_pid)
detector_running = is_running(detector_pid)

total_received, new_files = update_counters()
recent_df = load_recent_rows()
anomalies_detected = int((recent_df.get("is_anomaly", pd.Series(dtype=bool)) == True).sum()) if not recent_df.empty else 0

st.title("IoMT Anomaly Detection Dashboard")
st.caption("Real-time monitoring of received data and anomalies")

page = st.sidebar.radio("Navigation", ["Overview", "Live Monitoring", "Threat Analysis", "Logs"])

st.sidebar.markdown("---")
st.sidebar.markdown("### Services")
st.sidebar.write(f"Producer: {'✅' if producer_running else '❌'}")
st.sidebar.write(f"Detector: {'✅' if detector_running else '❌'}")

col_s1, col_s2 = st.sidebar.columns(2)
with col_s1:
	if st.button("Start Producer"):
		start_process(PRODUCER_SCRIPT)
		st.rerun()
	if st.button("Stop Producer") and producer_pid:
		stop_process(producer_pid)
		st.rerun()
with col_s2:
	if st.button("Start Detector"):
		start_process(DETECTOR_SCRIPT)
		st.rerun()
	if st.button("Stop Detector") and detector_pid:
		stop_process(detector_pid)
		st.rerun()

st.sidebar.markdown("---")
if st.sidebar.button("Reset Counters + Clear Files"):
	removed_count = clear_all_data()
	st.sidebar.success(f"Removed {removed_count} files")
	st.rerun()


if page == "Overview":
	c1, c2, c3, c4 = st.columns(4)
	c1.metric("Total Data Received", f"{total_received:,}")
	c2.metric("Anomalies Detected (latest window)", f"{anomalies_detected:,}")
	c3.metric("New Files This Refresh", new_files)
	c4.metric("CSV Files", len(glob.glob(os.path.join(ANOMALY_DIR, "anomalies_*.csv"))))

	st.info("This page auto-refreshes every second.")

elif page == "Live Monitoring":
	st.subheader("Live Monitoring")
	st.metric("Total Data Received", f"{total_received:,}")
	if recent_df.empty:
		st.warning("No live data yet.")
	else:
		st.dataframe(recent_df.tail(100), width="stretch", height=480)

elif page == "Threat Analysis":
	st.subheader("Threat Analysis")
	st.metric("Total Data Received", f"{total_received:,}")

	# Load ALL data for threat analysis
	all_df = load_all_anomalies()
	
	if all_df.empty:
		st.warning("No data available yet.")
	else:
		# Severity analysis on ALL data
		sev = all_df.get("severity", pd.Series(dtype=str)).astype(str).str.upper()
		low = int((sev == "LOW").sum())
		med = int((sev == "MEDIUM").sum())
		high = int((sev == "HIGH").sum())
		missing_sev = int((sev.isin(["", "NAN", "NONE"])).sum())
		
		c1, c2, c3, c4 = st.columns(4)
		c1.metric("Low Severity", low)
		c2.metric("Medium Severity", med)
		c3.metric("High Severity", high)
		c4.metric("Missing Severity", missing_sev)

		st.markdown("### Severity Distribution (All Data)")
		if "severity" in all_df.columns:
			severity_data = all_df["severity"].astype(str).str.upper()
			severity_counts = severity_data[~severity_data.isin(["", "NAN", "NONE"])].value_counts()
			if not severity_counts.empty:
				st.bar_chart(severity_counts)
				st.dataframe(severity_counts.rename("count").reset_index().rename(columns={"index": "severity"}), width="stretch", height=200)
			else:
				st.info("No severity data found.")

		if "attack_label" in all_df.columns:
			st.markdown("### Attack Type Distribution (All Data)")
			attack_counts = all_df["attack_label"].astype(str).value_counts().head(20)
			st.bar_chart(attack_counts)

			st.markdown("### Required Attack Categories (All Data)")
			cat_series = all_df["attack_label"].astype(str).map(map_attack_category)
			cat_counts = cat_series.value_counts()
			cat_counts = cat_counts.reindex(ATTACK_CATEGORY_ORDER, fill_value=0)
			st.bar_chart(cat_counts)
			cat_df = cat_counts.rename("count").reset_index().rename(columns={"index": "attack_category"})
			st.dataframe(cat_df, width="stretch", height=320)

elif page == "Logs":
	st.subheader("Anomaly Logs")
	files = sorted(glob.glob(os.path.join(ANOMALY_DIR, "anomalies_*.csv")))
	st.write(f"Total files: {len(files)}")
	if files:
		selected = st.selectbox("Select file", [os.path.basename(x) for x in files[-200:]])
		target = os.path.join(ANOMALY_DIR, selected)
		try:
			df_log = pd.read_csv(target)
			st.dataframe(df_log.tail(300), width="stretch", height=480)
		except Exception as ex:
			st.error(f"Unable to open file: {ex}")


time.sleep(1)
st.rerun()
