# Incident Response & Machine Learning Threat Detection: APT Poison Ivy

## Executive Summary
This repository details a comprehensive Incident Response (IR) and Threat Hunting engagement conducted within Splunk Enterprise. The primary objective was to investigate a suspected network compromise, trace the adversary's actions via the Cyber Kill Chain, extract high-fidelity Indicators of Compromise (IoCs), and engineer an automated Machine Learning (ML) detection pipeline to preemptively identify reconnaissance anomalies and reduce Mean Time to Detect (MTTD).

## Architecture & Technologies
* **SIEM & Data Analysis:** Splunk Enterprise, Splunk Processing Language (SPL)
* **Machine Learning:** Splunk Machine Learning Toolkit (MLTK), Python for Scientific Computing
* **Algorithms Utilized:** `DensityFunction` (Statistical Anomaly Detection)
* **Telemetry Sources:** Sysmon (Event IDs 1 & 3), Network Stream Logs (`stream:http`)
* **Core Competencies:** Threat Hunting, Regular Expression (RegEx) parsing, Dashboard Engineering, ML Train-Test Split validation.

## Dataset Attribution
The investigation was conducted utilizing the **Splunk Boss of the SOC (BOTS) Dataset v1**. This is a realistic, captured dataset containing 24 hours of telemetry from a simulated enterprise environment (WayneCorp). It includes real-world noise, legitimate business traffic, and a multi-stage APT attack lifecycle, providing a high-fidelity environment for Incident Response and Machine Learning training. 

## Attack Chain Analysis

### 1. Reconnaissance (Scanner Detection)
The initial investigation was prompted by a volumetric anomaly in external web traffic. Analysis of the `stream:http` indices revealed a sustained, high-frequency request pattern originating from a singular external IP address. The user-agent and request cadence confirmed the use of an automated Acunetix web vulnerability scanner attempting to enumerate server directories.
* **Attacker IP:** `40.80.148.42`
* **Tactic:** Reconnaissance / Active Scanning (T1595)

### 2. Execution (Payload Detonation)
Pivoting the investigation to endpoint telemetry, I analyzed Sysmon Event ID 1 (Process Creation) logs to identify successful exploitation. To bypass XML parsing limitations within the raw logs, I utilized SPL's `rex` command for custom field extraction, successfully uncovering the execution of a malicious payload spawned via a command-line interface.
* **Malware Executable:** `3791.exe`
* **Command Line Execution:** `cmd.exe /c 3791.exe 2>&1`
* **Tactic:** Execution / Command and Scripting Interpreter (T1059)

### 3. Command & Control (C2)
To ascertain the extent of the breach, I tracked the payload's outbound network communications utilizing Sysmon Event ID 3 (Network Connection) logs. The executable successfully initiated a connection to an external, unauthorized infrastructure. The destination port directly mirrored the payload nomenclature, a documented behavioral indicator of the Poison Ivy Remote Access Trojan (RAT).
* **C2 IP Address:** `23.22.63.114`
* **Target Port:** `3791`
* **Tactic:** Command and Control / Application Layer Protocol (T1071)

## Threat Visualization & Reporting

<img width="1919" height="789" alt="Screenshot 2026-03-19 123422" src="https://github.com/user-attachments/assets/244468b2-6e27-402f-a795-e9cf1f886fcb" />


To provide actionable intelligence to security leadership, I engineered a dynamic Splunk dashboard. This visualization aggregated the extracted IoCs, mapped the timeline of the attack lifecycle, and provided real-time visibility into compromised endpoints.

## Engineering Automated Detection via Machine Learning
Relying exclusively on manual query execution for reconnaissance detection introduces unacceptable latency and alert fatigue within a Security Operations Center (SOC). To remediate this, I engineered a mathematical baseline of standard server traffic utilizing the Splunk MLTK.

### Phase 1: Model Training (`fit`)
Deploying the `DensityFunction` algorithm, I trained a model to analyze request frequency over 1-minute intervals. The threshold was strictly configured to `0.01`, instructing the algorithm to isolate the 99th percentile of extreme statistical deviations, effectively filtering out standard business traffic.

```splunk
index="botsv1" earliest=0 sourcetype="stream:http" 
| timechart span=1m count 
| fit DensityFunction count threshold=0.01 into baseline_web_traffic
```


### Phase 2: Production Deployment (apply)
The saved baseline_web_traffic model was then applied against the raw data stream. The ML pipeline successfully generated a binary IsOutlier flag, dropping all normal traffic (0.0) and mathematically isolating the exact 53 minutes of the Acunetix brute-force attack (1.0). This established a high-fidelity, automated alerting mechanism with minimal false positives.

```Code snippet
index="botsv1" earliest=0 sourcetype="stream:http" 
| timechart span=1m count 
| apply baseline_web_traffic
| search "IsOutlier(count)"=1
```

<img width="1919" height="921" alt="Screenshot 2026-03-19 110525" src="https://github.com/user-attachments/assets/7ddd000a-fcc8-471c-bd38-d32ee5c75722" />


Business Impact
By transitioning from manual log analysis to an ML-driven detection model, this project demonstrates how to significantly reduce SOC analyst workload, automate the identification of early-stage kill chain activities, and fortify the network against automated exploitation frameworks.
