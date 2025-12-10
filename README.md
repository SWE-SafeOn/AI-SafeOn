# SafeOn: An Anomaly Detection System for Smart Home IoT Security  
> 한양대학교 2025-2 소프트웨어공학 / 인공지능및응용 공동 프로젝트 (SWE/AI Project in Hanyang Univ. 2025-2)

---

## Members

| Name | Organization | Email |
|------|-------------|--------|
| Juseong Jeon | Department of Information Systems, Hanyang University | hyu22ix@hanyang.ac.kr |
| Jaemin Jung | Department of Information Systems, Hanyang University | woals5633@hanyang.ac.kr |
| Wonyoung Shin | Department of Information Systems, Hanyang University | pingu090@hanyang.ac.kr |
| Seungmin Son | Department of Information Systems, Hanyang University | andyson0205@gmail.com |

---

## I. Introduction & Motivation

### 1. Problem Motivation: Why Are We Doing This?

Modern homes are filled with networked devices: robot vacuums, smart TVs, air purifiers, IP cameras, smart plugs, and more. Most of these IoT devices:

- Run proprietary, tightly constrained firmware  
- Receive infrequent or no security updates  
- Expose network-facing services that users rarely monitor  

This creates an asymmetric environment where:

- **Attackers need to compromise only one weak IoT device**,  
- While home users and ISPs have almost no visibility into what each device is actually doing on the network.

The problem is amplified in architectures such as **LG ThinQ + Cloud**, where smart appliances communicate exclusively with vendor cloud endpoints over encrypted channels. From the router’s perspective, *every packet looks like “HTTPS to the same LG server”*: payloads are encrypted and destinations are fixed. As a result:

- Traditional router-level security (port-based firewalls, simple IP blocking) is blind to malicious behaviors hidden inside “normal-looking” TLS traffic.
- Even if a compromised fridge or camera exfiltrates data or joins a botnet, its packets can still appear benign at the network layer.

We wanted to answer a simple question:

> “Without decrypting any payloads or sending data to a third-party cloud, **can the home router itself learn the ‘normal behavior’ of IoT devices and detect abnormal patterns in real time?**”

### 2. What Do We Want to See at the End?

SafeOn is our answer to this question:  
a **network-edge anomaly detection framework for smart home IoT**, centered around the home gateway.

Our concrete goals are:

1. **Edge-first, privacy-preserving detection**  
   - Perform all analysis at the home gateway and local ML server.  
   - Never inspect or store application payloads; only use flow metadata.

2. **Flow-based anomaly detection tailored to IoT traffic**  
   - Learn typical behavioral patterns of a real ESP32-CAM smart camera.  
   - Detect deviations such as bursty scanning, abnormal external connections, or unusual throughput.

3. **End-to-end system, not just a model**  
   - Implement the full pipeline:
     - Packet capture on OpenWrt  
     - Flow aggregation and MQTT publication  
     - ML inference via FastAPI  
     - Anomaly score persistence in PostgreSQL/TimescaleDB  
     - Spring Boot backend for alert logic and REST APIs  
     - Flutter mobile app for visualization and notifications

4. **Actionable, user-facing alerts**  
   - Present anomalies in a way that non-expert users can understand:  
     *“Your living room camera is contacting an external IP that it normally never talks to.”*  
   - Support basic incident response (acknowledge alerts, inspect the device, potentially block or remove).

By the end of the project, our desired outcome is:

- A **working prototype** where, in a controlled lab environment:
  - An ESP32-CAM generates network traffic through an OpenWrt router.
  - SafeOn’s ML engine labels flows as anomalous or benign.
  - The backend aggregates evidence and creates alerts.
  - The Flutter app displays real-time status and notifications to the user.

- A **reusable architecture** that can be extended to:
  - Multiple IoT device types,
  - Richer anomaly models,
  - And, eventually, digital-twin–like behavioral baselines.

SafeOn is not just a single ML model; it is a **full-stack security experiment** exploring what a “home-level EDR for IoT” could look like when implemented concretely.

---

## II. Datasets

### 1. Overview

SafeOn’s anomaly detection pipeline is trained and evaluated using **custom-collected traffic** from a real **ESP32-CAM** device. We intentionally avoid public datasets to:

- Capture realistic, noisy traffic from an actual low-power smart camera.
- Reflect the exact network environment and configurations we use in the system.

We maintain two main CSV datasets (stored under `datasets/esp32-cam/`):

- `dataset.csv` – Baseline flows (predominantly normal behavior)
- `attacker.csv` – Flows generated under intentionally abnormal or attack-like scenarios

In total, the dataset contains on the order of **38789 flow-level samples**. (Normal: 28286 samples, Abnormal: 10503 samples)
### 2. Data Collection Setup

Traffic was collected under the following lab setup:

- **Device**: ESP32-CAM (real-time video streaming)
- **Gateway**: OpenWrt-based router configured as the home gateway
- **Capture Tooling**:
  - `tcpdump` on the router interface
  - Periodic scripts to aggregate packets into flows and export to CSV
  - MQTT-based delivery of flow metadata to the ML service

We emulate various scenarios:

- Continuous streaming from the ESP32-CAM to a viewer
- Normal control operations (e.g., HTTP configuration, status queries)
- Intentional “abnormal” behavior such as:
  - Unusual bursts of short-lived connections
  - Unexpected external IP destinations
  - Traffic patterns that differ significantly from baseline streaming

All of this is done inside a controlled LAN, ensuring we always know *whether* a given scenario is intended as normal or anomalous.

### 3. Dataset Composition

We conceptually divide flows into three categories:

1. **Video Streaming Flows**  
   - Long-lived TCP connections with:
     - High `byte_count`
     - Stable but non-uniform `packet_count`
     - Continuous outbound direction toward a viewing endpoint  
   - These flows represent the **dominant normal behavior** of the camera.

2. **HTTP / Control Flows**  
   - Shorter request–response exchanges:
     - Configuration checks
     - Single-frame requests
     - Status polling  
   - Typical characteristics:
     - Small `byte_count`
     - Limited `duration`
     - Often distinct `src_port` / `dst_port` patterns  
   - These flows are benign in our dataset but are structurally similar to what an attacker might generate during reconnaissance.

3. **Background / Miscellaneous Flows**  
   - Keep-alive messages  
   - Internal metadata or service management communications  
   - Sporadic and small flows with:
     - Low `packet_count`
     - Short duration
     - Low frequency  

These categories collectively build a **rich baseline** of what one IoT smart camera “normally” does on a home network.

### 4. Feature Extraction

SafeOn does **not** inspect packet payloads. Instead, it converts raw packets into **flow-level features** and operates purely on metadata.

At the ML layer, the core feature set is:

| Feature            | Description |
|--------------------|-------------|
| `src_ip`           | Source IP address (categorical; encoded) |
| `dst_ip`           | Destination IP address (categorical; encoded) |
| `src_port`         | Source transport-layer port |
| `dst_port`         | Destination transport-layer port |
| `proto`            | Protocol (e.g., TCP, UDP; categorical; encoded) |
| `packet_count`     | Total number of packets in the flow |
| `byte_count`       | Total bytes transferred in the flow |
| `duration`         | Flow duration in seconds |
| `pps`              | Packets per second (`packet_count / duration`) |
| `bps`              | Bytes per second (`byte_count / duration`) |
| `pps_delta`        | Change in pps compared to previous flow for the same device/endpoint |
| `bps_delta`        | Change in bps compared to previous flow |
| `pps_cum_increase` | Cumulative positive change in pps over recent flows |
| `bps_cum_increase` | Cumulative positive change in bps over recent flows |

Some additional fields (like `start_time`, `end_time`, or `time_bucket`) exist at the database level for temporal analysis and dashboard visualization, even if they are not directly used as ML features.

### 5. Dataset Statistics (High-Level)

While we do not expose exact numerical metrics in the repository, the dataset roughly shows:

- **Strong class imbalance**: normal flows are the vast majority.
- **Clear distributional differences** between:
  - Streaming flows vs short control flows vs injected anomalous flows.
- **Temporal dependencies**: anomalies often appear as short bursts within otherwise stable streaming sessions.

These characteristics make the dataset well-suited for **unsupervised / semi-supervised anomaly detection** based on Isolation Forest, complemented by a supervised classifier when attack labels are available.

---

## III. Methodology

### 1. System Architecture

SafeOn is designed as a **four-layer pipeline**:

1. **Edge Capture Layer (OpenWrt Router)**  
   - Captures raw packets via `tcpdump`.  
   - Aggregates them into flow records (with packet/byte counts, duration, rates).  
   - Publishes flow metadata as JSONL to an MQTT broker (`safeon/ml/request`).

2. **ML Service Layer (`safeon_ML-FastAPI`)**  
   - Implements the anomaly detection engine using Python, FastAPI, and scikit-learn.  
   - Provides both:
     - An HTTP REST API (`/predict`) for direct calls, and  
     - An MQTT bridge that subscribes to flow data and publishes prediction results back (`safeon/ml/result`).

3. **Backend Layer (`safeon_backend`, Spring Boot)**  
   - Listens to the ML result topic via an MQTT client.  
   - Persists flow metadata (`packet_meta`) and anomaly scores (`anomaly_scores`) in PostgreSQL/TimescaleDB.  
   - Applies **alert logic** (e.g., three consecutive anomalies or suspicious external IP behavior).  
   - Exposes REST APIs and real-time endpoints (WebSocket/SSE) to the frontend.

4. **Frontend Layer (`safeon_frontend`, Flutter)**  
   - Mobile app that:
     - Displays a dashboard of device status and anomaly statistics,
     - Shows alert timelines and device-specific traffic,
     - Triggers local push notifications for new alerts.

Together, these layers implement an **end-to-end, real-time IoT anomaly detection system** that remains under the user’s control and visibility.

### 2. Algorithms and Models

Our current implementation focuses on a **hybrid ML pipeline** combining:

1. **Isolation Forest (unsupervised anomaly detection)**  
   - Trained primarily on normal flows to model typical behavior.  
   - Produces a continuous **anomaly score** per flow based on how “isolated” it is in the feature space.

2. **Random Forest Classifier (supervised anomaly classification)**  
   - When labeled attack flows are available (from `attacker.csv`), we train a Random Forest to distinguish normal vs. anomalous flows.  
   - This model helps refine decisions in regimes where the Isolation Forest alone might be too conservative or too sensitive.

3. **Hybrid Scoring**  
   - For each flow, the ML pipeline computes:
     - `iso_score`: Isolation Forest–based anomaly score  
     - `rf_score`: Random Forest–based anomaly probability (where applicable)  
     - `hybrid_score`: a merged score combining unsupervised and supervised evidence  
   - A configurable threshold (default around `0.5`) determines `is_anom` (boolean).  
   - Thresholds and hybrid weighting can be tuned to trade off false positives vs false negatives.

The models and preprocessing artifacts (encoders, scaler, etc.) are saved under `safeon_ML-FastAPI/app/models/` and loaded by the FastAPI service at runtime.

### 3. Feature Engineering and Flow Representation

At the ML layer, flows are represented by the `FlowFeatures` Pydantic model, which:

- Validates and normalizes timestamps (string → epoch seconds).
- Computes missing durations from `start_time` and `end_time` if necessary.
- Normalizes protocol strings (e.g., `"tcp"` → `"TCP"`).
- Fills derived features (deltas and cumulative increases) using an in-memory cache of recent flow statistics per key.

Before feeding into the models:

- Categorical fields (`src_ip`, `dst_ip`, `proto`) are encoded.  
- Numeric features are scaled (e.g., MinMaxScaler).  
- The final feature vector strictly follows a **fixed column order** shared across training and inference.

This engineering ensures that flows are **lightweight but expressive enough** to capture:

- Volume,
- Rate,
- Sudden changes,
- And rough endpoint behavior — without ever touching payload content.

### 4. Backend Alert Logic

The ML engine outputs **scores per flow**, but users should not be overwhelmed by raw detections. The Spring Boot backend therefore applies higher-level logic:

1. **External IP detection**  
   - Using `PacketMeta` records, the backend determines whether a flow involves an external IP (outside private address ranges).  
   - Even if the ML model is uncertain, **external connections that deviate from normal patterns are treated with extra suspicion.**

2. **Consecutive anomaly detection**  
   - The backend queries the `anomaly_scores` table to find **runs of consecutive anomalous flows**.  
   - Only when at least **three consecutive anomalies** occur (within a reasonable time window) and no alert has been raised recently for that device do we create a new `Alert`.

3. **Alert creation and delivery**  
   - On triggering conditions, a new `Alert` entity is created with:
     - Severity (e.g., `HIGH` by default),
     - Reason (e.g., “Anomaly detected by ML” or “External access detected”),
     - Evidence (JSON describing key flow parameters: IPs, ports, timing, scores).  
   - `UserAlert` entities link alerts to users and delivery channels (currently in-app and local push).

This architecture allows SafeOn to **filter noisy per-flow predictions** into **human-meaningful events** that users can actually respond to.

### 5. Frontend and User Experience

The Flutter app is designed to make SafeOn’s behavior understandable at a glance:

- **Onboarding + Login**  
  - Simple onboarding sequence explaining what SafeOn does.  
  - Login/signup backed by JWT authentication via the Spring API.

- **Dashboard**  
  - High-level overview of:
    - Total devices,
    - Recent anomalies per day,
    - Latest alerts.  
  - Uses `fl_chart` to visualize daily anomaly counts and trends.

- **Device View**  
  - Lists devices known to the system (claimed by the user) and newly discovered devices.  
  - For each device, the user can inspect recent flows and anomalies.

- **Alerts & Notifications**  
  - A dedicated alerts tab shows recent alerts, their severity, and whether they have been acknowledged.  
  - On Android/iOS/macOS, `flutter_local_notifications` is used to surface new alerts as OS-level notifications whenever possible.

The goal is to make complex network and ML signals **digestible** to non-security experts while still exposing enough detail for advanced users.

---

## IV. Evaluation & Analysis

### 1. Offline Model Evaluation

Using the `dataset.csv` and `attacker.csv` files, we conducted offline experiments to evaluate the:

- Discriminative ability of **Isolation Forest alone**,  
- Performance of the **Random Forest classifier** when labels are available, and  
- Behavior of the **hybrid scoring scheme** under different anomaly thresholds.

While precise metrics are not published in the repository, our experiments yielded several key observations:

- Isolation Forest is effective at identifying **obvious outliers**, such as:
  - Flows with extremely short durations and unusually high packet rates,
  - Flows targeting previously unseen IP/port combinations.  
- The Random Forest model can refine these decisions when enough labeled anomalies are present, particularly in edge cases where attack traffic mimics normal control flows.
- The hybrid approach helps:
  - Reduce false positives in sustained streaming conditions,
  - While maintaining sensitivity to rare, structurally different flows.

### 2. System-Level Behavior

We also evaluate SafeOn as a system, not just as a model:

- **Real-time detection latency**  
  - In our lab setup, the end-to-end path:
    - (packet capture → flow aggregation → MQTT → ML inference → DB persist → alert creation → mobile notification)  
    typically remains fast enough to support near real-time alerts for home users.

- **Alert quality**  
  - The combination of:
    - Consecutive anomaly checks, and
    - External IP detection  
    substantially reduces “single noisy flow” alerts, focusing instead on *sustained suspicious behavior*.

- **User visibility**  
  - By correlating anomaly scores with device names and simple evidence messages (“external IP contacted”, “abnormal throughput spike”), SafeOn surfaces **clear, actionable information** instead of opaque ML scores.

### 3. Limitations

Our current system has several important limitations:

- **Single-device training**  
  - Models are primarily trained on an ESP32-CAM profile; generalization to other IoT devices is not guaranteed.

- **Limited dataset size**  
  - Despite being realistic, the dataset is modest in scale. More diverse, long-term traffic traces would improve robustness.

- **Static thresholds and feature set**  
  - Thresholds and feature engineering choices are manually tuned; there is room for adaptive methods and more principled optimization.

Despite these limitations, SafeOn successfully demonstrates that **a practical, end-to-end IoT anomaly detection system can run at the network edge** with modest resources.

---

## V. Related Work

### 1. IoT Anomaly Detection and Network Security

SafeOn is conceptually related to:

- **Flow-based anomaly detection research** for IoT and industrial control systems, where models such as Isolation Forest, Random Forest, and various anomaly-specific models have been used to detect abnormal network traces.
- **Network Intrusion Detection Systems (NIDS)** that operate on flow-level data (e.g., NetFlow) instead of packet payloads to preserve privacy and reduce overhead.
- **Smart home security platforms** that try to infer device roles and behaviors from encrypted traffic patterns, rather than deep packet inspection.

Our contribution is to **instantiate these ideas end-to-end** in a concrete, reproducible project with modern tooling and mobile UX.

### 2. Tools, Libraries, and Frameworks

We heavily rely on the following technologies:

- **Edge / Networking**
  - OpenWrt (router OS + package infrastructure)
  - `tcpdump` for packet capture
  - MQTT broker (e.g., Mosquitto) and Eclipse Paho client libraries

- **ML & Backend**
  - Python 3 & FastAPI for the ML microservice
  - `pandas`, `scikit-learn` for data processing and model training
  - PostgreSQL + TimescaleDB for time-series storage
  - Spring Boot 3, Spring Data JPA, Spring Security for REST APIs, authentication, and DB access
  - `springdoc-openapi` for API documentation

- **Frontend & UX**
  - Flutter (Dart) for cross-platform mobile development
  - `http`, `fl_chart`, and `flutter_local_notifications` for networking, visualization, and alerts

These tools were chosen to balance **developer productivity**, **performance**, and **deployability** in a student project setting.

---

## VI. Conclusion: Discussion

SafeOn explores what it would mean to bring **EDR-like capabilities to smart home IoT** by leveraging the **home router as a security vantage point**. Through this project, we:

- Designed and implemented a **full-stack architecture** covering data capture, ML inference, backend alert logic, and mobile UX.
- Built a **flow-based anomaly detection engine** that operates solely on network metadata, preserving user privacy while still exposing abnormal behaviors.
- Integrated detection results into a **human-friendly dashboard** with real-time alerts and device-level context.

### What We Learned

- **Visibility at the network edge is powerful.**  
  Even without payloads, flow-level features can reveal meaningful deviations in behavior.

- **Modeling is only half the battle.**  
  Without good alert logic and UX, raw anomaly scores are not actionable. Our backend logic and mobile app were crucial to turning detections into usable security signals.

- **IoT security is inherently longitudinal.**  
  Understanding a device requires sustained observation over time; single snapshots are rarely enough.

### Future Directions

Going forward, SafeOn can be extended in several directions:

1. **Multi-device profiling**  
   - Train per-device or per-class models (e.g., cameras vs TVs vs sensors).  
   - Automatically infer device roles from traffic to boot-strap baselines.

2. **Adaptive modeling and thresholds**  
   - Incorporate online learning or drift detection to adapt to evolving device behaviors.  
   - Use more advanced anomaly methods when sufficient data is available.

3. **Richer behavior modeling**  
   - Extend SafeOn further toward **behavioral digital twins**, where we predict expected traffic patterns for each device and compute residuals between predicted and observed behavior.

4. **User-centric incident response**  
   - Provide guided workflows:
     - “Quarantine device,”
     - “Check firmware update,”
     - “Block external IP/domain,” etc.

5. **Explainability and transparency**  
   - Improve explanations for why a flow or alert was considered anomalous, bridging the gap between ML outputs and user understanding.
