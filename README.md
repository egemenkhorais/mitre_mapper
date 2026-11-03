# 🛡️ MITRE Mapper — AI-Powered Live SOC & Network-Observable MITRE ATT&CK Pipeline

**MITRE Mapper**, gerçek zamanlı ağ trafiğini (NetFlow / PCAP) çok katmanlı makine öğrenmesi modelleri, davranışsal korelasyon motoru ve yerel büyük dil modeli (**Ollama / Qwen Threat Validator**) ile analiz ederek doğrulanmış siber tehditleri **ağdan gözlemlenebilir (Network-Observable) MITRE ATT&CK** teknikleriyle eşleştiren uçtan uca bir Güvenlik Operasyon Merkezi (SOC) hattıdır.

## 🚀 Mimari Genel Bakış

Geleneksel makine öğrenmesi tabanlı saldırı tespit sistemlerinin (IDS) kurumsal ağlardaki standart protokolleri (OSPF, SSDP, mDNS, Multicast, standart bulut servisleri) yanlış pozitif (*false positive*) olarak etiketlemesini ve yalnızca ağ üstverisiyle kanıtlanamayacak host tabanlı MITRE tekniklerine (ör. *Process Injection*, *OS Credential Dumping*) hatalı eşleme yapmasını önlemek amacıyla 6 aşamalı deterministik ve yapay zekâ destekli bir doğrulama mimarisi kurgulanmıştır:

`Canlı Ağ Akışı (PyShark / PCAP)` ➔ `Layer 1: XGBoost Akış Sınıflandırıcı` ➔ `Layer 2: HTTP Payload Derin Paket Analizi` ➔ `Davranışsal Analiz & Korelasyon Motoru` ➔ `Qwen Threat Validator (Yerel LLM)` ➔ `Network-Observable MITRE ATT&CK Mapper` ➔ `Canlı SOC API & Web Dashboard`

| Katman | Bileşen / Modül | Görev ve Teknik Detaylar |
| :--- | :--- | :--- |
| **Veri Yakalama & PCAP** | `live_soc.py` | `PyShark` / `tshark` ile canlı arayüz (`en0`, hotspot vb.) dinleme, çift yönlü (`canonical_flow_key`) paket birleştirme ve `Scapy` (`wrpcap`) ile olay bazlı `.pcap` dışa aktarma |
| **Layer 1 (Akış ML)** | `xgb_nfv2_model.joblib` | NetFlow istatistikleri üzerinden çok sınıflı saldırı tespiti (Reconnaissance, DoS, Fuzzers, Brute Force vb.) ve olasılık eşikleme (`ALERT_THRESHOLD = 0.80`, `REVIEW_THRESHOLD = 0.50`) |
| **Layer 2 (Payload ML)** | `extract_http_request_from_pcap` | Yakalanan PCAP kayıtlarından HTTP katmanı yüklerini ayrıştırarak SQL Injection, XSS ve web tabanlı istismar girişimlerini yakalama |
| **Davranış & Korelasyon** | `behaviour_engine` | Tekil akış olasılığı düşük (`< 0.50`) olsa bile kaynak IP aktivite penceresindeki anomalileri ve korelasyon bulgularını (`BEHAVIOR_ALERT`) tespit etme |
| **Threat Validator (LLM)** | `threat_validator.py` | Yerel **Ollama / Qwen** modeli (`temperature=0`, `format=json`) ile deterministik ağ gerçeklerini (Multicast/Private/Link-Local IP, trafik yönü, bilinen hedef port servisi) birleştirerek `Benign`, `Likely Benign`, `Suspicious` veya `Malicious` kararı üretme |
| **MITRE ATT&CK Filtresi** | `network_mitre.py` & `mitre_runner.py` | `cache/attack_enterprise.json` üzerinden yalnızca veri kaynağı **Network Traffic** olan teknikleri **Tier 1 (`flow_visible`)** ve **Tier 2 (`content_visible`)** olarak süzme; host-only teknikleri havuz dışına çıkarma |
| **Canlı SOC Arayüzü** | `soc_api.py` & `dashboard.html` | Server-Sent Events (SSE) ile gerçek zamanlı uyarı akışı, interaktif ATT&CK matrisi, tek tıkla LLM doğrulama/eşleme ve resmi **ATT&CK Navigator (`layer.json`)** dışa aktarma |

## 📂 Proje Dosya Yapısı

* **`live_soc.py`**: Canlı paket yakalama döngüsü (`process_batch`), çift yönlü akış anahtarlama (`canonical_flow_key`, `reverse_flow_key`), karar eşikleri (`decide`), MITRE kanıt kapısı (`should_run_mitre`), kaynak/hedef/protokol bazlı önbellek imzası (`build_mitre_signature`) ve atomik uyarı dosyası oluşturma (`create_alert_paths`).
* **`threat_validator.py`**: Uyarıları MITRE eşlemesine göndermeden önce yerel Ollama/Qwen modeliyle doğrulayan, yanlış pozitifleri (OSPF, mDNS, SSDP, yerel servisler) eleyen ve teknik gerekçe (`reasoning`) üreten doğrulama ajanı.
* **`network_mitre.py`**: Kurumsal MITRE ATT&CK veri tabanını (`cache/attack_enterprise.json`) tarayarak yalnızca ağ trafiğinden kanıtlanabilir teknikleri dinamik olarak filtreleyen ve sınıflandıran modül:
  * **Tier 1 (`flow_visible`)**: Doğrudan akış üstverisinden tespit edilebilen teknikler (`T1046` Network Service Discovery, `T1018` Remote System Discovery, `T1110` Brute Force, `T1071` Application Layer Protocol, `T1041` Exfiltration Over C2 Channel, `T1498.001` / `T1499.001` DoS, `T1592` / `T1590` Reconnaissance).
  * **Tier 2 (`content_visible`)**: Paket yükü (payload) incelemesi gerektiren teknikler.
* **`mitre_runner.py`**: Yalnızca `Malicious` veya yüksek güvenli (`>= %80`) `Suspicious` kararlarında (veya SOC arayüzünden manuel tetiklendiğinde) `mitre_agent` üzerinden MITRE ATT&CK eşlemesini çalıştıran yürütücü modül.
* **`soc_api.py` & `dashboard.html`**: Canlı SOC izleme sunucusu ve web tabanlı kontrol paneli.

## ⚙️ Kurulum ve Gereksinimler

### 1. Ön Koşullar
* **Python 3.10+** (Python 3.12+ / PyShark 0.6 asenkron olay döngüsü uyumlu)
* **Wireshark / tshark**: Canlı paket yakalama için sistemde `tshark` kurulu olmalıdır.
* **Ollama**: Yerel LLM doğrulaması ve MITRE eşlemesi için Ollama servisi çalışır durumda olmalı ve ilgili **Qwen** modeli indirilmiş olmalıdır.

### 2. Depoyu Klonlayın ve Bağımlılıkları Yükleyin

```bash
git clone https://github.com/egemenkhorais/mitre_mapper.git
cd mitre_mapper
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Yerel LLM (Ollama) Servisini Hazırlayın

```bash
ollama serve
ollama pull qwen2.5
```

## 💻 Kullanım

### Canlı Ağ Trafiği Analiz Hattını Başlatma
Ağ arayüzünü dinleyerek gerçek zamanlı akış yakalama, Layer 1/Layer 2 sınıflandırma ve Threat Validator hattını çalıştırmak için:

```bash
sudo python3 live_soc.py
```

### Canlı SOC Backend API ve Web Dashboard'u Başlatma
Web tabanlı SOC arayüzünü ve REST/SSE uç noktalarını ayağa kaldırmak için:

```bash
python3 soc_api.py
```

Tarayıcınızdan ilgili yerel sunucu adresine giderek **Canlı SOC Dashboard (`dashboard.html`)** üzerinden gerçek zamanlı uyarıları, ağ gerçeklerini, Qwen Threat Validator gerekçelerini ve MITRE ATT&CK matrisini inceleyebilirsiniz.

## 🔌 SOC Backend API Uç Noktaları (`soc_api.py`)

| Metot | Uç Nokta | Açıklama |
| :--- | :--- | :--- |
| `GET` | `/api/stream` | Server-Sent Events (SSE) üzerinden gerçek zamanlı uyarı ve olay akışı sağlar |
| `GET` | `/api/stats` | Toplam akış, tehdit dağılımı, doğrulama durumları ve SOC özet istatistiklerini döndürür |
| `GET` | `/api/matrix` | Tespit edilen saldırıların taktik ve teknik bazlı MITRE ATT&CK matris kırılımını döndürür |
| `GET` | `/api/navigator` | Resmi **MITRE ATT&CK Navigator** aracıyla doğrudan uyumlu `layer.json` çıktısı üretir |
| `POST` | `/api/alerts/<id>/validate` | Seçilen uyarı için arayüzden tek tıkla Qwen Threat Validator doğrulamasını tetikler |
| `POST` | `/api/alerts/<id>/mitre` | Seçilen uyarı için ağdan gözlemlenebilir MITRE ATT&CK eşlemesini tetikler |

## 🧠 Temel Mühendislik İyileştirmeleri

* **Çift Yönlü Akış Birleştirme & Eksiksiz PCAP Kaydı**: İleri ve geri yönlü ağ akışları (`A:port -> B:port` ve `B:port -> A:port`) `canonical_flow_key()` ile tek konuşmaya indirgenir; ham paket baytları korunarak Layer 2 HTTP ayrıştırıcısına ve `.pcap` kanıt dosyalarına eksiksiz aktarılır.
* **Çok Kademeli Kanıt Kapısı (`should_run_mitre`)**: Düşük güvenli tahmin gürültüsünü (`< 0.50` `LOW_CONFIDENCE`) filtreler; LLM çağrısını yalnızca güçlü davranışsal bulgu, Layer 2 web saldırı tespiti veya yüksek Layer 1 güven skoru (`>= 0.80`) varlığında tetikler.
* **Çakışma Korumalı Cooldown & Önbellek İmzası**: `build_mitre_signature()` fonksiyonu kaynak IP'nin yanı sıra `dst_port`, `protocol` ve olasılık kovalamasını (`_bucket`) hesaba katarak aynı kaynaktan gelen farklı saldırı tiplerinin (ör. Fuzzers vs. DoS/Reconnaissance) birbirini ezmesini engeller.

## 👤 Geliştirici

**Egemen Koray Keleş**
* GitHub: [@egemenkhorais](https://github.com/egemenkhorais)
* LinkedIn: [Egemen Koray Keleş](https://www.linkedin.com/in/egemenkeles05)
