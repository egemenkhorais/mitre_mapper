# MITRE Mapper

MITRE Mapper is a cybersecurity automation tool that continuously monitors network traffic, classifies potential attacks in real-time using a custom-trained machine learning dataset, and maps these findings directly to the MITRE ATT&CK framework.

## The Vision: Towards a Fully Autonomous Agentic System

While MITRE Mapper currently acts as an intelligent real-time classifier, **the ultimate goal of this project is to integrate with NVIDIA Morpheus to build a fully autonomous, agentic action system.** 

By leveraging Morpheus's AI pipeline, MITRE Mapper will evolve from just a "classifier" into an "agentic operator"—not only detecting and classifying network anomalies in real-time but also taking autonomous, intelligent mitigation actions against identified threats.

## Our Journey: How It Started vs. How It's Going

The project was born out of the need to automate network threat detection and contextualization.

### How It Started (v0.1)
Initially, the project was a simple, manual analysis tool:
* It relied on post-incident reading of static network logs (like PCAPs).
* It used static, rule-based signature matching.
* Required manual triggering for every analysis without any automation.
* MITRE ATT&CK mapping was basic and limited.

### What It Does Now (Current Version)
Today, MITRE Mapper operates as a fully automated, real-time classification engine:
* **Real-Time Traffic Classification:** Listens to live network flows and classifies attacks in real-time using a specially trained dataset.
* **Automated Continuous Monitoring:** Operates as a background automation process, requiring no human intervention to monitor traffic.
* **Instant Threat Identification:** The moment an anomaly is captured in the network flow, the model classifies the type of attack.
* **Dynamic MITRE ATT&CK Mapping:** Automatically correlates the classified attacks with the corresponding MITRE tactics and techniques.

## Features
* **Network Flow Analysis:** Reads live traffic directly from the network interface or flow protocols.
* **Machine Learning-Based Classification:** High accuracy inference against complex threats using a custom-trained dataset.
* **Automated Alerting:** Logs and alerts immediately upon threat classification.

## Roadmap
- [ ] **NVIDIA Morpheus Integration:** Porting the ML pipeline to NVIDIA Morpheus for massive scale and speed.
- [ ] **Agentic Action System:** Developing autonomous agents capable of executing defensive actions based on the classified threats.
- [ ] Real-time web dashboard for live monitoring of network flow and classified attacks.

---

<br>

# MITRE Mapper (Türkçe)

MITRE Mapper, ağ trafiğini sürekli olarak izleyen, özel olarak eğitilmiş bir veri seti kullanarak potansiyel saldırıları gerçek zamanlı olarak sınıflandıran (classify) ve bu bulguları MITRE ATT&CK framework'ü ile eşleştiren bir siber güvenlik otomasyon aracıdır.

## Vizyonumuz: Tam Otonom "Agentic" Sisteme Doğru

MITRE Mapper şu an akıllı ve gerçek zamanlı bir sınıflandırıcı (classifier) olarak çalışsa da, **bu projenin nihai hedefi NVIDIA Morpheus ile entegre olarak tam otonom bir "agentic" (ajan tabanlı) aksiyon sistemi kurmaktır.**

Morpheus'un yapay zeka boru hattından (pipeline) güç alarak MITRE Mapper'ın sadece tehditleri sınıflandıran bir araç olmaktan çıkıp, tespit edilen tehditlere karşı otonom ve akıllı savunma aksiyonları alabilen "operatör bir ajana" dönüşmesi planlanmaktadır.

## Hikayemiz: İlk Başta Neydi, Şu An Ne Yapabiliyor?

Proje, ağ üzerindeki tehdit tespitini otomatize etme ve anlamlandırma ihtiyacından doğdu.

### İlk Başta Neydi? (v0.1)
Başlangıçta proje daha manuel süreçlere dayanan basit bir yapıdaydı:
* Sadece statik ağ loglarını (PCAP vb.) sonradan okuyup analiz edebiliyordu.
* Kural tabanlı (rule-based) ve statik imzalara dayalı eşleştirme yapıyordu.
* Otomasyon yeteneği yoktu, her analiz için manuel tetikleme gerekiyordu.
* MITRE ATT&CK eşleştirmeleri kısıtlı ve temel seviyedeydi.

### Şu An Ne Yapabiliyor? (Güncel Sürüm)
Bugün MITRE Mapper, tam otomatik çalışan gerçek zamanlı bir sınıflandırma motorudur:
* **Gerçek Zamanlı Trafik Sınıflandırması:** Canlı ağ akışını (network flow) dinler ve eğitilmiş veri setini kullanarak ağdaki saldırıları anında sınıflandırır.
* **Otomatik ve Sürekli İzleme:** İnsan müdahalesi gerektirmeden, arka planda çalışan bir otomasyon olarak ağ trafiğini sürekli izler.
* **Anında Tehdit Tespiti:** Trafik akışındaki anormallikleri yakaladığı an bunun ne tür bir saldırı olduğunu model üzerinden belirler.
* **Dinamik MITRE ATT&CK Eşleştirmesi:** Sınıflandırılan saldırıları anında analiz ederek ilgili MITRE taktik ve teknikleriyle haritalandırır.

## Temel Özellikler
* **Network Flow Analizi:** Doğrudan ağ arayüzü üzerinden canlı trafik okuma.
* **Makine Öğrenmesi Tabanlı Sınıflandırma:** Eğitilmiş veri seti kullanılarak tehditlerin yüksek doğrulukla sınıflandırılması.
* **Otomasyon:** Tehdit sınıflandırıldığında otomatik loglama ve uyarı mekanizmaları.

## Gelecek Planları (Roadmap)
- [ ] **NVIDIA Morpheus Entegrasyonu:** Makine öğrenmesi süreçlerinin çok daha yüksek hız ve ölçek için Morpheus'a taşınması.
- [ ] **Agentic Aksiyon Sistemi:** Sınıflandırılan tehditlere göre kendi kendine savunma kararları alıp uygulayabilen otonom ajanların (agents) geliştirilmesi.
- [ ] Gerçek zamanlı ağ akışını ve tespit edilen saldırıları izlemek için canlı web dashboard.

*Geliştirici:* [@egemenkhorais](https://github.com/egemenkhorais)