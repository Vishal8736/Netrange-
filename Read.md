# 🚀 Netrange Ultra Pro v2.0
**Advanced Network Surface Extractor & Multi-Format Reporter**

Developed with ❤️ by **Vishal & Subhi**.

Netrange Ultra Pro ek powerful cross-platform tool hai jo raw domains ya IP lists ko analyze karta hai, unhe clean CIDR ranges mein collapse karta hai, aur professional-grade reports (HTML, PDF, CSV, JSON) generate karta hai.

---

## ✨ Key Features
- **Parallel Resolution:** DNS resolving ko fast karne ke liye multi-threading support.
- **Auto-CIDR:** Scattered IPs ko automatically valid network ranges mein convert karta hai.
- **Multi-Format Export:** - 📄 **HTML:** Modern, interactive dashboard style report.
  - 📑 **PDF:** Client-ready professional documents.
  - 📊 **CSV:** Excel mein sorting aur filtering ke liye.
  - 📦 **JSON:** Doosre tools ke saath integrate karne ke liye.
- **Branding:** Built-in "Vishal ❤️ Subhi" signature branding in all reports.
- **Cross-Platform:** Linux, macOS, aur WSL (Windows) par smoothly chalta hai.

---

## 🛠️ Installation & Dependencies
Script ko use karne ke liye aapke system mein niche diye gaye tools hone chahiye:

```bash
# Update and install basic tools
sudo apt update && sudo apt install python3 whois pandoc -y

chmod +x netrange.sh

./netrange.sh targets.txt

