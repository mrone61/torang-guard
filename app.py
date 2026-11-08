from flask import Flask, render_template, request, jsonify
import re
from urllib.parse import urlparse
import difflib

app = Flask(__name__)

# ===== TORANG GUARD v2.1 - Campus Edition - Powered by MR ONE =====
# OTAK NYA DISINI, JANGAN DIUBAH KECUALI MAU TAMBAH DOMAIN

LEGIT_DOMAINS = {
    "https://ustj.ac.id": "Universitas Sains dan Teknologi Jayapura (USTJ) - Kampus Kita!",
    "https://siakad.ustj.ac.id": "SIAKAD USTJ - Portal Akademik Resmi USTJ",
    "https://portal.ustj.ac.id": "Portal USTJ",
    "https://pmb.ustj.ac.id": "PMB USTJ - Penerimaan Mahasiswa Baru",
    "https://elearning.ustj.ac.id": "E-Learning USTJ",
    "in8.ustj.ac.id": "IN8 USTJ - Portal Akademik USTJ",
    "https://simak.ustj.ac.id": "SIMAK USTJ",
    "uncen.ac.id": "Universitas Cenderawasih (UNCEN) Jayapura",
    "siakad.uncen.ac.id": "SIAKAD UNCEN",
    "unipa.ac.id": "Universitas Papua (UNIPA) Manokwari",
    "unmus.ac.id": "Universitas Musamus Merauke",
    "unhas.ac.id": "Universitas Hasanuddin Makassar",
    "siakad.unhas.ac.id": "SIAKAD UNHAS",
    "unm.ac.id": "Universitas Negeri Makassar",
    "siakad.unm.ac.id": "SIAKAD UNM",
    "uin-alauddin.ac.id": "UIN Alauddin Makassar",
    "umi.ac.id": "Universitas Muslim Indonesia Makassar",
    "unismuh.ac.id": "Universitas Muhammadiyah Makassar",
    "unibos.ac.id": "Universitas Bosowa Makassar",
    "unima.ac.id": "Universitas Negeri Manado",
    "unsrat.ac.id": "Universitas Sam Ratulangi Manado",
    "untad.ac.id": "Universitas Tadulako Palu",
    "ui.ac.id": "Universitas Indonesia",
    "ugm.ac.id": "UGM Yogyakarta",
    "itb.ac.id": "Institut Teknologi Bandung",
    "its.ac.id": "ITS Surabaya",
    "unair.ac.id": "Universitas Airlangga",
    "undip.ac.id": "Universitas Diponegoro",
    "unpad.ac.id": "Universitas Padjadjaran",
    "ub.ac.id": "Universitas Brawijaya",
    "unand.ac.id": "Universitas Andalas",
    "usu.ac.id": "Universitas Sumatera Utara",
    "unila.ac.id": "Universitas Lampung",
    "unram.ac.id": "Universitas Mataram",
    "unud.ac.id": "Universitas Udayana Bali",
    "unmul.ac.id": "Universitas Mulawarman",
    "unj.ac.id": "Universitas Negeri Jakarta",
    "uny.ac.id": "Universitas Negeri Yogyakarta",
    "unesa.ac.id": "Universitas Negeri Surabaya",
    "unimed.ac.id": "Universitas Negeri Medan",
    "uns.ac.id": "Universitas Sebelas Maret",
    "unsoed.ac.id": "Universitas Jenderal Soedirman",
    "ipb.ac.id": "IPB Bogor",
    "telkomuniversity.ac.id": "Telkom University",
    "binus.ac.id": "BINUS University",
    "gunadarma.ac.id": "Gunadarma",
    "siakad.ac.id": "SIAKAD - Sistem Informasi Akademik",
    "siakad.ugm.ac.id": "SIAKAD UGM",
    "siakad.itb.ac.id": "SIAKAD ITB",
    "siakad.ui.ac.id": "SIAKAD UI",
    "in8.ac.id": "IN8 - Portal Akademik IN8",
    "bri.co.id": "Bank BRI",
    "bca.co.id": "Bank BCA",
    "mandiri.co.id": "Bank Mandiri",
    "bni.co.id": "Bank BNI",
    "dana.id": "DANA",
    "ovo.id": "OVO",
    "gopay.co.id": "GoPay",
    "tvri.go.id": "TVRI",
    "kemdikbud.go.id": "Kemendikbud",
    "polri.go.id": "Polri",
    "papua.go.id": "Pemprov Papua",
    "makassar.go.id": "Pemkot Makassar",
    "shopee.co.id": "Shopee",
    "tokopedia.com": "Tokopedia",
    "instagram.com": "Instagram",
    "facebook.com": "Facebook",
    "whatsapp.com": "WhatsApp",
    "google.com": "Google",
    "youtube.com": "YouTube",
    "tiktok.com": "TikTok",
}

SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.buzz', '.online', '.site', '.fun', '.live', '.cc', '.tk']
SUSPICIOUS_WORDS = ['login', 'verify', 'verifikasi', 'promo', 'hadiah', 'gratis', 'bonus', 'akun', 'suspended', 'blocked', 'update', 'secure', 'confirm', 'beasiswa', 'bantuan', 'klaim', 'undian', 'ukt', 'pembayaran']

def check_url(raw_url):
    url = raw_url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(':')[0].replace("www.", "")
    except:
        domain = url
    score = 0; reasons = []; category = "Tidak Dikenal / Umum"
    if domain.endswith(".ac.id"):
        category = "Kampus Indonesia (.ac.id) - Resmi"
    elif domain.endswith(".go.id"):
        category = "Pemerintah Indonesia (.go.id) - Resmi"
    elif domain.endswith(".sch.id"):
        category = "Sekolah Indonesia (.sch.id)"
    elif domain.endswith(".co.id"):
        category = "Perusahaan Indonesia (.co.id)"
    elif "siakad" in domain:
        category = "Portal Akademik SIAKAD"
    elif "in8" in domain:
        category = "Portal Akademik IN8"
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        score += 40; reasons.append("⛔ Pakai IP Address langsung.")
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 35; reasons.append(f"⛔ Pakai TLD mencurigakan {tld}. Kampus asli tidak pernah pakai ini, selalu .ac.id")
            break
    found_words = [w for w in SUSPICIOUS_WORDS if w in domain]
    if found_words:
        score += 25; reasons.append(f"⚠️ Ada kata penipu: {', '.join(found_words)} - Modus beasiswa palsu / UKT palsu sering pakai kata ini.")
    if domain in LEGIT_DOMAINS:
        reasons.append(f"✅ TERDAFTAR di TORANG GUARD sebagai: {LEGIT_DOMAINS[domain]}")
        score = max(0, score - 10)
        if found_words:
            score += 20
    else:
        parent_found = None
        for legit in LEGIT_DOMAINS:
            if domain.endswith("." + legit):
                parent_found = legit
                break
        if parent_found:
            reasons.append(f"✅ Subdomain resmi dari {parent_found} ({LEGIT_DOMAINS[parent_found]}). Contoh: siakad.ustj.ac.id itu anak dari ustj.ac.id, jadi ASLI.")
            score = max(0, score - 15)
        else:
            best_match = None; best_ratio = 0
            for legit, name in LEGIT_DOMAINS.items():
                ratio = difflib.SequenceMatcher(None, domain, legit).ratio()
                if legit.split('.')[0] in domain and domain != legit and not domain.endswith("."+legit):
                    ratio = max(ratio, 0.85)
                if ratio > best_ratio:
                    best_ratio = ratio; best_match = (legit, name)
            if best_match:
                legit, name = best_match
                if best_ratio > 0.82:
                    score += 55
                    reasons.append(f"⛔ SANGAT MIRIP dengan {name} ({legit}) - Kemiripan {int(best_ratio*100)}%. Ini TYPO SQUATTING! Domain lu: {domain} vs Asli: {legit}")
                elif best_ratio > 0.65:
                    score += 30
                    reasons.append(f"⚠️ Mirip dengan {name} ({legit}) - Kemiripan {int(best_ratio*100)}%. Domain lu: {domain}")
                else:
                    if domain.endswith(".ac.id"):
                        reasons.append(f"✅ Domain .ac.id ini belum ada di database, tapi .ac.id hanya bisa dimiliki kampus resmi di Indonesia (lewat PANDI). Kemungkinan besar ASLI. Nama: {domain}")
                    elif "siakad" in domain and not domain.endswith(".ac.id"):
                        score += 40
                        reasons.append(f"⛔ BAHAYA! Ngaku SIAKAD tapi TIDAK pakai .ac.id. SIAKAD asli selalu .ac.id. Domain lu: {domain}")
                    else:
                        reasons.append(f"ℹ️ Domain {domain} tidak ada di database, tapi tidak mirip domain penting. Polanya aman.")
            if domain.count('.') >= 3 and not parent_found:
                score += 20
                reasons.append(f"⚠️ Subdomain terlalu banyak ({domain}). Aslinya bisa jadi domain lain. Contoh: ustj.ac.id.maling.com -> aslinya maling.com")
    if not url.startswith("https://"):
        score += 10; reasons.append("⚠️ Tidak pakai HTTPS.")
    else:
        reasons.append("✅ Sudah pakai HTTPS.")
    if score >= 70:
        verdict = "SANGAT BERBAHAYA. Jangan diklik, jangan isi NIM / password / bayar UKT lewat link ini."
    elif score >= 40:
        verdict = "MENCURIGAKAN. Jangan isi data pribadi dulu. Cek lewat aplikasi resmi kampus."
    elif score == 0:
        verdict = "Terlihat AMAN dan terdaftar sebagai domain resmi di TORANG GUARD."
    else:
        verdict = "Relatif aman, tapi tetap waspada. Kalau diminta bayar UKT / password, itu penipuan."
    return {"domain": domain, "score": min(score,100), "reasons": reasons, "verdict": verdict, "category": category}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def api_check():
    data = request.get_json()
    return jsonify(check_url(data.get('url','')))

if __name__ == '__main__':
    print("Buka Browser, lalu ketik: http://127.0.0.1:5000")
    print("Powered by MR ONE")
    app.run(host='127.0.0.1', port=5000, debug=True)
