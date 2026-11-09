from flask import Flask, render_template, request, jsonify
import re
from urllib.parse import urlparse 
import difflib
from datetime import datetime

try:
    import requests
except:
    requests = None

try:
    import whois
except:
    whois = None

app = Flask(__name__)

LEGIT_DOMAINS = {
    "ustj.ac.id": "Universitas Sains dan Teknologi Jayapura (USTJ)",
    "siakad.ustj.ac.id": "SIAKAD USTJ - Portal Akademik Resmi USTJ",
    "portal.ustj.ac.id": "Portal USTJ",
    "pmb.ustj.ac.id": "PMB USTJ - Penerimaan Mahasiswa Baru",
    "elearning.ustj.ac.id": "E-Learning USTJ",
    "in8.ustj.ac.id": "IN8 USTJ - Portal Akademik USTJ",
    "uncen.ac.id": "Universitas Cenderawasih (UNCEN) Jayapura",
    "unhas.ac.id": "Universitas Hasanuddin Makassar",
    "unm.ac.id": "Universitas Negeri Makassar",
    "ui.ac.id": "Universitas Indonesia",
    "ugm.ac.id": "UGM Yogyakarta",
    "itb.ac.id": "Institut Teknologi Bandung",
    "unair.ac.id": "Universitas Airlangga",
    "undip.ac.id": "Universitas Diponegoro",
    "ipb.ac.id": "IPB Bogor",
    "telkomuniversity.ac.id": "Telkom University",
    "binus.ac.id": "BINUS University",
    "bri.co.id": "Bank BRI",
    "bca.co.id": "Bank BCA",
    "mandiri.co.id": "Bank Mandiri",
    "bni.co.id": "Bank BNI",
    "dana.id": "DANA",
    "ovo.id": "OVO",
    "gopay.co.id": "GoPay",
    "shopee.co.id": "Shopee",
    "tokopedia.com": "Tokopedia",
    "kemdikbud.go.id": "Kemendikbud",
    "polri.go.id": "Polri",
    "papua.go.id": "Pemprov Papua",
    "makassar.go.id": "Pemkot Makassar",
}
GLOBAL_BRANDS = {
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "google.com": "Google",
    "youtube.com": "YouTube",
    "tiktok.com": "TikTok",
    "whatsapp.com": "WhatsApp",
    "twitter.com": "Twitter / X",
    "x.com": "X (Twitter)",
    "gmail.com": "Gmail",
    "yahoo.com": "Yahoo",
    "amazon.com": "Amazon",
    "netflix.com": "Netflix",
}

ALL_FOR_TYPO = {**LEGIT_DOMAINS, **GLOBAL_BRANDS}

BLOCKED_TLDS = ['.xyz', '.top', '.click', '.buzz', '.tk', '.ml', '.ga', '.cf', '.gq']
SUSPICIOUS_TLDS = ['.online', '.site', '.fun', '.live', '.cc', '.shop', '.store', '.bond', '.sbs', '.icu']
SUSPICIOUS_WORDS = ['login', 'verify', 'verifikasi', 'promo', 'hadiah', 'gratis', 'bonus', 'akun', 'suspended', 'blocked', 'update', 'secure', 'confirm', 'beasiswa', 'bantuan', 'klaim', 'undian', 'ukt', 'pembayaran', 'gift', 'saldo', 'danaid', 'danabonus', 'ovobonus', 'gopaybonus', 'saldo-gratis', 'klaim-saldo', 'cek-saldo', 'reward', 'cashback', 'voucher', 'giveaway', 'menang', 'terpilih']

BRAND_IMPERSONATION = {
    'dana': 'dana.id', 'ovo': 'ovo.id', 'gopay': 'gopay.co.id',
    'bri': 'bri.co.id', 'bca': 'bca.co.id', 'mandiri': 'mandiri.co.id', 'bni': 'bni.co.id',
    'shopee': 'shopee.co.id', 'tokopedia': 'tokopedia.com',
    'ustj': 'ustj.ac.id', 'siakad': 'siakad.ustj.ac.id', 'unhas': 'unhas.ac.id', 'uncen': 'uncen.ac.id',
    'facebook': 'facebook.com', 'instagram': 'instagram.com', 'google': 'google.com', 'tiktok': 'tiktok.com',
}

SENSITIVE_INPUTS_STRICT = {
    'pin': 30, 'p1n': 30, 'pin_atm': 30, 'otp': 30, 'kode_otp': 30, 'kode_verifikasi': 25,
    'cvv': 35, 'cvc': 35, 'kk': 20, 'nik': 20, 'ktp': 15,
}
SENSITIVE_INPUTS_LOOSE = {
    'password': 20, 'passcode': 25, 'kata_sandi': 20, 'kata-sandi': 20, 'sandi': 15,
    'rekening': 20, 'nomor_rekening': 20, 'kartu_kredit': 25, 'kartu_atm': 25,
}

PANIC_WORDS = ['segera', 'hangus', 'diblokir', 'blokir', 'terblokir', 'suspended', 'akun anda akan', 'segera verifikasi', 'batas waktu', 'kedaluwarsa', 'expire', 'urgent', 'sekarang juga']

# ===== LOGIKA FUZZY MAMDANI 2 INPUT =====
def fuzz_rendah(x):
    if x <= 50: return 1.0
    if x >= 70: return 0.0
    return (70 - x) / 20

def fuzz_sedang(x):
    if x <= 60 or x >= 90: return 0.0
    if x <= 75: return (x - 60) / 15
    return (90 - x) / 15

def fuzz_tinggi(x):
    if x <= 80: return 0.0
    if x >= 95: return 1.0
    return (x - 80) / 15

def fuzz_ciri_rendah(x):
    if x <= 20: return 1.0
    if x >= 50: return 0.0
    return (50 - x) / 30

def fuzz_ciri_tinggi(x):
    if x <= 30: return 0.0
    if x >= 70: return 1.0
    return (x - 30) / 40

def fuzzy_typo_score(similarity_persen, ciri_score):
    r = fuzz_rendah(similarity_persen)
    s = fuzz_sedang(similarity_persen)
    t = fuzz_tinggi(similarity_persen)
    c_rendah = fuzz_ciri_rendah(ciri_score)
    c_tinggi = fuzz_ciri_tinggi(ciri_score)
    rule1 = min(t, c_tinggi)
    rule2 = min(t, c_rendah)
    rule3 = min(s, c_tinggi)
    rule4 = min(s, c_rendah)
    rule5 = r
    tinggi_val = max(rule1, rule3)
    sedang_val = max(rule2, rule4)
    pembilang = (rule5 * 10) + (sedang_val * 50) + (tinggi_val * 90)
    penyebut = rule5 + sedang_val + tinggi_val
    if penyebut == 0:
        return 0, "RENDAH", r, s, t, c_rendah, c_tinggi
    hasil = pembilang / penyebut
    if hasil >= 70:
        status = "TINGGI"
    elif hasil >= 40:
        status = "SEDANG"
    else:
        status = "RENDAH"
    return hasil, status, r, s, t, c_rendah, c_tinggi

# ===== CEK UMUR DOMAIN VIA WHOIS =====
def check_domain_age(domain):
    if whois is None:
        return None, 0, ""
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return None, 0, ""
        if isinstance(created, str):
            for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                try:
                    created = datetime.strptime(created.split(".")[0], fmt)
                    break
                except:
                    continue
        umur = (datetime.now() - created).days
        if umur < 0:
            umur = 0
        if umur <= 30:
            return umur, 30, f"⛔ <b>Domain Baru / Umur Sangat Muda</b><br><b>Domain:</b> {domain}<br><b>Umur:</b> {umur} hari (Dibuat: {created.strftime('%d-%m-%Y')})<br><span style='color:#fca5a5'>Domain ini baru dibuat kurang dari 30 hari. 90% situs phishing menggunakan domain baru agar sulit dilacak dan cepat berganti.</span>"
        elif umur <= 90:
            return umur, 15, f"⚠️ <b>Domain Relatif Baru</b><br><b>Domain:</b> {domain}<br><b>Umur:</b> {umur} hari (Dibuat: {created.strftime('%d-%m-%Y')})<br><span style='color:#fde68a'>Domain ini masih relatif baru (kurang dari 90 hari). Tetap waspada jika meminta data sensitif.</span>"
        else:
            return umur, 0, f"✅ <b>Umur Domain Tua / Terpercaya</b><br><b>Domain:</b> {domain}<br><b>Umur:</b> {umur} hari (Dibuat: {created.strftime('%d-%m-%Y')})<br><span style='color:#bbf7d0'>Domain ini sudah berumur lama, cenderung lebih terpercaya.</span>"
    except Exception:
        return None, 0, ""

def check_website_content(url, domain):
    if requests is None:
        return 0, [], {}
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (TORANG-GUARD-Checker/3.1)'}
        resp = requests.get(url, headers=headers, timeout=5, allow_redirects=True, verify=True)
        html = resp.text.lower()
        html_clean = re.sub(r'<script.*?</script>', '', html, flags=re.DOTALL)
        html_clean = re.sub(r'<style.*?</style>', '', html_clean, flags=re.DOTALL)
    except requests.exceptions.SSLError:
        return 20, ["⛔ <b>Sertifikat SSL Tidak Valid / Palsu</b><br><span style='color:#fca5a5'>Sertifikat keamanan situs ini tidak valid. Situs resmi selalu memiliki sertifikat SSL yang valid. Ini indikasi kuat situs penipuan.</span>"], {}
    except Exception as e:
        return 0, ["ℹ️ <b>Isi Website Tidak Dapat Diakses</b><br><span style='color:#cbd5e1'>Situs tidak dapat dibuka untuk pemeriksaan isi. Kemungkinan situs sudah tidak aktif atau diblokir. Penilaian hanya berdasarkan nama domain.</span>"], {}
    score_add = 0
    reasons_add = []
    found_inputs = {}
    inputs = re.findall(r'<input[^>]+>', html_clean)
    inputs_text = " ".join(inputs)
    for keyword, poin in SENSITIVE_INPUTS_STRICT.items():
        if re.search(r'\b' + re.escape(keyword) + r'\b', inputs_text):
            found_inputs[keyword] = poin
    text_only = re.sub(r'<[^>]+>', ' ', html_clean)
    for keyword, poin in SENSITIVE_INPUTS_LOOSE.items():
        if re.search(r'\b' + re.escape(keyword) + r'\b', inputs_text):
            found_inputs[keyword] = poin
        elif re.search(r'\b' + re.escape(keyword) + r'\b', text_only):
            found_inputs[keyword + "_teks"] = poin // 2
    panic_found = [w for w in PANIC_WORDS if w in text_only]
    if panic_found:
        score_add += 15
        reasons_add.append(f"⚠️ <b>Penggunaan Bahasa Mendesak Terdeteksi</b><br><b>Kata yang ditemukan:</b> {', '.join(panic_found[:3])}<br><span style='color:#fde68a'>Situs menggunakan kata yang menimbulkan rasa panik atau urgensi. Situs resmi tidak menggunakan bahasa yang menekan pengguna untuk segera bertindak.</span>")
    if found_inputs:
        total_input_score = sum(found_inputs.values())
        total_input_score = min(total_input_score, 60)
        score_add += total_input_score
        input_names = []
        for k in found_inputs.keys():
            clean = k.replace("_teks", "").replace("_", " ").upper()
            if clean not in input_names:
                input_names.append(clean)
        reasons_add.append(f"🔍 <b>Hasil Pemeriksaan Isi Website</b><br><b>Data yang diminta:</b> {', '.join(input_names)}<br><span style='color:#fca5a5'>Situs ini meminta data sensitif melalui formulir. Data tersebut sering disalahgunakan untuk pengambilalihan akun atau pencurian dana.</span>")
        has_pin = any('pin' in k or 'p1n' in k for k in found_inputs.keys())
        has_otp = any('otp' in k or 'kode_verifikasi' in k for k in found_inputs.keys())
        if has_pin and has_otp:
            score_add += 20
            reasons_add.append("⛔ <b>Permintaan PIN + OTP Secara Bersamaan</b><br><span style='color:#fca5a5'>Situs ini meminta PIN dan kode OTP pada halaman yang sama. Bank, dompet digital, maupun marketplace resmi tidak pernah meminta PIN dan OTP secara bersamaan. Permintaan ini mengindikasikan upaya pencurian akun.</span>")
        has_cvv = any('cvv' in k or 'cvc' in k for k in found_inputs.keys())
        if has_cvv:
            score_add += 20
            reasons_add.append("⛔ <b>Permintaan CVV / CVC Kartu</b><br><span style='color:#fca5a5'>Situs ini meminta CVV / CVC, yaitu 3 digit di belakang kartu. Kode ini bersifat sangat rahasia. Situs resmi tidak pernah meminta CVV melalui tautan WhatsApp / SMS.</span>")
    else:
        reasons_add.append("✅ <b>Hasil Pemeriksaan Isi Website</b><br><span style='color:#cbd5e1'>Tidak ditemukan formulir yang meminta PIN, OTP, kata sandi, atau data rekening. Situs ini kemungkinan hanya berisi informasi / berita.</span>")
    return score_add, reasons_add, found_inputs

def check_url(raw_url, deep_check=True):
    url = raw_url.strip()
    if not url:
        return {"domain": "", "score": 0, "reasons": ["Tautan masih kosong. Silakan masukkan tautan yang akan diperiksa."], "verdict": "Tautan kosong. Silakan masukkan tautan yang akan diperiksa.", "category": "Kosong"}
    if not url.startswith("http"):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(':')[0].replace("www.", "")
    except:
        domain = url
    score = 0; reasons = []; category = "Tidak Dikenal / Umum"
    ciri_score = 0
    is_campus = domain.endswith(".ac.id") or "siakad" in domain or "in8" in domain
    is_legit_domain = domain in LEGIT_DOMAINS or domain in GLOBAL_BRANDS
    if domain in GLOBAL_BRANDS:
        category = f"Media Sosial / Global - {GLOBAL_BRANDS[domain]}"
    elif domain.endswith(".ac.id"):
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
    tld_blocked = False
    for tld in BLOCKED_TLDS:
        if domain.endswith(tld):
            score += 50; ciri_score += 50
            reasons.append(f"⛔ <b>Ekstensi Domain Berisiko Tinggi</b><br><b>Ekstensi:</b> {tld}<br><b>Domain yang dicek:</b> {domain}<br><span style='color:#fca5a5'>Ekstensi ini jarang digunakan oleh situs resmi Indonesia dan sering disalahgunakan untuk penipuan karena biaya pendaftaran yang rendah dan proses pembuatan yang mudah.</span>")
            tld_blocked = True
            break
    if not tld_blocked:
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 30; ciri_score += 30
                reasons.append(f"⚠️ <b>Ekstensi Domain Perlu Diwaspadai</b><br><b>Ekstensi:</b> {tld}<br><b>Domain yang dicek:</b> {domain}<br><span style='color:#fde68a'>Ekstensi ini cukup sering digunakan untuk situs penipuan. Situs resmi umumnya menggunakan .id, .co.id, .com, .ac.id, atau .go.id.</span>")
                break
    brand_found = None
    for brand, legit_domain in BRAND_IMPERSONATION.items():
        if brand in domain:
            is_legit = False
            if domain == legit_domain or domain.endswith("." + legit_domain):
                is_legit = True
            if domain in LEGIT_DOMAINS or domain in GLOBAL_BRANDS:
                is_legit = True
            else:
                for legit in list(LEGIT_DOMAINS.keys()) + list(GLOBAL_BRANDS.keys()):
                    if domain.endswith("." + legit) and brand in legit:
                        is_legit = True
                        break
            if not is_legit:
                brand_found = (brand, legit_domain)
                break
    if brand_found:
        brand, legit_domain = brand_found
        score += 60; ciri_score += 60
        reasons.append(f"⛔ <b>Penyamaran Brand Terdeteksi</b><br><b>Domain yang dicek:</b> {domain}<br><b>Mengatasnamakan:</b> {brand.upper()}<br><b>Domain resmi {brand.upper()}:</b> {legit_domain}<br><span style='color:#fca5a5'>Domain ini mengatasnamakan {brand.upper()} tetapi bukan domain resmi. Modus ini umumnya digunakan untuk meminta PIN, OTP, kata sandi, atau mengarahkan korban untuk melakukan transfer.</span>")
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        score += 40; ciri_score += 40
        reasons.append(f"⛔ <b>Menggunakan Alamat IP Langsung</b><br><b>Domain yang dicek:</b> {domain}<br><span style='color:#fca5a5'>Situs menggunakan alamat IP, bukan nama domain. Situs resmi tidak menggunakan cara ini.</span>")
    found_words = [w for w in SUSPICIOUS_WORDS if w in domain]
    if found_words:
        score += 25; ciri_score += 25
        reasons.append(f"⚠️ <b>Kata Kunci Penipuan Terdeteksi</b><br><b>Kata yang ditemukan:</b> {', '.join(found_words)}<br><b>Domain yang dicek:</b> {domain}<br><span style='color:#fde68a'>Kata tersebut sering digunakan pada modus hadiah palsu, saldo gratis, atau pemberitahuan akun diblokir untuk mendorong pengguna segera mengklik.</span>")
    ciri_score = min(ciri_score, 100)
    if is_legit_domain:
        nama_asli = LEGIT_DOMAINS.get(domain) or GLOBAL_BRANDS.get(domain)
        reasons.append(f"✅ <b>Terdaftar di TORANG GUARD</b><br><b>Domain:</b> {domain}<br><b>Identitas:</b> {nama_asli}<br><span style='color:#bbf7d0'>Domain ini tercatat sebagai domain resmi.</span>")
        score = max(0, score - 10)
        if found_words:
            score += 20
    else:
        parent_found = None
        for legit in list(LEGIT_DOMAINS.keys()) + list(GLOBAL_BRANDS.keys()):
            if domain.endswith("." + legit):
                parent_found = legit
                break
        if parent_found:
            nama_parent = LEGIT_DOMAINS.get(parent_found) or GLOBAL_BRANDS.get(parent_found)
            reasons.append(f"✅ <b>Subdomain Resmi</b><br><b>Domain yang dicek:</b> {domain}<br><b>Induk resmi:</b> {parent_found} ({nama_parent})<br><span style='color:#bbf7d0'>Domain ini merupakan subdomain dari domain resmi.</span>")
            score = max(0, score - 15)
        else:
            best_match = None; best_ratio = 0
            for legit, name in ALL_FOR_TYPO.items():
                ratio = difflib.SequenceMatcher(None, domain, legit).ratio()
                if ratio > best_ratio:
                    best_ratio = ratio; best_match = (legit, name)
            if best_match:
                legit, name = best_match
                sim_persen = int(best_ratio * 100)
                fuzzy_skor, fuzzy_status, fr, fs, ft, cr, ct = fuzzy_typo_score(sim_persen, ciri_score)
                if fuzzy_status == "TINGGI":
                    score += 70
                    reasons.append(f"⛔<b>TYPO SQUATTING TERDETEKSI [FUZZY 2 INPUT: TINGGI]</b><br><b>Domain yang dicek:</b> {domain}<br><b>Domain resmi:</b> {legit} ({name})<br><b>Tingkat kemiripan:</b> {sim_persen}%<br><b>Skor Ciri Bahaya:</b> {ciri_score}<br><b>Derajat Fuzzy - Rendah:</b> {fr:.2f}, <b>Sedang:</b> {fs:.2f}, <b>Tinggi:</b> {ft:.2f}<br><b>Ciri Rendah:</b> {cr:.2f}, <b>Ciri Tinggi:</b> {ct:.2f}<br><b>Skor Defuzzifikasi:</b> {fuzzy_skor:.1f}<br><span style='color:#fca5a5'>Berdasarkan inferensi Fuzzy Mamdani 2 input, domain ini masuk kategori bahaya TINGGI.</span>")
                elif fuzzy_status == "SEDANG":
                    score += 30
                    reasons.append(f"⚠️<b>Kemiripan Domain Terdeteksi [FUZZY 2 INPUT: SEDANG]</b><br><b>Domain yang dicek:</b> {domain}<br><b>Domain resmi:</b> {legit} ({name})<br><b>Tingkat kemiripan:</b> {sim_persen}%<br><b>Skor Ciri Bahaya:</b> {ciri_score}<br><b>Derajat Fuzzy - Rendah:</b> {fr:.2f}, <b>Sedang:</b> {fs:.2f}, <b>Tinggi:</b> {ft:.2f}<br><b>Skor Defuzzifikasi:</b> {fuzzy_skor:.1f}<br><span style='color:#fde68a'>Domain ini memiliki kemiripan sedang dengan domain resmi berdasarkan Logika Fuzzy 2 input.</span>")
                else:
                    if domain.endswith(".ac.id"):
                        reasons.append(f"✅ <b>Domain Kampus (.ac.id) [FUZZY: RENDAH]</b><br><b>Domain yang dicek:</b> {domain}<br><b>Kemiripan tertinggi:</b> {sim_persen}% dengan {legit}<br><span style='color:#bbf7d0'>Ekstensi .ac.id hanya dapat dimiliki oleh perguruan tinggi resmi di Indonesia melalui PANDI. Kemungkinan besar domain ini asli.</span>")
                    elif "siakad" in domain and not domain.endswith(".ac.id"):
                        score += 40
                        reasons.append(f"⛔ <b>Portal Akademik Tidak Resmi</b><br><b>Domain yang dicek:</b> {domain}<br><span style='color:#fca5a5'>Domain mengatasnamakan SIAKAD tetapi tidak menggunakan ekstensi .ac.id. Portal akademik resmi selalu menggunakan .ac.id.</span>")
                    else:
                        reasons.append(f"ℹ️ <b>Domain Belum Terdaftar [FUZZY: RENDAH]</b><br><b>Domain yang dicek:</b> {domain}<br><b>Kemiripan tertinggi:</b> {sim_persen}% dengan {legit}<br><span style='color:#cbd5e1'>Domain ini belum tercatat di database TORANG GUARD dan tidak memiliki kemiripan signifikan dengan domain resmi. Tetap berhati-hati jika situs meminta kata sandi, PIN, kode OTP, atau data rekening.</span>")
            if domain.count('.') >= 3 and not parent_found:
                score += 20
                reasons.append(f"⚠️ <b>Struktur Subdomain Berlapis</b><br><b>Domain yang dicek:</b> {domain}<br><span style='color:#fde68a'>Domain memiliki terlalu banyak subdomain. Domain asli dapat dilihat dari bagian paling belakang. Contoh: ustj.ac.id.maling.com - domain aslinya adalah maling.com, bukan ustj.ac.id.</span>")
    # CEK WHOIS - Hanya untuk domain tidak resmi, biar tidak lambat
    if not is_legit_domain:
        umur_domain, whois_skor, whois_pesan = check_domain_age(domain)
        if whois_skor > 0:
            score += whois_skor
            ciri_score = min(100, ciri_score + whois_skor)
            reasons.append(whois_pesan)
        elif whois_pesan:
            reasons.append(whois_pesan)
    if not url.startswith("https://"):
        score += 10; reasons.append("⚠️ <b>Tidak Menggunakan HTTPS</b><br><span style='color:#fde68a'>Situs tidak menggunakan HTTPS. Situs resmi umumnya sudah menggunakan HTTPS (ditandai ikon gembok).</span>")
    else:
        reasons.append("✅ <b>Koneksi Menggunakan HTTPS</b><br><span style='color:#bbf7d0'>Situs sudah menggunakan HTTPS.</span>")
    if deep_check and not is_legit_domain and score < 70:
        c_score, c_reasons, c_inputs = check_website_content(url, domain)
        score += c_score
        reasons.extend(c_reasons)
    elif is_legit_domain:
        reasons.append("ℹ️ <b>Domain Resmi Terverifikasi</b><br><span style='color:#cbd5e1'>Domain ini sudah terdaftar sebagai domain resmi, sehingga pemeriksaan isi website tidak diperlukan. Formulir login pada domain ini merupakan hal yang wajar.</span>")
    score = min(score, 100)
    if score >= 70:
        if is_campus:
            verdict = "SANGAT BERBAHAYA. Jangan akses tautan ini. Jangan masukkan NIM, kata sandi, PIN, atau kode OTP. Jika sudah terlanjur mengisi, segera ganti kata sandi dan hubungi pihak kampus / bank / aplikasi resmi."
        else:
            verdict = "SANGAT BERBAHAYA. Jangan akses tautan ini. Jangan masukkan kata sandi, PIN, kode OTP, atau data rekening / kartu ATM. Jika sudah terlanjur mengisi, segera ganti kata sandi dan hubungi bank / aplikasi resmi."
    elif score >= 40:
        verdict = "MENCURIGAKAN. Jangan masukkan data pribadi. Verifikasi melalui aplikasi resmi secara langsung (buka aplikasi DANA / BRI / Shopee tanpa melalui tautan ini), atau hubungi layanan pelanggan resmi."
    elif score == 0:
        verdict = "Terlihat AMAN dan terdaftar sebagai domain resmi di TORANG GUARD."
    else:
        verdict = "Relatif aman, tetapi tetap waspada. TORANG GUARD belum mengenal domain ini. Jika situs meminta kata sandi, PIN, kode OTP, atau meminta transfer, hentikan dan tutup situs tersebut."
    return {"domain": domain, "score": score, "reasons": reasons, "verdict": verdict, "category": category}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def api_check():
    data = request.get_json() or {}
    url = data.get('url','')
    deep = data.get('deep_check', True)
    return jsonify(check_url(url, deep_check=deep))

if __name__ == '__main__':
    print("Buka Browser, lalu ketik: http://127.0.0.1:5000")
    print("Powered by MR ONE")
    app.run(host='127.0.0.1', port=5000, debug=True)
