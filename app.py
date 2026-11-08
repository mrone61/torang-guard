from flask import Flask, render_template, request, jsonify
import re
from urllib.parse import urlparse 
import difflib

try:
    import requests
except:
    requests = None

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

# Gabungan buat cek typo: LEGIT + GLOBAL
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

# FIX 2: Daftar input sensitif - Sekarang dibedain mana yang bahaya kalau di teks, mana yang harus di input
# Kata pendek (pin, otp, kk, cvv) -> HARUS ada di <input> beneran, gak boleh cuma di teks
SENSITIVE_INPUTS_STRICT = {
    'pin': 30, 'otp': 30, 'cvv': 35, 'cvc': 35, 'kk': 20, 'nik': 20, 'ktp': 15,
}
# Kata panjang (password, rekening) -> Boleh di teks, karena jarang muncul kebetulan
SENSITIVE_INPUTS_LOOSE = {
    'password': 20, 'passcode': 25, 'rekening': 20, 'nomor_rekening': 20, 'kartu_kredit': 25, 'kartu_atm': 25,
}

PANIC_WORDS = ['segera', 'hangus', 'diblokir', 'blokir', 'terblokir', 'suspended', 'akun anda akan', 'segera verifikasi', 'batas waktu', 'kedaluwarsa', 'expire', 'urgent', 'sekarang juga']

def check_website_content(url, domain):
    if requests is None:
        return 0, [], {}
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (TORANG-GUARD-Checker/3.1)'}
        resp = requests.get(url, headers=headers, timeout=5, allow_redirects=True, verify=False)
        html = resp.text.lower()
        html_clean = re.sub(r'<script.*?</script>', '', html, flags=re.DOTALL)
        html_clean = re.sub(r'<style.*?</style>', '', html_clean, flags=re.DOTALL)
    except Exception as e:
        return 0, ["ℹ️ Website-nya tidak bisa dibuka untuk dicek isinya (mungkin sudah mati / diblokir). TORANG GUARD hanya cek dari nama domainnya saja."], {}
    score_add = 0
    reasons_add = []
    found_inputs = {}
    # 1. Cari di <input> BENERAN - Ini yang paling akurat
    inputs = re.findall(r'<input[^>]+>', html_clean)
    inputs_text = " ".join(inputs)
    # FIX: Untuk kata pendek, HARUS ada di input, pake word boundary biar gak kena 'cookie' / 'click'
    for keyword, poin in SENSITIVE_INPUTS_STRICT.items():
        # Cari dengan batas kata: name="pin", id="otp", placeholder="Masukkan PIN", dll
        # Pakai regex \b biar 'kk' di 'cookie' gak kehitung, 'pin' di 'shipping' gak kehitung
        if re.search(r'\b' + re.escape(keyword) + r'\b', inputs_text):
            found_inputs[keyword] = poin
    # 2. Untuk kata panjang, boleh cari di teks juga, tapi juga pake \b
    text_only = re.sub(r'<[^>]+>', ' ', html_clean)
    for keyword, poin in SENSITIVE_INPUTS_LOOSE.items():
        # Cek di input dulu
        if re.search(r'\b' + re.escape(keyword) + r'\b', inputs_text):
            found_inputs[keyword] = poin
        # Kalau gak ada di input, tapi ada di teks "Masukkan Password Anda" -> hitung setengah
        elif re.search(r'\b' + re.escape(keyword) + r'\b', text_only):
            found_inputs[keyword + "_teks"] = poin // 2
    panic_found = [w for w in PANIC_WORDS if w in text_only]
    if panic_found:
        score_add += 15
        reasons_add.append(f"⚠️ Website-nya pakai kata yang bikin panik: {', '.join(panic_found[:3])} - Penipu suka bikin orang panik biar langsung klik / isi tanpa mikir. Website resmi tidak pernah nakut-nakutin kayak gini.")
    if found_inputs:
        total_input_score = sum(found_inputs.values())
        total_input_score = min(total_input_score, 60)
        score_add += total_input_score
        input_names = []
        for k in found_inputs.keys():
            clean = k.replace("_teks", "").replace("_", " ").upper()
            if clean not in input_names:
                input_names.append(clean)
        reasons_add.append(f"🔍 HASIL CEK ISI WEBSITE: Website ini minta data sensitif: {', '.join(input_names)}. Hati-hati, ini yang sering dipakai penipu untuk maling akun / duit kamu.")
        has_pin = any('pin' in k for k in found_inputs.keys())
        has_otp = any('otp' in k for k in found_inputs.keys())
        if has_pin and has_otp:
            score_add += 20
            reasons_add.append("⛔ BAHAYA TINGKAT TERTINGGI! Website ini minta PIN + OTP SEKALIGUS! Tidak ada Bank / DANA / OVO / Shopee asli yang minta PIN + OTP di halaman yang sama. Ini sudah pasti PENIPU!")
        has_cvv = any('cvv' in k or 'cvc' in k for k in found_inputs.keys())
        if has_cvv:
            score_add += 20
            reasons_add.append("⛔ Website ini minta CVV / CVC Kartu ATM! CVV itu 3 angka di belakang kartu, sangat rahasia. Tidak ada website resmi yang minta CVV lewat link WA / SMS. Ini PENIPU!")
    else:
        reasons_add.append("✅ HASIL CEK ISI WEBSITE: Website ini TIDAK minta PIN / OTP / Password / Data Rekening di form-nya. Kemungkinan website ini hanya untuk dibaca / berita / informasi saja, jadi lebih aman.")
    return score_add, reasons_add, found_inputs

def check_url(raw_url, deep_check=True):
    url = raw_url.strip()
    if not url:
        return {"domain": "", "score": 0, "reasons": ["Linknya kosong bro, paste link dulu ya."], "verdict": "Link kosong. Paste link yang mau dicek dulu.", "category": "Kosong"}
    if not url.startswith("http"):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(':')[0].replace("www.", "")
    except:
        domain = url
    score = 0; reasons = []; category = "Tidak Dikenal / Umum"
    is_campus = domain.endswith(".ac.id") or "siakad" in domain or "in8" in domain
    is_legit_domain = domain in LEGIT_DOMAINS or domain in GLOBAL_BRANDS
    # Kalau domainnya facebook.com yang asli, kategori-nya jadi Media Sosial, bukan Tidak Dikenal
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
            score += 50
            reasons.append(f"⛔ Pakai akhiran domain {tld} yang 99% dipakai penipu. Website resmi Indonesia hampir tidak pernah pakai {tld}. Penipu suka pakai ini karena murah (cuma 10rb-an) dan gampang dibikin.")
            tld_blocked = True
            break
    if not tld_blocked:
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 30
                reasons.append(f"⚠️ Pakai akhiran domain {tld} yang sering dipakai penipu. Hati-hati, website resmi biasanya pakai .id, .co.id, .com, atau .go.id.")
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
        score += 60
        reasons.append(f"⛔ NGAKU-NGAKU {brand.upper()}! Domain ini: {domain} ngaku {brand.upper()} tapi domain aslinya cuma {legit_domain}. Ini MODUS PENIPUAN! Biasanya minta PIN, OTP, Password, atau suruh transfer.")
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        score += 40; reasons.append("⛔ Pakai IP Address langsung, bukan nama domain asli. Website resmi tidak pernah pakai cara ini.")
    found_words = [w for w in SUSPICIOUS_WORDS if w in domain]
    if found_words:
        score += 25
        reasons.append(f"⚠️ Ada kata yang sering dipakai penipu di namanya: {', '.join(found_words)} - Modus hadiah palsu / saldo gratis / akun diblokir sering pakai kata ini untuk bikin orang panik dan langsung klik.")
    if is_legit_domain:
        # Cari nama asli-nya di mana
        nama_asli = LEGIT_DOMAINS.get(domain) or GLOBAL_BRANDS.get(domain)
        reasons.append(f"✅ TERDAFTAR di TORANG GUARD sebagai: {nama_asli}")
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
            reasons.append(f"✅ Subdomain resmi dari {parent_found} ({nama_parent}).")
            score = max(0, score - 15)
        else:
            # FIX UTAMA: Cek typo pake ALL_FOR_TYPO (LEGIT + GLOBAL), bukan cuma LEGIT doang
            best_match = None; best_ratio = 0
            for legit, name in ALL_FOR_TYPO.items():
                ratio = difflib.SequenceMatcher(None, domain, legit).ratio()
                # Kalau domainnya mengandung nama brand-nya, tapi bukan domain aslinya, langsung anggap mirip banget
                # Contoh: faceboook.com mengandung 'faceboo' -> mirip facebook.com
                if legit.split('.')[0] in domain and domain != legit and not domain.endswith("."+legit):
                    ratio = max(ratio, 0.90)
                # Khusus buat typo 1-2 huruf: faceboook vs facebook, gogle vs google
                # SequenceMatcher udah tinggi, tapi kita pastiin lagi pake edit distance kasar
                if ratio > best_ratio:
                    best_ratio = ratio; best_match = (legit, name)
            if best_match:
                legit, name = best_match
                if best_ratio > 0.82:
                    # FIX: Naikin dari 55 jadi 70, biar langsung MERAH, gak bisa lagi jadi AMAN
                    score += 70
                    reasons.append(f"⛔ SANGAT MIRIP dengan {name} ({legit}) - Kemiripan {int(best_ratio*100)}%. Ini TYPO SQUATTING! Domain kamu: {domain} vs Asli: {legit}. Bedanya tipis, cuma 1 huruf, tapi itu yang bikin orang ketipu. Ini cara penipu yang paling sering dipakai!")
                elif best_ratio > 0.65:
                    score += 30
                    reasons.append(f"⚠️ Mirip dengan {name} ({legit}) - Kemiripan {int(best_ratio*100)}%. Domain kamu: {domain}")
                else:
                    if domain.endswith(".ac.id"):
                        reasons.append(f"✅ Domain .ac.id ini belum ada di database, tapi .ac.id hanya bisa dimiliki kampus resmi di Indonesia (lewat PANDI). Kemungkinan besar ASLI.")
                    elif "siakad" in domain and not domain.endswith(".ac.id"):
                        score += 40
                        reasons.append(f"⛔ BAHAYA! Ngaku SIAKAD tapi TIDAK pakai .ac.id. Portal akademik asli selalu .ac.id. Domain kamu: {domain}")
                    else:
                        reasons.append(f"ℹ️ Domain {domain} tidak ada di database TORANG GUARD. Tapi dari namanya, tidak mirip dengan domain penipu yang terkenal. Tetap hati-hati ya, jangan asal isi Password, PIN, Kode OTP, atau data rekening kalau diminta di website ini.")
            if domain.count('.') >= 3 and not parent_found:
                score += 20
                reasons.append(f"⚠️ Subdomain terlalu banyak ({domain}). Hati-hati, domain aslinya bisa jadi yang paling belakang. Contoh: ustj.ac.id.maling.com -> aslinya maling.com, bukan ustj.ac.id")
    if not url.startswith("https://"):
        score += 10; reasons.append("⚠️ Tidak pakai HTTPS. Website resmi biasanya sudah pakai HTTPS (ada gemboknya).")
    else:
        reasons.append("✅ Sudah pakai HTTPS.")
    if deep_check and not is_legit_domain and score < 70:
        c_score, c_reasons, c_inputs = check_website_content(url, domain)
        score += c_score
        reasons.extend(c_reasons)
    elif is_legit_domain:
        reasons.append("ℹ️ Ini domain resmi yang sudah terdaftar, jadi TORANG GUARD tidak perlu buka isi website-nya lagi. Form login di sini wajar, karena memang tempatnya login.")
    score = min(score, 100)
    if score >= 70:
        if is_campus:
            verdict = "SANGAT BERBAHAYA. Jangan diklik. Jangan isi NIM / Password / PIN / Kode OTP di link ini. Kalau sudah terlanjur isi, langsung ganti password dan hubungi kampus / bank / aplikasi resminya."
        else:
            verdict = "SANGAT BERBAHAYA. Jangan diklik. Jangan isi Password, PIN, Kode OTP, atau data rekening / kartu ATM di link ini. Kalau sudah terlanjur isi, langsung ganti password dan hubungi bank / aplikasi resminya."
    elif score >= 40:
        verdict = "MENCURIGAKAN. Jangan isi data pribadi dulu. Cek lewat aplikasi resminya langsung (buka aplikasi DANA / BRI / Shopee-nya, jangan lewat link ini), atau tanya ke CS resminya."
    elif score == 0:
        verdict = "Terlihat AMAN dan terdaftar sebagai domain resmi di TORANG GUARD."
    else:
        verdict = "Relatif aman, tapi tetap waspada. TORANG GUARD belum kenal domain ini. Kalau website-nya minta Password, PIN, Kode OTP, atau suruh transfer, itu sudah pasti penipuan. Berhenti dan tutup saja."
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
