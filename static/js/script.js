async function cek(){
  let url = document.getElementById('url').value;
  if(!url){ alert('Masukin dulu linknya bro!'); return; }

  let deepCheckEl = document.getElementById('deep_check');
  let deep_check = deepCheckEl ? deepCheckEl.checked : true;

  if(deep_check){
    document.getElementById('hasil').innerHTML = '<p style="text-align:center">Torang Guard lagi ngecek link-nya + buka isi website-nya... ⏳ (3-5 detik ya bro)</p>';
  } else {
    document.getElementById('hasil').innerHTML = '<p style="text-align:center">Torang Guard lagi ngecek link-nya... ⏳</p>';
  }

  try {
    let r = await fetch('/api/check', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url:url, deep_check: deep_check})});
    let d = await r.json();

    // ===== FIX - INI YANG TADI NGAUR =====
    // DULU: score 0-39 semua dibilang AMAN -> SALAH
    // SEKARANG: 0 = AMAN Resmi, 1-39 = BELUM DIKENAL, 40-69 = WASPADA, 70+ = BAHAYA
    let cls = '';
    let label = '';

    if (d.category === 'Sistem TORANG GUARD') {
      cls = 'aman';
      label = '✅ INI DOMAIN TORANG GUARD SENDIRI';
    } else if (d.score === 0) {
      cls = 'aman';
      label = '✅ AMAN - Terdaftar Resmi';
    } else if (d.score < 40) {
      cls = 'belum-dikenal';
      label = 'ℹ️ BELUM DIKENAL - Relatif Aman';
    } else if (d.score < 70) {
      cls = 'waspada';
      label = '⚠️ WASPADA - HATI-HATI!';
    } else {
      cls = 'bahaya';
      label = '⛔ BAHAYA - JANGAN DI KLIK!';
    }

    let h = `<div class="${cls}"><div class="score">${d.score}/100</div><p style="text-align:center;font-weight:bold;font-size:18px">${label}</p><p style="text-align:center">Domain: <b>${d.domain}</b> | Kategori: <b>${d.category}</b></p><table>`;
    d.reasons.forEach(x=>{ h+=`<tr><td>${x}</td></tr>` });
    h+=`</table><p style="margin-top:12px"><b>Kesimpulan Torang Guard:</b> ${d.verdict}</p><p style="margin-top:8px;font-size:11px;opacity:.7;text-align:center">* Hasil ini prediksi Fuzzy + WHOIS, bukan vonis final. Tetap verifikasi lewat aplikasi resmi.</p></div>`;
    document.getElementById('hasil').innerHTML = h;
  } catch(e) {
    document.getElementById('hasil').innerHTML = '<p style="text-align:center">Aduh bro, gagal ngecek. Coba cek lagi, pastikan internet lu nyala.</p>';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('url');
  if(input){
    input.addEventListener('keydown', (e) => {
      if(e.key === 'Enter'){ cek(); }
    });
  }
});
