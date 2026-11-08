
async function cek(){
  let url = document.getElementById('url').value;
  if(!url){ alert('Masukin dulu linknya bro!'); return; }
  document.getElementById('hasil').innerHTML = '<p style="text-align:center">Torang Guard lagi ngecek database kampus... ⏳</p>';
  let r = await fetch('/api/check', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url:url})});
  let d = await r.json();
  let cls = d.score >= 70 ? 'bahaya' : d.score >= 40 ? 'waspada' : 'aman';
  let label = d.score >= 70 ? '⛔ BAHAYA - JANGAN DI KLIK!' : d.score >= 40 ? '⚠️ WASPADA - HATI-HATI!' : '✅ AMAN - Kemungkinan Asli';
  let h = `<div class="${cls}"><div class="score">${d.score}/100</div><p style="text-align:center;font-weight:bold;font-size:18px">${label}</p><p style="text-align:center">Domain: <b>${d.domain}</b> | Kategori: <b>${d.category}</b></p><table>`;
  d.reasons.forEach(x=>{ h+=`<tr><td>${x}</td></tr>` });
  h+=`</table><p style="margin-top:12px"><b>Kesimpulan Torang Guard:</b> ${d.verdict}</p></div>`;
  document.getElementById('hasil').innerHTML = h;
}

// Biar bisa tekan Enter di keyboard langsung cek
document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('url');
  if(input){
    input.addEventListener('keydown', (e) => {
      if(e.key === 'Enter'){ cek(); }
    });
  }
});
