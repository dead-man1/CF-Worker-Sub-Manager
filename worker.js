const _d = (s) => atob(s);
const K = {
  VL: _d('dmxlc3M='), VM: _d('dm1lc3M='), TR: _d('dHJvamFu'),
  SS: _d('c2hhZG93c29ja3M='), WG: _d('d2lyZWd1YXJk'),
  HY: _d('aHlzdGVyaWEy'), TU: _d('dHVpYw=='), CS: _d('Y3VzdG9t'),
  MX: _d('bWl4'), SB: _d('L3N1Yi8='), AP: _d('L2FwaS8='), 
  PN: _d('L3BhbmVs'), DB: _d('Tk9ERVM='), US: _d('VVNFUlM='), TK: 'x-auth-token'
};
const STD = [K.VL, K.VM, K.TR, K.SS, K.WG, K.HY, K.TU];
const ALL = [...STD, K.CS];
const P_NAMES = {
  [K.VL]: 'VLESS', [K.VM]: 'VMess', [K.TR]: 'Trojan',
  [K.SS]: 'Shadowsocks', [K.WG]: 'Wireguard', [K.HY]: 'Hysteria2',
  [K.TU]: 'TUIC', [K.CS]: 'CUSTOM'
};
const NG = `<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;background:#fff;color:#333}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>`;

export default {
  async fetch(r, e, c) {
    try {
      const u = new URL(r.url);
      const p = u.pathname;
      if (p === '/' || p === '/index.html') return new Response(NG, { headers: { 'Content-Type': 'text/html' } });
      if (p === K.PN) return hP(r, e);
      if (p.startsWith(K.SB)) return hS(u, e);
      if (p.startsWith(K.AP)) {
        if (!await cA(r, e)) return new Response(JSON.stringify({e:401}), { status: 401 });
        return hA(r, e);
      }
      return pX(r, 'speed.cloudflare.com');
    } catch (x) { return new Response(null, { status: 500 }); }
  }
};

async function pX(r, h) {
  const u = new URL(r.url); u.hostname = h; u.protocol = 'https:';
  const nr = new Request(u, { method: r.method, headers: r.headers, body: r.body, redirect: 'follow' });
  nr.headers.set('Host', h); nr.headers.set('Referer', `https://${h}/`);
  if (!nr.headers.get('User-Agent')) nr.headers.set('User-Agent', 'Mozilla/5.0');
  try {
    const res = await fetch(nr);
    const nh = new Headers(res.headers);
    nh.delete('Content-Security-Policy'); nh.delete('X-Frame-Options'); nh.delete('X-Content-Type-Options');
    nh.set('Access-Control-Allow-Origin', '*');
    const ct = nh.get('content-type');
    if (ct && ct.includes('text/html')) {
      let b = await res.text();
      b = b.replace(/<head>/i, `<head><base href="https://${h}/">`);
      return new Response(b, { status: res.status, headers: nh });
    }
    return new Response(res.body, { status: res.status, headers: nh });
  } catch (e) { return new Response(null, { status: 502 }); }
}

async function cA(r, e) {
  const c = r.headers.get('Cookie');
  return c && c.includes(`${K.TK}=${e.PASS}`);
}

function gT(c) {
  c = c.trim();
  if (c.startsWith('{')) return K.CS; 
  if (c.startsWith(K.VM + '://')) return K.VM;
  if (c.startsWith(K.VL + '://')) return K.VL;
  if (c.startsWith(K.TR + '://')) return K.TR;
  if (c.startsWith('ss://')) return K.SS;
  if (c.startsWith('wg://') || c.startsWith('wireguard://')) return K.WG;
  if (c.startsWith(K.HY + '://') || c.startsWith('hy2://')) return K.HY;
  if (c.startsWith(K.TU + '://')) return K.TU;
  return null;
}

async function hS(u, e) {
  const s = u.pathname.split('/'); 
  const path = s[2]; 
  const type = s[3]; 
  const d = await gD(e); 
  let r = [];

  if (path === e.SUB_PATH) {
    if (type === K.MX) {
      STD.forEach(x => { 
        if (d[x]) d[x].forEach(i => { if(i.e) r.push(i.c); });
      });
    } else if (type === K.CS) {
      const l = d[K.CS] || [];
      const j = l.filter(i => i.e).map(i => { try { return JSON.parse(i.c); } catch(z) { return null; } }).filter(i => i !== null);
      return new Response(JSON.stringify(j, null, 2), { headers: { 'content-type': 'application/json; charset=utf-8' } });
    } else if (STD.includes(type)) {
      if(d[type]) d[type].forEach(i => { if(i.e) r.push(i.c); });
    } else {
      return new Response(null, { status: 400 });
    }
  } 
  else {
    const users = await gU(e);
    const user = users.find(x => x.path === path);
    if (!user || user.active === false) return new Response('Invalid User', { status: 403 });
    
    if (type === 'protocol') {
      STD.forEach(proto => {
        if (user.access && user.access[proto] && d[proto]) {
          user.access[proto].forEach(idx => {
            if (d[proto][idx]) r.push(d[proto][idx].c);
          });
        }
      });
    } else if (type === 'custom') {
      if (user.access && user.access[K.CS] && d[K.CS]) {
        user.access[K.CS].forEach(idx => {
          if (d[K.CS][idx]) {
            try { r.push(JSON.parse(d[K.CS][idx].c)); } catch(err){}
          }
        });
      }
      return new Response(JSON.stringify(r, null, 2), { headers: { 'content-type': 'application/json; charset=utf-8' } });
    } else {
      return new Response(null, { status: 400 });
    }
  }

  return new Response(btoa(unescape(encodeURIComponent(r.join('\n')))), { headers: { 'content-type': 'text/plain; charset=utf-8' } });
}

async function hA(r, e) {
  const u = new URL(r.url);
  const a = u.pathname.replace(K.AP, ''); 
  let d = await gD(e);
  let us = await gU(e);

  if (r.method === 'GET') {
    if (a === 'list') return new Response(JSON.stringify(d));
    if (a === 'users') return new Response(JSON.stringify(us));
  }

  if (r.method === 'POST') {
    if (a === 'logout') return new Response('ok', { headers: { 'Set-Cookie': `${K.TK}=; Path=/; HttpOnly; Secure; Max-Age=0` } });
    const b = await r.json();
    
    if (a === 'add') {
      let c = b.content ? b.content.trim() : '';
      const t = gT(c);
      if (!t) return new Response('{"e":"inv"}', { status: 400 });
      if (t === K.CS) { try { c = JSON.stringify(JSON.parse(c)); } catch(z) {} }
      if (!d[t]) d[t] = [];
      const exists = d[t].some(x => x.c === c);
      if (exists) return new Response('{"e":"dup"}', { status: 409 });
      d[t].push({c: c, e: 1});
      await sD(e, d);
      return new Response('{"ok":true}');
    }
    if (a === 'del') {
      if (d[b.type] && d[b.type][b.index]) {
        d[b.type].splice(b.index, 1);
        await sD(e, d);
        return new Response('{"ok":true}');
      }
    }
    if (a === 'edit') {
      if (d[b.type] && d[b.type][b.index]) {
        let nc = b.newContent.trim();
        const nt = gT(nc);
        if (nt !== b.type) return new Response('{"e":"mis"}', { status: 400 });
        if (nt === K.CS) { try { nc = JSON.stringify(JSON.parse(nc)); } catch(z) {} }
        d[b.type][b.index].c = nc;
        await sD(e, d);
        return new Response('{"ok":true}');
      }
    }
    if (a === 'toggle') {
      if (d[b.type] && d[b.type][b.index]) {
        d[b.type][b.index].e = d[b.type][b.index].e ? 0 : 1;
        await sD(e, d);
        return new Response('{"ok":true}');
      }
    }

    if (a === 'u_add') {
      if (us.find(x => x.path === b.path)) return new Response('{"e":"dup"}', { status: 409 });
      us.push({ name: b.name, path: b.path, access: b.access, active: true });
      await sU(e, us);
      return new Response('{"ok":true}');
    }
    if (a === 'u_edit') {
      us[b.index] = { name: b.name, path: b.path, access: b.access, active: b.active };
      await sU(e, us);
      return new Response('{"ok":true}');
    }
    if (a === 'u_del') {
      us.splice(b.index, 1);
      await sU(e, us);
      return new Response('{"ok":true}');
    }
  }
  return new Response(null, { status: 400 });
}

async function hP(r, e) {
  if (r.method === 'POST') {
    const f = await r.formData();
    if (f.get('p') === e.PASS) {
      return new Response('{"ok":true}', { status: 200, headers: { 'Set-Cookie': `${K.TK}=${e.PASS}; Path=/; HttpOnly; Secure; Max-Age=86400; SameSite=Lax` } });
    }
    return new Response('{"ok":false}', { status: 401 });
  }
  if (!await cA(r, e)) return new Response(gH('l', e), { headers: { 'Content-Type': 'text/html' } });
  return new Response(gH('d', e), { headers: { 'Content-Type': 'text/html' } });
}

async function gD(e) {
  const v = await e.KV.get(K.DB);
  let d = {};
  if (!v) { 
    ALL.forEach(x => d[x] = []); 
  } else {
    d = JSON.parse(v);
    ALL.forEach(k => {
      if (d[k] && d[k].length > 0 && typeof d[k][0] === 'string') {
        d[k] = d[k].map(s => ({c: s, e: 1}));
      }
      if (!d[k]) d[k] = [];
    });
  }
  return d;
}
async function sD(e, d) { await e.KV.put(K.DB, JSON.stringify(d)); }
async function gU(e) { const v = await e.KV.get(K.US); return v ? JSON.parse(v) : []; }
async function sU(e, d) { await e.KV.put(K.US, JSON.stringify(d)); }

function gH(v, e) {
  const sp = e.SUB_PATH;
  const jv = `const API='${K.AP}';const SUB='${K.SB}';const PNL='${K.PN}';const SP='${sp}';const CS='${K.CS}';const PN=${JSON.stringify(P_NAMES)};`;
  return `<!DOCTYPE html><html lang="en" data-bs-theme="dark"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no"><title>DM Panel</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css"><style>:root{--bg:#09090b;--c:#18181b;--t:#e4e4e7;--a:#6366f1;--ah:#4f46e5;--b:rgba(255,255,255,0.08);--mt:#fbbf24}[data-bs-theme=light]{--bg:#f4f4f5;--c:#ffffff;--t:#18181b;--a:#4f46e5;--ah:#4338ca;--b:rgba(0,0,0,0.08);--mt:#78350f}*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}html,body{width:100%;height:100%;margin:0;padding:0;overflow:hidden;position:fixed;overscroll-behavior:none}body{background:var(--bg);color:var(--t);font-family:'Segoe UI',sans-serif;transition:0.3s}#app{width:100%;height:100%;overflow-y:auto;-webkit-overflow-scrolling:touch;display:flex;flex-direction:column}.ng{background:rgba(24,24,27,0.8);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--b);position:sticky;top:0;z-index:100}[data-bs-theme=light] .ng{background:rgba(255,255,255,0.8)}.bt{color:#fff!important;font-weight:800;font-size:1.4rem;letter-spacing:-0.5px;text-shadow:0 0 15px rgba(99,102,241,0.5)}[data-bs-theme=light] .bt{color:#4f46e5!important;text-shadow:none}.ac{padding:20px 0}.mig{background:rgba(255,255,255,0.05);border:1px solid var(--b);border-radius:16px;padding:6px;display:flex;transition:all 0.3s ease;box-shadow:0 4px 20px -5px rgba(0,0,0,0.2)}[data-bs-theme=light] .mig{background:rgba(0,0,0,0.03)}.mig:focus-within{border-color:var(--a);box-shadow:0 0 0 4px rgba(99,102,241,0.15);background:var(--c)}.mi{background:transparent;border:none;color:var(--t);padding:12px 16px;flex-grow:1;outline:none;font-size:0.95rem}.mi::placeholder{color:#71717a}.mba{border-radius:12px;padding:8px 24px;font-weight:600;border:none;background:linear-gradient(135deg,#10b981 0%,#059669 100%);color:white;transition:transform 0.2s}.mba:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(16,185,129,0.3)}.mba:active{transform:translateY(0)}.card{background:var(--c);border:1px solid var(--b);border-radius:16px}.ai{background:var(--c);border:1px solid var(--b);margin-bottom:12px;border-radius:12px!important;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)}.ah{display:flex;align-items:stretch;width:100%;border-bottom:1px solid transparent}.at{flex:1;background:var(--c);color:var(--t);font-weight:600;padding:1.2rem;border:none;text-align:left;display:flex;align-items:center;justify-content:space-between;min-width:0}.at:hover{background:rgba(128,128,128,0.03)}.at:not(.collapsed){color:var(--a);background:rgba(99,102,241,0.05)}.cb{width:50px;flex-shrink:0;display:flex;align-items:center;justify-content:center;border-left:1px solid var(--b);cursor:pointer;transition:0.2s;background:var(--c)}.cb:hover{background:rgba(99,102,241,0.1);color:var(--a)}.acc-vless{border-left:4px solid #3b82f6}.acc-vmess{border-left:4px solid #8b5cf6}.acc-trojan{border-left:4px solid #ec4899}.acc-shadowsocks{border-left:4px solid #14b8a6}.acc-wireguard{border-left:4px solid #ef4444}.acc-hysteria2{border-left:4px solid #f97316}.acc-tuic{border-left:4px solid #10b981}.acc-custom{border-left:4px solid #a1a1aa}.cf{font-family:monospace;font-size:.85rem;opacity:.8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr}.lw{position:fixed;top:0;left:0;width:100%;height:100%;display:flex;flex-direction:column;justify-content:space-between;background:radial-gradient(circle at top,rgba(99,102,241,0.15) 0%,var(--bg) 100%);overflow:hidden;z-index:9999}.lh{padding:20px;display:flex;justify-content:flex-end;width:100%}.lc{width:90%;max-width:400px;padding:2.5rem;background:var(--c);border:1px solid var(--b);border-radius:24px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);margin:0 auto}.li{font-size:3rem;color:var(--a);margin-bottom:1rem}.fc{background:rgba(128,128,128,0.1);border:1px solid var(--b);color:var(--t);padding:0.8rem}.fc:focus{background:rgba(128,128,128,0.1);border-color:var(--a);color:var(--t);box-shadow:0 0 0 2px rgba(99,102,241,0.2)}.bp{background:var(--a);border:none;padding:0.8rem;font-weight:600}.bp:hover{background:var(--ah)}.mc{background:linear-gradient(135deg,rgba(234,179,8,0.05),rgba(234,88,12,0.05));border:1px solid rgba(234,179,8,0.2);border-radius:16px}.bm{background:rgba(234,179,8,0.1);color:var(--mt);border:1px solid rgba(234,179,8,0.2);transition:0.2s;border-radius:10px;padding:8px 20px}.bm:hover{background:rgba(234,179,8,0.2);transform:translateY(-1px)}#gl{position:fixed;top:0;left:0;width:100%;height:100%;background:var(--bg);z-index:9999;display:flex;justify-content:center;align-items:center;transition:opacity 0.3s ease-out}#ac{opacity:0;transition:opacity 0.4s ease-in}.bi-btn{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;transition:0.2s;border:1px solid var(--b);color:var(--t)}.bi-btn:hover{background:rgba(128,128,128,0.1)}.blo{color:#ef4444;border-color:rgba(239,68,68,0.2)}.blo:hover{background:rgba(239,68,68,0.1)}.lig{display:flex;align-items:center;background:rgba(255,255,255,0.05);border:1px solid var(--b);border-radius:12px;overflow:hidden;transition:0.3s;height:52px;position:relative}[data-bs-theme=light] .lig{background:rgba(0,0,0,0.03)}.lig:focus-within{border-color:var(--a);box-shadow:0 0 0 3px rgba(99,102,241,0.15)}.lin{width:100%;height:100%;background:transparent;border:none;color:var(--t);padding:0 55px 0 16px;outline:none;font-size:1rem}.lbt{position:absolute;right:0;top:0;bottom:0;width:50px;background:transparent;border:none;border-left:1px solid var(--b);color:var(--t);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:0.2s}.lbt:hover{background:rgba(255,255,255,0.1);color:var(--a)}.ft{text-align:center;padding:20px;width:100%}.th-btn{position:absolute;top:20px;right:20px}.nav-tabs-c{display:flex;gap:5px;background:rgba(128,128,128,0.1);padding:4px;border-radius:25px;margin-bottom:15px}.nav-tab{padding:6px 16px;border-radius:20px;cursor:pointer;transition:0.2s;font-weight:600;color:var(--t);opacity:0.6;font-size:0.9rem}.nav-tab.active{background:var(--a);color:#fff;opacity:1}.nav-tab:hover:not(.active){background:rgba(128,128,128,0.1);opacity:1}.chk-row{display:flex;align-items:center;padding:10px;border-bottom:1px solid var(--b)}.chk-in{width:20px;height:20px;margin-right:10px;accent-color:var(--a)}.tgl-act{cursor:pointer;font-size:1.2rem;margin-right:10px;color:var(--t);opacity:0.5;transition:0.2s}.tgl-act.on{color:#10b981;opacity:1}.uc{display:flex;flex-direction:column;gap:10px;padding:15px}@media(min-width:500px){.uc{flex-direction:row;justify-content:space-between;align-items:center}}.ua{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}@media(min-width:500px){.ua{margin-top:0}}.us-sw{display:flex;align-items:center;justify-content:space-between;margin-bottom:15px;padding:10px;background:rgba(128,128,128,0.1);border-radius:10px}.sw-in{width:40px;height:20px;appearance:none;background:#555;border-radius:20px;position:relative;transition:0.3s;cursor:pointer}.sw-in:checked{background:var(--a)}.sw-in::after{content:'';position:absolute;top:2px;left:2px;width:16px;height:16px;background:#fff;border-radius:50%;transition:0.3s}.sw-in:checked::after{left:22px}.add-user-btn{width:100%;padding:12px;border-radius:16px;background:linear-gradient(135deg,#10b981 0%,#059669 100%);border:none;color:white;font-weight:600;transition:0.2s;display:flex;align-items:center;justify-content:center;gap:10px;box-shadow:0 4px 12px rgba(16,185,129,0.2)}.add-user-btn:hover{transform:translateY(-1px);box-shadow:0 6px 15px rgba(16,185,129,0.3)}.content-wrapper{flex:1;display:flex;flex-direction:column}.content-grow{flex-grow:1}.user-card{border-left:4px solid #06b6d4}</style></head><body><div id="app" style="flex:1">${v==='l'?rL():rD(sp)}</div><div class="modal fade" id="em"><div class="modal-dialog modal-dialog-centered"><div class="modal-content" style="background:var(--c);color:var(--t);border:1px solid var(--b)"><div class="modal-header border-bottom border-secondary border-opacity-25"><h5 class="modal-title">Edit Config</h5><button type="button" class="btn-close" data-bs-dismiss="modal" style="filter:invert(1)"></button></div><div class="modal-body"><textarea id="et" class="form-control" rows="10" style="font-family:monospace;font-size:0.8rem"></textarea><input type="hidden" id="ey"><input type="hidden" id="ex"></div><div class="modal-footer border-top border-secondary border-opacity-25"><button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary" onclick="sv()">Save Changes</button></div></div></div></div><div class="modal fade" id="um"><div class="modal-dialog modal-dialog-centered modal-lg"><div class="modal-content" style="background:var(--c);color:var(--t);border:1px solid var(--b)"><div class="modal-header border-bottom border-secondary border-opacity-25"><h5 class="modal-title" id="umt">Add User</h5><button type="button" class="btn-close" data-bs-dismiss="modal" style="filter:invert(1)"></button></div><div class="modal-body"><div class="us-sw"><label>User Active</label><input type="checkbox" id="uact" class="sw-in" checked></div><div class="mb-3"><label>Name</label><input type="text" id="un" class="form-control fc"></div><div class="mb-3"><label>Path (Slug)</label><input type="text" id="up" class="form-control fc"></div><div id="u_cfgs" class="accordion" style="max-height:300px;overflow-y:auto;border:1px solid var(--b);border-radius:8px"></div><input type="hidden" id="uix"></div><div class="modal-footer border-top border-secondary border-opacity-25"><button class="btn btn-primary" onclick="sUser()">Save User</button></div></div></div></div><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script><script>${jv}if(history.scrollRestoration)history.scrollRestoration='manual';window.scrollTo(0,0);let M=null;let UM=null;let G_DATA={};let G_USERS=[];function tt(){const h=document.documentElement;const c=h.getAttribute('data-bs-theme');const n=c==='dark'?'light':'dark';h.setAttribute('data-bs-theme',n);localStorage.setItem('theme',n);const is=document.querySelectorAll('.ti-icon');is.forEach(i=>i.className=n==='dark'?'bi bi-moon-stars ti-icon':'bi bi-sun ti-icon');const l=document.getElementById('gl');if(l)l.style.background=getComputedStyle(document.body).getPropertyValue('--bg')}function it(){const s=localStorage.getItem('theme')||'dark';document.documentElement.setAttribute('data-bs-theme',s);const is=document.querySelectorAll('.ti-icon');is.forEach(i=>i.className=s==='dark'?'bi bi-moon-stars ti-icon':'bi bi-sun ti-icon');const l=document.getElementById('gl');if(l)l.style.background=getComputedStyle(document.body).getPropertyValue('--bg')}function tp(){const i=document.getElementById('pi');const b=document.getElementById('ei');if(i.type==='password'){i.type='text';b.className='bi bi-eye-slash'}else{i.type='password';b.className='bi bi-eye'}}async function lg(e){e.preventDefault();const p=document.getElementById('pi').value;if(!p)return;const d=new FormData();d.append('p',p);const r=await fetch(PNL,{method:'POST',body:d});if(r.ok)location.reload();else{const i=document.querySelector('.lig');i.style.borderColor='#ef4444';setTimeout(()=>i.style.borderColor='var(--b)',1000)}}async function ld(){if(!document.getElementById('ls'))return;const t=localStorage.getItem('tab')||'res';swTab(t);const o=Array.from(document.querySelectorAll('.collapse.show')).map(e=>e.id);try{const r=await fetch(API+'list');if(r.status===401){location.reload();return}G_DATA=await r.json();rl(G_DATA,o);const l=document.getElementById('gl');const c=document.getElementById('ac');if(l&&c){l.style.opacity='0';c.style.opacity='1';setTimeout(()=>l.remove(),300)}}catch(e){const l=document.getElementById('gl');if(l)l.remove();document.getElementById('ac').style.opacity='1';document.getElementById('ls').innerHTML='<div class="text-center text-danger mt-5">Connection Error. Please Refresh.</div>'}}function rl(d,o=[]){const c=document.getElementById('ls');c.innerHTML='';['${K.VL}','${K.VM}','${K.TR}','${K.SS}','${K.WG}','${K.HY}','${K.TU}','${K.CS}'].forEach(k=>{const l=d[k]||[];const id=\`c-\${k}\`;const io=o.includes(id);const sc=io?'show':'';const bc=io?'':'collapsed';c.innerHTML+=\`<div class="accordion-item ai acc-\${k}"><div class="accordion-header ah"><button class="accordion-trigger at \${bc}" type="button" data-bs-toggle="collapse" data-bs-target="#\${id}"><span>\${PN[k]} <span class="badge bg-secondary ms-2">\${l.length}</span></span><i class="bi bi-chevron-down"></i></button><div class="cb" onclick="cp('\${k}')" title="Copy Link"><i class="bi bi-link-45deg fs-4"></i></div></div><div id="\${id}" class="collapse \${sc}"><div class="accordion-body p-0">\${l.length===0?'<div class="text-muted text-center p-3 small">No configs added yet</div>':l.map((x,i)=>\`<div class="d-flex justify-content-between align-items-center p-3 border-bottom" style="border-color:var(--b)!important"><div class="d-flex align-items-center overflow-hidden" style="width:70%"><i class="bi \${x.e?'bi-check-circle-fill on':'bi-circle'} tgl-act" onclick="tg('\${k}',\${i})"></i><span class="badge bg-dark me-3">#\${i+1}</span><div class="cf">\${x.c}</div></div><div class="d-flex gap-2"><button class="btn btn-sm btn-outline-warning" onclick="ed('\${k}',\${i},'\${encodeURIComponent(x.c)}')" style="width:32px;height:32px"><i class="bi bi-pencil"></i></button><button class="btn btn-sm btn-outline-danger" onclick="rm('\${k}',\${i})" style="width:32px;height:32px"><i class="bi bi-trash"></i></button></div></div>\`).join('')}</div></div></div>\`})}async function ad(){const i=document.getElementById('ni');if(!i.value)return;const r=await fetch(API+'add',{method:'POST',body:JSON.stringify({content:i.value})});if(r.ok){i.value='';ld()}else{const e=await r.json();alert(e.e==='dup'?'Duplicate Config!':'Invalid Protocol!')}}async function rm(t,i){if(!confirm('Delete this config?'))return;await fetch(API+'del',{method:'POST',body:JSON.stringify({type:t,index:i})});ld()}async function tg(t,i){await fetch(API+'toggle',{method:'POST',body:JSON.stringify({type:t,index:i})});ld()}function ed(t,i,c){document.getElementById('ey').value=t;document.getElementById('ex').value=i;let v=decodeURIComponent(c);if(t===CS){try{v=JSON.stringify(JSON.parse(v),null,2)}catch(e){}}document.getElementById('et').value=v;if(!M)M=new bootstrap.Modal(document.getElementById('em'));M.show()}async function sv(){const r=await fetch(API+'edit',{method:'POST',body:JSON.stringify({type:document.getElementById('ey').value,index:document.getElementById('ex').value,newContent:document.getElementById('et').value})});if(r.ok){M.hide();ld()}else alert('Invalid Protocol!')}function cp(t){navigator.clipboard.writeText(\`\${location.origin}\${SUB}\${SP}/\${t}\`);const b=event.currentTarget;const i=b.querySelector('i');const o=i.className;i.className='bi bi-check-lg text-success fs-4';setTimeout(()=>i.className=o,1500)}async function lo(){await fetch(API+'logout',{method:'POST'});location.reload()}function swTab(t){localStorage.setItem('tab',t);document.querySelectorAll('.nav-tab').forEach(e=>e.classList.remove('active'));document.getElementById('tab-'+t).classList.add('active');if(t==='res'){document.getElementById('v-res').style.display='block';document.getElementById('v-usr').style.display='none'}else{document.getElementById('v-res').style.display='none';document.getElementById('v-usr').style.display='block';ldUsers()}}async function ldUsers(){const r=await fetch(API+'users');G_USERS=await r.json();const c=document.getElementById('ul');c.innerHTML='';G_USERS.forEach((u,i)=>{const st=u.active!==false?'<span class="text-success">●</span>':'<span class="text-danger">●</span>';c.innerHTML+=\`<div class="card p-3 mb-3 user-card"><div class="uc"><div style="overflow:hidden;text-overflow:ellipsis"><h5 class="mb-1 text-truncate">\${st} \${u.name}</h5></div><div class="ua"><button class="btn btn-sm btn-outline-warning" onclick="edU(\${i})"><i class="bi bi-pencil"></i></button><div class="btn-group"><button class="btn btn-sm btn-outline-primary" onclick="cpU('\${u.path}','protocol')">Protocol</button><button class="btn btn-sm btn-outline-info" onclick="cpU('\${u.path}','custom')">Custom</button><button class="btn btn-sm btn-outline-danger" onclick="rmU(\${i})"><i class="bi bi-trash"></i></button></div></div></div></div>\`})}function opU(){if(!UM)UM=new bootstrap.Modal(document.getElementById('um'));document.getElementById('umt').innerText='Add User';document.getElementById('un').value='';document.getElementById('up').value='';document.getElementById('uix').value='-1';document.getElementById('uact').checked=true;renderUserConfigSelector({});UM.show()}function edU(i){if(!UM)UM=new bootstrap.Modal(document.getElementById('um'));const u=G_USERS[i];document.getElementById('umt').innerText='Edit User';document.getElementById('un').value=u.name;document.getElementById('up').value=u.path;document.getElementById('uix').value=i;document.getElementById('uact').checked=u.active!==false;renderUserConfigSelector(u.access);UM.show()}function renderUserConfigSelector(acc){const c=document.getElementById('u_cfgs');c.innerHTML='';['${K.VL}','${K.VM}','${K.TR}','${K.SS}','${K.WG}','${K.HY}','${K.TU}','${K.CS}'].forEach(k=>{const l=G_DATA[k]||[];if(l.length>0){const id=\`ua-\${k}\`;c.innerHTML+=\`<div class="accordion-item ai acc-\${k}"><h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#\${id}">\${PN[k]}</button></h2><div id="\${id}" class="accordion-collapse collapse" data-bs-parent="#u_cfgs"><div class="accordion-body">\${l.map((x,i)=>{const chk=acc[k]&&acc[k].includes(i)?'checked':'';return \`<div class="chk-row"><input type="checkbox" class="chk-in" data-t="\${k}" data-i="\${i}" \${chk}><span class="badge bg-secondary me-2">#\${i+1}</span><div class="cf small">\${x.c}</div></div>\`}).join('')}</div></div></div>\`}})}async function sUser(){const n=document.getElementById('un').value;const p=document.getElementById('up').value;const idx=document.getElementById('uix').value;const act=document.getElementById('uact').checked;if(!n||!p)return alert('Name & Path required');const acc={};document.querySelectorAll('.chk-in:checked').forEach(e=>{const t=e.getAttribute('data-t');const i=parseInt(e.getAttribute('data-i'));if(!acc[t])acc[t]=[];acc[t].push(i)});const a=idx==='-1'?'u_add':'u_edit';const r=await fetch(API+a,{method:'POST',body:JSON.stringify({index:idx,name:n,path:p,access:acc,active:act})});if(r.ok){UM.hide();ldUsers()}else alert('Error!')}async function rmU(i){if(!confirm('Delete User?'))return;await fetch(API+'u_del',{method:'POST',body:JSON.stringify({index:i})});ldUsers()}function cpU(p,t){navigator.clipboard.writeText(\`\${location.origin}\${SUB}\${p}/\${t}\`);alert('Copied!')}it();if(document.getElementById('ls')){window.scrollTo(0,0);ld()}</script></body></html>`;
}
function rL(){return `<div class="lw"><div class="lh"><button class="bi-btn" onclick="tt()"><i class="bi bi-moon-stars ti-icon" id="ti"></i></button></div><div class="lc text-center"><div class="li"><i class="bi bi-shield-lock"></i></div><h2 class="text-white fw-bold mb-1">DM Panel</h2><p class="text-white-50 mb-4">Secure Access</p><form onsubmit="lg(event)"><div class="lig mb-4"><input type="password" id="pi" class="lin" placeholder="Enter Password" required><button class="lbt" type="button" onclick="tp()"><i class="bi bi-eye" id="ei"></i></button></div><button type="submit" class="btn bp w-100 btn-lg shadow-sm">Unlock Panel</button></form></div><div class="ft"><small style="color:var(--t);font-weight:bold">Created With <span style="color:#ef4444">❤️</span> By <a href="https://github.com/dead-man1" style="color:var(--t);text-decoration:none">dead-man1</a></small></div></div>`}
function rD(sp){return `<div id="gl"><div class="spinner-border text-primary" style="width:3rem;height:3rem"></div></div><div id="ac"><nav class="navbar ng mb-4"><div class="container"><span class="navbar-brand bt"><i class="bi bi-hdd-network me-2"></i>DM Panel</span><div class="d-flex gap-2"><button class="bi-btn" onclick="tt()"><i class="bi bi-moon-stars ti-icon" id="ti"></i></button><button class="bi-btn blo" onclick="lo()"><i class="bi bi-power"></i></button></div></div></nav><div class="container pb-5"><div class="nav-tabs-c"><div class="nav-tab active" id="tab-res" onclick="swTab('res')">Resources</div><div class="nav-tab" id="tab-usr" onclick="swTab('usr')">Users</div></div><div class="content-wrapper"><div id="v-res"><div class="ac"><div class="mig"><input type="text" id="ni" class="mi" placeholder="Paste config link here..."><button class="mba" onclick="ad()">Add</button></div></div><div id="ls" class="d-flex flex-column gap-2"></div><div class="card p-4 mt-5 mc"><div class="d-flex justify-content-between align-items-center flex-wrap gap-3"><div><h5 class="mb-1" style="color:var(--mt);font-weight:bold">Universal Subscription</h5><small class="text-muted">All protocols in one link</small></div><button onclick="cp('mix')" class="bm"><i class="bi bi-clipboard me-2"></i>Copy Link</button></div></div><div class="ft" style="margin-top:20px"><small style="color:var(--t);font-weight:bold">Created With <span style="color:#ef4444">❤️</span> By <a href="https://github.com/dead-man1" style="color:var(--t);text-decoration:none">dead-man1</a></small></div></div><div id="v-usr" style="display:none"><div class="d-flex justify-content-between align-items-center mb-3"><button class="add-user-btn" onclick="opU()"><i class="bi bi-plus-lg"></i> Create New User</button></div><div id="ul"></div></div></div></div></div>`}