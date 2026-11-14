// ===== HIMOYA QATLAMI =====
// Parollar PBKDF2-SHA256 (150 000 aylanish, har akkauntga alohida salt) bilan saqlanadi.
// Noto‘g‘ri urinishlar bloklanadi, faol bo‘lmagan sessiya avtomatik yopiladi.
const SEC_ITER = 310000; // PBKDF2 aylanishlari (yangi parollar va ma’lumot kaliti uchun)
const SEC_IDLE_MS = 30 * 60 * 1000;
const SEC_MAX_TRIES = 5;
const SEC_LOCK_STEPS = [60e3, 5 * 60e3, 15 * 60e3, 60 * 60e3];
const OWNER_CREDS = [
  {salt:'a4dcd6d9a83b1d01de7f47902b2cecf9',hash:'5a999bf03c62f0d1ffacaa770e0e5344e9e3fb73168d0282c9e93ef14d628816'},
  {salt:'74c4e6108acba3733130e7f96e29686d',hash:'551f02a25e76ddf2d8a1dfa2414a11259f2eb9cac982538bbaaa9ff3a92689d1'}
];
function toHex(buf){return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');}
async function hashSecret(secret,salt,iter=150000){
  if(!window.crypto||!crypto.subtle) throw new Error('Xavfsiz kirish uchun sayt HTTPS orqali ochilishi kerak.');
  const enc=new TextEncoder();
  const key=await crypto.subtle.importKey('raw',enc.encode(String(secret)),'PBKDF2',false,['deriveBits']);
  return toHex(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:enc.encode(salt),iterations:iter},key,256));
}
async function makeCredential(secret){const salt=toHex(crypto.getRandomValues(new Uint8Array(16)));return {salt,passHash:await hashSecret(secret,salt,SEC_ITER),iter:SEC_ITER};}
function safeEqual(a,b){a=String(a);b=String(b);if(a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0;}
// Akkaunt parolini tekshiradi. Eski (ochiq matnli) parol to‘g‘ri bo‘lsa, avtomatik hashga o‘tkaziladi.
async function verifyAndUpgrade(accounts,name,secret){
  const acc=accounts[name]; if(!acc) return false;
  const save=()=>localStorage.setItem('furaTruckAccounts',JSON.stringify(accounts));
  if(acc.passHash&&acc.salt){
    const it=acc.iter||150000;
    const ok=safeEqual(await hashSecret(secret,acc.salt,it),acc.passHash);
    // Eski (kuchsizroq) hash to‘g‘ri parol bilan kirilganda yangi, kuchli hashga almashtiriladi.
    if(ok&&it<SEC_ITER){const cred=await makeCredential(secret);acc.salt=cred.salt;acc.passHash=cred.passHash;acc.iter=cred.iter;save();}
    return ok;
  }
  if(acc.password!==undefined&&safeEqual(acc.password,secret)){
    const cred=await makeCredential(secret); acc.salt=cred.salt; acc.passHash=cred.passHash; acc.iter=cred.iter; delete acc.password; save(); return true;
  }
  return false;
}
function lockState(key){try{return JSON.parse(localStorage.getItem('furaLock:'+key)||'{}')}catch(e){return {}}}
function lockRemaining(key){const st=lockState(key);return st.until&&st.until>Date.now()?st.until-Date.now():0;}
function lockText(ms){const m=Math.ceil(ms/60000);return `Juda ko‘p noto‘g‘ri urinish. ${m} daqiqadan keyin qayta urinib ko‘ring.`;}
function registerFail(key){
  const st=lockState(key);st.fails=(st.fails||0)+1;
  if(st.fails>=SEC_MAX_TRIES){const step=Math.min(st.level||0,SEC_LOCK_STEPS.length-1);st.until=Date.now()+SEC_LOCK_STEPS[step];st.level=(st.level||0)+1;st.fails=0;}
  localStorage.setItem('furaLock:'+key,JSON.stringify(st));
}
function clearFails(key){localStorage.removeItem('furaLock:'+key);}
// Parol so‘raydigan oyna (yulduzchalar bilan; prompt() parolni ochiq ko‘rsatadi).
function askPassword(title){
  return new Promise(resolve=>{
    const o=document.createElement('div');o.className='vehicle-modal';
    o.innerHTML='<div class="vehicle-modal-card" role="dialog" aria-modal="true"><h2></h2><input type="password" class="pw-input" autocomplete="off" style="width:100%;height:44px;padding:0 12px;border:1px solid #d8e1ee;border-radius:9px;margin:10px 0 14px"><div class="vehicle-modal-add"><button type="button" data-ok>Tasdiqlash</button><button type="button" data-cancel style="background:#e9eef8;color:#253653">Bekor qilish</button></div></div>';
    o.querySelector('h2').textContent=title;document.body.appendChild(o);
    const input=o.querySelector('.pw-input');input.focus();
    const done=v=>{o.remove();resolve(v)};
    o.querySelector('[data-ok]').addEventListener('click',()=>done(input.value));
    o.querySelector('[data-cancel]').addEventListener('click',()=>done(null));
    input.addEventListener('keydown',e=>{if(e.key==='Enter')done(input.value);if(e.key==='Escape')done(null)});
  });
}
// Faol bo‘lmasa 30 daqiqadan keyin avtomatik chiqish.
let idleTimer=null;
function logoutNow(){vaultClose();serverFirm=null;serverVeh=null;activeTruck='';activeCompany='';clearTimeout(idleTimer);try{location.reload();return}catch(e){}document.getElementById('vehiclePickerModal')?.classList.add('hidden');dashboardPage.classList.add('hidden');loginPage.classList.remove('hidden');}
document.getElementById('logoutBtn')?.addEventListener('click',()=>logoutNow());
function resetIdle(){clearTimeout(idleTimer);if(!activeTruck)return;idleTimer=setTimeout(()=>{logoutNow();alert('Xavfsizlik uchun faol bo‘lmagan sessiya yopildi. Qayta kiring.')},SEC_IDLE_MS);}
['click','keydown','mousemove','touchstart'].forEach(ev=>document.addEventListener(ev,resetIdle,{passive:true}));
// ===== SERVER REJIMI (Netlify Functions + Supabase) =====
// Server sozlangan bo‘lsa ma’lumotlar serverda saqlanadi (istalgan qurilmadan kirish mumkin).
// Sozlanmagan bo‘lsa sayt avvalgidek lokal rejimda (faqat shu brauzerda) ishlaydi.
const API_URL='/.netlify/functions/api';
let SERVER_MODE=false,serverFirm=null,serverVeh=null;
const sleepMs=ms=>new Promise(r=>setTimeout(r,ms));
async function api(action,payload,token){
  let r,j;
  try{r=await fetch(API_URL,{method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify({action,...(payload||{})})});}
  catch(e){const err=new Error('Serverga ulanib bo‘lmadi. Internetni tekshiring.');err.network=true;throw err;}
  try{j=await r.json();}catch(e){const err=new Error('Server javobi noto‘g‘ri.');err.status=r.status;throw err;}
  if(!r.ok||j.error){const err=new Error(j.error||'Server xatosi.');err.status=r.status;err.locked=!!j.locked;throw err;}
  return j;
}
const modeReady=(async()=>{
  try{
    const ctl=typeof AbortController!=='undefined'?new AbortController():null,timer=ctl?setTimeout(()=>ctl.abort(),4000):null;
    const r=await fetch(API_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'ping'}),signal:ctl?ctl.signal:undefined});
    if(timer)clearTimeout(timer);
    const j=await r.json();SERVER_MODE=!!(j&&j.ok&&j.configured);
  }catch(e){SERVER_MODE=false;}
  const b=document.getElementById('modeBadge');
  if(b){b.textContent=SERVER_MODE?'Server rejimi: ma’lumotlar serverda saqlanadi, istalgan qurilmadan kirish mumkin.':'Lokal rejim: ma’lumotlar faqat shu brauzerda saqlanadi.';b.className='login-hint mode-'+(SERVER_MODE?'server':'local');}
})();
let saveWarned=false;
function warnOnce(msg){if(saveWarned)return;saveWarned=true;alert(msg);setTimeout(()=>{saveWarned=false},30000);}
async function serverSaveItem(holder,short,blob){
  for(let i=0;i<4;i++){
    try{const r=await api('data-set',{items:[{key:short,value:blob}]},holder.token);if(r.token)holder.token=r.token;return;}
    catch(e){if(e.status===401||e.status===400){warnOnce('Sessiya tugagan yoki xatolik: ma’lumot saqlanmadi. Qayta kiring.');throw e;}await sleepMs(500*(2**i));}
  }
  warnOnce('Ma’lumot serverga saqlanmadi. Internetni tekshiring va qayta urinib ko‘ring.');throw new Error('saqlanmadi');
}
async function serverEnterVehicle(plate){
  const r=await api('vehicle-open',{plate},serverFirm.token);
  serverVeh={token:r.token,plate:r.vehicle.plate};
  await vaultOpen(r.vehicle.plate);
}
// ===== /SERVER REJIMI =====

// ===== MA’LUMOTLAR OMBORI =====
// Mashinalarda parol yo‘q: kirish faqat firma paroli bilan. Server rejimida ma’lumot serverda shifrlab saqlanadi (DATA_KEY).
// Faqat eski (mashina paroli bilan shifrlangan) mahalliy ma’lumotlar bir marta eski parol bilan ochiladi.
const vault={key:null,plate:'',mem:new Map(),queue:Promise.resolve(),server:false};
const b64=u=>{let t='';new Uint8Array(u).forEach(x=>t+=String.fromCharCode(x));return btoa(t)};
const unb64=t=>Uint8Array.from(atob(t),x=>x.charCodeAt(0));
async function legacyDerive(salt,password){
  const enc=new TextEncoder();
  const base=await crypto.subtle.importKey('raw',enc.encode(String(password)),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:enc.encode('vault:'+salt),iterations:SEC_ITER},base,{name:'AES-GCM',length:256},false,['decrypt']);
}
async function legacyDecrypt(key,fullKey,blob){
  const parts=blob.slice(5).split('.');
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(parts[0]),additionalData:new TextEncoder().encode(fullKey)},key,unb64(parts[1]));
  return new TextDecoder().decode(pt);
}
function vaultPersist(key,fullKey,value){
  const server=vault.server,holder=serverVeh,plate=vault.plate;
  vault.queue=vault.queue.then(async()=>{
    if(server) await serverSaveItem(holder,fullKey.slice(`furaTruck:${plate}:`.length),String(value));
    else localStorage.setItem(fullKey,String(value));
  }).catch(e=>console.warn('Saqlashda xato:',e));
}
function vaultClose(){vault.key=null;vault.plate='';vault.mem=new Map();vault.server=false;}
async function vaultOpenServer(plate){
  const r=await api('data-get',{},serverVeh.token);if(r.token)serverVeh.token=r.token;
  const mem=new Map();
  for(const it of r.items){ if(typeof it.value==='string') mem.set(it.key,it.value); }
  vault.key=true;vault.plate=plate;vault.mem=mem;vault.server=true;
}
async function vaultOpen(plate){
  vaultClose();
  if(SERVER_MODE) return vaultOpenServer(plate);
  const prefix=`furaTruck:${plate}:`,enc=[];
  for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);if(k&&k.startsWith(prefix)&&String(localStorage.getItem(k)).startsWith('enc1:'))enc.push(k)}
  const salt=localStorage.getItem('furaVault:'+plate);
  if(enc.length&&salt){
    for(;;){
      const pw=await askPassword(`${plate}: eski ma’lumotlarni ochish uchun mashinaning ESKI parolini kiriting (bir marta so‘raladi)`);
      if(pw===null) throw new Error('Eski ma’lumotlar ochilmadi (bekor qilindi).');
      let key; try{ key=await legacyDerive(salt,pw); await legacyDecrypt(key,enc[0],localStorage.getItem(enc[0])); }catch(e){ alert('Eski parol noto‘g‘ri.'); continue; }
      let bad=0;
      for(const k of enc){ try{ localStorage.setItem(k,await legacyDecrypt(key,k,localStorage.getItem(k))); }catch(e){ bad++; } }
      localStorage.removeItem('furaVault:'+plate);
      if(bad)alert(`${bad} ta yozuvni o‘qib bo‘lmadi.`);
      break;
    }
  }
}

// ===== /SHIFRLASH =====

// ===== /HIMOYA =====

const loginPage = document.getElementById('loginPage');
const dashboardPage = document.getElementById('dashboardPage');
const loginForm = document.getElementById('loginForm');
const routeForm = document.getElementById('routeForm');
let lastRoute = null;
let activeTruck = '';
let activeCompany = ''; 
// Sahifa qayta yuklanganda oldingi dashboard holati tiklanmasin: har safar login sahifasidan boshlanadi.
window.addEventListener('pageshow',()=>{
  vaultClose(); serverFirm=null; serverVeh=null; activeTruck=''; activeCompany='';
  loginPage.classList.remove('hidden');
  dashboardPage.classList.add('hidden');
});
function scopedKey(key){ return `furaTruck:${activeTruck}:${key}`; }
function getTruckValue(key){ if(vault.key&&vault.plate===activeTruck) return vault.mem.has(key)?vault.mem.get(key):null; return localStorage.getItem(scopedKey(key)); }
function setTruckValue(key,value){ if(vault.key&&vault.plate===activeTruck){ const v=String(value); vault.mem.set(key,v); vaultPersist(vault.key,scopedKey(key),v); return; } localStorage.setItem(scopedKey(key),value); }
function truckAccounts(){
  try { const value=JSON.parse(localStorage.getItem('furaTruckAccounts')||'{}'); return value && typeof value==='object' ? value : {}; }
  catch(e){ console.warn('Firma ma’lumotlarini o‘qib bo‘lmadi:',e); return {}; }
}
function normalizeCompanyName(value){ return String(value||'').trim().replace(/\s+/g,' ').toLocaleUpperCase('uz-UZ'); }
function findCompanyAccount(accounts, typedName){
  const wanted=normalizeCompanyName(typedName);
  if(!wanted) return null;
  const entry=Object.entries(accounts).find(([name,account]) =>
    normalizeCompanyName(name)===wanted && account && (account.isCompany===true || account.role==='company' || account.type==='company')
  );
  return entry ? {name:entry[0], data:entry[1]} : null;
}
function syncRouteFields(from,to){const tf=document.getElementById('tripFrom'),tt=document.getElementById('tripTo'),cf=document.getElementById('cargoFrom'),ct=document.getElementById('cargoTo');if(tf)tf.value=from;if(tt)tt.value=to;if(cf)cf.value=from;if(ct)ct.value=to;}
function readVehicleProfile(){try{const p=JSON.parse(getTruckValue('vehicleProfile')||'null');if(p&&typeof p==='object')return p}catch(e){}return truckAccounts()[activeTruck]||{};}
function loadTruckBasics(){
  document.getElementById('driverNumber').textContent=activeTruck;
  document.getElementById('vehicleNumberDisplay').textContent=activeTruck;
  const profile=readVehicleProfile();
  document.getElementById('vehicleModel').value=profile.model||'';
  document.getElementById('vehiclePlate').value=activeTruck;
  document.getElementById('vehicleNote').value=profile.note||'';
  const route=JSON.parse(getTruckValue('route')||'null');
  if(route){document.getElementById('fromCity').value=route.from||'';document.getElementById('toCity').value=route.to||'';document.getElementById('cargoInfo').value=route.cargo||'';document.getElementById('routeStatus').textContent=`${route.from||''} → ${route.to||''}`;document.getElementById('savedRoute').innerHTML=`<strong>${escapeHtml(route.from||'—')}</strong> → <strong>${escapeHtml(route.to||'—')}</strong><p>Yuk: ${escapeHtml(route.cargo||'Kiritilmagan')}</p>`;syncRouteFields(route.from||'',route.to||'');}
  smaskaDateInput.value=getTruckValue('furaSmaskaChangedDate')||dateToLocalInput(new Date());
  renderSmaska();
  renderOil();
  document.getElementById('kalodDate').value=getTruckValue('kalodChangedDate')||dateToLocalInput(new Date());document.getElementById('kalodDays').value=getTruckValue('kalodDurationDays')||'';renderKalod(); if(typeof setRepairCostInputs==='function')setRepairCostInputs();
}
function ensureVehicleModal(){
  if(document.getElementById('vehiclePickerModal')) return;
  const modal=document.createElement('div'); modal.id='vehiclePickerModal'; modal.className='vehicle-modal hidden';
  modal.innerHTML=`<div class="vehicle-modal-card" role="dialog" aria-modal="true" aria-labelledby="vehicleModalTitle"><button class="vehicle-modal-close" type="button" aria-label="Yopish">×</button><div class="vehicle-modal-icon"><i class="fa-solid fa-truck"></i></div><h2 id="vehicleModalTitle">Mashinani tanlang</h2><p class="vehicle-modal-subtitle"></p><div id="vehicleModalList" class="vehicle-modal-list"></div><div class="vehicle-modal-add"><input id="newVehiclePlate" type="text" placeholder="Yangi mashina raqami"><button id="addVehicleNow" type="button"><i class="fa-solid fa-plus"></i> Mashina qo‘shish</button></div><p id="vehicleModalMessage" class="vehicle-modal-message"></p></div>`;
  document.body.appendChild(modal);
  modal.querySelector('.vehicle-modal-close').addEventListener('click',()=>modal.classList.add('hidden'));
  modal.addEventListener('click',e=>{if(e.target===modal)modal.classList.add('hidden')});
  modal.querySelector('#addVehicleNow').addEventListener('click',async()=>{
    const plate=modal.querySelector('#newVehiclePlate').value.trim().toUpperCase();
    const accounts=truckAccounts(), company=accounts[activeCompany];
    const msg=modal.querySelector('#vehicleModalMessage');
    if(SERVER_MODE){
      if(!serverFirm){msg.textContent='Firma ma’lumoti topilmadi. Qayta kiring.';return;}
      if(!plate){msg.textContent='Mashina raqamini kiriting.';return;}
      let added;
      try{const r=await api('firm-add-vehicle',{plate},serverFirm.token);added=r.vehicle;serverFirm.vehicles.push(added);await serverEnterVehicle(added.plate);}
      catch(err){msg.textContent=err.message;return;}
      modal.classList.add('hidden');enterTruck(added.plate);return;
    }
    if(!company||!company.isCompany){msg.textContent='Firma ma’lumoti topilmadi. Qayta kiring.';return;}
    if(!plate){msg.textContent='Mashina raqamini kiriting.';return;}
    company.vehicles=Array.isArray(company.vehicles)?company.vehicles:[];
    if(company.vehicles.length>=Number(company.vehicleLimit||0)){msg.textContent=`Mashina limiti tugagan (${company.vehicleLimit} ta).`;return;}
    if(accounts[plate]){msg.textContent='Bu mashina raqami allaqachon ishlatilgan.';return;}
    accounts[plate]={company:activeCompany,createdAt:new Date().toISOString(),model:'',note:''}; company.vehicles.push(plate);
    localStorage.setItem('furaTruckAccounts',JSON.stringify(accounts)); modal.classList.add('hidden'); enterTruck(plate);
  });
}
function renderVehicleModal(){
  ensureVehicleModal(); const modal=document.getElementById('vehiclePickerModal'),list=modal.querySelector('#vehicleModalList'),accounts=truckAccounts(),company=accounts[activeCompany];
  list.innerHTML=''; const names=SERVER_MODE&&serverFirm?serverFirm.vehicles.map(v=>v.plate):(company&&Array.isArray(company.vehicles)?company.vehicles:[]).filter(n=>accounts[n]);
  if(!names.length){const empty=document.createElement('div');empty.className='vehicle-modal-empty';empty.textContent='Hali mashina qo‘shilmagan. Quyidan birinchi mashinani qo‘shing.';list.appendChild(empty)}
  names.forEach(name=>{const item=document.createElement('button');item.type='button';item.className='vehicle-option';item.innerHTML='<i class="fa-solid fa-truck-fast"></i><span></span><i class="fa-solid fa-chevron-right"></i>';item.querySelector('span').textContent=name;item.addEventListener('click',async()=>{const msgEl=modal.querySelector('#vehicleModalMessage');msgEl.textContent='';try{if(SERVER_MODE)await serverEnterVehicle(name);else await vaultOpen(name)}catch(err){msgEl.textContent=err.message;return}modal.classList.add('hidden');enterTruck(name)});list.appendChild(item)});
  const limit=SERVER_MODE&&serverFirm?serverFirm.limit:Number(company?.vehicleLimit||0);modal.querySelector('.vehicle-modal-subtitle').textContent=`${names.length} / ${limit} ta mashina qo‘shilgan`;
  modal.querySelector('#vehicleModalMessage').textContent='';modal.querySelector('#newVehiclePlate').value='';modal.classList.remove('hidden');
}
document.getElementById('vehiclePickerBtn')?.addEventListener('click',renderVehicleModal);
function enterTruck(number){
  activeTruck=number;
  resetIdle();
  loadTruckBasics();
  renderRouteCargo();
  loadRepairNotes();
  loginPage.classList.add('hidden');
  dashboardPage.classList.remove('hidden');
  showView('home');
  if(typeof renderOverall==='function')renderOverall(); if(typeof renderChina==='function')renderChina();
  backfillChinaUsd();
  window.scrollTo(0,0);
  checkSmaskaReminder();
}
loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const number=document.getElementById('truckNumber').value.trim();
  const password=document.getElementById('password').value;
  const accounts=truckAccounts();
  if(!number||!password){alert('Firma nomi va parolni kiriting.');return;}
  await modeReady;
  if(SERVER_MODE){
    try{
      const r=await api('firm-login',{name:number,password});
      serverFirm={token:r.token,name:r.firm.name,limit:r.firm.limit,vehicles:r.vehicles};
      activeCompany=r.firm.name;document.getElementById('password').value='';
      renderVehicleModal();
    }catch(err){alert(err.message||'Kirishda xatolik.');}
    return;
  }
  const lockKey='firm:'+normalizeCompanyName(number);
  const wait=lockRemaining(lockKey);
  if(wait){alert(lockText(wait));return;}
  const matched=findCompanyAccount(accounts,number);
  // Firma topilmasa ham bir xil javob va bir xil kutish: firma nomlarini taxmin qilib bo‘lmasin.
  let ok=false;
  try{ ok=matched?await verifyAndUpgrade(accounts,matched.name,password):(await hashSecret(password,'x',SEC_ITER),false); }
  catch(err){alert(err.message||'Tekshirishda xatolik.');return;}
  if(!ok){registerFail(lockKey);alert('Firma nomi yoki paroli noto‘g‘ri.');return;}
  clearFails(lockKey);
  activeCompany=matched.name;
  document.getElementById('password').value='';
  // Firma loginidan so‘ng doim mashina tanlash oynasi ochiladi.
  renderVehicleModal();
});
const views = {
  home: ['homeView', 'Asosiy joy'],
  vehicle: ['vehicleView', 'Mashina haqida ma’lumot'],
  routes: ['routesView', 'Yo‘nalishlar'],
  repair: ['repairView', 'Remont'],
  expenses: ['expensesView', 'Xarajat'],
  garage: ['garageView', 'Garaj'],
  overall: ['overallView', 'Obshiy rasxod'],
  china: ['chinaView', 'Xitoy'],
  history: ['historyView', 'Eski reyslar'],
  payments: ['paymentsView', 'To‘lov']
};
document.querySelectorAll('.menu-link').forEach(button => {
  button.addEventListener('click', () => showView(button.dataset.view));
});
function showView(name) {
  Object.values(views).forEach(([id]) => document.getElementById(id).classList.add('hidden'));
  document.getElementById(views[name][0]).classList.remove('hidden');
  document.getElementById('pageTitle').textContent = views[name][1];
  if (name === 'history') renderHistory();
  if (name === 'payments') renderPayments();
  document.querySelectorAll('.menu-link').forEach(button => button.classList.toggle('active', button.dataset.view === name));
}
document.getElementById('backToMap').addEventListener('click', () => showView('home'));

// Interactive OpenStreetMap + Leaflet map.
let routeMap = null;
let originMarker = null;
let destinationMarker = null;
let routeLine = null;

function initRouteMap() {
  if (routeMap || !window.L) return;
  routeMap = L.map('mapCanvas').setView([42, 85], 3);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 18,
    attribution: '&copy; OpenStreetMap contributors'
  }).addTo(routeMap);
}
function coloredPin(colorClass) {
  return L.divIcon({
    className: '',
    html: `<div class="route-pin ${colorClass}"></div>`,
    iconSize: [18, 18],
    iconAnchor: [9, 9]
  });
}
async function findCity(city) {
  const url = `https://nominatim.openstreetmap.org/search?format=json&limit=1&q=${encodeURIComponent(city)}`;
  const response = await fetch(url, { headers: { 'Accept-Language': 'uz,en,ru' } });
  if (!response.ok) throw new Error('Shahar qidiruvi vaqtincha ishlamayapti.');
  const results = await response.json();
  if (!results.length) throw new Error(`“${city}” shahri topilmadi. Shahar nomini aniqroq yozing.`);
  return { lat: Number(results[0].lat), lon: Number(results[0].lon), name: results[0].display_name };
}
function formatDistance(meters) {
  if (meters >= 1000) return `${Math.round(meters / 100) / 10} km`;
  return `${Math.round(meters)} m`;
}
async function getRoadRoute(from, to) {
  const url = `https://router.project-osrm.org/route/v1/driving/${from.lon},${from.lat};${to.lon},${to.lat}?overview=full&geometries=geojson`;
  const response = await fetch(url);
  if (!response.ok) throw new Error('Yo‘l masofasini hisoblab bo‘lmadi.');
  const data = await response.json();
  if (data.code !== 'Ok' || !data.routes || !data.routes.length) {
    throw new Error('Bu shaharlar orasida avtomobil yo‘li topilmadi.');
  }
  return data.routes[0];
}
routeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const fromName = document.getElementById('fromCity').value.trim();
  const toName = document.getElementById('toCity').value.trim();
  const cargo = document.getElementById('cargoInfo').value.trim();
  if (!fromName || !toName) return;

  const message = document.getElementById('routeMessage');
  message.textContent = 'Shaharlar qidirilmoqda va yo‘l masofasi hisoblanmoqda...';
  const submitButton = routeForm.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  submitButton.style.opacity = '.7';

  try {
    initRouteMap();
    const from = await findCity(fromName);
    // Pause briefly between geocoding requests to be polite to the public geocoder.
    await new Promise(resolve => setTimeout(resolve, 1100));
    const to = await findCity(toName);
    const road = await getRoadRoute(from, to);

    if (originMarker) routeMap.removeLayer(originMarker);
    if (destinationMarker) routeMap.removeLayer(destinationMarker);
    if (routeLine) routeMap.removeLayer(routeLine);

    originMarker = L.marker([from.lat, from.lon], { icon: coloredPin('origin') })
      .addTo(routeMap).bindPopup(`<strong style="color:#1674ff">Boshlanish:</strong> ${escapeHtml(fromName)}`);
    destinationMarker = L.marker([to.lat, to.lon], { icon: coloredPin('destination') })
      .addTo(routeMap).bindPopup(`<strong style="color:#f04452">Manzil:</strong> ${escapeHtml(toName)}`);
    routeLine = L.geoJSON(road.geometry, {
      style: { color: '#2865f6', weight: 5, opacity: 0.85 }
    }).addTo(routeMap);
    routeMap.fitBounds(routeLine.getBounds().pad(0.12), { maxZoom: 7 });
    setTimeout(() => routeMap.invalidateSize(), 100);

    lastRoute = { from: fromName, to: toName, cargo, distance: road.distance, duration: road.duration };
    syncRouteFields(fromName,toName);
    setTruckValue('route',JSON.stringify(lastRoute));
    document.getElementById('largeMapLink').href = `https://www.openstreetmap.org/directions?engine=fossgis_osrm_car&route=${from.lat}%2C${from.lon}%3B${to.lat}%2C${to.lon}`;
    document.getElementById('routeStatus').textContent = `${fromName} → ${toName}`;
    message.innerHTML = `<div class="route-result"><strong><span style="color:#1674ff">● ${escapeHtml(fromName)}</span> → <span style="color:#f04452">● ${escapeHtml(toName)}</span></strong><p><b>Yo‘l masofasi:</b> ${formatDistance(road.distance)}</p><p><b>Taxminiy haydash vaqti:</b> ${Math.round(road.duration / 3600 * 10) / 10} soat</p>${cargo ? `<p><b>Yuk:</b> ${escapeHtml(cargo)}</p>` : ''}<small>Masofa avtomobil yo‘li bo‘yicha taxminiy hisoblanadi.</small></div>`;
    document.getElementById('savedRoute').innerHTML = `<strong style="color:#1674ff">● ${escapeHtml(fromName)}</strong> → <strong style="color:#f04452">● ${escapeHtml(toName)}</strong><p><b>Masofa:</b> ${formatDistance(road.distance)}</p><p><b>Taxminiy vaqt:</b> ${Math.round(road.duration / 3600 * 10) / 10} soat</p>${cargo ? '<p>Yuk: ' + escapeHtml(cargo) + '</p>' : ''}`;
  } catch (error) {
    message.textContent = error.message || 'Xatolik yuz berdi. Internet aloqasini tekshirib qayta urinib ko‘ring.';
  } finally {
    submitButton.disabled = false;
    submitButton.style.opacity = '1';
  }
});

document.getElementById('vehicleForm').addEventListener('submit', (event) => {
  event.preventDefault();
  const model = document.getElementById('vehicleModel').value.trim();
  const plate = document.getElementById('vehiclePlate').value.trim();
  document.getElementById('vehicleSaved').textContent = `Ma’lumot saqlandi: ${model || 'Model kiritilmagan'} · ${plate || 'Raqam kiritilmagan'}`;
  if (plate) document.getElementById('vehicleNumberDisplay').textContent = plate;
  setTruckValue('vehicleProfile',JSON.stringify({model,note:document.getElementById('vehicleNote').value.trim()}));
});
function escapeHtml(value) {
  return value.replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}


// Xarajatlar: valyuta kursi internetdan olinadi va yozuvga biriktiriladi.
let liveRates=null, ratesPromise=null, ratesDate='';
const safeCur=c=>String(c||'').replace(/[^A-Za-z]/g,'').slice(0,5);
const currencyNames={USD:'$',UZS:'so‘m',CNY:'yuan',KZT:'tenge',RUB:'rubl'};
async function getRates(){if(liveRates)return liveRates;if(!ratesPromise)ratesPromise=fetch('https://open.er-api.com/v6/latest/USD').then(r=>{if(!r.ok)throw Error('Kurs servisi javob bermadi');return r.json()}).then(d=>{if(d.result!=='success')throw Error('Valyuta kursini olib bo‘lmadi');liveRates=d.rates;ratesDate=d.time_last_update_utc||new Date().toISOString();return liveRates}).catch(e=>{ratesPromise=null;throw e});return ratesPromise}
function readExpense(k){try{return JSON.parse(getTruckValue(k)||'[]')}catch(e){return []}}
function saveExpense(k,x){const a=readExpense(k);a.unshift({...x,trip:Number(x.trip||getTruckValue('currentReysNo')||1)});setTruckValue(k,JSON.stringify(a))}
function fmtMoney(n,c){return new Intl.NumberFormat('en-US',{maximumFractionDigits:2}).format(Number(n)||0)+' '+(currencyNames[safeCur(c)]||safeCur(c))}
function dateToLocalInput(d){return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`}
function setTodayIfEmpty(id){const e=document.getElementById(id);if(e&&!e.value)e.value=dateToLocalInput(new Date())}
function convertMoney(amount,currency,r){if(!r[currency]||!r.UZS)throw Error('Tanlangan valyuta kursi mavjud emas.');const usd=Number(amount)/r[currency];return {usd,uzs:usd*r.UZS}}
function previewMoney(a,c,p){const amount=Number(document.getElementById(a).value),cur=document.getElementById(c).value,out=document.getElementById(p);if(!amount||amount<=0){out.textContent='Dollar va so‘mdagi qiymat kurs asosida chiqadi.';return}getRates().then(r=>{const x=convertMoney(amount,cur,r);out.textContent=`≈ ${fmtMoney(x.usd,'USD')} · ${fmtMoney(x.uzs,'UZS')} (kurs: ${ratesDate.slice(0,16)})`}).catch(()=>out.textContent='Kursni olish uchun internetni tekshiring.')}
[['dieselPrice','dieselCurrency','dieselConversion'],['cargoPrice','cargoCurrency','cargoConversion'],['platonAmount','platonCurrency','platonConversion']].forEach(([a,c,p])=>{document.getElementById(a).addEventListener('input',()=>previewMoney(a,c,p));document.getElementById(c).addEventListener('change',()=>previewMoney(a,c,p))});
['dieselDate','cargoDate','platonDate'].forEach(setTodayIfEmpty);
const dieselLitersEl=document.getElementById('dieselLiters'), dieselUnitEl=document.getElementById('dieselUnitPrice'), dieselTotalEl=document.getElementById('dieselTotalPreview');
function calcDieselTotal(){
  const l=Number(dieselLitersEl.value)||0,p=Number(dieselUnitEl.value)||0,cur=document.getElementById('dieselCurrency').value;
  const total=Math.round(l*p*100)/100;
  document.getElementById('dieselPrice').value=total?String(total):'';
  dieselTotalEl.textContent=total?`Jami: ${l.toLocaleString('uz-UZ')} litr × ${p.toLocaleString('uz-UZ')} = ${total.toLocaleString('uz-UZ')} ${currencyNames[cur]||cur}`:'';
  // Dasturiy yozilgan qiymat "input" hodisasini chiqarmaydi, shuning uchun dollar qiymatini qo‘lda yangilaymiz.
  previewMoney('dieselPrice','dieselCurrency','dieselConversion');
}
[dieselLitersEl,dieselUnitEl].forEach(el=>el?.addEventListener('input',calcDieselTotal));
document.getElementById('dieselCurrency')?.addEventListener('change',calcDieselTotal);
document.getElementById('dieselPrice')?.addEventListener('input',()=>{dieselTotalEl.textContent='';});
document.getElementById('dieselForm')?.addEventListener('reset',()=>{dieselTotalEl.textContent='';document.getElementById('dieselConversion').textContent='Dollar va so‘mdagi qiymat kurs asosida chiqadi.';});
// Obshiy rasxod: qo'shimcha kategoriyalar valyuta kursi bilan USD ga aylantirib saqlanadi.
document.querySelectorAll('.overall-category-form').forEach(form=>{
  const dateInput=form.querySelector('[name="date"]'); if(dateInput) dateInput.value=dateToLocalInput(new Date());
  const tripInput=form.querySelector('[name="trip"]'); if(tripInput) tripInput.value=Number(getTruckValue('currentReysNo')||1);
  form.addEventListener('submit',async e=>{
    e.preventDefault(); const fd=new FormData(form), amount=Number(fd.get('amount')), currency=String(fd.get('currency'));
    const button=form.querySelector('button[type="submit"]'); button.disabled=true;
    try{
      const rates=await getRates(), converted=convertMoney(amount,currency,rates), category=form.dataset.category;
      const records=readExpense('furaOverallExpenses');
      records.unshift({category,trip:Number(fd.get('trip')),place:String(fd.get('place')).trim(),amount,currency,date:String(fd.get('date')),amountUsd:converted.usd,amountUzs:converted.uzs,rateDate:ratesDate,savedAt:new Date().toISOString()});
      setTruckValue('furaOverallExpenses',JSON.stringify(records)); form.reset();
      form.querySelector('[name="date"]').value=dateToLocalInput(new Date());
      form.querySelector('[name="trip"]').value=Number(getTruckValue('currentReysNo')||1);
      renderOverall();
    }catch(err){alert(err.message||'Valyuta kursini olib bo‘lmadi. Internetni tekshiring.')}finally{button.disabled=false;}
  });
});
function renderRouteCargo(){
  const box=document.getElementById('routeCargoPrice'); if(!box) return;
  const cur=Number(getTruckValue('currentReysNo')||1);
  const recs=readExpense('furaCargoExpenses').filter(x=>Number(x.trip||cur)===cur);
  if(!recs.length){box.innerHTML='<b>Yuk narxi:</b> hali kiritilmagan (Asosiy joy → pastda “Yuk narxi”).';return;}
  const total=recs.reduce((sum,x)=>sum+usdValue(x),0);
  box.innerHTML='<b>Yuk narxi</b>'+recs.map(x=>`<p>${escapeHtml(String(x.from||'—'))} → ${escapeHtml(String(x.to||'—'))}: ${escapeHtml(fmtMoney(x.amount,x.currency))} (≈ ${escapeHtml(fmtMoney(x.amountUsd,'USD'))}) · ${escapeHtml(String(x.date||''))}</p>`).join('')+`<p><b>Jami yuk narxi:</b> ${escapeHtml(fmtMoney(total,'USD'))}</p>`;
}
function usdValue(x){return Number(x.amountUsd??(x.currency==='USD'?x.amount:0))||0;}
const CAT_ORDER=['Remont','Yeb-ichish','Shafyor oyligi','Solyarka (dizel)','Platon','Xitoy xarajatlari','To‘lovlar'];
function breakdownHtml(list){
  const sums={};CAT_ORDER.forEach(c=>sums[c]=0);
  list.forEach(x=>{sums[x.cat]=(sums[x.cat]||0)+x.usd});
  const total=list.reduce((sum,x)=>sum+x.usd,0);
  return `<div class="expense-breakdown"><div class="expense-breakdown-title">Rasxod qayerga ishlatildi</div>${Object.entries(sums).map(([c,v])=>`<div class="expense-breakdown-row"><span>${escapeHtml(c)}</span><b>$${v.toFixed(2)}</b></div>`).join('')}<div class="expense-breakdown-row expense-breakdown-total"><span>Obshiy rasxod</span><b>$${total.toFixed(2)}</b></div></div>`;
}
// Barcha reyslar bo‘yicha yuk narxi va rasxodlar ro‘yxati (dollarda).
function collectTripFinance(){
  const cargo=readExpense('furaCargoExpenses'),costList=[];
  const add=(cat,arr)=>arr.forEach(x=>costList.push({cat,trip:Number(x.trip||0),usd:usdValue(x)}));
  add('Remont',readRepairCosts().map(x=>({...x,currency:'USD',amountUsd:Number(x.amount)||0})));
  add('Solyarka (dizel)',readExpense('furaDieselExpenses'));add('Platon',readExpense('furaPlatonExpenses'));
  add('Shafyor oyligi',readExpense('furaSalaryExpenses'));add('Xitoy xarajatlari',readExpense('furaChinaExpenses'));add('To‘lovlar',readExpense('furaPaymentExpenses'));
  readExpense('furaOverallExpenses').filter(x=>x.category).forEach(x=>costList.push({cat:x.category,trip:Number(x.trip||0),usd:usdValue(x)}));
  return {cargo,costList};
}
const openHist=new Set();
function toggleHistoryCard(head){
  const body=head.nextElementSibling,n=String(head.dataset.n),opening=body.classList.contains('hidden');
  body.classList.toggle('hidden',!opening);head.setAttribute('aria-expanded',String(opening));
  const ch=head.querySelector('.hchev');if(ch)ch.textContent=opening?'▴':'▾';
  if(opening)openHist.add(n);else openHist.delete(n);
}
document.getElementById('historyList')?.addEventListener('click',ev=>{const h=ev.target.closest('.history-head');if(h)toggleHistoryCard(h)});
document.getElementById('historyList')?.addEventListener('keydown',ev=>{if(ev.key!=='Enter'&&ev.key!==' ')return;const h=ev.target.closest('.history-head');if(h){ev.preventDefault();toggleHistoryCard(h)}});
function renderHistory(){
  const box=document.getElementById('historyList'); if(!box) return;
  const current=Number(getTruckValue('currentReysNo')||1),trips=readTrips(),{cargo,costList}=collectTripFinance(),ids=new Set();
  const old=n=>Number.isFinite(n)&&n>0&&n<current;
  trips.forEach(t=>{if(old(Number(t.reysNo)))ids.add(Number(t.reysNo))});
  cargo.forEach(x=>{if(old(Number(x.trip)))ids.add(Number(x.trip))});
  costList.forEach(x=>{if(old(x.trip))ids.add(x.trip)});
  const list=[...ids].sort((a,b)=>b-a);
  if(!list.length){box.innerHTML='<div class="empty-report">Hozircha tugagan (eski) reys yo‘q. Reys “Garaj → Reysni saqlash” bilan yopilgach shu yerda ko‘rinadi.</div>';return;}
  const e=v=>escapeHtml(String(v||'—'));
  box.innerHTML=list.map(n=>{
    const t=trips.find(x=>Number(x.reysNo)===n)||{},cr=cargo.filter(x=>Number(x.trip)===n);
    const revenue=cr.reduce((sum,x)=>sum+usdValue(x),0),mine=costList.filter(x=>x.trip===n),expenses=mine.reduce((sum,x)=>sum+x.usd,0),profit=revenue-expenses;
    const pick=t.date||(cr.length?cr[cr.length-1].date:''),from=t.from||(cr[0]&&cr[0].from),to=t.to||(cr[0]&&cr[0].to);
    const deliv=t.deliveryDate?['Topshirilgan sana',t.deliveryDate]:['Reys yopilgan sana',t.savedAt?String(t.savedAt).slice(0,10):''];
    const orig=cr.map(x=>fmtMoney(x.amount,x.currency)).join(' + ');
    const cls=profit>=0?'profit-positive':'profit-negative';
    return `<article class="panel history-card"><div class="history-head" data-n="${n}" role="button" tabindex="0" aria-expanded="${openHist.has(String(n))}"><span class="hchev">${openHist.has(String(n))?'▴':'▾'}</span><strong>${n}-reys</strong><span class="history-sum">${e(from)} → ${e(to)}</span><span class="${cls}">${profit>=0?'Foyda':'Zarar'} $${Math.abs(profit).toFixed(2)}</span></div>
<div class="history-body${openHist.has(String(n))?'':' hidden'}"><div class="history-grid"><div><small>Yuk</small><b>${e(t.cargo)}${t.weight?' · '+escapeHtml(String(t.weight)):''}</b></div><div><small>Yuk olingan joy</small><b>${e(from)}</b></div><div><small>Topshirilgan joy</small><b>${e(to)}</b></div><div><small>Yuk olingan sana</small><b>${e(pick)}</b></div><div><small>${deliv[0]}</small><b>${e(deliv[1])}</b></div><div><small>Yuk narxi (olingan)</small><b>${e(orig)}</b></div></div>
<div class="trip-profit-values"><div><small>Yuk narxi</small><b>$${revenue.toFixed(2)}</b></div><div><small>Rasxod</small><b>$${expenses.toFixed(2)}</b></div><div><small>${profit>=0?'Foyda':'Zarar'}</small><b class="${cls}">$${profit.toFixed(2)}</b></div></div>${breakdownHtml(mine)}</div></article>`;
  }).join('');
}
// Aftol va Moy: erkin yozuv (input ochiladi, avtomatik saqlanadi).
function loadRepairNotes(){
  document.querySelectorAll('.repair-note-box').forEach(box=>{
    const v=getTruckValue(box.dataset.noteKey)||'',input=box.querySelector('.repair-note-input');
    input.value=v;box.querySelector('.repair-note-field').classList.toggle('hidden',!v);box.querySelector('.repair-note-saved').textContent='';
  });
}
document.querySelectorAll('.repair-note-box').forEach(box=>{
  const field=box.querySelector('.repair-note-field'),input=box.querySelector('.repair-note-input'),saved=box.querySelector('.repair-note-saved');
  box.querySelector('.repair-note-toggle').addEventListener('click',()=>{field.classList.toggle('hidden');if(!field.classList.contains('hidden'))input.focus();});
  input.addEventListener('input',()=>{setTruckValue(box.dataset.noteKey,input.value);saved.textContent='Saqlandi ✓';});
});
// ===== Davlat/shahar nomiga qarab valyutani avtomatik tanlash =====
const CURRENCIES={USD:'Dollar ($)',UZS:'So‘m (UZS)',CNY:'Yuan (CNY)',KZT:'Tenge (KZT)',RUB:'Rubl (RUB)',KGS:'Qirg‘iz somi (KGS)',TJS:'Somoni (TJS)',TMT:'Manat (TMT)',TRY:'Lira (TRY)',AZN:'Ozarbayjon manati (AZN)',GEL:'Lari (GEL)',AMD:'Dram (AMD)',BYN:'Belarus rubli (BYN)',UAH:'Grivna (UAH)',PLN:'Zlotiy (PLN)',EUR:'Yevro (EUR)',IRR:'Eron riyoli (IRR)',AFN:'Afg‘oni (AFN)',MNT:'Tugrik (MNT)',PKR:'Pokiston rupiyasi (PKR)',INR:'Hind rupiyasi (INR)',KRW:'Von (KRW)',JPY:'Iyena (JPY)',AED:'Dirham (AED)',SAR:'Saudiya riyoli (SAR)'};
const PLACE_CURRENCY=[
 ['UZS',['ozbekiston','uzbekistan','узбекистан','toshkent','tashkent','ташкент','samarqand','samarkand','buxoro','bukhara','andijon','namangan','fargona','nukus','termiz','qarshi','urganch','navoiy','jizzax','guliston','xiva','qoqon','angren','olmaliq','chirchiq','bekobod','sirdaryo','surxondaryo','qashqadaryo','xorazm','qoraqalpogiston','sariosiyo','gazli','kattaqorgon']],
 ['KZT',['qozogiston','qozoqiston','kazakhstan','kazakstan','kazaxstan','казахстан','almaty','алматы','astana','nur sultan','shymkent','shimkent','aktau','aqtau','aktobe','aqtobe','qizilorda','kyzylorda','taraz','oral','uralsk','atyrau','karaganda','qaraganda','semey','kostanay','pavlodar','turkistan','petropavl','taldiqorgan','kokshetau','ust kamenogorsk','oskemen','zhezkazgan','beyneu','boyneu','saryagash','sariagash','khorgos','xorgos']],
 ['RUB',['rossiya','russia','россия','moskva','moscow','москва','sankt peterburg','peterburg','novosibirsk','yekaterinburg','ekaterinburg','kazan','samara','orenburg','chelyabinsk','omsk','rostov','krasnodar','volgograd','ufa','saratov','nijniy novgorod','nizhny novgorod','tyumen','kemerovo','krasnoyarsk','irkutsk','vladivostok','perm','voronej','voronezh','tolyatti','ulyanovsk','penza','kurgan','tula','ryazan','astraxan','astrakhan','kaliningrad','smolensk','bryansk','kursk','lipetsk','tambov','chita','novokuznetsk','barnaul','tomsk']],
 ['CNY',['xitoy','qitay','kitay','china','китай','urumchi','urumqi','kashgar','kashi','guangzhou','guanchjou','shanghai','shanxay','beijing','pekin','yiwu','shenzhen','lanzhou','xian','chengdu','tianjin','alashankou','irkeshtam','turpan','hami','dunhuang','wuhan','chongqing','ningbo','qingdao','harbin','xinjiang','sinszyan','korla','aksu','hotan','yining','kuytun','changji','shihezi']],
 ['KGS',['qirgiziston','kyrgyzstan','kirgiziston','kirgizstan','bishkek','jalal abad','jalalabad','karakol','naryn','torugart']],
 ['TJS',['tojikiston','tajikistan','dushanbe','xujand','khujand','kulob','panjakent']],
 ['TMT',['turkmaniston','turkmenistan','ashgabat','ashxobod','turkmenbashi','dashoguz','mary','turkmenabat']],
 ['TRY',['turkiya','turkey','turkiye','istanbul','ankara','izmir','bursa','antalya','mersin']],
 ['AZN',['ozarbayjon','azerbaijan','azerbaydjan','baku']],
 ['GEL',['gruziya','georgia','tbilisi','batumi','poti','kutaisi']],
 ['AMD',['armaniston','armenia','yerevan']],
 ['BYN',['belarus','belorussiya','minsk','brest','gomel','grodno','vitebsk','mogilev']],
 ['UAH',['ukraina','ukraine','kiev','kyiv','xarkov','kharkiv','odessa','lvov','lviv','dnepr']],
 ['PLN',['polsha','poland','varshava','warsaw','krakow','gdansk','poznan','lodz']],
 ['EUR',['germaniya','germany','berlin','fransiya','france','parij','italiya','italy','ispaniya','spain','niderlandiya','gollandiya','netherlands','litva','lithuania','vilnyus','latviya','latvia','riga','estoniya','estonia','tallin','avstriya','austria','vena','belgiya','finlyandiya','gretsiya','portugaliya','yevropa','euro','yevro','hamburg','munich','myunxen','rotterdam','antwerp']],
 ['IRR',['eron','iran','tehron','tehran','mashhad','bandar abbas']],
 ['AFN',['afgoniston','afganistan','afghanistan','kabul','hairatan','mazori sharif','mazar i sharif']],
 ['MNT',['mongoliya','mongolia','ulanbator','ulaanbaatar']],
 ['PKR',['pokiston','pakistan','karachi','lahore','islamabad']],
 ['INR',['hindiston','india','dehli','delhi','mumbai','bombay']],
 ['KRW',['janubiy koreya','koreya','korea','seul','seoul','busan']],
 ['JPY',['yaponiya','japan','tokio','tokyo','osaka']],
 ['AED',['baa','uae','dubay','dubai','abu dabi','abu dhabi','sharja','sharjah','emirates','arab amirliklari']],
 ['SAR',['saudiya','saudi','saudiya arabistoni','riyod','riyadh','jidda','jeddah']],
 ['USD',['aqsh','usa','amerika','america','united states','nyu york','new york','los angeles','texas','california']]
];
function normPlace(v){return String(v||'').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g,'').replace(/[ʻʼ'’`‘´]/g,'').replace(/[^a-z0-9Ѐ-ӿ]+/g,' ').trim();}
const PLACE_INDEX=PLACE_CURRENCY.map(([code,keys])=>[code,keys.map(normPlace)]);
function currencyForPlace(text){
  const words=normPlace(text); if(!words) return null;
  const padded=' '+words+' ',tokens=words.split(' ');
  for(const [code,keys] of PLACE_INDEX) for(const k of keys){
    if(padded.includes(' '+k+' ')) return code;
    if(k.length>=5&&!k.includes(' ')&&tokens.some(w=>w.startsWith(k))) return code;
  }
  return null;
}
function ensureCurrencyOption(select,code){
  if(![...select.options].some(o=>o.value===code)){const o=document.createElement('option');o.value=code;o.textContent=CURRENCIES[code]||code;select.appendChild(o);}
}
function fillCurrencySelect(id){const sel=document.getElementById(id);if(!sel)return;sel.innerHTML='';Object.entries(CURRENCIES).forEach(([code,label])=>{const o=document.createElement('option');o.value=code;o.textContent=label;sel.appendChild(o);});}
// Joy/davlat maydoniga yozilganda valyuta tanlovi o‘zi almashadi (keyin qo‘lda o‘zgartirsa bo‘ladi).
function bindCountryCurrency(place,select){
  if(!place||!select) return;
  const apply=()=>{
    const code=currencyForPlace(place.value);
    if(!code||code===place.dataset.autoCur) return;
    place.dataset.autoCur=code;ensureCurrencyOption(select,code);
    if(select.value!==code){select.value=code;try{select.dispatchEvent(new Event('change',{bubbles:true}))}catch(e){}}
  };
  ['input','change','blur'].forEach(ev=>place.addEventListener(ev,apply));
  place.closest('form')?.addEventListener('reset',()=>{delete place.dataset.autoCur});
}
bindCountryCurrency(document.getElementById('dieselLocation'),document.getElementById('dieselCurrency'));
bindCountryCurrency(document.getElementById('platonLocation'),document.getElementById('platonCurrency'));
bindCountryCurrency(document.getElementById('payCountry'),document.getElementById('payCurrency'));
document.querySelectorAll('.overall-category-form').forEach(f=>bindCountryCurrency(f.querySelector('[name="place"]'),f.querySelector('[name="currency"]')));

// ===== To‘lov bo‘limi =====
fillCurrencySelect('payCurrency');
document.getElementById('payAmount')?.addEventListener('input',()=>previewMoney('payAmount','payCurrency','payConversion'));
document.getElementById('payCurrency')?.addEventListener('change',()=>previewMoney('payAmount','payCurrency','payConversion'));
setTodayIfEmpty('payDate');
document.getElementById('paymentForm')?.addEventListener('submit',async e=>{
  e.preventDefault();
  const country=document.getElementById('payCountry').value.trim().slice(0,60),reason=document.getElementById('payReason').value.trim().slice(0,200);
  if(!country||!reason){document.getElementById('paySaved').textContent='Davlat va to‘lov sababini yozing.';return;}
  await storeMoney(e.target,'payAmount','payCurrency','payDate','furaPaymentExpenses',()=>({country,reason}),'paySaved');
  renderPayments();renderOverall();
});
document.getElementById('paymentReport')?.addEventListener('click',e=>{
  const btn=e.target.closest('.pay-del'); if(!btn) return;
  if(!confirm('Bu to‘lov yozuvini o‘chirasizmi?')) return;
  const id=btn.dataset.id;setTruckValue('furaPaymentExpenses',JSON.stringify(readExpense('furaPaymentExpenses').filter(x=>String(x.savedAt)!==id)));
  renderPayments();renderOverall();
});
function renderPayments(){
  const box=document.getElementById('paymentReport'); if(!box) return;
  const recs=readExpense('furaPaymentExpenses');
  if(!recs.length){box.innerHTML='<div class="empty-report">Hozircha to‘lov yozuvi yo‘q.</div>';return;}
  const by={};recs.forEach(x=>{const c=safeCur(x.currency)||'USD';by[c]=(by[c]||0)+(Number(x.amount)||0)});
  const usd=recs.reduce((sum,x)=>sum+usdValue(x),0);
  const rows=recs.map(x=>`<tr><td><strong>${escapeHtml(x.country||'—')}</strong></td><td>${escapeHtml(x.reason||'—')}</td><td><strong>${escapeHtml(fmtMoney(x.amount,x.currency))}</strong><span class="report-subline">≈ ${escapeHtml(fmtMoney(x.amountUsd,'USD'))}</span></td><td>${escapeHtml(x.date||'')}</td><td><button type="button" class="report-btn pay-del" data-id="${escapeHtml(String(x.savedAt))}">O‘chirish</button></td></tr>`).join('');
  box.innerHTML=`<div class="report-table-wrap"><table class="report-table"><thead><tr><th>Davlat</th><th>Nima uchun</th><th>Summa</th><th>Sana</th><th></th></tr></thead><tbody>${rows}</tbody></table></div><div class="report-total">Valyutalar bo‘yicha: ${Object.entries(by).map(([c,v])=>escapeHtml(fmtMoney(v,c))).join(' · ')}<br>Jami dollarda: $${usd.toFixed(2)}</div>`;
}
function renderOverall(){
  const manual=readExpense('furaOverallExpenses');
  const diesel=readExpense('furaDieselExpenses'), cargo=readExpense('furaCargoExpenses'), platon=readExpense('furaPlatonExpenses'), salary=readExpense('furaSalaryExpenses'), china=readExpense('furaChinaExpenses'), repairs=readRepairCosts().map(x=>({...x,category:'Remont',currency:'USD',amountUsd:Number(x.amount)||0,trip:Number(x.trip||0)}));
  const categoryRecords={
    'Remont':[...manual.filter(x=>x.category==='Remont'),...repairs.map(x=>({...x,category:'Remont',place:x.details||x.name,amountUsd:Number(x.amount)||0,currency:'USD',trip:Number(x.trip||0)}))],
    'Yeb-ichish':manual.filter(x=>x.category==='Yeb-ichish'),
    'Platon':[...manual.filter(x=>x.category==='Platon'),...platon]
  };
  document.querySelectorAll('[data-report-category]').forEach(box=>{
    const cat=box.dataset.reportCategory, rows=categoryRecords[cat]||[], byCurrency={};
    rows.forEach(x=>byCurrency[x.currency||'USD']=(byCurrency[x.currency||'USD']||0)+(Number(x.amount)||0));
    const usd=rows.reduce((sum,x)=>sum+usdValue(x),0);
    const lines=Object.entries(byCurrency).map(([c,v])=>`<p><b>${escapeHtml(c)}:</b> ${v.toLocaleString('uz-UZ')}</p>`).join('')||'<p class="garage-muted">Hozircha yozuv yo‘q</p>';
    box.innerHTML=`<div class="overall-category-total"><div class="overall-currency-totals">${lines}</div><strong class="overall-usd-final">Jami dollarda: $${usd.toFixed(2)}</strong></div>`;
  });
  const allExpenses=[...diesel,...platon,...salary,...china,...manual.filter(x=>x.category),...repairs.map(x=>({...x,amountUsd:Number(x.amount)||0,trip:x.trip||0}))];
  const grouped={};
  [...diesel,...cargo,...platon,...salary,...china,...manual,...repairs.map(x=>({...x,currency:'USD'}))].forEach(x=>{const c=x.currency||'USD';grouped[c]=(grouped[c]||0)+(Number(x.amount)||0)});
  const liters=diesel.reduce((sum,x)=>sum+(Number(x.liters)||0),0), dieselUsd=diesel.reduce((sum,x)=>sum+usdValue(x),0);
  document.getElementById('overallSummary').innerHTML=`<div class="overall-fuel-summary"><h3>⛽ Solyarka bo‘yicha jami</h3><div class="overall-fuel-stats"><div><span>Jami quyilgan solyarka</span><strong>${liters.toLocaleString('uz-UZ')} litr</strong></div><div><span>Solyarkaga jami to‘lov</span><strong>$${dieselUsd.toFixed(2)}</strong></div></div></div><h3>Asl valyutalar bo‘yicha sarflangan jami</h3><div class="overall-currency-totals">${Object.entries(grouped).map(([c,n])=>`<p><b>${escapeHtml(c)}:</b> ${n.toLocaleString('uz-UZ')}</p>`).join('')||'<p>Hozircha xarajat yo‘q.</p>'}</div>`;
  // Har bir reys: yuk narxi daromad, qolgan saqlangan yozuvlar xarajat hisoblanadi.
  const tripIds=new Set();
  [...cargo,...diesel,...platon,...salary,...china,...manual,...repairs,...readExpense('furaPaymentExpenses')].forEach(x=>{const n=Number(x.trip||0);if(n>0)tripIds.add(n)});
  readTrips().forEach(x=>tripIds.add(Number(x.reysNo)));
  const currentReysNo=Number(getTruckValue('currentReysNo')||1);
  const ids=[...tripIds].filter(n=>n===currentReysNo);
  const costList=[];
  const addCost=(cat,arr)=>arr.forEach(x=>costList.push({cat,trip:Number(x.trip||0),usd:usdValue(x)}));
  addCost('Remont',repairs);addCost('Solyarka (dizel)',diesel);addCost('Platon',platon);addCost('Shafyor oyligi',salary);addCost('Xitoy xarajatlari',china);addCost('To‘lovlar',readExpense('furaPaymentExpenses'));
  manual.filter(x=>x.category).forEach(x=>costList.push({cat:x.category,trip:Number(x.trip||0),usd:usdValue(x)}));
  const tripRows=ids.map(n=>{
    const revenue=cargo.filter(x=>Number(x.trip||0)===n).reduce((sum,x)=>sum+usdValue(x),0);
    const expenses=costList.filter(x=>x.trip===n).reduce((sum,x)=>sum+x.usd,0), profit=revenue-expenses;
    return `<div class="trip-profit-row"><div class="trip-profit-title"><strong>${n}-reys</strong><span>${profit>=0?'Foyda':'Zarar'}</span></div><div class="trip-profit-values"><div><small>Yuk narxi</small><b>$${revenue.toFixed(2)}</b></div><div><small>Rasxod</small><b>$${expenses.toFixed(2)}</b></div><div><small>Foyda</small><b class="${profit>=0?'profit-positive':'profit-negative'}">$${profit.toFixed(2)}</b></div></div>${revenue>0?`<p class="trip-profit-note">Foyda: ${(profit/revenue*100).toFixed(2)}% (yuk narxiga nisbatan)</p>`:''}${breakdownHtml(costList.filter(x=>x.trip===n))}</div>`;
  }).join('');
  document.getElementById('tripProfitSummary').innerHTML=(tripRows||'<p class="empty-report">Hozircha reys bo‘yicha hisob yo‘q. Yuk narxi va xarajatlarni tegishli reys raqami bilan saqlang.</p>');
}
const chinaTypeInput=document.getElementById('chinaType'),chinaStayFields=document.getElementById('chinaStayFields');function updateChinaStayFields(){const isHotel=/mehmonxona|hotel|гостиниц/i.test(chinaTypeInput?.value||'');chinaStayFields?.classList.toggle('hidden',!isHotel);if(!isHotel){document.getElementById('chinaCheckIn').value='';document.getElementById('chinaCheckOut').value='';}}chinaTypeInput?.addEventListener('input',updateChinaStayFields);updateChinaStayFields();setTodayIfEmpty('chinaDate');document.getElementById('chinaForm')?.addEventListener('submit',async e=>{e.preventDefault();const form=e.target,btn=form.querySelector('button[type=submit],button:not([type])');if(btn)btn.disabled=true;const amountVal=Number(document.getElementById('chinaAmount').value),curVal=document.getElementById('chinaCurrency').value;let usdInfo;try{usdInfo=convertMoney(amountVal,curVal,await getRates())}catch(err){alert(err.message||'Valyuta kursini olib bo‘lmadi. Internetni tekshiring.');if(btn)btn.disabled=false;return}const a=JSON.parse(getTruckValue('furaChinaExpenses')||'[]');a.unshift({amountUsd:usdInfo.usd,amountUzs:usdInfo.uzs,type:document.getElementById('chinaType').value.trim(),checkIn:document.getElementById('chinaCheckIn').value,checkOut:document.getElementById('chinaCheckOut').value,amount:Number(document.getElementById('chinaAmount').value),currency:document.getElementById('chinaCurrency').value,note:document.getElementById('chinaNote').value.trim(),date:dateToLocalInput(new Date()),trip:Number(getTruckValue('currentReysNo')||1)});setTruckValue('furaChinaExpenses',JSON.stringify(a));form.reset();if(btn)btn.disabled=false;updateChinaStayFields();renderChina();renderOverall();});async function backfillChinaUsd(){
  try{
    const a=JSON.parse(getTruckValue('furaChinaExpenses')||'[]');
    if(!a.some(x=>x.amountUsd===undefined))return;
    const r=await getRates();
    a.forEach(x=>{if(x.amountUsd===undefined){try{const c=convertMoney(x.amount,x.currency,r);x.amountUsd=c.usd;x.amountUzs=c.uzs}catch(e){}}});
    setTruckValue('furaChinaExpenses',JSON.stringify(a));renderOverall();renderChina();
  }catch(e){}
}
function renderChina(){const a=JSON.parse(getTruckValue('furaChinaExpenses')||'[]');const sums={};a.forEach(x=>sums[x.currency]=(sums[x.currency]||0)+Number(x.amount||0));document.getElementById('chinaReport').innerHTML='<h3>Xitoy bo‘yicha jami</h3>'+Object.entries(sums).map(([c,n])=>`<p>${escapeHtml(c)}: ${n.toLocaleString('uz-UZ')}</p>`).join('')+`<p><b>Jami dollarda: $${a.reduce((sum,x)=>sum+usdValue(x),0).toFixed(2)}</b></p>`+a.map(x=>`<p><b>${escapeHtml(x.type)}</b> — ${escapeHtml(String(x.amount))} ${escapeHtml(safeCur(x.currency))}; kirish: ${escapeHtml(x.checkIn||'—')}; chiqish: ${escapeHtml(x.checkOut||'—')}; ${escapeHtml(x.note||'')}</p>`).join('');}
async function storeMoney(form,amountId,currencyId,dateId,key,extra,feedbackId){const amount=Number(document.getElementById(amountId).value),currency=document.getElementById(currencyId).value,date=document.getElementById(dateId).value,btn=form.querySelector('button[type="submit"]');btn.disabled=true;try{const r=await getRates(),x=convertMoney(amount,currency,r);saveExpense(key,{...extra(),amount,currency,date,amountUsd:x.usd,amountUzs:x.uzs,rateDate:ratesDate,savedAt:new Date().toISOString()});if(typeof renderRouteCargo==='function')renderRouteCargo();document.getElementById(feedbackId).textContent=`Saqlandi: ${fmtMoney(amount,currency)} ≈ ${fmtMoney(x.usd,'USD')} · ${fmtMoney(x.uzs,'UZS')}.`;form.reset();setTodayIfEmpty(dateId);previewMoney(amountId,currencyId,currencyId.replace('Currency','Conversion'))}catch(e){document.getElementById(feedbackId).textContent=e.message||'Kursni olishda xatolik. Internetni tekshiring.'}finally{btn.disabled=false}}
document.getElementById('dieselForm').addEventListener('submit',e=>{e.preventDefault();storeMoney(e.target,'dieselPrice','dieselCurrency','dieselDate','furaDieselExpenses',()=>({liters:Number(document.getElementById('dieselLiters').value),location:document.getElementById('dieselLocation').value.trim()}),'dieselSaved')});
document.getElementById('cargoForm').addEventListener('submit',e=>{e.preventDefault();storeMoney(e.target,'cargoPrice','cargoCurrency','cargoDate','furaCargoExpenses',()=>({from:document.getElementById('cargoFrom').value.trim(),to:document.getElementById('cargoTo').value.trim()}),'cargoSaved')});
document.getElementById('platonForm').addEventListener('submit',e=>{e.preventDefault();storeMoney(e.target,'platonAmount','platonCurrency','platonDate','furaPlatonExpenses',()=>({location:document.getElementById('platonLocation').value.trim()}),'dieselSaved')});
['China','Russia'].forEach(country=>{const lower=country.toLowerCase(),form=document.getElementById('platon'+country+'Form');setTodayIfEmpty('platon'+country+'Date');form?.addEventListener('submit',async e=>{e.preventDefault();const amount=Number(document.getElementById('platon'+country+'Amount').value),currency=document.getElementById('platon'+country+'Currency').value;try{const r=await getRates(),x=convertMoney(amount,currency,r);saveExpense('furaPlatonExpenses',{location:document.getElementById('platon'+country+'Location').value.trim(),country,amount,currency,date:document.getElementById('platon'+country+'Date').value,amountUsd:x.usd,amountUzs:x.uzs,rateDate:ratesDate,savedAt:new Date().toISOString()});e.target.reset();setTodayIfEmpty('platon'+country+'Date');alert(country==='China'?'Xitoy Platon to‘lovi saqlandi.':'Rossiya Platon to‘lovi saqlandi.')}catch(err){alert('Valyuta kursini olishda xatolik.')}})});
document.querySelectorAll('[data-report]').forEach(b=>b.addEventListener('click',()=>renderExpenseReport(b.dataset.report)));document.getElementById('closeReport').addEventListener('click',()=>document.getElementById('expenseReport').classList.add('hidden'));
function renderExpenseReport(type){const box=document.getElementById('expenseReport'),title=document.getElementById('reportTitle'),table=document.getElementById('reportTable'),diesel=type==='diesel',salary=type==='salary',records=readExpense(salary?'furaSalaryExpenses':diesel?'furaDieselExpenses':'furaPlatonExpenses');title.textContent=salary?'Shafyor oyligi hisoboti':diesel?'Dizel / Solyarka hisoboti':'Platon to‘lovlari hisoboti';box.classList.remove('hidden');if(!records.length){table.innerHTML='<div class="empty-report">Hozircha yozuv yo‘q. Avval ma’lumot kiritib saqlang.</div>';box.scrollIntoView({behavior:'smooth',block:'start'});return}const rows=records.map(x=>`<tr><td><strong>${salary?'Shafyor oyligi':diesel?'Dizel / Solyarka':'Platon'}</strong><span class="report-original">${escapeHtml(salary?(x.routes||[]).join(' → '):(x.location||''))}</span></td><td>${diesel?Number(x.liters).toLocaleString('uz-UZ')+' litr':'—'}</td><td><strong>${fmtMoney(x.amount,x.currency)}</strong><span class="report-subline">≈ ${fmtMoney(x.amountUsd,'USD')}</span><span class="report-original">${fmtMoney(x.amountUzs,'UZS')}</span></td><td>${escapeHtml(x.date)}</td></tr>`).join(''),usd=records.reduce((s,x)=>s+(Number(x.amountUsd)||0),0),uzs=records.reduce((s,x)=>s+(Number(x.amountUzs)||0),0);table.innerHTML=`<div class="report-table-wrap"><table class="report-table"><thead><tr><th>${diesel?'Xarajat / qayerda':'To‘lov / qayerda'}</th><th>${diesel?'Miqdor':'—'}</th><th>Asl valyuta / USD / UZS</th><th>Sana</th></tr></thead><tbody>${rows}</tbody></table></div><div class="report-total">Jami: ${fmtMoney(usd,'USD')} · ${fmtMoney(uzs,'UZS')}<br><small>Har bir yozuvda o‘sha paytdagi kurs saqlanadi. Kurs sanasi: ${escapeHtml(String(records[0].rateDate||'—'))}</small></div>`;box.scrollIntoView({behavior:'smooth',block:'start'})}

// Smaska muddati: almashtirilgan kundan boshlab 25 kun.
const SMASKA_DAYS = 25;
const smaskaDateInput = document.getElementById('smaskaDate');
const smaskaCard = document.getElementById('smaskaCard');

function parseLocalDate(value) {
  const [year, month, day] = value.split('-').map(Number);
  return new Date(year, month - 1, day);
}
function formatDate(date) {
  return new Intl.DateTimeFormat('uz-UZ', { year: 'numeric', month: 'long', day: 'numeric' }).format(date);
}
function renderSmaska() {
  const savedDate = getTruckValue('furaSmaskaChangedDate');
  if (!savedDate) {
    document.getElementById('smaskaChanged').textContent = 'Kiritilmagan';
    document.getElementById('smaskaDue').textContent = '—';
    document.getElementById('smaskaRemaining').textContent = 'Sanani kiriting';
    document.getElementById('smaskaBadge').textContent = 'Sana kerak';
    document.getElementById('smaskaHint').textContent = 'Smaska almashtirilgan sanani kiriting. Tugash sanasi 25 kun keyin avtomatik hisoblanadi.';
    smaskaCard.classList.remove('warning', 'danger');
    return;
  }
  const changed = parseLocalDate(savedDate);
  const due = new Date(changed);
  due.setDate(due.getDate() + SMASKA_DAYS);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const daysLeft = Math.ceil((due.getTime() - today.getTime()) / 86400000);

  document.getElementById('smaskaChanged').textContent = formatDate(changed);
  document.getElementById('smaskaDue').textContent = formatDate(due);
  const remaining = document.getElementById('smaskaRemaining');
  const badge = document.getElementById('smaskaBadge');
  const hint = document.getElementById('smaskaHint');
  smaskaCard.classList.remove('warning', 'danger');

  if (daysLeft < 0) {
    remaining.textContent = `${Math.abs(daysLeft)} kun o‘tib ketdi`;
    badge.textContent = 'Muddati o‘tgan';
    hint.textContent = 'Smaska almashtirish muddati o‘tgan. Imkon qadar tezroq almashtiring.';
    smaskaCard.classList.add('danger');
  } else if (daysLeft <= 3) {
    remaining.textContent = `${daysLeft} kun qoldi`;
    badge.textContent = 'Zudlik bilan';
    hint.textContent = 'Smaska almashtirish vaqti yaqin — qizil rang ogohlantirishi.';
    smaskaCard.classList.add('danger');
  } else if (daysLeft <= 5) {
    remaining.textContent = `${daysLeft} kun qoldi`;
    badge.textContent = 'Yaqinlashmoqda';
    hint.textContent = 'Smaska almashtirishga 5 kun yoki undan kam vaqt qoldi — sariq rang ogohlantirishi.';
    smaskaCard.classList.add('warning');
  } else {
    remaining.textContent = `${daysLeft} kun qoldi`;
    badge.textContent = 'Nazoratda';
    hint.textContent = 'Muddat nazoratda. Garajda smaska almashtirilganda sanani yangilang.';
  }
}
smaskaDateInput.value = dateToLocalInput(new Date());
document.getElementById('smaskaForm').addEventListener('submit', (event) => {
  event.preventDefault();
  if (!smaskaDateInput.value) return;
  setTruckValue('furaSmaskaChangedDate', smaskaDateInput.value);
  renderSmaska();
});
renderSmaska();

// Remont eslatmalari: 5, 3 va 1 kun qolganda brauzer bildirishnomasi.
// Haqiqiy SMS yuborish uchun server va SMS operator xizmati kerak bo‘ladi.
function checkSmaskaReminder(){
  if(!activeTruck) return;
  const savedDate=getTruckValue('furaSmaskaChangedDate');
  if(!savedDate) return;
  const due=parseLocalDate(savedDate); due.setDate(due.getDate()+SMASKA_DAYS);
  const today=new Date(); today.setHours(0,0,0,0);
  const daysLeft=Math.ceil((due.getTime()-today.getTime())/86400000);
  if(![5,3,1].includes(daysLeft)) return;
  const reminderKey=`smaskaReminder:${activeTruck}:${savedDate}:${daysLeft}`;
  if(localStorage.getItem(reminderKey)==='sent') return;
  const message=`${activeTruck}: smaska almashtirishga ${daysLeft} kun qoldi!`;
  if('Notification' in window){
    const send=()=>{try{new Notification('FURA SYSTEM — Remont eslatmasi',{body:message,tag:reminderKey});localStorage.setItem(reminderKey,'sent')}catch(e){console.warn(e)}};
    if(Notification.permission==='granted') send();
    else if(Notification.permission==='default') Notification.requestPermission().then(permission=>{if(permission==='granted')send()});
  } else { alert(message); localStorage.setItem(reminderKey,'sent'); }
}

// Moy: har 3-garaj kelishida almashtirish; 2-kelishda qizil ogohlantirish.
function getOilCount(){const n=parseInt(getTruckValue('oilGarageCount')||'0',10);return Number.isFinite(n)?Math.max(0,n):0;}
function renderOil(){
  const count=getOilCount(),card=document.getElementById('oilCard');
  const oilChanged=getTruckValue('oilChangedDate');const oilDateEl=document.getElementById('oilChangedDate');if(oilDateEl)oilDateEl.textContent=oilChanged||'—';
  if(!card)return;
  card.classList.remove('warning','danger');
  document.getElementById('oilCount').textContent=`${count} / 3`;
  document.getElementById('oilBadge').textContent=`${count} / 3 garaj`;
  if(count>=2){
    card.classList.add('danger');
    document.getElementById('oilStatus').textContent='Moyni almashtirish vaqti yaqin!';
    document.getElementById('oilNext').textContent='3-garajda almashtiring';
    document.getElementById('oilHint').textContent='Qizil ogohlantirish: keyingi garajga kelganda moyni almashtiring.';
  }else{
    document.getElementById('oilStatus').textContent='Nazoratda';
    document.getElementById('oilNext').textContent=`Yana ${2-count} marta garaj`;
    document.getElementById('oilHint').textContent='Moy har 3 marta garajga kelganda almashtiriladi.';
  }
}
function countOilGarageArrival(){
  const previous=getOilCount();
  let count=Math.min(previous+1,3);
  if(previous<3 && count===3){
    document.getElementById('oilNotice')?.remove();
    const notice=document.createElement('div');notice.id='oilNotice';notice.className='oil-notice';
    notice.innerHTML='<strong>FURA SYSTEM eslatmasi</strong><p>3-marta garajga keldi. Moyni almashtiring!</p><button type="button" id="oilNoticeClose">Tushunarli</button>';
    document.body.appendChild(notice);
    document.getElementById('oilNoticeClose').addEventListener('click',()=>notice.remove());
    count=3;
  }
  setTruckValue('oilGarageCount',String(count));
  renderOil();
}
document.getElementById('oilResetBtn')?.addEventListener('click',()=>{
  const today=dateToLocalInput(new Date());setTruckValue('oilChangedDate',today);
  setTruckValue('oilGarageCount','0');
  document.getElementById('oilNotice')?.remove();
  renderOil();
  alert('Moy almashtirilgani saqlandi. Hisob 0 dan boshlandi.');
});

// Kalodka: foydalanuvchi muddatni kunlarda belgilaydi.
function renderKalod(){const date=getTruckValue('kalodChangedDate'),days=parseInt(getTruckValue('kalodDurationDays')||'',10),card=document.getElementById('kalodCard');if(!card)return;const changedEl=document.getElementById('kalodChanged'),dueEl=document.getElementById('kalodDue'),remainingEl=document.getElementById('kalodRemaining'),badge=document.getElementById('kalodBadge');card.classList.remove('warning','danger');if(!date||!Number.isFinite(days)||days<1){changedEl.textContent=date||'—';dueEl.textContent='—';remainingEl.textContent='Muddatni kiriting';badge.textContent='Sozlanmagan';return;}const due=parseLocalDate(date);due.setDate(due.getDate()+days);const today=new Date();today.setHours(0,0,0,0);const left=Math.ceil((due-today)/86400000);dueEl.textContent=dateToLocalInput(due);remainingEl.textContent=left<0?`${Math.abs(left)} kun o‘tgan`:left===0?'Bugun tugaydi':`${left} kun`;changedEl.textContent=date;badge.textContent=left<=0?'Almashtirish kerak':`${days} kunlik`;if(left<=0)card.classList.add('danger');else if(left<=3)card.classList.add('warning');}
document.getElementById('kalodForm')?.addEventListener('submit',e=>{e.preventDefault();const date=document.getElementById('kalodDate').value,days=document.getElementById('kalodDays').value;if(!date||!days||Number(days)<1)return;setTruckValue('kalodChangedDate',date);setTruckValue('kalodDurationDays',String(Number(days)));renderKalod();});
// Garaj va 1-reys: barcha ma’lumotlar mashina raqami bo‘yicha alohida saqlanadi.
function safeText(v){return escapeHtml(String(v==null||v===''?'—':v));}
function renderGarageSummary(){
  const route=JSON.parse(getTruckValue('route')||'null');
  const diesel=readExpense('furaDieselExpenses'),platon=readExpense('furaPlatonExpenses'),cargo=readExpense('furaCargoExpenses');
  const changed=getTruckValue('furaSmaskaChangedDate');
  let smaska='Smaska sanasi kiritilmagan';
  if(changed){const due=parseLocalDate(changed);due.setDate(due.getDate()+SMASKA_DAYS);const today=new Date();today.setHours(0,0,0,0);smaska=`Almashtirilgan: ${safeText(changed)} · Tugash sanasi: ${safeText(dateToLocalInput(due))} · ${Math.ceil((due-today)/86400000)} kun qoldi`;}
  const profile=readVehicleProfile();
  const expenses=(label,arr)=>`<h4>${label}</h4>${arr.length?'<ul>'+arr.slice(0,12).map(x=>`<li>${safeText(x.date)} · ${safeText(x.location||((x.from||'')+' → '+(x.to||'')))} · ${safeText(fmtMoney(x.amount,x.currency))} (≈ ${safeText(fmtMoney(x.amountUsd,'USD'))})${x.liters?` · ${safeText(x.liters)} litr`:''}</li>`).join('')+'</ul>':'<p class="garage-muted">Hozircha ma’lumot yo‘q.</p>'}`;
  document.getElementById('garageSummaryContent').innerHTML=`<div class="garage-summary-grid"><div><h4>Mashina</h4><p><b>Raqam:</b> ${safeText(activeTruck)}</p><p><b>Model:</b> ${safeText(profile.model)}</p><p><b>Izoh:</b> ${safeText(profile.note)}</p></div><div><h4>Yo‘nalish</h4><p><b>Qayerdan:</b> ${safeText(route&&route.from)}</p><p><b>Qayerga:</b> ${safeText(route&&route.to)}</p><p><b>Yuk:</b> ${safeText(route&&route.cargo)}</p></div><div><h4>Remont / smaska</h4><p>${smaska}</p></div></div>${expenses('Dizel / solyarka',diesel)}${expenses('Platon',platon)}${expenses('Yuk narxi',cargo)}`;
}
function readTrips(){try{return JSON.parse(getTruckValue('trips')||'[]')}catch(e){return []}}
function renderTrips(){const trips=readTrips(),box=document.getElementById('tripHistory');if(!trips.length){box.innerHTML='<div class="empty-report">Hozircha 1-reys saqlanmagan. Formani to‘ldirib saqlang.</div>';return;}box.innerHTML='<h4>Saqlangan reyslar</h4>'+trips.map((t,i)=>`<article class="trip-record"><h4>${safeText(String(t.reysNo||trips.length-i))}-reys · ${safeText(t.date)}</h4><p><b>Yuk:</b> ${safeText(t.cargo)} · <b>Og‘irligi:</b> ${safeText(t.weight)}</p><p><b>Yo‘nalish:</b> ${safeText(t.from)} → ${safeText(t.to)}</p><p><b>Solyarka:</b> ${safeText(t.liters||'—')} litr · ${safeText(t.fuelLocation)} · <b>To‘lov:</b> ${safeText(t.fuelCost||'—')}</p><p><b>Platon / yo‘l to‘lovi:</b> ${safeText(t.platon||'—')} · <b>Shafyor oyligi:</b> ${safeText(t.salary||'—')} $ · <b>Remont:</b> ${safeText(t.repairCost||'—')} $</p><p><b>Izoh:</b> ${safeText(t.notes)}</p></article>`).join('');}
document.getElementById('garageSummaryBtn').addEventListener('click',()=>{countOilGarageArrival();renderGarageSummary();document.getElementById('garageSummary').classList.remove('hidden');document.getElementById('tripPanel').classList.add('hidden');});
function autofillTripFromExpenses(){
  // Har bir reysda bir necha marta kiritilgan to'lovlar jamlanadi.
  const currentReys=Number(getTruckValue('currentReysNo')||1);const onlyCurrent=a=>a.filter(x=>Number(x.trip||currentReys)===currentReys);const dieselRecords=onlyCurrent(readExpense('furaDieselExpenses')), platonRecords=onlyCurrent(readExpense('furaPlatonExpenses')), salaryRecords=onlyCurrent(readExpense('furaSalaryExpenses')), cargoRecords=onlyCurrent(readExpense('furaCargoExpenses'));
  const sumField=(records,field)=>records.reduce((sum,item)=>sum+(Number(item[field])||0),0);
  const totalLiters=sumField(dieselRecords,'liters');
  const totalDieselUsd=sumField(dieselRecords,'amountUsd');
  const totalPlatonUsd=sumField(platonRecords,'amountUsd');
  const totalSalaryUsd=sumField(salaryRecords,'amountUsd');
  const fields={tripLiters:totalLiters,tripFuelCost:totalDieselUsd,tripPlaton:totalPlatonUsd,tripSalary:totalSalaryUsd};
  Object.entries(fields).forEach(([id,value])=>{const el=document.getElementById(id);if(el)el.value=value?Number(value).toFixed(2).replace(/\.00$/,''):''});
  const route=JSON.parse(getTruckValue('route')||'null');
  if(route){document.getElementById('tripFrom').value=route.from||'';document.getElementById('tripTo').value=route.to||'';if(route.cargo)document.getElementById('tripCargo').value=route.cargo;}
  const cargo=cargoRecords[0];
  if(cargo){document.getElementById('tripCargoWeight').dataset.cargoPriceUsd=String(cargo.amountUsd||0);}
  const repairTotal=readRepairCosts().filter(item=>Number(item.trip||currentReys)===currentReys).reduce((sum,item)=>sum+(Number(item.amount)||0),0);
  document.getElementById('tripRepairCost').value=repairTotal?repairTotal.toFixed(2).replace(/\.00$/,''):'';
}
document.getElementById('firstTripBtn').addEventListener('click',()=>{document.getElementById('tripPanel').classList.remove('hidden');document.getElementById('garageSummary').classList.add('hidden');setTodayIfEmpty('tripDate');autofillTripFromExpenses();const n=Number(getTruckValue('currentReysNo')||1);document.getElementById('tripPanelTitle').textContent=`${n}-reys ma’lumotlari`;document.querySelector('#tripForm button[type=submit]').innerHTML=`<i class="fa-solid fa-floppy-disk"></i> ${n}-reysni saqlash`;renderTrips();});
document.querySelectorAll('[data-garage-close]').forEach(b=>b.addEventListener('click',()=>document.getElementById(b.dataset.garageClose==='summary'?'garageSummary':'tripPanel').classList.add('hidden')));
setTodayIfEmpty('tripDate');
document.getElementById('tripForm').addEventListener('submit',()=>setTimeout(()=>{renderRouteCargo();renderOverall();},0));
document.getElementById('tripForm').addEventListener('submit',e=>{e.preventDefault();const trips=readTrips();const reysNo=Number(getTruckValue('currentReysNo')||1);const trip={reysNo,date:document.getElementById('tripDate').value,deliveryDate:document.getElementById('tripDeliveryDate').value,cargo:document.getElementById('tripCargo').value.trim(),from:document.getElementById('tripFrom').value.trim(),to:document.getElementById('tripTo').value.trim(),liters:document.getElementById('tripLiters').value,fuelLocation:'',fuelCost:document.getElementById('tripFuelCost').value,platon:document.getElementById('tripPlaton').value,salary:document.getElementById('tripSalary').value,repairCost:document.getElementById('tripRepairCost').value,weight:document.getElementById('tripCargoWeight').value.trim(),notes:document.getElementById('tripNotes').value.trim(),savedAt:new Date().toISOString()};trips.unshift(trip);setTruckValue('trips',JSON.stringify(trips));setTruckValue('currentReysNo',String(reysNo+1));document.getElementById('tripSaved').textContent=`${reysNo}-reys ma’lumotlari saqlandi. Endi ${reysNo+1}-reysni kiriting.`;e.target.reset();setTodayIfEmpty('tripDate');document.getElementById('tripPanelTitle').textContent=`${reysNo+1}-reys ma’lumotlari`;document.querySelector('#tripForm button[type=submit]').innerHTML=`<i class="fa-solid fa-floppy-disk"></i> ${reysNo+1}-reysni saqlash`;renderTrips();});

// Remont xarajatlari: har bir xizmat narxi alohida saqlanadi.
function readRepairCosts(){try{return JSON.parse(getTruckValue('repairCosts')||'[]')}catch(e){return []}}
function addRepairCost(name,amount,date,details=''){const price=Number(amount)||0;const list=readRepairCosts();list.unshift({name,amount:price,date:date||dateToLocalInput(new Date()),details,trip:Number(getTruckValue('currentReysNo')||1),savedAt:new Date().toISOString()});setTruckValue('repairCosts',JSON.stringify(list));}
function setRepairCostInputs(){
  ['aftolMasloFilter','aftolSolyarkaFilter','aftolStistolniy'].forEach((id,i)=>{const el=document.getElementById(id);if(el)el.value=getTruckValue(id)??['18','22','14'][i]});
  const today=dateToLocalInput(new Date());
  ['aftolDate'].forEach(id=>{const el=document.getElementById(id);if(el&&!el.value)el.value=getTruckValue('aftolChangedDate')||today});
  document.getElementById('aftolDays').value=getTruckValue('aftolDurationDays')||'';
  document.getElementById('aftolPrice').value=getTruckValue('aftolPrice')??'54';
  document.getElementById('oilPrice').value=getTruckValue('oilPrice')??'310';
  document.getElementById('oilServicePrice').value=getTruckValue('oilServicePrice')??'0';
  document.getElementById('oilDescription').value=getTruckValue('oilDescription')||'Kastrol 10x40 40 litr 310 $';
  document.getElementById('smaskaPrice').value=getTruckValue('smaskaPrice')??'0';
  document.getElementById('kalodPrice').value=getTruckValue('kalodPrice')??'0';
  renderAftol();
}
function renderAftol(){const date=getTruckValue('aftolChangedDate'),days=Number(getTruckValue('aftolDurationDays')),card=document.getElementById('aftolCard');if(!card)return;card.classList.remove('warning','danger');const changed=document.getElementById('aftolChanged'),dueEl=document.getElementById('aftolDue'),remaining=document.getElementById('aftolRemaining'),badge=document.getElementById('aftolBadge');if(!date||!days){changed.textContent=date||'—';dueEl.textContent='—';remaining.textContent='Muddatni kiriting';badge.textContent='Sozlanmagan';return}const due=parseLocalDate(date);due.setDate(due.getDate()+days);const today=new Date();today.setHours(0,0,0,0);const left=Math.ceil((due-today)/86400000);changed.textContent=date;dueEl.textContent=dateToLocalInput(due);remaining.textContent=left<0?`${Math.abs(left)} kun o‘tgan`:left===0?'Bugun tugaydi':`${left} kun`;badge.textContent=left<=0?'Almashtirish kerak':`${days} kunlik`;if(left<=0)card.classList.add('danger');else if(left<=3)card.classList.add('warning')}
document.getElementById('aftolForm')?.addEventListener('submit',e=>{e.preventDefault();const date=document.getElementById('aftolDate').value,days=Number(document.getElementById('aftolDays').value),price=Number(document.getElementById('aftolPrice').value);if(!date||days<1)return;const extras=[['aftolMasloFilter','Maslo filter'],['aftolSolyarkaFilter','Solyarka filter'],['aftolStistolniy','Stistolniy']].map(([id,n])=>{const v=document.getElementById(id).value;setTruckValue(id,v);return `${n} ${v} $`});const fullPrice=price+['aftolMasloFilter','aftolSolyarkaFilter','aftolStistolniy'].reduce((a,id)=>a+(Number(document.getElementById(id).value)||0),0);const oldDate=getTruckValue('aftolChangedDate');if(oldDate!==date||getTruckValue('aftolDurationDays')!==String(days))addRepairCost('Aftol',fullPrice,date,`Aftol: ${price} $; ${extras.join('; ')}`);setTruckValue('aftolChangedDate',date);setTruckValue('aftolDurationDays',String(days));setTruckValue('aftolPrice',String(price));renderAftol();alert('Aftol ma’lumotlari saqlandi.')});
document.getElementById('oilResetBtn')?.addEventListener('click',()=>{const oilPrice=Number(document.getElementById('oilPrice').value)||0,servicePrice=Number(document.getElementById('oilServicePrice').value)||0,price=oilPrice+servicePrice,description=document.getElementById('oilDescription').value;setTruckValue('oilPrice',String(oilPrice));setTruckValue('oilServicePrice',String(servicePrice));setTruckValue('oilDescription',description);addRepairCost('Moy',price,dateToLocalInput(new Date()),`${description}; Kastrol moyi: ${oilPrice} $; almashtirish xizmati: ${servicePrice} $`);});
document.getElementById('smaskaForm')?.addEventListener('submit',()=>{setTruckValue('smaskaPrice',document.getElementById('smaskaPrice').value);addRepairCost('Smaska',document.getElementById('smaskaPrice').value,document.getElementById('smaskaDate').value)});
document.getElementById('kalodForm')?.addEventListener('submit',()=>{setTruckValue('kalodPrice',document.getElementById('kalodPrice').value);addRepairCost('Kalodka',document.getElementById('kalodPrice').value,document.getElementById('kalodDate').value)});
document.getElementById('repairExpenseBtn')?.addEventListener('click',()=>{const box=document.getElementById('repairExpenseReport'),items=readRepairCosts();const total=items.reduce((sum,x)=>sum+(Number(x.amount)||0),0);box.classList.remove('hidden');box.innerHTML=items.length?`<div class="report-table-wrap"><table class="report-table"><thead><tr><th>Remont turi</th><th>Narxi</th><th>Sana</th><th>Izoh</th></tr></thead><tbody>${items.map(x=>`<tr><td>${escapeHtml(x.name)}</td><td>${fmtMoney(x.amount,'USD')}</td><td>${escapeHtml(x.date||'—')}</td><td>${escapeHtml(x.details||'—')}</td></tr>`).join('')}</tbody></table></div><div class="report-total">Remontning umumiy xarajati: ${fmtMoney(total,'USD')}</div>`:'<div class="empty-report">Hozircha remont xarajati qayd etilmagan. Moyni almashtirish yoki xizmat muddatini saqlashda narxlarni kiriting.</div>';box.scrollIntoView({behavior:'smooth',block:'nearest'})});
setRepairCostInputs();

// Shafyor oyligi va qo‘shimcha manzillar
let salaryRouteCount=1;document.getElementById('addSalaryRoute')?.addEventListener('click',()=>{if(salaryRouteCount>=10)return;salaryRouteCount++;const wrap=document.getElementById('salaryExtraRoutes');const row=document.createElement('div');row.className='salary-extra-row';row.innerHTML=`<label for="salaryRoute${salaryRouteCount}">${salaryRouteCount}-manzil</label><input id="salaryRoute${salaryRouteCount}" type="text" placeholder="${salaryRouteCount}-manzil" required>`;wrap.appendChild(row)});setTodayIfEmpty('salaryDate');document.getElementById('salaryForm')?.addEventListener('submit',e=>{e.preventDefault();const routes=[...document.querySelectorAll('#salaryForm input[id^=salaryRoute]')].map(x=>x.value.trim()).filter(Boolean);saveExpense('furaSalaryExpenses',{routes,amount:Number(document.getElementById('salaryAmount').value),currency:'USD',date:document.getElementById('salaryDate').value,amountUsd:Number(document.getElementById('salaryAmount').value),amountUzs:0,rateDate:'Kiritilgan dollar qiymati'});e.target.reset();document.getElementById('salaryExtraRoutes').innerHTML='';salaryRouteCount=1;setTodayIfEmpty('salaryDate');document.getElementById('salaryRoute1').required=true;});


// OWNER access gate + interface language selector.
(function initOwnerAndLanguages(){
  // OWNER tugmasi login sahifasida ham, kabinet ichida ham ishlaydi.
  const ownerAccess = async () => {
    sessionStorage.removeItem('furaOwnerGate');
    const lk='owner'; const w=lockRemaining(lk);
    if(w){alert(lockText(w));return;}
    const ownerPws=[];
    await modeReady;
    try{
      if(SERVER_MODE){
        for(let i=0;i<2;i++){const pw=await askPassword(`OWNER — ${i+1}-bosqich parolini kiriting`);if(pw===null)return;ownerPws.push(pw);}
        const r=await api('owner-login',{p1:ownerPws[0],p2:ownerPws[1]});
        sessionStorage.setItem('furaOwnerToken',r.token);
      } else for(let i=0;i<OWNER_CREDS.length;i++){
        const pw=await askPassword(`OWNER — ${i+1}-bosqich parolini kiriting`);
        if(pw===null) return;
        if(!safeEqual(await hashSecret(pw,OWNER_CREDS[i].salt,OWNER_CREDS[i].iter||150000),OWNER_CREDS[i].hash)){registerFail(lk);alert(`${i+1}-bosqich paroli noto‘g‘ri.`);return;}
        ownerPws.push(pw);
      }
    }catch(err){alert(err.message||'Tekshirishda xatolik.');return;}
    clearFails(lk);
    try{const e=new TextEncoder();const base=await crypto.subtle.importKey('raw',e.encode(ownerPws.join('\u0000')),'PBKDF2',false,['deriveBits']);sessionStorage.setItem('furaOwnerKey',b64(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:e.encode('fura-owner-vault-v1'),iterations:SEC_ITER},base,256)))}catch(err){}
    sessionStorage.setItem('furaOwnerGate',JSON.stringify({t:Date.now()}));
    window.location.href = 'owner.html';
  };
  document.getElementById('loginOwnerAccessBtn')?.addEventListener('click', ownerAccess);

  const translations = {
    uz: {home:'Asosiy joy',vehicle:'Mashina haqida ma’lumot',routes:'Yo‘nalishlar',repair:'Remont',expenses:'Xarajat',garage:'Garaj',overall:'Obshiy rasxod',china:'Xitoy',payments:'To‘lov',owner:'OWNER',language:'Til',active:'Tizim faol'},
    ru: {home:'Главная',vehicle:'Информация об автомобиле',routes:'Маршруты',repair:'Ремонт',expenses:'Расходы',garage:'Гараж',overall:'Общие расходы',china:'Китай',payments:'Платежи',owner:'ВЛАДЕЛЕЦ',language:'Язык',active:'Система активна'},
    kk: {home:'Басты бет',vehicle:'Көлік туралы ақпарат',routes:'Бағыттар',repair:'Жөндеу',expenses:'Шығындар',garage:'Гараж',overall:'Жалпы шығын',china:'Қытай',payments:'Төлемдер',owner:'ИЕСІ',language:'Тіл',active:'Жүйе белсенді'},
    zh: {home:'主页',vehicle:'车辆信息',routes:'路线',repair:'维修',expenses:'费用',garage:'车库',overall:'总支出',china:'中国',payments:'付款',owner:'管理员',language:'语言',active:'系统运行中'}
  };
  const selector = document.getElementById('languageSelect');
  if (!selector) return;
  function applyLanguage(lang){
    const t=translations[lang]||translations.uz;
    document.documentElement.lang=lang;
    const keys=['home','vehicle','routes','repair','expenses','garage','overall','china','payments'];
    document.querySelectorAll('.menu-link').forEach((el)=>{
      const key=el.dataset.view; const icon=el.querySelector('i');
      if(keys.includes(key)) { const label=t[key]; el.innerHTML=''; if(icon) el.appendChild(icon); el.append(' '+label); }
    });
    const langLabel=document.querySelector('.language-label'); if(langLabel) langLabel.textContent=t.language;
    const status=document.querySelector('.status'); if(status){const dot=status.querySelector('span');status.textContent='';if(dot)status.appendChild(dot);status.append(' '+t.active);}
    const title=document.getElementById('pageTitle');
    const active=document.querySelector('.menu-link.active');
    if(title && active && t[active.dataset.view]) title.textContent=t[active.dataset.view];
    localStorage.setItem('furaLanguage',lang);
  }
  selector.value=localStorage.getItem('furaLanguage')||'uz';
  selector.addEventListener('change',()=>applyLanguage(selector.value));
  applyLanguage(selector.value);
  // Keep translated page heading when user changes dashboard section.
  document.querySelectorAll('.menu-link').forEach(el=>el.addEventListener('click',()=>{
    const lang=selector.value; const t=translations[lang]||translations.uz;
    if(t[el.dataset.view]) document.getElementById('pageTitle').textContent=t[el.dataset.view];
  }));
})();
