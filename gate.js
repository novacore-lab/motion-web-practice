/* The password and derived key are never sent to a server. */
(() => {
  'use strict';
  const base = new URL('./', new URL(document.currentScript.src));
  const storageKey = 'motion-access:' + base.pathname;
  const form = document.getElementById('gate-form');
  const input = document.getElementById('password');
  const button = document.getElementById('enter');
  const status = document.getElementById('status');
  const bytes = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
  let configPromise;
  const config = () => configPromise ??= fetch(new URL('access.json', base), {cache:'no-store'}).then(r => {if(!r.ok) throw Error('通信に失敗しました。');return r.json();});
  const encode = data => btoa(String.fromCharCode(...new Uint8Array(data)));
  const rawKey = async password => {
    const c = await config();
    const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    return crypto.subtle.deriveBits({name:'PBKDF2',salt:bytes(c.salt),iterations:c.iterations,hash:'SHA-256'},material,256);
  };
  async function verify(raw) {
    const c = await config();
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(c.checkIv)},key,bytes(c.check));
    if(new TextDecoder().decode(plain)!=='MOTION LAB access v1') throw Error('Invalid password');
  }
  async function unlock(raw) {
    await verify(raw);
    const registration = await navigator.serviceWorker.register(new URL('sw.js',base), {scope:base.pathname,updateViaCache:'none'});
    await navigator.serviceWorker.ready;
    const worker = registration.active;
    if(!worker) throw Error('準備が完了しませんでした。もう一度お試しください。');
    const channel = new MessageChannel();
    await new Promise((resolve,reject) => {
      const timer = setTimeout(()=>reject(Error('通信がタイムアウトしました。もう一度お試しください。')),15000);
      channel.port1.onmessage = e => {clearTimeout(timer);channel.port1.close();e.data?.ok ? resolve() : reject(Error('パスワードを確認してください。'));};
      worker.postMessage({type:'UNLOCK',raw:encode(raw)},[channel.port2]);
    });
    // Keep only the derived key in this tab's session; do not save the password.
    try{sessionStorage.setItem(storageKey,encode(raw));}catch{}
    const target = new URL('index.html',base);
    const returnPath = new URL(location.href).searchParams.get('return');
    if(returnPath) {
      const candidate = new URL(returnPath,base);
      if(candidate.origin===base.origin && candidate.pathname.startsWith(base.pathname) && !candidate.pathname.endsWith('login.html')) target.href=candidate.href;
    }
    target.hash = location.hash || target.hash || '#home';
    location.replace(target.href);
  }
  document.getElementById('show').addEventListener('click',e=>{
    const show=input.type==='password';input.type=show?'text':'password';e.currentTarget.textContent=show?'非表示':'表示';e.currentTarget.setAttribute('aria-pressed',String(show));e.currentTarget.setAttribute('aria-label',show?'パスワードを非表示':'パスワードを表示');
  });
  form.addEventListener('submit',async e=>{
    e.preventDefault();button.disabled=true;status.textContent='パスワードを確認しています…';
    try{
      if(!isSecureContext || !crypto.subtle || !navigator.serviceWorker) throw Error('HTTPSで開き、最新版のブラウザーをご利用ください。');
      const raw=await rawKey(input.value);await unlock(raw);
    }catch(error){
      const wrong=error.name==='OperationError'||error.message==='Invalid password';
      status.textContent=wrong?'パスワードが違います。もう一度入力してください。':error.message;
      if(wrong){input.value='';input.focus();}
      button.disabled=false;
    }
  });
  if(!isSecureContext || !crypto.subtle || !navigator.serviceWorker){status.textContent='HTTPSで開き、最新版のブラウザーをご利用ください。';return;}
  button.disabled=false;
  let saved;try{saved=sessionStorage.getItem(storageKey);}catch{}
  if(saved){button.disabled=true;status.textContent='サイトを開いています…';unlock(bytes(saved)).catch(()=>{try{sessionStorage.removeItem(storageKey);}catch{}button.disabled=false;status.textContent='もう一度パスワードを入力してください。';});}
})();
