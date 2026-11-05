(() => {
  'use strict';
  const base = new URL('./',document.currentScript.src);
  const storageKey = 'motion-access:' + base.pathname;
  addEventListener('pageshow',event=>{
    if(!event.persisted)return;
    let raw;try{raw=sessionStorage.getItem(storageKey);}catch{}
    if(!raw)location.replace(new URL('login.html',base));
  });
  navigator.serviceWorker?.addEventListener('message',event=>{
    if(event.data?.type==='LOCKED'){
      try{sessionStorage.removeItem(storageKey);}catch{}
      location.replace(new URL('login.html',base));return;
    }
    if(event.data?.type!=='KEY_REQUEST') return;
    let raw;try{raw=sessionStorage.getItem(storageKey);}catch{}
    if(raw) event.source?.postMessage({type:'RESTORE_KEY',requestId:event.data.requestId,raw});
  });
  if(window.top!==window) return;
  const button=document.createElement('button');
  button.textContent='退出';button.type='button';button.setAttribute('aria-label','サイトをロックして退出');
  button.style.cssText='position:fixed;right:15px;bottom:15px;z-index:99999;border:1px solid #68737e;border-radius:999px;padding:9px 17px;background:#14191fee;color:#f3f6fa;font:13px system-ui;cursor:pointer;box-shadow:0 3px 15px #0003';
  button.addEventListener('click',async()=>{
    button.disabled=true;try{sessionStorage.removeItem(storageKey);}catch{}
    const registration=await navigator.serviceWorker.getRegistration(base.href);
    const worker=registration?.active;
    if(worker){const channel=new MessageChannel();await new Promise(resolve=>{channel.port1.onmessage=resolve;worker.postMessage({type:'LOCK'},[channel.port2]);setTimeout(resolve,1500);});}
    location.replace(new URL('login.html',base));
  });
  document.body.append(button);
})();
