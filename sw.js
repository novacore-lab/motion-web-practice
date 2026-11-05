'use strict';
const ROOT = new URL('./', self.location.href);
const dec = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
let key=null, manifestPromise, locked=false;
const restorations=new Map();
const manifest = () => manifestPromise ??= fetch(new URL('access.json',ROOT),{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Missing access manifest');return r.json();}).catch(e=>{manifestPromise=null;throw e;});
async function accept(raw){
  const c=await manifest();
  const candidate=await crypto.subtle.importKey('raw',dec(raw),'AES-GCM',false,['decrypt']);
  const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:dec(c.checkIv)},candidate,dec(c.check));
  if(new TextDecoder().decode(plain)!=='MOTION LAB access v1') throw Error('Invalid key');
  key=candidate;
}
self.addEventListener('install',e=>e.waitUntil(self.skipWaiting()));
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('message',e=>{
  if(!e.source?.url || !e.source.url.startsWith(ROOT.href)) return;
  if(e.data?.type==='UNLOCK') e.waitUntil(accept(e.data.raw).then(()=>{locked=false;e.ports[0]?.postMessage({ok:true});}).catch(()=>e.ports[0]?.postMessage({ok:false})));
  if(e.data?.type==='RESTORE_KEY'&&!locked) e.waitUntil(accept(e.data.raw).then(()=>{restorations.get(e.data.requestId)?.();}).catch(()=>{}));
  if(e.data?.type==='LOCK'){key=null;locked=true;e.ports[0]?.postMessage({ok:true});e.waitUntil(self.clients.matchAll({type:'window'}).then(clients=>clients.filter(c=>c.url.startsWith(ROOT.href)).forEach(c=>c.postMessage({type:'LOCKED'}))));}
});
async function restore(){
  if(key)return key;
  if(locked)return null;
  const clients=(await self.clients.matchAll({type:'window',includeUncontrolled:true})).filter(c=>c.url.startsWith(ROOT.href));
  if(!clients.length)return null;
  const requestId=crypto.randomUUID();
  await new Promise(resolve=>{
    const done=()=>{clearTimeout(timer);restorations.delete(requestId);resolve();};
    const timer=setTimeout(done,1200);restorations.set(requestId,done);
    clients.forEach(client=>client.postMessage({type:'KEY_REQUEST',requestId}));
  });
  return key;
}
const PUBLIC=new Set(['login.html','gate.js','sw.js','lock-control.js','access.json','robots.txt','.nojekyll']);
self.addEventListener('fetch',e=>{
  const url=new URL(e.request.url);
  if(url.origin!==ROOT.origin || !url.pathname.startsWith(ROOT.pathname) || e.request.method!=='GET') return;
  let relative=decodeURIComponent(url.pathname.slice(ROOT.pathname.length));
  if(relative.startsWith('encrypted/')||PUBLIC.has(relative))return;
  if(relative===''||relative.endsWith('/'))relative+='index.html';
  e.respondWith((async()=>{
    const entry=(await manifest()).files[relative];
    if(!entry)return new Response('Not found',{status:404,headers:{'Content-Type':'text/plain;charset=utf-8','Cache-Control':'no-store'}});
    const currentKey=await restore();
    if(!currentKey){
      if(e.request.mode==='navigate'){
        const login=new URL('login.html',ROOT);login.searchParams.set('return',url.pathname+url.search);
        return Response.redirect(login.href,302);
      }
      return new Response('Password required',{status:401,headers:{'Cache-Control':'no-store'}});
    }
    try{
      const encrypted=await fetch(new URL('encrypted/'+entry.file,ROOT),{cache:'no-store'});
      if(!encrypted.ok)throw Error('Unable to load encrypted file');
      const body=await crypto.subtle.decrypt({name:'AES-GCM',iv:dec(entry.iv)},currentKey,await encrypted.arrayBuffer());
      const headers={'Content-Type':entry.type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
      const range=e.request.headers.get('Range');
      if(range){
        const match=/^bytes=(\d*)-(\d*)$/.exec(range);
        if(match){
          const size=body.byteLength;let start=match[1]?Number(match[1]):Math.max(0,size-Number(match[2]));let end=match[1]&&match[2]?Number(match[2]):size-1;
          end=Math.min(end,size-1);
          if(start>end||start>=size)return new Response(null,{status:416,headers:{...headers,'Content-Range':'bytes */'+size}});
          return new Response(body.slice(start,end+1),{status:206,headers:{...headers,'Content-Range':`bytes ${start}-${end}/${size}`,'Accept-Ranges':'bytes'}});
        }
      }
      return new Response(body,{headers});
    }catch{
      return new Response('Unable to open protected content. Please reload and sign in again.',{status:503,headers:{'Content-Type':'text/plain;charset=utf-8','Cache-Control':'no-store'}});
    }
  })());
});
