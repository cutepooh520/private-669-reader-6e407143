(()=>{
"use strict";
let secretKey=null;
const objectUrls=new Map();
const pending=new Map();
let settings;
function encPath(n){return "vault/"+String(n).padStart(3,"0")+".bin"}
async function decode(n){
 if(objectUrls.has(n))return objectUrls.get(n);
 if(pending.has(n))return pending.get(n);
 const promise=(async()=>{
  const response=await fetch(encPath(n));
  if(!response.ok)throw Error("load");
  const data=new Uint8Array(await response.arrayBuffer());
  const result=await crypto.subtle.decrypt({name:"AES-GCM",iv:data.slice(0,12)},secretKey,data.slice(12));
  const url=URL.createObjectURL(new Blob([result],{type:"image/webp"}));
  objectUrls.set(n,url);
  if(objectUrls.size>32){const k=objectUrls.keys().next().value;URL.revokeObjectURL(objectUrls.get(k));objectUrls.delete(k)}
  return url
 })();
 pending.set(n,promise);
 try{return await promise}finally{pending.delete(n)}
}
const status=t=>document.querySelector("#unlockStatus").textContent=t;
async function derive(value){
 const bytes=new TextEncoder().encode(value);
 const base=await crypto.subtle.importKey("raw",bytes,"PBKDF2",false,["deriveKey"]);
 const salt=Uint8Array.from(atob(settings.pinSalt),c=>c.charCodeAt(0));
 const kek=await crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:settings.iterations,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["decrypt"]);
 const packed=Uint8Array.from(atob(settings.wrappedKey),c=>c.charCodeAt(0));
 const unwrapped=await crypto.subtle.decrypt({name:"AES-GCM",iv:packed.slice(0,12)},kek,packed.slice(12));
 return crypto.subtle.importKey("raw",unwrapped,{name:"AES-GCM",length:256},false,["decrypt"]);
}
async function getDb(){
 return new Promise((done,fail)=>{
  const req=indexedDB.open("private-reader-669-v2",1);
  req.onupgradeneeded=()=>req.result.createObjectStore("access");
  req.onsuccess=()=>done(req.result);req.onerror=()=>fail(req.error);
 })
}
async function save(k){
 try{const db=await getDb();await new Promise(res=>{const tx=db.transaction("access","readwrite");tx.objectStore("access").put(k,"only");tx.oncomplete=res;tx.onerror=res});db.close()}catch(e){}
}
async function restore(){
 try{const db=await getDb();return await new Promise(res=>{const q=db.transaction("access","readonly").objectStore("access").get("only");q.onsuccess=()=>{db.close();res(q.result)};q.onerror=()=>{db.close();res(null)}})}catch(e){return null}
}
async function unlock(k,callback,remember){
 secretKey=k;try{await decode(1);if(remember)await save(k);document.body.classList.add("vault-open");document.querySelector("#unlockGate").style.display="none";callback();return true}catch(e){secretKey=null;status("無法解鎖：請確認密碼或連線");return false}
}
async function start(callback){
 try{
  settings=await (await fetch("vault-meta.json",{cache:"no-store"})).json();
  const found=location.hash.match(/^#open=(.*)$/);
  if(found){const pass=decodeURIComponent(found[1]);history.replaceState(null,"",location.pathname+location.search);status("正在驗證私人連結…");try{if(await unlock(await derive(pass),callback,true))return}catch(e){status("舊連結已失效，請使用新密碼解鎖。")}}
  else{const k=await restore();if(k){status("正在恢復閱讀權限…");if(await unlock(k,callback,false))return}}
  status("閱讀密碼只在本裝置使用，不會傳送。");
  document.querySelector("#unlockForm").onsubmit=async e=>{
   e.preventDefault();
   status("正在解鎖…");
   const val=document.querySelector("#unlockPassword").value;
   try{if(await unlock(await derive(val),callback,document.querySelector("#rememberDevice").checked))document.querySelector("#unlockPassword").value=""}catch(e){status("目前無法解鎖")}
  };
 }catch(e){status("無法開啟閱讀器，請稍後重試。")}
}
async function load(img,n){
 img.dataset.encNum=String(n);
 try{const url=await decode(n);if(img.dataset.encNum===String(n))img.src=url}catch(e){img.alt="圖片無法載入"}
}
const loader=new IntersectionObserver(entries=>{for(const e of entries)if(e.isIntersecting){loader.unobserve(e.target);load(e.target,Number(e.target.dataset.encNum))}},{rootMargin:"500px"});
function observe(img,n){img.dataset.encNum=String(n);loader.observe(img)}
window.VaultReader={start,decode,load,observe};
})();