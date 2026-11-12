import { createClient } from '@supabase/supabase-js';
const cors={ 'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGIN || 'https://YOUR-SITE.netlify.app', 'Access-Control-Allow-Headers':'authorization, content-type', 'Access-Control-Allow-Methods':'POST, OPTIONS' };
const reply=(statusCode,body)=>({statusCode,headers:{...cors,'Content-Type':'application/json'},body:JSON.stringify(body)});
export async function handler(event){
 if(event.httpMethod==='OPTIONS') return {statusCode:204,headers:cors,body:''};
 if(event.httpMethod!=='POST') return reply(405,{error:'Method not allowed'});
 try {
  const token=(event.headers.authorization||'').replace(/^Bearer\s+/i,''); if(!token) return reply(401,{error:'Kirish talab qilinadi'});
  const url=process.env.SUPABASE_URL, anon=process.env.SUPABASE_ANON_KEY, service=process.env.SUPABASE_SERVICE_ROLE_KEY;
  if(!url||!anon||!service) return reply(500,{error:'Server sozlamalari to‘liq emas'});
  const userClient=createClient(url,anon,{global:{headers:{Authorization:`Bearer ${token}`}}});
  const {data:{user},error:authErr}=await userClient.auth.getUser(); if(authErr||!user||user.app_metadata?.role!=='owner') return reply(403,{error:'Faqat OWNER ruxsatiga ega'});
  const {companyId,decision,vehicleLimit}=JSON.parse(event.body||'{}');
  if(!companyId||!['approved','rejected','suspended'].includes(decision)) return reply(400,{error:'Noto‘g‘ri so‘rov'});
  if(decision==='approved'&&(!Number.isInteger(vehicleLimit)||vehicleLimit<0||vehicleLimit>10000)) return reply(400,{error:'Mashina limiti 0–10000 oralig‘ida butun son bo‘lsin'});
  const admin=createClient(url,service);
  const update={status:decision,reviewed_at:new Date().toISOString(),reviewed_by:user.id}; if(decision==='approved') update.vehicle_limit=vehicleLimit;
  const {data:company,error}=await admin.from('companies').update(update).eq('id',companyId).select('id,name,owner_user_id,status,vehicle_limit').single();
  if(error) return reply(400,{error:error.message});
  await admin.from('owner_audit').insert({owner_user_id:user.id,company_id:companyId,action:decision,details:{vehicleLimit:decision==='approved'?vehicleLimit:null}});
  return reply(200,{company});
 } catch(e){return reply(500,{error:'Server xatosi'});}
}
