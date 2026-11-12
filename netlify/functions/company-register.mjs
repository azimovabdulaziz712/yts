import { createClient } from '@supabase/supabase-js';
const headers={'Access-Control-Allow-Origin':process.env.ALLOWED_ORIGIN||'https://YOUR-SITE.netlify.app','Access-Control-Allow-Headers':'authorization, content-type','Access-Control-Allow-Methods':'POST, OPTIONS'};
const out=(statusCode,x)=>({statusCode,headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify(x)});
export async function handler(e){
 if(e.httpMethod==='OPTIONS')return {statusCode:204,headers,body:''}; if(e.httpMethod!=='POST')return out(405,{error:'Method not allowed'});
 try{const token=(e.headers.authorization||'').replace(/^Bearer\s+/i,'');if(!token)return out(401,{error:'Kirish talab qilinadi'});
 const url=process.env.SUPABASE_URL,anon=process.env.SUPABASE_ANON_KEY,service=process.env.SUPABASE_SERVICE_ROLE_KEY;
 const client=createClient(url,anon,{global:{headers:{Authorization:`Bearer ${token}`}}});const {data:{user},error:ue}=await client.auth.getUser();if(ue||!user)return out(401,{error:'Sessiya yaroqsiz'});
 const {name}=JSON.parse(e.body||'{}');if(typeof name!=='string'||name.trim().length<2||name.trim().length>100)return out(400,{error:'Firma nomini to‘g‘ri kiriting'});
 const admin=createClient(url,service);const {data,error}=await admin.from('companies').insert({name:name.trim(),owner_user_id:user.id,status:'pending',vehicle_limit:0}).select('id,name,status').single();if(error)return out(400,{error:error.message});
 return out(201,{company:data,message:'So‘rov OWNER tasdig‘ini kutmoqda'});
 }catch{return out(500,{error:'Server xatosi'});}
}
