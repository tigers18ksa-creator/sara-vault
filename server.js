import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pg from 'pg';
import crypto from 'node:crypto';
import path from 'node:path';
const app=express();app.disable('x-powered-by');app.use(helmet({contentSecurityPolicy:false}));app.use(express.json({limit:'8kb'}));app.use('/api',rateLimit({windowMs:15*60*1000,limit:80,standardHeaders:'draft-7',legacyHeaders:false}));
const secret=process.env.SESSION_SECRET;const admin=process.env.ADMIN_PASSWORD;const dburl=process.env.DATABASE_URL;
if(!secret||secret.length<32||!admin||admin.length<12||!dburl) console.error('Missing secure configuration: SESSION_SECRET, ADMIN_PASSWORD, DATABASE_URL');
const pool=dburl?new pg.Pool({connectionString:dburl,ssl:dburl.includes('localhost')?false:{rejectUnauthorized:false}}):null;
const initial={closed:false,locked:Array(12).fill(false),pinHash:null,pinVersion:0};
async function init(){if(!pool)return;await pool.query('CREATE TABLE IF NOT EXISTS vault_settings (id integer PRIMARY KEY CHECK(id=1), data jsonb NOT NULL)');await pool.query('INSERT INTO vault_settings(id,data) VALUES(1,$1) ON CONFLICT DO NOTHING',[JSON.stringify(initial)]);}
let ready=init().then(()=>true).catch(e=>{console.error('Database unavailable',e.message);return false});
const hash=s=>{const salt=crypto.randomBytes(16).toString('hex');return salt+':'+crypto.scryptSync(s,salt,64).toString('hex')};
const verify=(s,v)=>{if(!v)return false;const [salt,h]=v.split(':');if(!salt||!h)return false;const actual=crypto.scryptSync(s,salt,64),expected=Buffer.from(h,'hex');return actual.length===expected.length&&crypto.timingSafeEqual(actual,expected)};
function sign(data){const p=Buffer.from(JSON.stringify(data)).toString('base64url');return p+'.'+crypto.createHmac('sha256',secret).update(p).digest('base64url')}
function token(req){const raw=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('sv_auth='));if(!raw||!secret)return null;const t=raw.slice(8),parts=t.split('.');if(parts.length!==2)return null;const sig=crypto.createHmac('sha256',secret).update(parts[0]).digest('base64url');if(sig.length!==parts[1].length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(parts[1])))return null;try{const obj=JSON.parse(Buffer.from(parts[0],'base64url').toString());return obj.exp>Date.now()?obj:null}catch{return null}}
function cookie(res,obj){res.setHeader('Set-Cookie','sv_auth='+sign(obj)+'; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200')}
const owner=req=>token(req)?.role==='owner';
async function state(){if(!(await ready))throw Error('database unavailable');const {rows}=await pool.query('SELECT data FROM vault_settings WHERE id=1');return rows[0].data}
async function change(fn){if(!(await ready))throw Error('database unavailable');const client=await pool.connect();try{await client.query('BEGIN');const r=await client.query('SELECT data FROM vault_settings WHERE id=1 FOR UPDATE');const d=fn(r.rows[0].data);await client.query('UPDATE vault_settings SET data=$1 WHERE id=1',[JSON.stringify(d)]);await client.query('COMMIT');return d}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}
function route(fn){return async(req,res)=>{try{await fn(req,res)}catch(e){console.error(e.message);res.status(503).json({error:'الخدمة غير متاحة مؤقتًا'})}}}
app.get('/api/status',route(async(req,res)=>{const d=await state(),t=token(req);res.set('Cache-Control','no-store').json({closed:d.closed,locked:d.locked,owner:t?.role==='owner',unlocked:t?.role==='owner'||(t?.role==='guest'&&t.version===d.pinVersion)})}));
app.post('/api/login',route(async(req,res)=>{if(!admin||typeof req.body.password!=='string'||req.body.password!==admin)return res.status(401).json({error:'بيانات الدخول غير صحيحة'});cookie(res,{role:'owner',exp:Date.now()+43200000});res.json({ok:true})}));
app.post('/api/unlock',route(async(req,res)=>{const d=await state();if(typeof req.body.pin!=='string'||!verify(req.body.pin,d.pinHash))return res.status(401).json({error:'الرقم السري غير صحيح'});cookie(res,{role:'guest',version:d.pinVersion,exp:Date.now()+43200000});res.json({ok:true})}));
app.post('/api/logout',(req,res)=>{res.setHeader('Set-Cookie','sv_auth=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');res.json({ok:true})});
app.post('/api/admin',route(async(req,res)=>{if(!owner(req))return res.status(403).json({error:'للمالك فقط'});const {closed,locked,pin}=req.body;if(closed!==undefined&&typeof closed!=='boolean'||locked!==undefined&&(!Array.isArray(locked)||locked.length!==12||locked.some(x=>typeof x!=='boolean'))||pin!==undefined&&(typeof pin!=='string'||pin.length<4||pin.length>64))return res.status(400).json({error:'إعدادات غير صالحة'});await change(d=>{if(closed!==undefined)d.closed=closed;if(locked!==undefined)d.locked=locked;if(pin!==undefined){d.pinHash=hash(pin);d.pinVersion++}return d});res.json({ok:true})}));
app.get('/api/health',async(req,res)=>res.status(await ready?200:503).json({ready:await ready}));
app.get('/',(req,res)=>res.sendFile(path.resolve('app.html')));app.use(express.static(path.resolve('.'),{index:false}));
app.listen(process.env.PORT||3000,()=>console.log('Sara Vault server listening'));
