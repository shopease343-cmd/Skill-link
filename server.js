
const express=require("express");
const path=require("path");
const fs=require("fs");
const crypto=require("crypto");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const cookieParser=require("cookie-parser");
const helmet=require("helmet");
const rateLimit=require("express-rate-limit");
const multer=require("multer");
const {Pool}=require("pg");
const {z}=require("zod");
require("dotenv").config();

const app=express();
const PORT=Number(process.env.PORT||3000);
const JWT_SECRET=process.env.JWT_SECRET;
if(!JWT_SECRET || JWT_SECRET.length<32) throw new Error("JWT_SECRET must be at least 32 characters.");
const pool=new Pool({connectionString:process.env.DATABASE_URL});
const uploadDir=path.resolve(process.env.UPLOAD_DIR||"./uploads");
fs.mkdirSync(uploadDir,{recursive:true});

app.set("trust proxy",1);
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:false,limit:"1mb"}));
app.use(cookieParser());
app.use(rateLimit({windowMs:15*60*1000,max:300,standardHeaders:true,legacyHeaders:false}));

const upload=multer({
  storage:multer.diskStorage({
    destination:(req,file,cb)=>cb(null,uploadDir),
    filename:(req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).toLowerCase())
  }),
  limits:{fileSize:8*1024*1024,files:1},
  fileFilter:(req,file,cb)=>{
    const allowed=new Set(["image/png","image/jpeg","image/webp","application/pdf"]);
    if(!allowed.has(file.mimetype)) return cb(new Error("Unsupported file type."));
    cb(null,true);
  }
});

const loginLimiter=rateLimit({windowMs:15*60*1000,max:10,message:{error:"Too many login attempts. Try again later."}});
const resetLimiter=rateLimit({windowMs:15*60*1000,max:8});

function hashToken(v){return crypto.createHash("sha256").update(v).digest("hex")}
function getCookie(req,name){
  const raw=req.headers.cookie||"";
  const part=raw.split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="));
  return part?decodeURIComponent(part.slice(name.length+1)):"";
}
function csrfToken(){return crypto.randomBytes(32).toString("hex")}
function ensureCsrf(req,res,next){
  if(["GET","HEAD","OPTIONS"].includes(req.method)) return next();
  const supplied=req.get("x-csrf-token");
  const cookie=getCookie(req,"sl_csrf");
  if(!supplied || !cookie || supplied!==cookie) return res.status(403).json({error:"CSRF validation failed."});
  next();
}
function signSession(user){
  return jwt.sign({sub:String(user.id),role:user.role},JWT_SECRET,{expiresIn:"8h",issuer:"skilllink"});
}
async function db(q,p){return pool.query(q,p)}
async function audit(req,actor,action,targetType,targetId,beforeValue,afterValue){
  const ip=String(req.headers["x-forwarded-for"]||req.socket.remoteAddress||"").split(",")[0];
  const ipHash=hashToken(ip);
  await db(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,before_value,after_value,ip_hash,user_agent) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
    [actor?.id||null,action,targetType||null,targetId||null,beforeValue?JSON.stringify(beforeValue):null,afterValue?JSON.stringify(afterValue):null,ipHash,req.get("user-agent")||null]);
}
async function getUserById(id){
  const r=await db(`SELECT u.*,r.code role, p.full_name,p.profile_picture_url,p.upi_id FROM users u JOIN roles r ON r.id=u.role_id LEFT JOIN profiles p ON p.user_id=u.id WHERE u.id=$1`,[id]);
  return r.rows[0];
}
async function auth(req,res,next){
  try{
    const token=req.cookies.sl_session;
    if(!token) return res.status(401).json({error:"Authentication required."});
    const payload=jwt.verify(token,JWT_SECRET,{issuer:"skilllink"});
    const s=await db(`SELECT * FROM sessions WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>now()`,[hashToken(token)]);
    if(!s.rowCount) return res.status(401).json({error:"Session expired."});
    const user=await getUserById(Number(payload.sub));
    if(!user || user.status!=="ACTIVE") return res.status(403).json({error:"Account inactive."});
    req.user=user;
    next();
  }catch(e){return res.status(401).json({error:"Invalid session."})}
}
function requireRole(...roles){return (req,res,next)=>roles.includes(req.user.role)?next():res.status(403).json({error:"Insufficient role permission."})}
async function hasPermission(userId,permission){
  const r=await db(`SELECT 1 FROM users u JOIN roles r ON r.id=u.role_id LEFT JOIN user_permissions up ON up.user_id=u.id LEFT JOIN permissions p ON p.id=up.permission_id WHERE u.id=$1 AND (r.code='CEO' OR p.code=$2) LIMIT 1`,[userId,permission]);
  return !!r.rowCount;
}
function requirePermission(permission){return async(req,res,next)=>{if(await hasPermission(req.user.id,permission))return next();return res.status(403).json({error:"Permission denied."})}}

const loginSchema=z.object({username:z.string().min(1).max(80),password:z.string().min(1).max(200),referral_id:z.string().max(80).optional().or(z.literal(""))});
const registerSchema=z.object({name:z.string().min(2).max(160),email:z.string().email().max(255),mobile:z.string().min(7).max(30),username:z.string().min(3).max(80).regex(/^[a-zA-Z0-9._-]+$/),password:z.string().min(8).max(200),referral_id:z.string().max(80).optional().or(z.literal(""))});

app.get("/api/auth/csrf",(req,res)=>{const token=csrfToken();res.cookie("sl_csrf",token,{httpOnly:false,secure:process.env.COOKIE_SECURE==="true",sameSite:"lax",maxAge:8*60*60*1000,path:"/"});res.json({token})});

app.get("/api/health",async(req,res)=>{try{await db("SELECT 1");res.json({ok:true,database:true})}catch(e){res.status(503).json({ok:false,database:false})}});

app.post("/api/auth/login",loginLimiter,ensureCsrf,async(req,res)=>{
  try{
    const body=loginSchema.parse(req.body);
    const r=await db(`SELECT u.*,r.code role FROM users u JOIN roles r ON r.id=u.role_id WHERE lower(u.username)=lower($1)`,[body.username]);
    if(!r.rowCount) return res.status(401).json({error:"Invalid credentials."});
    const u=r.rows[0];
    if(u.locked_until && new Date(u.locked_until)>new Date()) return res.status(429).json({error:"Account temporarily locked."});
    const ok=await bcrypt.compare(body.password,u.password_hash);
    if(!ok){
      await db(`UPDATE users SET failed_login_count=failed_login_count+1,locked_until=CASE WHEN failed_login_count+1>=5 THEN now()+interval '15 minutes' ELSE locked_until END WHERE id=$1`,[u.id]);
      await audit(req,u,"LOGIN_FAILED","USER",u.id,null,null);
      return res.status(401).json({error:"Invalid credentials."});
    }
    if(u.status!=="ACTIVE") return res.status(403).json({error:"Account is not active."});
    await db(`UPDATE users SET failed_login_count=0,locked_until=NULL,last_login_at=now() WHERE id=$1`,[u.id]);
    const token=signSession(u);
    await db(`INSERT INTO sessions(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '8 hours')`,[u.id,hashToken(token)]);
    res.cookie("sl_session",token,{httpOnly:true,secure:process.env.COOKIE_SECURE==="true",sameSite:"lax",maxAge:8*60*60*1000,path:"/"});
    await audit(req,u,"LOGIN","USER",u.id,null,null);
    res.json({ok:true,user:{id:u.id,role:u.role,username:u.username,forcePasswordChange:u.force_password_change}});
  }catch(e){res.status(400).json({error:e.issues?"Invalid input.":e.message})}
});

app.post("/api/auth/register",ensureCsrf,async(req,res)=>{
  try{
    const b=registerSchema.parse(req.body);
    const exists=await db(`SELECT 1 FROM users WHERE lower(username)=lower($1) OR lower(email)=lower($2)`,[b.username,b.email]);
    if(exists.rowCount)return res.status(409).json({error:"Username or email already exists."});
    let ref=null;
    if(b.referral_id){
      const rr=await db(`SELECT id FROM users WHERE referral_code=$1 AND status='ACTIVE'`,[b.referral_id]);
      if(!rr.rowCount)return res.status(400).json({error:"Invalid referral ID."});
      ref=rr.rows[0].id;
    }
    const role=await db(`SELECT id FROM roles WHERE code='PARTNER'`);
    const hash=await bcrypt.hash(b.password,12);
    const client=await pool.connect();
    try{
      await client.query("BEGIN");
      const u=await client.query(`INSERT INTO users(role_id,username,password_hash,email,mobile,status,referred_by_user_id,referral_code) VALUES($1,$2,$3,$4,$5,'PENDING',$6,$7) RETURNING id`,[role.rows[0].id,b.username,hash,b.email,b.mobile,ref,`SL-${crypto.randomBytes(5).toString("hex").toUpperCase()}`]);
      await client.query(`INSERT INTO profiles(user_id,full_name) VALUES($1,$2)`,[u.rows[0].id,b.name]);
      if(ref) await client.query(`INSERT INTO referrals(referrer_id,referred_user_id,code) VALUES($1,$2,$3)`,[ref,u.rows[0].id,b.referral_id]);
      await client.query("COMMIT");
      res.status(201).json({ok:true});
    }catch(e){await client.query("ROLLBACK");throw e}finally{client.release()}
  }catch(e){res.status(400).json({error:e.issues?"Invalid registration data.":e.message})}
});

app.get("/api/auth/me",auth,async(req,res)=>res.json({user:{id:req.user.id,role:req.user.role,username:req.user.username,name:req.user.full_name,email:req.user.email,mobile:req.user.mobile,forcePasswordChange:req.user.force_password_change}}));
app.post("/api/auth/logout",auth,ensureCsrf,async(req,res)=>{const t=req.cookies.sl_session;await db(`UPDATE sessions SET revoked_at=now() WHERE token_hash=$1`,[hashToken(t)]);await audit(req,req.user,"LOGOUT","USER",req.user.id,null,null);res.clearCookie("sl_session");res.json({ok:true})});

app.post("/api/auth/change-password",auth,ensureCsrf,async(req,res)=>{
  const s=z.object({current:z.string(),next:z.string().min(8).max(200)}).parse(req.body);
  const ok=await bcrypt.compare(s.current,req.user.password_hash);if(!ok)return res.status(400).json({error:"Current password is incorrect."});
  const hash=await bcrypt.hash(s.next,12);await db(`UPDATE users SET password_hash=$1,force_password_change=false WHERE id=$2`,[hash,req.user.id]);await audit(req,req.user,"PASSWORD_CHANGE","USER",req.user.id,null,null);res.json({ok:true});
});

app.get("/api/packages",async(req,res)=>res.json({packages:(await db(`SELECT * FROM packages WHERE status='ACTIVE' ORDER BY id`)).rows}));
app.get("/api/courses",async(req,res)=>res.json({courses:(await db(`SELECT c.*,p.name package_name FROM courses c LEFT JOIN packages p ON p.id=c.package_id WHERE c.status='PUBLISHED' ORDER BY c.id DESC`)).rows}));

app.get("/api/dashboard",auth,async(req,res)=>{
  const uid=req.user.id, role=req.user.role;
  const params=[uid];
  let q;
  if(role==="PARTNER"){
    q=await db(`SELECT
      COALESCE(SUM(partner_share),0) total_earnings,
      COALESCE(SUM(available_amount),0) available_balance,
      COALESCE(SUM(pending_amount),0) pending_earnings,
      COALESCE(SUM(withdrawn_amount),0) withdrawn_amount
      FROM earnings_ledger WHERE user_id=$1`,params);
  }else{
    q=await db(`SELECT 0::numeric total_earnings,0::numeric available_balance,0::numeric pending_earnings,0::numeric withdrawn_amount`);
  }
  res.json({role,financial:q.rows[0]});
});

app.get("/api/withdrawals",auth,async(req,res)=>{
  if(req.user.role!=="CEO" && req.user.role!=="PARTNER" && req.user.role!=="ADMIN") return res.status(403).json({error:"Denied."});
  const q=req.user.role==="CEO"
    ? await db(`SELECT w.*,u.username,u.mobile,p.full_name,p.upi_id FROM withdrawals w JOIN users u ON u.id=w.user_id LEFT JOIN profiles p ON p.user_id=u.id ORDER BY w.request_date DESC`)
    : await db(`SELECT w.*,u.username,u.mobile,p.full_name,p.upi_id FROM withdrawals w JOIN users u ON u.id=w.user_id LEFT JOIN profiles p ON p.user_id=u.id WHERE w.user_id=$1 ORDER BY w.request_date DESC`,[req.user.id]);
  res.json({withdrawals:q.rows});
});

app.post("/api/withdrawals",auth,ensureCsrf,async(req,res)=>{
  if(req.user.role!=="PARTNER"&&req.user.role!=="ADMIN")return res.status(403).json({error:"Only Partner/Admin can request withdrawals."});
  const b=z.object({amount:z.number().min(100),payment_method:z.string().min(2).max(40),payment_details:z.string().min(2).max(500)}).parse(req.body);
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const bal=await client.query(`SELECT COALESCE(SUM(available_amount),0) balance FROM earnings_ledger WHERE user_id=$1`,[req.user.id]);
    if(Number(bal.rows[0].balance)<b.amount){await client.query("ROLLBACK");return res.status(400).json({error:"Insufficient available balance."})}
    const w=await client.query(`INSERT INTO withdrawals(user_id,amount,payment_method,payment_details,status) VALUES($1,$2,$3,$4,'PENDING') RETURNING *`,[req.user.id,b.amount,b.payment_method,b.payment_details]);
    await client.query(`UPDATE earnings_ledger SET available_amount=available_amount-$1,pending_amount=pending_amount+$1 WHERE user_id=$2 AND available_amount>0`,[b.amount,req.user.id]);
    await client.query("COMMIT");
    await audit(req,req.user,"WITHDRAWAL_REQUEST","WITHDRAWAL",w.rows[0].id,null,w.rows[0]);
    res.status(201).json({withdrawal:w.rows[0]});
  }catch(e){await client.query("ROLLBACK");res.status(500).json({error:"Withdrawal transaction failed."})}finally{client.release()}
});

app.post("/api/withdrawals/:id/decision",auth,ensureCsrf,requireRole("CEO"),async(req,res)=>{
  const b=z.object({action:z.enum(["APPROVE","REJECT","PAID","FAIL"]),payment_reference:z.string().max(160).optional(),remarks:z.string().max(1000).optional()}).parse(req.body);
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const w=await client.query(`SELECT * FROM withdrawals WHERE id=$1 FOR UPDATE`,[req.params.id]);
    if(!w.rowCount){await client.query("ROLLBACK");return res.status(404).json({error:"Withdrawal not found."})}
    const row=w.rows[0];
    const next={APPROVE:"APPROVED",REJECT:"REJECTED",PAID:"PAID",FAIL:"FAILED"}[b.action];
    if((row.status==="PAID"||row.status==="REJECTED"||row.status==="FAILED") && row.status!==next){await client.query("ROLLBACK");return res.status(409).json({error:"Withdrawal already finalized."})}
    await client.query(`UPDATE withdrawals SET status=$1,payment_reference=$2,remarks=$3,reviewed_by=$4,reviewed_at=now() WHERE id=$5`,[next,b.payment_reference||null,b.remarks||null,req.user.id,row.id]);
    if(["REJECTED","FAILED"].includes(next)){
      await client.query(`UPDATE earnings_ledger SET available_amount=available_amount+$1,pending_amount=GREATEST(pending_amount-$1,0) WHERE user_id=$2 AND available_amount>=0`,[row.amount,row.user_id]);
    }else if(next==="PAID"){
      await client.query(`UPDATE earnings_ledger SET pending_amount=GREATEST(pending_amount-$1,0),withdrawn_amount=withdrawn_amount+$1 WHERE user_id=$2`,[row.amount,row.user_id]);
    }
    await client.query("COMMIT");
    await audit(req,req.user,"WITHDRAWAL_"+b.action,"WITHDRAWAL",row.id,row,{...row,status:next});
    res.json({ok:true,status:next});
  }catch(e){await client.query("ROLLBACK");res.status(500).json({error:"Withdrawal decision failed."})}finally{client.release()}
});

app.get("/api/notifications",auth,async(req,res)=>{
  const q=await db(`SELECT n.*,nr.read_at FROM notifications n LEFT JOIN notification_reads nr ON nr.notification_id=n.id AND nr.user_id=$1 WHERE n.target_user_id=$1 OR n.target_user_id IS NULL ORDER BY n.created_at DESC LIMIT 100`,[req.user.id]);
  res.json({notifications:q.rows});
});
app.post("/api/notifications/:id/read",auth,ensureCsrf,async(req,res)=>{await db(`INSERT INTO notification_reads(notification_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,[req.params.id,req.user.id]);res.json({ok:true})});

app.post("/api/upload",auth,ensureCsrf,upload.single("file"),async(req,res)=>{
  if(!req.file)return res.status(400).json({error:"File required."});
  const purpose=String(req.body.purpose||"OTHER");
  const r=await db(`INSERT INTO uploads(owner_user_id,purpose,original_name,stored_name,mime_type,size_bytes) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,original_name,mime_type,size_bytes,created_at`,[req.user.id,purpose,req.file.originalname,req.file.filename,req.file.mimetype,req.file.size]);
  await audit(req,req.user,"FILE_UPLOAD","UPLOAD",r.rows[0].id,null,r.rows[0]);
  res.status(201).json({upload:r.rows[0]});
});

app.get("/api/audit-logs",auth,requireRole("CEO","ADMIN"),async(req,res)=>{
  if(req.user.role==="ADMIN" && !(await hasPermission(req.user.id,"view_audit_logs"))) return res.status(403).json({error:"Permission denied."});
  const q=await db(`SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.created_at DESC LIMIT 300`);
  res.json({logs:q.rows});
});

app.use(express.static(path.join(__dirname,"public")));
app.use("/uploads",express.static(uploadDir,{dotfiles:"deny",index:false}));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.use((err,req,res,next)=>{
  if(err instanceof multer.MulterError) return res.status(400).json({error:err.message});
  console.error(err);
  res.status(500).json({error:"Internal server error."});
});

app.listen(PORT,()=>console.log(`SkillLink running on http://localhost:${PORT}`));
