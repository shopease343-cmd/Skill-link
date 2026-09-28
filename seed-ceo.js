
require("dotenv").config();
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

(async()=>{
  const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL.includes("sslmode=require")?{rejectUnauthorized:false}:false});
  const username=process.env.CEO_USERNAME||"ceo";
  const password=process.env.CEO_PASSWORD;
  if(!password || password.length<12) throw new Error("Set CEO_PASSWORD to a strong password of at least 12 characters.");
  const hash=await bcrypt.hash(password,12);
  const r=await pool.query(`INSERT INTO users(name,mobile,email,username,password_hash,role,referral_code,first_login,status)
    VALUES($1,$2,$3,$4,$5,'CEO',$6,false,'ACTIVE')
    ON CONFLICT(username) DO UPDATE SET name=EXCLUDED.name,email=EXCLUDED.email,password_hash=EXCLUDED.password_hash,role='CEO',status='ACTIVE',first_login=false
    RETURNING id,username,role`,
    [process.env.CEO_NAME||"SkillLink CEO",process.env.CEO_MOBILE||null,process.env.CEO_EMAIL||null,username,hash,"CEO-"+require("crypto").randomBytes(5).toString("hex").toUpperCase()]);
  console.log("CEO ready:",r.rows[0]);
  await pool.end();
})().catch(e=>{console.error(e);process.exit(1)});
