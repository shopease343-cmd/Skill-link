
app.get("/api/auth/me",auth,(req,res)=>res.json({user:req.user}));

app.post("/api/auth/change-password",auth,asyncRoute(async(req,res)=>{
  const {currentPassword,newPassword}=req.body;
  if(!newPassword || newPassword.length<8) return res.status(400).json({message:"New password must be at least 8 characters"});
  const r=await q(`SELECT password_hash FROM users WHERE id=$1`,[req.user.id]);
  if(!(await bcrypt.compare(currentPassword,r.rows[0].password_hash))) return res.status(400).json({message:"Current password is incorrect"});
  const hash=await bcrypt.hash(newPassword,12);
  await q(`UPDATE users SET password_hash=$1,first_login=false,updated_at=now() WHERE id=$2`,[hash,req.user.id]);
  await audit(req.user.id,"CHANGE_PASSWORD","USER",req.user.id);
  res.json({message:"Password changed"});
}));


app.post("/api/auth/reset-password",asyncRoute(async(req,res)=>{
  const {token,newPassword}=req.body;
  if(!token || !newPassword || newPassword.length<8) return res.status(400).json({message:"Invalid reset request"});
  const hash=crypto.createHash("sha256").update(token).digest("hex");
  const r=await q(`SELECT * FROM password_reset_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now()`,[hash]);
  if(!r.rows[0]) return res.status(400).json({message:"Invalid or expired reset token"});
  const pass=await bcrypt.hash(newPassword,12);
  await q(`UPDATE users SET password_hash=$1,first_login=false,updated_at=now() WHERE id=$2`,[pass,r.rows[0].user_id]);
  await q(`UPDATE password_reset_tokens SET used_at=now() WHERE id=$1`,[r.rows[0].id]);
  res.json({message:"Password reset successful"});
}));

app.post("/api/users",auth,allow("CEO","ADMIN"),asyncRoute(async(req,res)=>{
  const {name,mobile,email,username,password,role,referralCode}=req.body;
  if(!["PARTNER","CLIENT"].includes(role)) return res.status(400).json({message:"Only Partner or Client can be created"});
  if(req.user.role==="ADMIN" && role==="CLIENT"===false) return res.status(403).json({message:"Admin cannot create this role"});
  const exists=await q(`SELECT id FROM users WHERE username=$1`,[username]);
  if(exists.rows[0]) return res.status(409).json({message:"Username already exists"});
  const hash=await bcrypt.hash(password,12);
  let referredBy=null;
  if(referralCode){
    const rr=await q(`SELECT id FROM users WHERE referral_code=$1 AND role='PARTNER'`,[referralCode]);
    if(rr.rows[0]) referredBy=rr.rows[0].id;
  }
  const refCode=`SL-${crypto.randomBytes(5).toString("hex").toUpperCase()}`;
  const r=await q(`INSERT INTO users(name,mobile,email,username,password_hash,role,referral_code,referred_by)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,name,username,role,status,first_login,referral_code`,
    [name,mobile||null,email||null,username,hash,role,refCode,referredBy]);
  if(referredBy) await q(`INSERT INTO referrals(referrer_id,referred_id,status) VALUES($1,$2,'REGISTERED') ON CONFLICT DO NOTHING`,[referredBy,r.rows[0].id]);
  await audit(req.user.id,"CREATE_USER","USER",r.rows[0].id,{role});
  res.status(201).json({user:r.rows[0]});
}));

app.patch("/api/users/:id/status",auth,allow("CEO","ADMIN"),asyncRoute(async(req,res)=>{
  if(!["ACTIVE","SUSPENDED","DEACTIVATED"].includes(req.body.status)) return res.status(400).json({message:"Invalid status"});
  const r=await q(`UPDATE users SET status=$1,updated_at=now() WHERE id=$2 AND role<>'CEO' RETURNING id,name,username,role,status`,[req.body.status,req.params.id]);
  if(!r.rows[0]) return res.status(404).json({message:"User not found or protected"});
  await audit(req.user.id,"UPDATE_USER_STATUS","USER",r.rows[0].id,{status:req.body.status});
  res.json(r.rows[0]);
}));

app.get("/api/users",auth,allow("CEO","ADMIN"),asyncRoute(async(req,res)=>{
  const roleFilter=req.query.role;
  const params=[];
  let where="role <> 'CEO'";
  if(roleFilter){params.push(roleFilter);where+=" AND role=$1";}
  const r=await q(`SELECT id,name,mobile,email,username,role,status,referral_code,created_at FROM users WHERE ${where} ORDER BY created_at DESC`,params);
  res.json(r.rows);
}));

app.get("/api/packages",asyncRoute(async(req,res)=>{
  const r=await q(`SELECT * FROM packages WHERE status='ACTIVE' ORDER BY price`);
  res.json(r.rows);
}));
app.post("/api/packages",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  const {name,positioning,description,thumbnail,price,partnerCommission,companyShare}=req.body;
  const r=await q(`INSERT INTO packages(name,positioning,description,thumbnail,price,partner_commission,company_share)
    VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [name,positioning,description,thumbnail,price,partnerCommission||0,companyShare||0]);
  await audit(req.user.id,"CREATE_PACKAGE","PACKAGE",r.rows[0].id);
  res.status(201).json(r.rows[0]);
}));
app.patch("/api/packages/:id",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  const b=req.body;
  const r=await q(`UPDATE packages SET name=COALESCE($1,name),positioning=COALESCE($2,positioning),description=COALESCE($3,description),
    thumbnail=COALESCE($4,thumbnail),price=COALESCE($5,price),partner_commission=COALESCE($6,partner_commission),
    company_share=COALESCE($7,company_share),status=COALESCE($8,status),updated_at=now() WHERE id=$9 RETURNING *`,
    [b.name,b.positioning,b.description,b.thumbnail,b.price,b.partnerCommission,b.companyShare,b.status,req.params.id]);
  if(!r.rows[0]) return res.status(404).json({message:"Package not found"});
  res.json(r.rows[0]);
}));

app.post("/api/packages/:id/purchase",auth,allow("PARTNER"),asyncRoute(async(req,res)=>{
  const p=await q(`SELECT * FROM packages WHERE id=$1 AND status='ACTIVE'`,[req.params.id]);
  if(!p.rows[0]) return res.status(404).json({message:"Package not found"});
  const r=await q(`INSERT INTO package_purchases(user_id,package_id,amount,payment_screenshot,transaction_id,payment_date)
    VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
    [req.user.id,p.rows[0].id,p.rows[0].price,req.body.paymentScreenshot||null,req.body.transactionId||null,req.body.paymentDate||null]);
  res.status(201).json(r.rows[0]);
}));

app.get("/api/packages/purchases",auth,asyncRoute(async(req,res)=>{
  const where=req.user.role==="CEO"||req.user.role==="ADMIN"?"":"WHERE pp.user_id=$1";
  const params=where?[req.user.id]:[];
  const r=await q(`SELECT pp.*,p.name package_name,u.name user_name FROM package_purchases pp JOIN packages p ON p.id=pp.package_id JOIN users u ON u.id=pp.user_id ${where} ORDER BY pp.created_at DESC`,params);
  res.json(r.rows);
}));

app.patch("/api/packages/purchases/:id",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  const status=req.body.status;
  if(!["PENDING","VERIFIED","REJECTED","RESUBMISSION_REQUIRED"].includes(status)) return res.status(400).json({message:"Invalid payment status"});
  const r=await q(`UPDATE package_purchases SET status=$1,verified_by=$2,verified_at=CASE WHEN $1='VERIFIED' THEN now() ELSE NULL END,updated_at=now() WHERE id=$3 RETURNING *`,
    [status,req.user.id,req.params.id]);
  if(!r.rows[0]) return res.status(404).json({message:"Purchase not found"});
  await audit(req.user.id,"VERIFY_PACKAGE_PAYMENT","PACKAGE_PURCHASE",r.rows[0].id,{status});
  res.json(r.rows[0]);
}));

app.post("/api/courses",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  const r=await q(`INSERT INTO courses(name,description,thumbnail,package_id,category,status,certificate_eligible)
    VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [req.body.name,req.body.description||null,req.body.thumbnail||null,req.body.packageId||null,req.body.category||null,req.body.status||"DRAFT",!!req.body.certificateEligible]);
  res.status(201).json(r.rows[0]);
}));
app.get("/api/courses",asyncRoute(async(req,res)=>{
  const r=await q(`SELECT c.*,p.name package_name FROM courses c LEFT JOIN packages p ON p.id=c.package_id WHERE c.status='PUBLISHED' ORDER BY c.created_at DESC`);
  res.json(r.rows);
}));
app.patch("/api/courses/:id",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  const b=req.body;
  const r=await q(`UPDATE courses SET name=COALESCE($1,name),description=COALESCE($2,description),thumbnail=COALESCE($3,thumbnail),
    package_id=COALESCE($4,package_id),category=COALESCE($5,category),status=COALESCE($6,status),
    certificate_eligible=COALESCE($7,certificate_eligible),updated_at=now() WHERE id=$8 RETURNING *`,
    [b.name,b.description,b.thumbnail,b.packageId,b.category,b.status,b.certificateEligible,req.params.id]);
  if(!r.rows[0]) return res.status(404).json({message:"Course not found"});
  res.json(r.rows[0]);
}));
app.put("/api/courses/:id/progress",auth,allow("PARTNER"),asyncRoute(async(req,res)=>{
  const b=req.body;
  const r=await q(`INSERT INTO course_progress(user_id,course_id,completed_chapters,quiz_score,assessment_completed,skill_mastery,completed,completed_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,CASE WHEN $7 THEN now() ELSE NULL END)
    ON CONFLICT(user_id,course_id) DO UPDATE SET completed_chapters=$3,quiz_score=$4,assessment_completed=$5,skill_mastery=$6,completed=$7,completed_at=CASE WHEN $7 THEN now() ELSE course_progress.completed_at END
    RETURNING *`,
    [req.user.id,req.params.id,b.completedChapters||[],b.quizScore??null,!!b.assessmentCompleted,!!b.skillMastery,!!b.completed]);
  res.json(r.rows[0]);
}));

app.post("/api/referrals/attach",auth,asyncRoute(async(req,res)=>{
  const rr=await q(`SELECT id FROM users WHERE referral_code=$1 AND role='PARTNER' AND status='ACTIVE'`,[req.body.referralCode]);
  if(!rr.rows[0] || String(rr.rows[0].id)===String(req.user.id)) return res.status(400).json({message:"Invalid referral ID"});
  const ex=await q(`SELECT id FROM referrals WHERE referred_id=$1`,[req.user.id]);
  if(ex.rows[0]) return res.status(409).json({message:"Referral ownership already assigned"});
  const r=await q(`INSERT INTO referrals(referrer_id,referred_id,status) VALUES($1,$2,'REGISTERED') RETURNING *`,[rr.rows[0].id,req.user.id]);
  res.status(201).json(r.rows[0]);
}));
app.get("/api/referrals/my",auth,allow("PARTNER"),asyncRoute(async(req,res)=>{
  const r=await q(`SELECT r.*,u.name,u.username,u.mobile,u.status user_status,p.name package_name FROM referrals r JOIN users u ON u.id=r.referred_id LEFT JOIN packages p ON p.id=r.package_id WHERE r.referrer_id=$1 ORDER BY r.created_at DESC`,[req.user.id]);
  res.json(r.rows);
}));

app.get("/api/earnings/my",auth,allow("PARTNER","ADMIN"),asyncRoute(async(req,res)=>{
  const r=await q(`SELECT * FROM earnings WHERE user_id=$1 ORDER BY created_at DESC`,[req.user.id]);
  const totals=await q(`SELECT COALESCE(SUM(CASE WHEN status='AVAILABLE' THEN partner_share ELSE 0 END),0) available,
    COALESCE(SUM(CASE WHEN status='PENDING' THEN partner_share ELSE 0 END),0) pending FROM earnings WHERE user_id=$1`,[req.user.id]);
  res.json({rows:r.rows,totals:totals.rows[0]});
}));

app.post("/api/withdrawals",auth,allow("PARTNER","ADMIN"),asyncRoute(async(req,res)=>{
  const amount=Number(req.body.amount);
  if(!Number.isFinite(amount)||amount<100) return res.status(400).json({message:"Minimum withdrawal is ₹100"});
  const client=await pool.connect();
  try {
    await client.query("BEGIN");
    const bal=await client.query(`SELECT COALESCE(SUM(partner_share),0) available FROM earnings WHERE user_id=$1 AND status='AVAILABLE' FOR UPDATE`,[req.user.id]);
    if(Number(bal.rows[0].available)<amount) throw Object.assign(new Error("Insufficient available balance"),{status:400});
    const w=await client.query(`INSERT INTO withdrawals(user_id,amount,upi_id) VALUES($1,$2,$3) RETURNING *`,[req.user.id,amount,req.body.upiId]);
    let remain=amount;
    const rows=await client.query(`SELECT id,partner_share FROM earnings WHERE user_id=$1 AND status='AVAILABLE' AND partner_share>0 ORDER BY created_at FOR UPDATE`,[req.user.id]);
    for(const row of rows.rows){
      if(remain<=0) break;
      const take=Math.min(Number(row.partner_share),remain);
      const left=Number(row.partner_share)-take;
      await client.query(`UPDATE earnings SET partner_share=$1,status=CASE WHEN $1=0 THEN 'WITHDRAWN' ELSE status END WHERE id=$2`,[left,row.id]);
      remain-=take;
    }
    await client.query("COMMIT");
    await audit(req.user.id,"CREATE_WITHDRAWAL","WITHDRAWAL",w.rows[0].id,{amount});
    res.status(201).json(w.rows[0]);
  } catch(e) {
    await client.query("ROLLBACK");
    res.status(e.status||500).json({message:e.status?e.message:"Withdrawal failed"});
  } finally { client.release(); }
}));
app.get("/api/withdrawals",auth,asyncRoute(async(req,res)=>{
  const sql=req.user.role==="CEO"?`SELECT w.*,u.name,u.username,u.mobile FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.created_at DESC`:
    `SELECT * FROM withdrawals WHERE user_id=$1 ORDER BY created_at DESC`;
  const r=await q(sql,req.user.role==="CEO"?[]:[req.user.id]); res.json(r.rows);
}));
app.patch("/api/withdrawals/:id",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  if(!["PENDING","APPROVED","REJECTED","PAID"].includes(req.body.status)) return res.status(400).json({message:"Invalid status"});
  const r=await q(`UPDATE withdrawals SET status=$1,remarks=$2,processed_by=$3,updated_at=now() WHERE id=$4 RETURNING *`,[req.body.status,req.body.remarks||null,req.user.id,req.params.id]);
  if(!r.rows[0]) return res.status(404).json({message:"Withdrawal not found"});
  await audit(req.user.id,"UPDATE_WITHDRAWAL","WITHDRAWAL",r.rows[0].id,{status:req.body.status});
  res.json(r.rows[0]);
}));

app.post("/api/projects",auth,allow("CEO","ADMIN","CLIENT"),asyncRoute(async(req,res)=>{
  const clientId=req.user.role==="CLIENT"?req.user.id:req.body.clientId;
  if(!clientId) return res.status(400).json({message:"Client is required"});
  const r=await q(`INSERT INTO projects(title,description,required_skills,budget,deadline,priority,client_id,attachments,created_by)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [req.body.title,req.body.description||null,req.body.requiredSkills||[],req.body.budget||null,req.body.deadline||null,req.body.priority||null,clientId,req.body.attachments||[],req.user.id]);
  res.status(201).json(r.rows[0]);
}));
app.get("/api/projects",auth,asyncRoute(async(req,res)=>{
  let sql=`SELECT * FROM projects WHERE 1=1`,params=[];
  if(req.user.role==="CLIENT"){params=[req.user.id];sql+=" AND client_id=$1";}
  if(req.user.role==="PARTNER"){params=[req.user.id];sql+=" AND assigned_partner_id=$1";}
  sql+=" ORDER BY created_at DESC";
  const r=await q(sql,params);res.json(r.rows);
}));
app.patch("/api/projects/:id",auth,asyncRoute(async(req,res)=>{
  const p=await q(`SELECT * FROM projects WHERE id=$1`,[req.params.id]);
  if(!p.rows[0]) return res.status(404).json({message:"Project not found"});
  const project=p.rows[0];
  const owner=req.user.role==="CEO"||req.user.role==="ADMIN"||
    (req.user.role==="CLIENT"&&String(project.client_id)===String(req.user.id))||
    (req.user.role==="PARTNER"&&String(project.assigned_partner_id)===String(req.user.id));
  if(!owner) return res.status(403).json({message:"Access denied"});
  const allowed={status:req.body.status,assigned_partner_id:req.body.assignedPartnerId};
  if(req.user.role==="PARTNER" && "assignedPartnerId" in req.body) return res.status(403).json({message:"Partner cannot self-assign"});
  const r=await q(`UPDATE projects SET status=COALESCE($1,status),assigned_partner_id=COALESCE($2,assigned_partner_id),updated_at=now() WHERE id=$3 RETURNING *`,
    [allowed.status||null,allowed.assigned_partner_id||null,req.params.id]);
  res.json(r.rows[0]);
}));
app.post("/api/projects/:id/messages",auth,asyncRoute(async(req,res)=>{
  const p=await q(`SELECT client_id,assigned_partner_id FROM projects WHERE id=$1`,[req.params.id]);
  if(!p.rows[0]) return res.status(404).json({message:"Project not found"});
  const x=p.rows[0];
  const ok=req.user.role==="CEO"||req.user.role==="ADMIN"||String(x.client_id)===String(req.user.id)||String(x.assigned_partner_id)===String(req.user.id);
  if(!ok) return res.status(403).json({message:"Access denied"});
  const r=await q(`INSERT INTO project_messages(project_id,sender_id,body,attachments) VALUES($1,$2,$3,$4) RETURNING *`,
    [req.params.id,req.user.id,req.body.body,req.body.attachments||[]]);
  res.status(201).json(r.rows[0]);
}));
app.get("/api/projects/:id/messages",auth,asyncRoute(async(req,res)=>{
  const p=await q(`SELECT client_id,assigned_partner_id FROM projects WHERE id=$1`,[req.params.id]);
  if(!p.rows[0]) return res.status(404).json({message:"Project not found"});
  const x=p.rows[0]; const ok=req.user.role==="CEO"||req.user.role==="ADMIN"||String(x.client_id)===String(req.user.id)||String(x.assigned_partner_id)===String(req.user.id);
  if(!ok) return res.status(403).json({message:"Access denied"});
  const r=await q(`SELECT m.*,u.name sender_name,u.role sender_role FROM project_messages m JOIN users u ON u.id=m.sender_id WHERE project_id=$1 ORDER BY m.created_at`,[req.params.id]);
  res.json(r.rows);
}));
app.post("/api/projects/:id/revisions",auth,allow("CLIENT"),asyncRoute(async(req,res)=>{
  const p=await q(`SELECT client_id FROM projects WHERE id=$1`,[req.params.id]);
  if(!p.rows[0]||String(p.rows[0].client_id)!==String(req.user.id)) return res.status(404).json({message:"Project not found"});
  const count=await q(`SELECT COUNT(*)::int count FROM project_revisions WHERE project_id=$1`,[req.params.id]);
  if(count.rows[0].count>=2) return res.status(400).json({message:"Two free revisions have already been used"});
  const n=count.rows[0].count+1;
  const r=await q(`INSERT INTO project_revisions(project_id,requested_by,reason,attachments,revision_number) VALUES($1,$2,$3,$4,$5) RETURNING *`,
    [req.params.id,req.user.id,req.body.reason||null,req.body.attachments||[],n]);
  await q(`UPDATE projects SET status='REVISION_REQUESTED',updated_at=now() WHERE id=$1`,[req.params.id]);
  res.status(201).json(r.rows[0]);
}));

app.post("/api/leads",auth,allow("CEO","ADMIN"),asyncRoute(async(req,res)=>{
  const r=await q(`INSERT INTO leads(name,mobile,source,partner_id,assigned_at,notes,status) VALUES($1,$2,$3,$4,CASE WHEN $4 IS NULL THEN NULL ELSE now() END,$5,$6) RETURNING *`,
    [req.body.name,req.body.mobile||null,req.body.source||null,req.body.partnerId||null,req.body.notes||null,req.body.status||"NEW"]);
  res.status(201).json(r.rows[0]);
}));
app.get("/api/leads",auth,asyncRoute(async(req,res)=>{
  const r=req.user.role==="PARTNER"
    ? await q(`SELECT * FROM leads WHERE partner_id=$1 ORDER BY created_at DESC`,[req.user.id])
    : await q(`SELECT * FROM leads ORDER BY created_at DESC`);
  res.json(r.rows);
}));
app.patch("/api/leads/:id",auth,asyncRoute(async(req,res)=>{
  const sql=req.user.role==="PARTNER"?`UPDATE leads SET status=COALESCE($1,status),notes=COALESCE($2,notes),conversion=COALESCE($3,conversion),updated_at=now() WHERE id=$4 AND partner_id=$5 RETURNING *`:
    `UPDATE leads SET status=COALESCE($1,status),notes=COALESCE($2,notes),conversion=COALESCE($3,conversion),partner_id=COALESCE($4,partner_id),assigned_at=CASE WHEN $4 IS NOT NULL THEN COALESCE(assigned_at,now()) ELSE assigned_at END,updated_at=now() WHERE id=$5 RETURNING *`;
  const params=req.user.role==="PARTNER"?[req.body.status,req.body.notes,req.body.conversion,req.params.id,req.user.id]:
    [req.body.status,req.body.notes,req.body.conversion,req.body.partnerId||null,req.params.id];
  const r=await q(sql,params); if(!r.rows[0]) return res.status(404).json({message:"Lead not found"}); res.json(r.rows[0]);
}));

app.get("/api/levels",auth,asyncRoute(async(req,res)=>res.json((await q(`SELECT * FROM levels WHERE active=true ORDER BY level`)).rows)));
app.post("/api/levels",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  const r=await q(`INSERT INTO levels(level,name,score_required,referral_required,skill_mastery_required,reward) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
    [req.body.level,req.body.name,req.body.scoreRequired,req.body.referralRequired||0,req.body.skillMasteryRequired||0,req.body.reward||null]);
  res.status(201).json(r.rows[0]);
}));
app.post("/api/scores",auth,allow("CEO","ADMIN"),asyncRoute(async(req,res)=>{
  const r=await q(`INSERT INTO score_transactions(user_id,points,source,reference_id,remarks) VALUES($1,$2,$3,$4,$5) RETURNING *`,
    [req.body.userId,req.body.points,req.body.source,req.body.referenceId||null,req.body.remarks||null]); res.status(201).json(r.rows[0]);
}));
app.get("/api/scores/me",auth,allow("PARTNER"),asyncRoute(async(req,res)=>{
  const s=await q(`SELECT COALESCE(SUM(points),0)::int score FROM score_transactions WHERE user_id=$1`,[req.user.id]);
  const rr=await q(`SELECT COUNT(*)::int count FROM referrals WHERE referrer_id=$1 AND status='VALID'`,[req.user.id]);
  res.json({score:s.rows[0].score,validReferrals:rr.rows[0].count});
}));

app.post("/api/certificates",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  const certificateId=`SL-${Date.now()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
  const verificationCode=crypto.randomBytes(12).toString("hex");
  const r=await q(`INSERT INTO certificates(user_id,course_id,certificate_id,verification_code,details) VALUES($1,$2,$3,$4,$5) RETURNING *`,
    [req.body.userId,req.body.courseId,certificateId,verificationCode,req.body.details||null]);
  res.status(201).json(r.rows[0]);
}));
app.get("/api/certificates/verify/:code",asyncRoute(async(req,res)=>{
  const r=await q(`SELECT c.certificate_id,c.verification_code,c.completion_date,c.details,u.name user_name,co.name course_name FROM certificates c JOIN users u ON u.id=c.user_id JOIN courses co ON co.id=c.course_id WHERE c.verification_code=$1`,[req.params.code]);
  if(!r.rows[0]) return res.status(404).json({valid:false});
  res.json({valid:true,certificate:r.rows[0]});
}));

app.post("/api/notifications",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  const r=await q(`INSERT INTO notifications(title,description,audience,created_by) VALUES($1,$2,$3,$4) RETURNING *`,
    [req.body.title,req.body.description||null,req.body.audience||"ALL",req.user.id]); res.status(201).json(r.rows[0]);
}));
app.get("/api/notifications",auth,asyncRoute(async(req,res)=>{
  const r=await q(`SELECT * FROM notifications WHERE audience='ALL' OR audience=$1 ORDER BY published_at DESC`,[req.user.role]); res.json(r.rows);
}));

app.post("/api/masterclasses",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  const r=await q(`INSERT INTO masterclasses(title,description,meeting_link,scheduled_at,status,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
    [req.body.title,req.body.description||null,req.body.meetingLink||null,req.body.scheduledAt||null,req.body.status||"DRAFT",req.user.id]); res.status(201).json(r.rows[0]);
}));
app.patch("/api/masterclasses/:id",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  const b=req.body; const r=await q(`UPDATE masterclasses SET title=COALESCE($1,title),description=COALESCE($2,description),meeting_link=COALESCE($3,meeting_link),scheduled_at=COALESCE($4,scheduled_at),status=COALESCE($5,status),updated_at=now() WHERE id=$6 RETURNING *`,
    [b.title,b.description,b.meetingLink,b.scheduledAt,b.status,req.params.id]); if(!r.rows[0]) return res.status(404).json({message:"Masterclass not found"}); res.json(r.rows[0]);
}));
app.get("/api/masterclasses",auth,asyncRoute(async(req,res)=>{
  const r=await q(`SELECT * FROM masterclasses WHERE status='PUBLISHED' ORDER BY scheduled_at`); res.json(r.rows);
}));

app.get("/api/company-settings",auth,asyncRoute(async(req,res)=>res.json((await q(`SELECT * FROM company_settings WHERE id=true`)).rows[0])));
app.patch("/api/company-settings",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  const b=req.body; const r=await q(`UPDATE company_settings SET company_qr_url=COALESCE($1,company_qr_url),company_upi_id=COALESCE($2,company_upi_id),payment_instructions=COALESCE($3,payment_instructions),updated_by=$4,updated_at=now() WHERE id=true RETURNING *`,
    [b.companyQrUrl,b.companyUpiId,b.paymentInstructions,req.user.id]); res.json(r.rows[0]);
}));

app.post("/api/disputes",auth,asyncRoute(async(req,res)=>{
  const r=await q(`INSERT INTO project_disputes(project_id,raised_by,reason,description,attachments) VALUES($1,$2,$3,$4,$5) RETURNING *`,
    [req.body.projectId,req.user.id,req.body.reason||null,req.body.description||null,req.body.attachments||[]]); res.status(201).json(r.rows[0]);
}));
app.get("/api/disputes",auth,asyncRoute(async(req,res)=>{
  const r=req.user.role==="CEO"||req.user.role==="ADMIN"
    ? await q(`SELECT * FROM project_disputes ORDER BY created_at DESC`)
    : await q(`SELECT d.* FROM project_disputes d JOIN projects p ON p.id=d.project_id WHERE p.client_id=$1 OR p.assigned_partner_id=$1 ORDER BY d.created_at DESC`,[req.user.id]);
  res.json(r.rows);
}));
app.patch("/api/disputes/:id",auth,allow("CEO"),asyncRoute(async(req,res)=>{
  const r=await q(`UPDATE project_disputes SET status=COALESCE($1,status),decision=COALESCE($2,decision),decided_by=$3,updated_at=now() WHERE id=$4 RETURNING *`,
    [req.body.status,req.body.decision||null,req.user.id,req.params.id]); if(!r.rows[0]) return res.status(404).json({message:"Dispute not found"}); await audit(req.user.id,"RESOLVE_DISPUTE","DISPUTE",r.rows[0].id,{status:req.body.status}); res.json(r.rows[0]);
}));

app.use((err,req,res,next)=>{
  console.error(err);
  if(res.headersSent) return next(err);
  res.status(500).json({message:"Internal server error"});
});

app.listen(PORT,()=>console.log(`SkillLink API running on port ${PORT}`));
