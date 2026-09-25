const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const path=require("path");

const app=express();
const db=new Database("primelend.db");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 full_name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'borrower',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS applications(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 loan_amount INTEGER NOT NULL,
 term_months INTEGER NOT NULL,
 purpose TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Pending',
 admin_notes TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);`);

const ADMIN_EMAIL=process.env.ADMIN_EMAIL||"admin@primelend.local";
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||"ChangeMe123!";
if(!db.prepare("SELECT id FROM users WHERE email=?").get(ADMIN_EMAIL)){
 db.prepare("INSERT INTO users(full_name,email,password_hash,role) VALUES(?,?,?,'admin')")
   .run("PrimeLend Admin",ADMIN_EMAIL,bcrypt.hashSync(ADMIN_PASSWORD,12));
}

app.use(express.json());
app.use(session({
 secret:process.env.SESSION_SECRET||"CHANGE_THIS_SESSION_SECRET",
 resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:"lax",maxAge:8*60*60*1000}
}));
app.use(express.static(path.join(__dirname,"public")));

function auth(req,res,next){return req.session.user?next():res.status(401).json({error:"Please sign in."})}
function admin(req,res,next){return req.session.user?.role==="admin"?next():res.status(403).json({error:"Admin access required."})}

app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));
app.post("/api/login",(req,res)=>{
 const email=(req.body.email||"").trim().toLowerCase();
 const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
 if(!u||!bcrypt.compareSync(req.body.password||"",u.password_hash))
   return res.status(401).json({error:"Invalid email or password."});
 req.session.user={id:u.id,name:u.full_name,email:u.email,role:u.role};
 res.json({ok:true,role:u.role});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.post("/api/register",(req,res)=>{
 const {full_name,password}=req.body,email=(req.body.email||"").trim().toLowerCase();
 if(!full_name||!email||!password||password.length<8)
   return res.status(400).json({error:"Name, email and password (8+ characters) required."});
 try{
  const r=db.prepare("INSERT INTO users(full_name,email,password_hash) VALUES(?,?,?)")
    .run(full_name,email,bcrypt.hashSync(password,12));
  req.session.user={id:Number(r.lastInsertRowid),name:full_name,email,role:"borrower"};
  res.json({ok:true});
 }catch(e){res.status(400).json({error:"Email already registered."})}
});

app.post("/api/applications",auth,(req,res)=>{
 if(req.session.user.role!=="borrower") return res.status(403).json({error:"Borrower account required."});
 const amount=Number(req.body.loan_amount),term=Number(req.body.term_months),purpose=(req.body.purpose||"").trim();
 if(amount<20000||amount>250000||![6,12,36].includes(term)||!purpose)
   return res.status(400).json({error:"Use ₱20,000–₱250,000 and a 6, 12, or 36 month term."});
 const r=db.prepare("INSERT INTO applications(user_id,loan_amount,term_months,purpose) VALUES(?,?,?,?)")
   .run(req.session.user.id,amount,term,purpose);
 res.json({ok:true,id:Number(r.lastInsertRowid)});
});

app.get("/api/admin/applications",admin,(req,res)=>{
 res.json(db.prepare(`SELECT a.*,u.full_name,u.email
 FROM applications a JOIN users u ON u.id=a.user_id ORDER BY a.id DESC`).all());
});
app.get("/api/admin/stats",admin,(req,res)=>{
 res.json(db.prepare(`SELECT COUNT(*) total,
 SUM(CASE WHEN status='Pending' THEN 1 ELSE 0 END) pending,
 SUM(CASE WHEN status='Approved' THEN 1 ELSE 0 END) approved,
 SUM(CASE WHEN status='Rejected' THEN 1 ELSE 0 END) rejected
 FROM applications`).get());
});
app.patch("/api/admin/applications/:id",admin,(req,res)=>{
 const allowed=["Pending","Needs Information","Approved","Rejected"];
 if(!allowed.includes(req.body.status)) return res.status(400).json({error:"Invalid status."});
 db.prepare("UPDATE applications SET status=?,admin_notes=? WHERE id=?")
   .run(req.body.status,req.body.admin_notes||"",req.params.id);
 res.json({ok:true});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(process.env.PORT||3000,()=>console.log("PrimeLend: http://localhost:"+(process.env.PORT||3000)));
