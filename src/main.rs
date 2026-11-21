#![cfg_attr(windows, windows_subsystem = "windows")]
//! CCS Computer Laboratory Asset & Maintenance Management System
//! Axum + SQLite, schema-driven CRUD, role-based access, audit trail.
use axum::{extract::{Path, Query, State}, http::{header, HeaderMap, StatusCode}, response::{Html, IntoResponse, Response}, routing::{get, post, put}, Json, Router};
use rusqlite::{params_from_iter, types::{Value as SV, ValueRef}, Connection};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use rand::{rngs::OsRng, RngCore};
use std::{collections::HashMap, time::{Duration, Instant}, sync::{Arc, Mutex}};

struct Col { n: &'static str, t: &'static str, o: &'static str }
struct Tbl { name: &'static str, title: &'static str, ro: bool, cols: &'static [Col] }
macro_rules! c { ($n:expr, $t:expr, $o:expr) => { Col { n: $n, t: $t, o: $o } }; }

const STATUS_ASSET: &str = "Serviceable|For Repair|Under Repair|Retired|Lost|Disposed";
const TYPES: &str = "Preventive|Hardware|Peripheral|Software|Malware|Network|OS Reinstall|Other";
static TABLES: &[Tbl] = &[
    Tbl { name: "labs", title: "Laboratories", ro: false, cols: &[c!("code","t",""), c!("name","t",""), c!("seats","i",""), c!("specs","t",""), c!("notes","t","area")] },
    Tbl { name: "assets", title: "Assets", ro: false, cols: &[c!("tag","t",""), c!("lab_id","i","fk:labs"), c!("category","t","Desktop PC|Mini PC|Monitor|Keyboard/Mouse|AVR/UPS|Network|Display/Projector|Tools|Consumables|Other"), c!("name","t",""), c!("specs","t","area"), c!("serial","t",""), c!("qty","i",""), c!("unit_no","t",""), c!("purchase_date","t","date"), c!("warranty_until","t","date"), c!("cost","r",""), c!("status","t",STATUS_ASSET), c!("notes","t","area")] },
    Tbl { name: "maintenance", title: "Maintenance Log", ro: false, cols: &[c!("lab_id","i","fk:labs"), c!("date","t","date"), c!("unit","t",""), c!("type","t",TYPES), c!("problem","t",""), c!("action","t",""), c!("technician","t",""), c!("status","t","Resolved|In Progress|Pending"), c!("cost","r","")] },
    Tbl { name: "repairs", title: "Repairs & Replacements", ro: false, cols: &[c!("ticket_no","t",""), c!("lab_id","i","fk:labs"), c!("item","t",""), c!("unit","t",""), c!("reported_date","t","date"), c!("issue","t",""), c!("action","t","Repair|Replace|Assess"), c!("priority","t","Low|Medium|High|Critical"), c!("status","t","Open|In Progress|For Replacement|Resolved|Closed"), c!("resolved_date","t","date"), c!("cost","r",""), c!("notes","t","area")] },
    Tbl { name: "incidents", title: "Incident Reports", ro: false, cols: &[c!("date","t","date"), c!("lab_id","i","fk:labs"), c!("unit","t",""), c!("description","t","area"), c!("cause","t",""), c!("action_taken","t","area"), c!("reported_by","t",""), c!("status","t","Open|Under Review|Closed")] },
    Tbl { name: "schedules", title: "Preventive Schedules", ro: false, cols: &[c!("lab_id","i","fk:labs"), c!("task","t",""), c!("frequency","t","Weekly|Monthly|Quarterly|Semestral|Yearly"), c!("last_done","t","date"), c!("next_due","t","date"), c!("assigned_to","t",""), c!("status","t","Scheduled|In Progress|Done")] },
    Tbl { name: "parts", title: "Spare Parts Stock", ro: false, cols: &[c!("name","t",""), c!("category","t",""), c!("qty","i",""), c!("min_qty","i",""), c!("location","t",""), c!("notes","t","area")] },
    Tbl { name: "accounts", title: "Lab Accounts", ro: false, cols: &[c!("lab_id","i","fk:labs"), c!("file","t",""), c!("count","i",""), c!("pattern","t",""), c!("notes","t","")] },
    Tbl { name: "users", title: "Users", ro: false, cols: &[c!("username","t",""), c!("full_name","t",""), c!("role","t","admin|technician|viewer"), c!("password","t","pw")] },
    Tbl { name: "audit", title: "Audit Log", ro: true, cols: &[c!("ts","t",""), c!("who","t",""), c!("action","t",""), c!("tbl","t",""), c!("rec_id","i",""), c!("detail","t","")] },
];

struct Session { user: String, role: String, expires: Instant }
struct App { db: Mutex<Connection>, sess: Mutex<HashMap<String, Session>>, login_failures: Mutex<HashMap<String, (u32, Instant)>> }
type S = Arc<App>;

fn tbl(n: &str) -> Option<&'static Tbl> { TABLES.iter().find(|t| t.name == n) }
fn dbcols(t: &Tbl) -> Vec<&'static Col> { t.cols.iter().filter(|c| c.o != "pw").collect() }
fn rnd() -> String {
 let mut bytes = [0u8; 32]; OsRng.fill_bytes(&mut bytes);
 bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
fn hash(p: &str) -> String {
 let salt = SaltString::generate(&mut OsRng);
 Argon2::default().hash_password(p.as_bytes(), &salt).expect("password hashing failed").to_string()
}
fn legacy_hash(p: &str, salt: &str) -> String {
 let mut h = Sha256::new(); h.update(salt.as_bytes()); h.update(p.as_bytes()); format!("{}${:x}", salt, h.finalize())
}
fn verify(p: &str, stored: &str) -> bool {
 if stored.starts_with("$argon2") { return PasswordHash::new(stored).ok().map(|h| Argon2::default().verify_password(p.as_bytes(), &h).is_ok()).unwrap_or(false); }
 stored.split_once('$').map(|(salt, _)| legacy_hash(p, salt) == stored).unwrap_or(false)
}
fn err(c: StatusCode, m: &str) -> Response { (c, Json(json!({ "error": m }))).into_response() }
fn auth(s: &S, h: &HeaderMap) -> Option<(String, String)> {
 let t = h.get("x-token")?.to_str().ok()?; let mut sessions = s.sess.lock().unwrap();
 let session = sessions.get(t)?; if session.expires <= Instant::now() { sessions.remove(t); return None; }
 Some((session.user.clone(), session.role.clone()))
}
fn can_write(t: &str, role: &str, del: bool) -> bool {
    match role { "admin" => true, "technician" => t != "users" && !(del && t == "labs"), _ => false }
}
fn vref(v: ValueRef) -> Value {
    match v { ValueRef::Null => Value::Null, ValueRef::Integer(x) => json!(x), ValueRef::Real(x) => json!(x), ValueRef::Text(t) => json!(String::from_utf8_lossy(t)), ValueRef::Blob(_) => Value::Null }
}
fn qj(db: &Connection, sql: &str) -> Vec<Value> {
    let mut st = match db.prepare(sql) { Ok(s) => s, Err(_) => return vec![] };
    let names: Vec<String> = st.column_names().iter().map(|x| x.to_string()).collect();
    let rows = st.query_map([], |r| { let mut m = Map::new(); for (i, n) in names.iter().enumerate() { m.insert(n.clone(), vref(r.get_ref(i)?)); } Ok(Value::Object(m)) });
    match rows { Ok(r) => r.filter_map(|x| x.ok()).collect(), Err(_) => vec![] }
}
fn conv(c: &Col, v: &Value) -> SV {
    let s = match v { Value::Null => String::new(), Value::String(x) => x.trim().to_string(), o => o.to_string() };
    if s.is_empty() { return SV::Null; }
    match c.t { "i" => s.parse::<f64>().map(|x| SV::Integer(x as i64)).unwrap_or(SV::Null), "r" => s.parse::<f64>().map(SV::Real).unwrap_or(SV::Null), _ => SV::Text(s) }
}
fn audit(db: &Connection, who: &str, action: &str, t: &str, id: i64, detail: &Value) {
 let mut safe = detail.clone(); if t == "users" { if let Some(fields) = safe.as_object_mut() { fields.remove("password"); fields.remove("pass_hash"); } }
 let d: String = safe.to_string().chars().take(400).collect();
 let _ = db.execute("INSERT INTO audit(ts,who,action,tbl,rec_id,detail) VALUES(datetime('now','localtime'),?1,?2,?3,?4,?5)", rusqlite::params![who, action, t, id, d]);
}
fn set_pw(db: &Connection, id: i64, b: &Value) -> rusqlite::Result<()> {
    if let Some(p) = b["password"].as_str() { if !p.is_empty() { db.execute("UPDATE users SET pass_hash=?1 WHERE id=?2", rusqlite::params![hash(p), id])?; } }
    Ok(())
}
fn insert(db: &Connection, t: &Tbl, b: &Value) -> rusqlite::Result<i64> {
    let cs = dbcols(t);
    let names: Vec<String> = cs.iter().map(|c| format!("\"{}\"", c.n)).collect();
    let ph: Vec<String> = (1..=cs.len()).map(|i| format!("?{}", i)).collect();
    let vals: Vec<SV> = cs.iter().map(|c| conv(c, &b[c.n])).collect();
    db.execute(&format!("INSERT INTO \"{}\"({}) VALUES({})", t.name, names.join(","), ph.join(",")), params_from_iter(vals))?;
    let id = db.last_insert_rowid();
    if t.name == "users" { set_pw(db, id, b)?; }
    Ok(id)
}
fn fetch(db: &Connection, t: &Tbl, q: Option<&str>) -> Vec<Value> {
    let cs = dbcols(t);
    let names: Vec<&str> = std::iter::once("id").chain(cs.iter().map(|c| c.n)).collect();
    let sel: Vec<String> = names.iter().map(|n| format!("\"{}\"", n)).collect();
    let mut sql = format!("SELECT {} FROM \"{}\"", sel.join(","), t.name);
    let mut args: Vec<SV> = vec![];
    if let Some(q) = q.filter(|x| !x.is_empty()) {
        let w: Vec<String> = cs.iter().map(|c| format!("\"{}\" LIKE ?1", c.n)).collect();
        sql += &format!(" WHERE {}", w.join(" OR ")); args.push(SV::Text(format!("%{}%", q)));
    }
    sql += " ORDER BY id DESC LIMIT 5000";
    let mut st = match db.prepare(&sql) { Ok(s) => s, Err(_) => return vec![] };
    let rows = st.query_map(params_from_iter(args), |r| { let mut m = Map::new(); for (i, n) in names.iter().enumerate() { m.insert(n.to_string(), vref(r.get_ref(i)?)); } Ok(Value::Object(m)) });
    match rows { Ok(r) => r.filter_map(|x| x.ok()).collect(), Err(_) => vec![] }
}

async fn index() -> Html<&'static str> { Html(include_str!("../static/index.html")) }
async fn login(State(s): State<S>, Json(b): Json<Value>) -> Response {
 let (u,p)=(b["username"].as_str().unwrap_or(""),b["password"].as_str().unwrap_or("")); let key=u.to_lowercase();
 { let mut failures=s.login_failures.lock().unwrap(); if let Some((count,until))=failures.get(&key) { if *count>=5 && Instant::now()<*until { return err(StatusCode::TOO_MANY_REQUESTS,"Too many failed attempts. Try again in one minute."); } } if failures.get(&key).map(|(_,until)|Instant::now()>=*until).unwrap_or(false) { failures.remove(&key); } }
 let row:Option<(String,String,String)>={ let db=s.db.lock().unwrap(); db.query_row("SELECT pass_hash,role,COALESCE(full_name,username) FROM users WHERE username=?1",[u],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).ok() };
 match row {
  Some((stored,role,name)) if verify(p,&stored)=>{
   s.login_failures.lock().unwrap().remove(&key); let tok=rnd();
   s.sess.lock().unwrap().insert(tok.clone(),Session{user:u.to_string(),role:role.clone(),expires:Instant::now()+Duration::from_secs(8*60*60)});
   if !stored.starts_with("$argon2") { let _=s.db.lock().unwrap().execute("UPDATE users SET pass_hash=?1 WHERE username=?2",rusqlite::params![hash(p),u]); }
   audit(&s.db.lock().unwrap(),u,"login","users",0,&json!({})); Json(json!({"token":tok,"role":role,"name":name})).into_response()
  }
  _=>{ let mut failures=s.login_failures.lock().unwrap(); let entry=failures.entry(key).or_insert((0,Instant::now()+Duration::from_secs(60))); entry.0+=1; if entry.0>=5 {entry.1=Instant::now()+Duration::from_secs(60);} err(StatusCode::UNAUTHORIZED,"Invalid username or password") }
 }
}
async fn schema() -> Json<Value> {
    Json(Value::Array(TABLES.iter().map(|t| json!({ "name": t.name, "title": t.title, "ro": t.ro,
        "cols": t.cols.iter().map(|c| json!({ "n": c.n, "t": c.t, "o": c.o })).collect::<Vec<_>>() })).collect()))
}
async fn list(State(s): State<S>, h: HeaderMap, Path(t): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    let Some((_, role)) = auth(&s, &h) else { return err(StatusCode::UNAUTHORIZED, "Login required") };
    let Some(tb) = tbl(&t) else { return err(StatusCode::NOT_FOUND, "No such table") };
    if (t == "users" || t == "audit") && role != "admin" { return err(StatusCode::FORBIDDEN, "Admin only"); }
    Json(fetch(&s.db.lock().unwrap(), tb, q.get("q").map(|x| x.as_str()))).into_response()
}
async fn export(State(s): State<S>, h: HeaderMap, Path(t): Path<String>) -> Response {
    let Some((_, role)) = auth(&s, &h) else { return err(StatusCode::UNAUTHORIZED, "Login required") };
    let Some(tb) = tbl(&t) else { return err(StatusCode::NOT_FOUND, "No such table") };
    if (t == "users" || t == "audit") && role != "admin" { return err(StatusCode::FORBIDDEN, "Admin only"); }
    let rows = fetch(&s.db.lock().unwrap(), tb, None);
    let names: Vec<&str> = std::iter::once("id").chain(dbcols(tb).iter().map(|c| c.n)).collect();
    let q = |v: &Value| {
        let raw = match v { Value::Null => String::new(), Value::String(x) => x.clone(), o => o.to_string() };
        let first = raw.trim_start().chars().next();
        let dangerous = matches!(first, Some('=' | '+' | '-' | '@' | '\t' | '\r'));
        let safe = if matches!(v, Value::String(_)) && dangerous { format!("'{}", raw) } else { raw };
        format!("\"{}\"", safe.replace('"', "\"\""))
    };
    let mut out = names.join(",") + "\n";
    for r in rows { out += &names.iter().map(|n| q(&r[*n])).collect::<Vec<_>>().join(","); out.push('\n'); }
    ([(header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}.csv\"", t))], out).into_response()
}
async fn create(State(s): State<S>, h: HeaderMap, Path(t): Path<String>, Json(b): Json<Value>) -> Response {
    let Some((user, role)) = auth(&s, &h) else { return err(StatusCode::UNAUTHORIZED, "Login required") };
    let Some(tb) = tbl(&t) else { return err(StatusCode::NOT_FOUND, "No such table") };
    if tb.ro || !can_write(&t, &role, false) { return err(StatusCode::FORBIDDEN, "Not allowed for your role"); }
    let db = s.db.lock().unwrap();
    match insert(&db, tb, &b) { Ok(id) => {
            audit(&db, &user, "create", &t, id, &b);
            let mut extra = json!({ "id": id });
            if t == "maintenance" {
                let lab = match &b["lab_id"] { Value::String(x) => x.clone(), Value::Number(n) => n.to_string(), _ => String::new() };
                let unit = b["unit"].as_str().unwrap_or("").trim().to_string();
                if unit.to_uppercase().starts_with("PC-") && b["type"].as_str().unwrap_or("") != "Preventive" {
                    let n: i64 = db.query_row("SELECT COUNT(*) FROM maintenance WHERE lab_id=?1 AND unit=?2 AND type!='Preventive'", rusqlite::params![lab, unit], |r| r.get(0)).unwrap_or(0);
                    if n >= 3 { extra = json!({ "id": id, "warn": format!("{} now has {} faults on record. Consider replacing it.", unit, n) }); }
                }
            }
            Json(extra).into_response()
        } Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()) }
}
async fn update(State(s): State<S>, h: HeaderMap, Path((t, id)): Path<(String, i64)>, Json(b): Json<Value>) -> Response {
    let Some((user, role)) = auth(&s, &h) else { return err(StatusCode::UNAUTHORIZED, "Login required") };
    let Some(tb) = tbl(&t) else { return err(StatusCode::NOT_FOUND, "No such table") };
    if tb.ro || !can_write(&t, &role, false) { return err(StatusCode::FORBIDDEN, "Not allowed for your role"); }
    let cs = dbcols(tb);
    let sets: Vec<String> = cs.iter().enumerate().map(|(i, c)| format!("\"{}\"=?{}", c.n, i + 1)).collect();
    let mut vals: Vec<SV> = cs.iter().map(|c| conv(c, &b[c.n])).collect(); vals.push(SV::Integer(id));
    let db = s.db.lock().unwrap();
    let r = db.execute(&format!("UPDATE \"{}\" SET {} WHERE id=?{}", t, sets.join(","), cs.len() + 1), params_from_iter(vals));
    match r.and_then(|_| if t == "users" { set_pw(&db, id, &b) } else { Ok(()) }) {
        Ok(_) => {
            audit(&db, &user, "update", &t, id, &b);
            let mut extra = json!({ "ok": true });
            if t == "schedules" && b["status"].as_str() == Some("Done") {
                let m = match b["frequency"].as_str().unwrap_or("") { "Weekly" => "+7 days", "Monthly" => "+1 month", "Quarterly" => "+3 months", "Semestral" => "+6 months", "Yearly" => "+1 year", _ => "" };
                if !m.is_empty() {
                    let _ = db.execute("UPDATE schedules SET last_done=date('now','localtime'), next_due=date(CASE WHEN next_due IS NOT NULL AND next_due>date('now','localtime') THEN next_due ELSE date('now','localtime') END, ?1), status='Scheduled' WHERE id=?2", rusqlite::params![m, id]);
                    let nd: String = db.query_row("SELECT COALESCE(next_due,'') FROM schedules WHERE id=?1", [id], |r| r.get(0)).unwrap_or_default();
                    audit(&db, &user, "auto-reschedule", "schedules", id, &json!({ "next_due": nd }));
                    extra = json!({ "ok": true, "auto": format!("Marked done. Next due {}", nd) });
                }
            }
            Json(extra).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}
async fn remove(State(s): State<S>, h: HeaderMap, Path((t, id)): Path<(String, i64)>) -> Response {
    let Some((user, role)) = auth(&s, &h) else { return err(StatusCode::UNAUTHORIZED, "Login required") };
    let Some(tb) = tbl(&t) else { return err(StatusCode::NOT_FOUND, "No such table") };
    if tb.ro || !can_write(&t, &role, true) { return err(StatusCode::FORBIDDEN, "Not allowed for your role"); }
    let db = s.db.lock().unwrap();
    match db.execute(&format!("DELETE FROM \"{}\" WHERE id=?1", t), [id]) { Ok(_) => { audit(&db, &user, "delete", &t, id, &json!({})); Json(json!({ "ok": true })).into_response() } Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()) }
}
async fn dash(State(s): State<S>, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if auth(&s, &h).is_none() { return err(StatusCode::UNAUTHORIZED, "Login required"); }
    let db = s.db.lock().unwrap();
    let w = match q.get("days").and_then(|d| d.parse::<i64>().ok()) { Some(d) if d > 0 => format!(" AND date>=date('now','-{} day')", d), _ => String::new() };
    let one = |sql: &str| qj(&db, sql).into_iter().next().unwrap_or(json!({}));
    Json(json!({
        "totals": one("SELECT (SELECT COALESCE(SUM(qty),0) FROM assets WHERE category IN ('Desktop PC','Mini PC') AND status!='Retired') pcs,
            (SELECT COALESCE(SUM(qty),0) FROM assets WHERE category IN ('Desktop PC','Mini PC') AND status='Serviceable') pcs_ok,
            (SELECT COALESCE(SUM(qty),0) FROM assets WHERE category IN ('Desktop PC','Mini PC') AND status IN ('For Repair','Under Repair')) pcs_repair,
            (SELECT COALESCE(SUM(qty),0) FROM assets WHERE status!='Retired') assets,
            (SELECT COUNT(*) FROM maintenance) maint,
            (SELECT COUNT(*) FROM repairs WHERE status NOT IN ('Resolved','Closed')) open_repairs,
            (SELECT COUNT(*) FROM incidents WHERE status!='Closed') open_incidents,
            (SELECT COALESCE(SUM(cost),0) FROM maintenance)+(SELECT COALESCE(SUM(cost),0) FROM repairs) spend"),
        "labs": qj(&db, "SELECT l.id,l.code,l.name,l.seats,
            COALESCE((SELECT SUM(qty) FROM assets a WHERE a.lab_id=l.id AND a.category IN ('Desktop PC','Mini PC') AND a.status!='Retired'),0) pcs,
            COALESCE((SELECT SUM(qty) FROM assets a WHERE a.lab_id=l.id AND a.category IN ('Desktop PC','Mini PC') AND a.status IN ('For Repair','Under Repair')),0) repair,
            (SELECT COUNT(*) FROM maintenance m WHERE m.lab_id=l.id) maint,
            (SELECT COUNT(*) FROM repairs r WHERE r.lab_id=l.id AND r.status NOT IN ('Resolved','Closed')) open_repairs FROM labs l ORDER BY l.id"),
        "by_type": qj(&db, &format!("SELECT type k, COUNT(*) n FROM maintenance WHERE 1=1{} GROUP BY type ORDER BY n DESC", w)),
        "by_month": qj(&db, &format!("SELECT strftime('%Y-%m',date) k, COUNT(*) n FROM maintenance WHERE date IS NOT NULL{} GROUP BY k ORDER BY k", w)),
        "by_status": qj(&db, "SELECT status k, SUM(qty) n FROM assets GROUP BY status ORDER BY n DESC"),
        "low_stock": qj(&db, "SELECT name,qty,min_qty FROM parts WHERE COALESCE(qty,0)<=COALESCE(min_qty,0) ORDER BY qty"),
        "overdue": qj(&db, "SELECT s.task,s.next_due,l.code lab FROM schedules s LEFT JOIN labs l ON l.id=s.lab_id WHERE s.status!='Done' AND s.next_due<date('now') ORDER BY s.next_due"),
        "due_soon": qj(&db, "SELECT s.task,s.next_due,l.code lab FROM schedules s LEFT JOIN labs l ON l.id=s.lab_id WHERE s.status!='Done' AND s.next_due BETWEEN date('now') AND date('now','+14 day') ORDER BY s.next_due"),
        "warranty": qj(&db, "SELECT a.name,a.tag,a.warranty_until,l.code lab FROM assets a LEFT JOIN labs l ON l.id=a.lab_id WHERE a.warranty_until BETWEEN date('now') AND date('now','+90 day') ORDER BY a.warranty_until"),
        "repeat": qj(&db, "SELECT l.code lab,m.unit,COUNT(*) n FROM maintenance m LEFT JOIN labs l ON l.id=m.lab_id WHERE m.unit LIKE 'PC-%' AND m.type!='Preventive' GROUP BY m.lab_id,m.unit HAVING n>1 ORDER BY n DESC"),
        "open": qj(&db, "SELECT ticket_no,item,priority,status,reported_date FROM repairs WHERE status NOT IN ('Resolved','Closed') ORDER BY CASE priority WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END LIMIT 10"),
    })).into_response()
}

fn init(db: &Connection) {
    let _ = db.execute_batch("PRAGMA journal_mode=WAL;");
    for t in TABLES {
        let cols: Vec<String> = dbcols(t).iter().map(|c| format!("\"{}\" {}", c.n, match c.t { "i" => "INTEGER", "r" => "REAL", _ => "TEXT" })).collect();
        let extra = if t.name == "users" { ",pass_hash TEXT NOT NULL DEFAULT ''" } else { "" };
        db.execute_batch(&format!("CREATE TABLE IF NOT EXISTS \"{}\"(id INTEGER PRIMARY KEY AUTOINCREMENT,{}{});", t.name, cols.join(","), extra)).expect("schema");
    }
    let _ = db.execute_batch("CREATE UNIQUE INDEX IF NOT EXISTS ux_users ON users(username); CREATE INDEX IF NOT EXISTS ix_maint ON maintenance(lab_id,date); CREATE INDEX IF NOT EXISTS ix_assets ON assets(lab_id,status);");
    // Remove credential-bearing details written by older versions of the audit logger.
    let _ = db.execute("UPDATE audit SET detail=?1 WHERE tbl='users' AND (instr(detail, '\"password\"') > 0 OR instr(detail, '\"pass_hash\"') > 0)", [r#"{"redacted":"legacy user credential data removed"}"#]);
    let n: i64 = db.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap_or(0);
    if n > 0 { return; }
    for (u, f, r, p) in [("admin", "Administrator", "admin", "admin123"), ("tech", "IT Technician", "technician", "tech123"), ("viewer", "Viewer", "viewer", "viewer123")] {
        let _ = insert(db, tbl("users").unwrap(), &json!({ "username": u, "full_name": f, "role": r, "password": p }));
    }
    let seed: Value = serde_json::from_str(include_str!("../seed.json")).expect("seed");
    for name in ["labs", "assets", "maintenance", "repairs", "incidents", "schedules", "parts", "accounts"] {
        let t = tbl(name).unwrap();
        for row in seed[name].as_array().cloned().unwrap_or_default() { let _ = insert(db, t, &row); }
    }
    audit(db, "system", "seed", "all", 0, &json!({ "note": "Initial data imported from CCS-Files" }));
}

async fn logout(State(s): State<S>, h: HeaderMap) -> Response {
 if let Some(t)=h.get("x-token").and_then(|v|v.to_str().ok()) { s.sess.lock().unwrap().remove(t); }
 Json(json!({"ok":true})).into_response()
}
async fn passwd(State(s): State<S>, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let Some((user, _)) = auth(&s, &h) else { return err(StatusCode::UNAUTHORIZED, "Login required") };
    let (old, new) = (b["old"].as_str().unwrap_or(""), b["new"].as_str().unwrap_or(""));
    if new.chars().count() < 6 { return err(StatusCode::BAD_REQUEST, "New password must be at least 6 characters"); }
    let db = s.db.lock().unwrap();
    let cur: String = db.query_row("SELECT pass_hash FROM users WHERE username=?1", [&user], |r| r.get(0)).unwrap_or_default();
    if !verify(old, &cur) { return err(StatusCode::FORBIDDEN, "Current password is incorrect"); }
    let _ = db.execute("UPDATE users SET pass_hash=?1 WHERE username=?2", rusqlite::params![hash(new), user]);
    audit(&db, &user, "password", "users", 0, &json!({}));
    Json(json!({ "ok": true })).into_response()
}
async fn backup(State(s): State<S>, h: HeaderMap) -> Response {
    let Some((user, role)) = auth(&s, &h) else { return err(StatusCode::UNAUTHORIZED, "Login required") };
    if role != "admin" { return err(StatusCode::FORBIDDEN, "Admin only"); }
    let tmp = std::env::temp_dir().join(format!("ccs_bak_{}.db", rnd()));
    let ok = { let db = s.db.lock().unwrap(); let r = db.execute("VACUUM INTO ?1", [tmp.to_string_lossy().to_string()]).is_ok(); if r { audit(&db, &user, "backup", "all", 0, &json!({})); } r };
    if !ok { return err(StatusCode::INTERNAL_SERVER_ERROR, "Backup failed"); }
    let data = std::fs::read(&tmp).unwrap_or_default(); let _ = std::fs::remove_file(&tmp);
    ([(header::CONTENT_TYPE, "application/octet-stream".to_string()), (header::CONTENT_DISPOSITION, "attachment; filename=\"ccs_lab_backup.db\"".to_string())], data).into_response()
}

async fn pulse(State(s): State<S>, h: HeaderMap) -> Response {
    if auth(&s, &h).is_none() { return err(StatusCode::UNAUTHORIZED, "Login required"); }
    let db = s.db.lock().unwrap();
    Json(qj(&db, "SELECT id,who,action,tbl FROM audit WHERE action NOT IN ('login','backup') ORDER BY id DESC LIMIT 1").into_iter().next().unwrap_or(json!({ "id": 0 }))).into_response()
}
async fn search(State(s): State<S>, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if auth(&s, &h).is_none() { return err(StatusCode::UNAUTHORIZED, "Login required"); }
    let term = q.get("q").map(|x| x.trim().to_string()).unwrap_or_default();
    if term.chars().count() < 2 { return Json(json!([])).into_response(); }
    let db = s.db.lock().unwrap();
    let mut out = vec![];
    for t in TABLES {
        if t.name == "users" || t.name == "audit" { continue; }
        let mut rows = fetch(&db, t, Some(&term)); rows.truncate(5);
        if !rows.is_empty() { out.push(json!({ "t": t.name, "title": t.title, "rows": rows })); }
    }
    Json(out).into_response()
}

fn data_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CCS_DB") { return p.into(); }
    let base = std::env::var("LOCALAPPDATA").map(std::path::PathBuf::from).unwrap_or_else(|_| std::path::PathBuf::from("."));
    let dir = base.join("CCS Lab Manager"); let _ = std::fs::create_dir_all(&dir); dir.join("ccs_lab.db")
}

fn main() {
    let lan = std::env::args().any(|a| a == "--lan");
    let path = data_path();
    let db = Connection::open(&path).expect("cannot open database");
    init(&db);
    let _ = db.execute("UPDATE assets SET name=trim(CASE WHEN instr(specs,',')>0 THEN substr(specs,1,instr(specs,',')-1) ELSE specs END) WHERE name=category AND specs IS NOT NULL AND specs!='' AND category NOT IN ('Tools','Consumables','Other')", []);
    let st: S = Arc::new(App { db: Mutex::new(db), sess: Mutex::new(HashMap::new()), login_failures: Mutex::new(HashMap::new()) });
    let app = Router::new().route("/", get(index)).route("/api/login", post(login)).route("/api/logout", post(logout)).route("/api/password", post(passwd)).route("/api/backup", get(backup)).route("/api/pulse", get(pulse)).route("/api/search", get(search)).route("/api/schema", get(schema)).route("/api/dashboard", get(dash))
        .route("/api/:t", get(list).post(create)).route("/api/:t/export", get(export)).route("/api/:t/:id", put(update).delete(remove)).with_state(st);
    let listener = if lan { std::net::TcpListener::bind("0.0.0.0:8080").or_else(|_| std::net::TcpListener::bind("127.0.0.1:0")) } else { std::net::TcpListener::bind("127.0.0.1:47831").or_else(|_| std::net::TcpListener::bind("127.0.0.1:0")) }.expect("cannot open a network port");
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(8080);
    listener.set_nonblocking(true).ok();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
        rt.block_on(async move { let l = tokio::net::TcpListener::from_std(listener).expect("listener"); let _ = axum::serve(l, app).await; });
    });
    let title = if lan { format!("CCS Lab Manager — LAN server (port {})", port) } else { "CCS Lab Manager".to_string() };
    gui(port, &title, path.parent().map(|p| p.to_path_buf()).unwrap_or_default());
}

fn gui(port: u16, title: &str, dir: std::path::PathBuf) {
    use tao::{dpi::LogicalSize, event::{Event, WindowEvent}, event_loop::{ControlFlow, EventLoop}, window::{Icon, WindowBuilder}};
    let ev = EventLoop::new();
    let icon = Icon::from_rgba(include_bytes!("../assets/icon64.rgba").to_vec(), 64, 64).ok();
    let (mw, mh) = ev.primary_monitor().map(|mo| { let sf = mo.scale_factor(); let z = mo.size(); (z.width as f64 / sf, z.height as f64 / sf) }).unwrap_or((1366.0, 768.0));
    let (w, h) = ((mw * 0.9).clamp(380.0, 1440.0), (mh * 0.88).clamp(520.0, 920.0));
    let win = WindowBuilder::new().with_title(title).with_window_icon(icon).with_inner_size(LogicalSize::new(w, h)).with_min_inner_size(LogicalSize::new(360.0, 520.0)).build(&ev).expect("window");
    let mut ctx = wry::WebContext::new(Some(dir.join("webview")));
    let _wv = wry::WebViewBuilder::new(&win).with_web_context(&mut ctx).with_url(&format!("http://127.0.0.1:{}/", port)).build().expect("WebView2 runtime is required");
    ev.run(move |e, _, cf| {
        *cf = ControlFlow::Wait;
        if let Event::WindowEvent { event: WindowEvent::CloseRequested, .. } = e { *cf = ControlFlow::Exit; }
    });
}
