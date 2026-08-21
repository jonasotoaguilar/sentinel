#![allow(dead_code, clippy::all, unused)]
use crate::osv::validate::{self, Advisory};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
pub const NETWORK_BUDGET: Duration = Duration::from_secs(30);
pub const MAX_RETRIES: u32 = 3;
pub const MAX_PAGES: usize = 3;
const BASE_MS: u64 = 100;
const OSV_BATCH: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN: &str = "https://api.osv.dev/v1/vulns/";
static CONSTRUCTIONS: AtomicUsize = AtomicUsize::new(0);
#[rustfmt::skip] pub fn constructions()->usize{CONSTRUCTIONS.load(Ordering::SeqCst)}
#[rustfmt::skip] pub fn backoff(a:u32)->Duration{let b=BASE_MS*(1u64<<a);let j=(a as u64*137)%1000;Duration::from_millis(b+j)}
#[rustfmt::skip] pub fn is_transient_status(c:u16)->bool{c==429||(500..=599).contains(&c)}
#[rustfmt::skip] pub fn should_retry(e:&ureq::Error)->bool{match e{ureq::Error::StatusCode(c)=>is_transient_status(*c),ureq::Error::Io(_)|ureq::Error::Timeout(_)|ureq::Error::HostNotFound|ureq::Error::ConnectionFailed=>true,_=>false}}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub eco: String,
    pub name: String,
    pub ver: String,
}
pub trait OsvApi {
    fn query_all(&self, qs: &[Query]) -> Result<Vec<Advisory>, String>;
    fn vuln(&self, id: &str) -> Result<Advisory, String>;
}
pub struct StubOsv {
    pages: Mutex<Vec<(Vec<serde_json::Value>, Option<String>)>>,
    details: Mutex<std::collections::HashMap<String, Advisory>>,
    fail_code: Mutex<Option<u16>>,
    fail_left: Mutex<u32>,
    pub calls: AtomicUsize,
    pub page_calls: AtomicUsize,
}
#[rustfmt::skip] impl StubOsv{pub fn new(p:Vec<(Vec<serde_json::Value>,Option<String>)>)->Self{Self{pages:Mutex::new(p),details:Mutex::new(Default::default()),fail_code:Mutex::new(None),fail_left:Mutex::new(0),calls:AtomicUsize::new(0),page_calls:AtomicUsize::new(0)}}pub fn with_transient_fail(p:Vec<(Vec<serde_json::Value>,Option<String>)>,c:u16,t:u32)->Self{Self{pages:Mutex::new(p),details:Mutex::new(Default::default()),fail_code:Mutex::new(Some(c)),fail_left:Mutex::new(t),calls:AtomicUsize::new(0),page_calls:AtomicUsize::new(0)}}pub fn set_detail(&self,id:&str,adv:Advisory){self.details.lock().unwrap().insert(id.into(),Advisory{id:adv.id,summary:adv.summary,severity:adv.severity});}}
#[rustfmt::skip] impl OsvApi for StubOsv{fn query_all(&self,_qs:&[Query])->Result<Vec<Advisory>,String>{let mut out=Vec::new();let mut tok:Option<String>=None;for _ in 0..MAX_PAGES{self.page_calls.fetch_add(1,Ordering::SeqCst);if let Some(c)=*self.fail_code.lock().unwrap(){let mut l=self.fail_left.lock().unwrap();if *l>0{*l-=1;self.calls.fetch_add(1,Ordering::SeqCst);if is_transient_status(c){continue;}return Err(format!("status {c}"));}}let mut pg=self.pages.lock().unwrap();if pg.is_empty(){break;}let(vulns,next)=pg.remove(0);for v in vulns{if v.get("severity").is_none(){if let Some(id)=v.get("id").and_then(|x|x.as_str()){if let Some(d)=self.details.lock().unwrap().get(id){out.push(Advisory{id:d.id.clone(),summary:d.summary.clone(),severity:d.severity});continue;}}}if let Some(a)=validate::validate_advisory(&v).map_err(|e|e.message)?{out.push(a);}else if validate::validate_advisory(&v).is_err(){continue;}}tok=next;if tok.is_none(){break;}if pg.is_empty(){break;}}Ok(out)}fn vuln(&self,id:&str)->Result<Advisory,String>{self.calls.fetch_add(1,Ordering::SeqCst);self.details.lock().unwrap().get(id).map(|a|Advisory{id:a.id.clone(),summary:a.summary.clone(),severity:a.severity}).ok_or_else(||"not found".into())}}
pub struct UreqOsvClient {
    agent: ureq::Agent,
}
#[rustfmt::skip] impl UreqOsvClient{pub fn new()->Self{CONSTRUCTIONS.fetch_add(1,Ordering::SeqCst);let cfg=ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(10))).https_only(true).build();Self{agent:ureq::Agent::new_with_config(cfg)}}pub fn maybe_new(o:bool)->Option<Self>{if o{None}else{Some(Self::new())}}fn do_post(&self,body:&str)->Result<String,ureq::Error>{let mut last:Option<ureq::Error>=None;for a in 0..=MAX_RETRIES{let r=self.agent.post(OSV_BATCH).header("Content-Type","application/json").send(body);match r{Ok(mut resp)=>{let s=resp.body_mut().with_config().limit(1024*1024).read_to_string()?;if s.len()>1024*1024{return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"body too large").into());}return Ok(s);},Err(e) if should_retry(&e)&&a<MAX_RETRIES=>{std::thread::sleep(backoff(a));last=Some(e);continue;},Err(e)=>return Err(e),}}Err(last.unwrap())}}
#[rustfmt::skip] impl OsvApi for UreqOsvClient{fn query_all(&self,qs:&[Query])->Result<Vec<Advisory>,String>{if qs.is_empty(){return Ok(Vec::new());}let qv:Vec<serde_json::Value>=qs.iter().map(|q|serde_json::json!({"package":{"name":q.name,"ecosystem":q.eco},"version":q.ver})).collect();let body=serde_json::json!({"queries":qv}).to_string();let mut out=Vec::new();let mut tok:Option<String>=None;let start=std::time::Instant::now();for _ in 0..MAX_PAGES{if start.elapsed()>NETWORK_BUDGET{return Err("network budget exceeded".into());}let cur=if let Some(t)=&tok{serde_json::json!({"queries":qv,"pageToken":t}).to_string()}else{body.clone()};let resp=self.do_post(&cur).map_err(|e|format!("{e}"))?;validate::check_size(resp.as_bytes()).map_err(|e|e.message)?;let v:serde_json::Value=serde_json::from_str(&resp).map_err(|e|e.to_string())?;let rs=v.get("results").and_then(|x|x.as_array()).ok_or("bad results")?;for r in rs{if let Some(vs)=r.get("vulns").and_then(|x|x.as_array()){for vuln in vs{if vuln.get("severity").is_none(){if let Some(id)=vuln.get("id").and_then(|x|x.as_str()){if let Ok(a)=self.vuln(id){out.push(a);continue;}}}if let Ok(Some(a))=validate::validate_advisory(vuln){out.push(a);}}}}tok=v.get("nextPageToken").and_then(|x|x.as_str()).map(|s|s.to_string());if tok.is_none(){break;}}Ok(out)}fn vuln(&self,id:&str)->Result<Advisory,String>{if !validate::is_valid_id(id){return Err("advisory-invalid".into());}let url=format!("{OSV_VULN}{id}");let mut last:Option<ureq::Error>=None;for a in 0..=MAX_RETRIES{let r=self.agent.get(&url).call();match r{Ok(mut resp)=>{let s=resp.body_mut().with_config().limit(1024*1024).read_to_string().map_err(|e|e.to_string())?;validate::check_size(s.as_bytes()).map_err(|e|e.message)?;let v:serde_json::Value=serde_json::from_str(&s).map_err(|e|e.to_string())?;if let Some(ad)=validate::validate_advisory(&v).map_err(|e|e.message)?{return Ok(ad);}else{return Err("withdrawn".into());}},Err(e) if should_retry(&e)&&a<MAX_RETRIES=>{std::thread::sleep(backoff(a));last=Some(e);continue;},Err(e)=>return Err(format!("{e}")),}}Err(format!("{}",last.unwrap()))}}
#[cfg(test)]#[rustfmt::skip] mod tests{use super::*;use crate::finding::Severity;#[test]fn all(){assert_eq!(NETWORK_BUDGET,Duration::from_secs(30));assert!(!is_transient_status(400)&&!is_transient_status(404)&&is_transient_status(429)&&is_transient_status(500)&&is_transient_status(503));assert!(!should_retry(&ureq::Error::StatusCode(400))&&!should_retry(&ureq::Error::StatusCode(404))&&should_retry(&ureq::Error::StatusCode(429))&&should_retry(&ureq::Error::StatusCode(500)));for n in 0..=MAX_RETRIES{let d=backoff(n);assert!(d>=Duration::from_millis(BASE_MS*(1<<n))&&d<=Duration::from_millis(BASE_MS*(1<<n)+1000));}let before=constructions();assert!(UreqOsvClient::maybe_new(true).is_none());assert_eq!(constructions(),before);let c=UreqOsvClient::maybe_new(false).unwrap();assert_eq!(constructions(),before+1);drop(c);let stub400=StubOsv::with_transient_fail(vec![(vec![serde_json::json!({"id":"GHSA-1"})],None)],400,1);assert!(stub400.query_all(&[]).is_err());assert_eq!(stub400.page_calls.load(Ordering::SeqCst),1);let mut ok_pages=vec![];for i in 0..4{ok_pages.push((vec![serde_json::json!({"id":format!("GHSA-{i}")})],Some(format!("tok{i}"))));}let stub_pages=StubOsv::new(ok_pages);let _=stub_pages.query_all(&[Query{eco:"npm".into(),name:"a".into(),ver:"1".into()}]);assert_eq!(stub_pages.page_calls.load(Ordering::SeqCst),MAX_PAGES);let stub_retry=StubOsv::with_transient_fail(vec![(vec![serde_json::json!({"id":"GHSA-1","severity":[{"type":"CVSS_V3","score":"9.8"}]})],None)],429,2);let r=stub_retry.query_all(&[]);assert!(r.is_ok()&&r.unwrap().len()==1);let mut attempts=0;for _ in 0..=MAX_RETRIES{if should_retry(&ureq::Error::StatusCode(429)){attempts+=1;}}assert_eq!(attempts,(MAX_RETRIES+1) as usize);let detail_stub=StubOsv::new(vec![(vec![serde_json::json!({"id":"GHSA-need-detail"})],None)]);detail_stub.set_detail("GHSA-need-detail",Advisory{id:"GHSA-need-detail".into(),summary:"detail".into(),severity:Severity::Critical});let advs=detail_stub.query_all(&[]).unwrap();assert_eq!(advs[0].severity,Severity::Critical);}}
