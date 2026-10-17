#![allow(dead_code, clippy::all, unused)]
use crate::finding::Diagnostic;
use crate::osv::validate::{self, Advisory};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
pub const NETWORK_BUDGET: Duration = Duration::from_secs(30);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
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
    /// One advisory list per query, index-aligned with `qs`, plus the diagnostics
    /// emitted while validating the response at the boundary.
    fn query_all(&self, qs: &[Query]) -> Result<(Vec<Vec<Advisory>>, Vec<Diagnostic>), String>;
    fn vuln(&self, id: &str) -> Result<Advisory, String>;
    fn query_all_with_deadline(
        &self,
        qs: &[Query],
        _deadline: Instant,
    ) -> Result<(Vec<Vec<Advisory>>, Vec<Diagnostic>), String> {
        self.query_all(qs)
    }
    fn vuln_with_deadline(&self, id: &str, _deadline: Instant) -> Result<Advisory, String> {
        self.vuln(id)
    }
}
#[rustfmt::skip] fn batch_invalid(q:&Query,e:&Diagnostic)->Diagnostic{Diagnostic::advisory_invalid(&format!("{}@{}: {}",q.name,q.ver,e.message))}
pub struct StubOsv {
    pages: Mutex<Vec<(Vec<serde_json::Value>, Option<String>)>>,
    details: Mutex<std::collections::HashMap<String, Advisory>>,
    fail_code: Mutex<Option<u16>>,
    fail_left: Mutex<u32>,
    pub calls: AtomicUsize,
    pub page_calls: AtomicUsize,
    pub deadlines: Mutex<Vec<Instant>>,
}
#[rustfmt::skip] impl StubOsv{pub fn new(p:Vec<(Vec<serde_json::Value>,Option<String>)>)->Self{Self{pages:Mutex::new(p),details:Mutex::new(Default::default()),fail_code:Mutex::new(None),fail_left:Mutex::new(0),calls:AtomicUsize::new(0),page_calls:AtomicUsize::new(0),deadlines:Mutex::new(Vec::new())}}pub fn with_transient_fail(p:Vec<(Vec<serde_json::Value>,Option<String>)>,c:u16,t:u32)->Self{Self{pages:Mutex::new(p),details:Mutex::new(Default::default()),fail_code:Mutex::new(Some(c)),fail_left:Mutex::new(t),calls:AtomicUsize::new(0),page_calls:AtomicUsize::new(0),deadlines:Mutex::new(Vec::new())}}pub fn set_detail(&self,id:&str,adv:Advisory){self.details.lock().unwrap().insert(id.into(),Advisory{id:adv.id,summary:adv.summary,severity:adv.severity});}}
#[rustfmt::skip] impl OsvApi for StubOsv{fn query_all(&self,qs:&[Query])->Result<(Vec<Vec<Advisory>>,Vec<Diagnostic>),String>{self.query_all_with_deadline(qs,Instant::now()+NETWORK_BUDGET)}fn query_all_with_deadline(&self,qs:&[Query],deadline:Instant)->Result<(Vec<Vec<Advisory>>,Vec<Diagnostic>),String>{self.deadlines.lock().unwrap().push(deadline);if Instant::now()+REQUEST_TIMEOUT>deadline{return Err("network budget exceeded".into());}let mut out:Vec<Vec<Advisory>>=qs.iter().map(|_|Vec::new()).collect();let mut dg:Vec<Diagnostic>=Vec::new();let mut tok:Option<String>=None;for _ in 0..MAX_PAGES{if Instant::now()+REQUEST_TIMEOUT>deadline{return Err("network budget exceeded".into());}self.page_calls.fetch_add(1,Ordering::SeqCst);if let Some(c)=*self.fail_code.lock().unwrap(){let mut l=self.fail_left.lock().unwrap();if *l>0{*l-=1;self.calls.fetch_add(1,Ordering::SeqCst);if is_transient_status(c){if Instant::now()+REQUEST_TIMEOUT>deadline{return Err("network budget exceeded".into());}continue;}return Err(format!("status {c}"));}}let mut pg=self.pages.lock().unwrap();if pg.is_empty(){break;}let(results,next)=pg.remove(0);for(i,r) in results.iter().enumerate().take(out.len()){for v in r.get("vulns").and_then(|x|x.as_array()).into_iter().flatten(){if v.get("severity").is_none(){if let Some(id)=v.get("id").and_then(|x|x.as_str()){if let Ok(a)=self.vuln_with_deadline(id,deadline){out[i].push(a);continue;}if validate::is_valid_id(id){dg.push(Diagnostic::advisory_severity_fallback(&format!("{id}: detail fetch failed, using default severity")))}}}match validate::validate_advisory(&v){Ok(Some(a))=>out[i].push(a),Ok(None)=>{},Err(e)=>dg.push(batch_invalid(&qs[i],&e)),}}}tok=next;if tok.is_none(){break;}if pg.is_empty(){break;}}if tok.is_some(){dg.push(Diagnostic::osv_truncated("page cap (3) reached with more results pending; results truncated"))}Ok((out,dg))}fn vuln(&self,id:&str)->Result<Advisory,String>{self.vuln_with_deadline(id,Instant::now()+NETWORK_BUDGET)}fn vuln_with_deadline(&self,id:&str,deadline:Instant)->Result<Advisory,String>{self.deadlines.lock().unwrap().push(deadline);if Instant::now()+REQUEST_TIMEOUT>deadline{return Err("network budget exceeded".into());}self.calls.fetch_add(1,Ordering::SeqCst);self.details.lock().unwrap().get(id).map(|a|Advisory{id:a.id.clone(),summary:a.summary.clone(),severity:a.severity}).ok_or_else(||"not found".into())}}
/// Decided transport policy for the OSV HTTP adapter: the endpoint, the
/// timeout, and the two settings the audit found silently inherited (proxy
/// from the environment, up to ten redirects). Every request the client
/// sends goes through this policy; production and tests share the same
/// code path and differ only in the endpoint (plus `https_only`, so a
/// loopback stub is reachable without TLS).
pub struct OsvTransportPolicy {
    /// Batch query endpoint receiving the POST (`OSV_BATCH` in production).
    pub batch_url: String,
    /// Advisory detail base; the client requests `{base}{id}`.
    pub vuln_base: String,
    /// End-to-end timeout of one HTTP call (ureq `timeout_global`). Only
    /// the global timeout is set, as before: no per-call, resolve, connect
    /// or body timeout is configured.
    pub timeout: Duration,
    /// Refuse every non-HTTPS URL before any byte is sent.
    pub https_only: bool,
    /// Proxy for outgoing requests. Always `None`: honouring `HTTP_PROXY`
    /// and friends would hand advisory queries to a third host the caller
    /// did not choose, and a curious proxy would learn exactly which
    /// dependencies each scan reviews.
    pub proxy: Option<ureq::Proxy>,
    /// Redirects followed before the response is returned as-is. Always
    /// `0`: a 3xx degrades like any other non-success, so one batched POST
    /// can never fan out into requests to hosts the caller did not choose.
    pub max_redirects: u32,
}

impl OsvTransportPolicy {
    /// Production policy: the OSV HTTPS endpoints, the shared
    /// `REQUEST_TIMEOUT`, HTTPS only, no proxy, no redirects. The proxy is
    /// disabled outright (`.proxy(None)`) instead of inherited from the
    /// environment, and redirects are refused (`.max_redirects(0)`).
    /// Consequence, stated plainly: proxy environment variables are
    /// ignored deliberately, so a user behind a corporate proxy reaches
    /// OSV directly or not at all.
    pub fn production() -> Self {
        Self {
            batch_url: OSV_BATCH.to_string(),
            vuln_base: OSV_VULN.to_string(),
            timeout: REQUEST_TIMEOUT,
            https_only: true,
            proxy: None,
            max_redirects: 0,
        }
    }

    /// Test-only loopback variant of the production policy: the same
    /// timeout, the same disabled proxy, the same refused redirects, but
    /// pointed at a loopback stub over plain HTTP.
    /// `https_only(false)` is what makes the stub reachable at all —
    /// hermetic tests have no TLS — and the endpoint override is the only
    /// behavioural difference from production, so redirect and proxy tests
    /// exercise the same code path that serves production.
    pub fn loopback_for_test(batch_url: &str, vuln_base: &str) -> Self {
        Self {
            batch_url: batch_url.to_string(),
            vuln_base: vuln_base.to_string(),
            timeout: REQUEST_TIMEOUT,
            https_only: false,
            proxy: None,
            max_redirects: 0,
        }
    }
}

pub struct UreqOsvClient {
    agent: ureq::Agent,
    batch_url: String,
    vuln_base: String,
}
#[rustfmt::skip] impl UreqOsvClient{pub fn new()->Self{Self::with_policy(OsvTransportPolicy::production())}pub fn with_policy(policy:OsvTransportPolicy)->Self{CONSTRUCTIONS.fetch_add(1,Ordering::SeqCst);let cfg=ureq::Agent::config_builder().timeout_global(Some(policy.timeout)).https_only(policy.https_only).proxy(policy.proxy).max_redirects(policy.max_redirects).build();Self{agent:ureq::Agent::new_with_config(cfg),batch_url:policy.batch_url,vuln_base:policy.vuln_base}}pub fn maybe_new(o:bool)->Option<Self>{if o{None}else{Some(Self::new())}}fn do_post(&self,body:&str,deadline:Instant)->Result<String,String>{if Instant::now()+REQUEST_TIMEOUT>deadline{return Err("network budget exceeded".into());}for a in 0..=MAX_RETRIES{if Instant::now()+REQUEST_TIMEOUT>deadline{return Err("network budget exceeded".into());}let r=self.agent.post(&self.batch_url).header("Content-Type","application/json").send(body);match r{Ok(mut resp)=>{let s=resp.body_mut().with_config().limit(1024*1024).read_to_string().map_err(|e|format!("{e}"))?;if s.len()>1024*1024{return Err("body too large".into());}return Ok(s);},Err(e) if should_retry(&e)&&a<MAX_RETRIES=>{if Instant::now()+REQUEST_TIMEOUT>deadline{return Err("network budget exceeded".into());}std::thread::sleep(backoff(a));continue;},Err(e)=>return Err(format!("{e}")),}}Err("retries exhausted".into())}}
#[rustfmt::skip] impl OsvApi for UreqOsvClient{fn query_all(&self,qs:&[Query])->Result<(Vec<Vec<Advisory>>,Vec<Diagnostic>),String>{self.query_all_with_deadline(qs,Instant::now()+NETWORK_BUDGET)}fn query_all_with_deadline(&self,qs:&[Query],deadline:Instant)->Result<(Vec<Vec<Advisory>>,Vec<Diagnostic>),String>{if Instant::now()+REQUEST_TIMEOUT>deadline{return Err("network budget exceeded".into());}if qs.is_empty(){return Ok((Vec::new(),Vec::new()));}let qv:Vec<serde_json::Value>=qs.iter().map(|q|serde_json::json!({"package":{"name":q.name,"ecosystem":q.eco},"version":q.ver})).collect();let body=serde_json::json!({"queries":qv}).to_string();let mut out:Vec<Vec<Advisory>>=qs.iter().map(|_|Vec::new()).collect();let mut dg:Vec<Diagnostic>=Vec::new();let mut tok:Option<String>=None;for _ in 0..MAX_PAGES{if Instant::now()+REQUEST_TIMEOUT>deadline{return Err("network budget exceeded".into());}let cur=if let Some(t)=&tok{serde_json::json!({"queries":qv,"pageToken":t}).to_string()}else{body.clone()};let resp=self.do_post(&cur,deadline).map_err(|e|format!("{e}"))?;validate::check_size(resp.as_bytes()).map_err(|e|e.message)?;let v:serde_json::Value=serde_json::from_str(&resp).map_err(|e|e.to_string())?;let rs=v.get("results").and_then(|x|x.as_array()).ok_or("malformed batch envelope")?;for(i,r) in rs.iter().enumerate(){if i>=out.len(){break;}if let Some(vs)=r.get("vulns").and_then(|x|x.as_array()){for vuln in vs{if vuln.get("severity").is_none(){if let Some(id)=vuln.get("id").and_then(|x|x.as_str()){if let Ok(a)=self.vuln_with_deadline(id,deadline){out[i].push(a);continue;}if validate::is_valid_id(id){dg.push(Diagnostic::advisory_severity_fallback(&format!("{id}: detail fetch failed, using default severity")))}}}match validate::validate_advisory(vuln){Ok(Some(a))=>out[i].push(a),Ok(None)=>{},Err(e)=>dg.push(batch_invalid(&qs[i],&e)),}}}}tok=v.get("nextPageToken").and_then(|x|x.as_str()).map(|s|s.to_string());if tok.is_none(){break;}}if tok.is_some(){dg.push(Diagnostic::osv_truncated("page cap (3) reached with more results pending; results truncated"))}Ok((out,dg))}fn vuln(&self,id:&str)->Result<Advisory,String>{self.vuln_with_deadline(id,Instant::now()+NETWORK_BUDGET)}fn vuln_with_deadline(&self,id:&str,deadline:Instant)->Result<Advisory,String>{if Instant::now()+REQUEST_TIMEOUT>deadline{return Err("network budget exceeded".into());}if !validate::is_valid_id(id){return Err("advisory-invalid".into());}let url=format!("{}{id}",self.vuln_base);for a in 0..=MAX_RETRIES{if Instant::now()+REQUEST_TIMEOUT>deadline{return Err("network budget exceeded".into());}let r=self.agent.get(&url).call();match r{Ok(mut resp)=>{let s=resp.body_mut().with_config().limit(1024*1024).read_to_string().map_err(|e|e.to_string())?;validate::check_size(s.as_bytes()).map_err(|e|e.message)?;let v:serde_json::Value=serde_json::from_str(&s).map_err(|e|e.to_string())?;if let Some(ad)=validate::validate_advisory_detail(&v).map_err(|e|e.message)?{return Ok(ad);}else{return Err("withdrawn".into());}},Err(e) if should_retry(&e)&&a<MAX_RETRIES=>{if Instant::now()+REQUEST_TIMEOUT>deadline{return Err("network budget exceeded".into());}std::thread::sleep(backoff(a));continue;},Err(e)=>return Err(format!("{e}")),}}Err("retries exhausted".into())}}
#[cfg(test)]#[rustfmt::skip] mod tests{use super::*;use crate::finding::Severity;fn q() -> Query{Query{eco:"npm".into(),name:"a".into(),ver:"1".into()}}#[test]fn all(){assert_eq!(NETWORK_BUDGET,Duration::from_secs(30));assert!(!is_transient_status(400)&&!is_transient_status(404)&&is_transient_status(429)&&is_transient_status(500)&&is_transient_status(503));assert!(!should_retry(&ureq::Error::StatusCode(400))&&!should_retry(&ureq::Error::StatusCode(404))&&should_retry(&ureq::Error::StatusCode(429))&&should_retry(&ureq::Error::StatusCode(500)));for n in 0..=MAX_RETRIES{let d=backoff(n);assert!(d>=Duration::from_millis(BASE_MS*(1<<n))&&d<=Duration::from_millis(BASE_MS*(1<<n)+1000));}let before=constructions();assert!(UreqOsvClient::maybe_new(true).is_none());assert_eq!(constructions(),before);let c=UreqOsvClient::maybe_new(false).unwrap();assert_eq!(constructions(),before+1);drop(c);let stub400=StubOsv::with_transient_fail(vec![(vec![serde_json::json!({"vulns":[{"id":"GHSA-1"}]})],None)],400,1);assert!(stub400.query_all(&[q()]).is_err());assert_eq!(stub400.page_calls.load(Ordering::SeqCst),1);let mut ok_pages=vec![];for i in 0..4{ok_pages.push((vec![serde_json::json!({"vulns":[{"id":format!("GHSA-{i}")}]})],Some(format!("tok{i}"))));}let stub_pages=StubOsv::new(ok_pages);let _=stub_pages.query_all(&[q()]);assert_eq!(stub_pages.page_calls.load(Ordering::SeqCst),MAX_PAGES);let stub_retry=StubOsv::with_transient_fail(vec![(vec![serde_json::json!({"vulns":[{"id":"GHSA-1","severity":[{"type":"CVSS_V3","score":"9.8"}]}]})],None)],429,2);let r=stub_retry.query_all(&[q()]);assert!(r.is_ok()&&r.unwrap().0[0].len()==1);let mut attempts=0;for _ in 0..=MAX_RETRIES{if should_retry(&ureq::Error::StatusCode(429)){attempts+=1;}}assert_eq!(attempts,(MAX_RETRIES+1) as usize);let two=StubOsv::new(vec![(vec![serde_json::json!({"vulns":[{"id":"GHSA-A1"},{"id":"GHSA-A2"}]}),serde_json::json!({"vulns":[{"id":"GHSA-B1"}]})],None)]);let (g,dg)=two.query_all(&[q(),Query{eco:"PyPI".into(),name:"b".into(),ver:"2".into()}]).unwrap();assert_eq!(dg.iter().filter(|d|d.code=="advisory-severity-fallback").count(),3);for id in ["GHSA-A1","GHSA-A2","GHSA-B1"]{assert!(dg.iter().any(|d|d.message.contains(id)),"{dg:?}");}assert_eq!(g.len(),2);assert_eq!(g[0].len(),2);assert_eq!(g[1].len(),1);assert_eq!(g[1][0].id,"GHSA-B1");let detail_stub=StubOsv::new(vec![(vec![serde_json::json!({"vulns":[{"id":"GHSA-need-detail"}]})],None)]);detail_stub.set_detail("GHSA-need-detail",Advisory{id:"GHSA-need-detail".into(),summary:"detail".into(),severity:Severity::Critical});let (advs,_)=detail_stub.query_all(&[q()]).unwrap();assert_eq!(advs[0][0].severity,Severity::Critical);let past=Instant::now()-Duration::from_secs(60);let cu=UreqOsvClient::new();assert_eq!(cu.query_all_with_deadline(&[q()],past).unwrap_err(),"network budget exceeded");assert_eq!(cu.vuln_with_deadline("GHSA-1234",past).unwrap_err(),"network budget exceeded");}
#[test]fn severity_fallback_names_advisory(){let stub=StubOsv::new(vec![(vec![serde_json::json!({"vulns":[{"id":"GHSA-NOSEV"}]})],None)]);let (advs,dg)=stub.query_all(&[q()]).unwrap();assert_eq!(advs[0].len(),1);assert!(dg.iter().any(|d|d.code=="advisory-severity-fallback"&&d.message.contains("GHSA-NOSEV")),"{dg:?}");}
#[test]fn page_cap_truncation_warns_once(){let pages=vec![(vec![serde_json::json!({"vulns":[{"id":"GHSA-1","severity":[{"type":"CVSS_V3","score":"9.8"}]}]})],Some("t0".into())),(vec![serde_json::json!({"vulns":[{"id":"GHSA-2","severity":[{"type":"CVSS_V3","score":"9.8"}]}]})],Some("t1".into())),(vec![serde_json::json!({"vulns":[{"id":"GHSA-3","severity":[{"type":"CVSS_V3","score":"9.8"}]}]})],Some("t2".into()))];let stub=StubOsv::new(pages);let (_,dg)=stub.query_all(&[q()]).unwrap();assert_eq!(dg.iter().filter(|d|d.code=="osv-truncated").count(),1,"{dg:?}");}}
