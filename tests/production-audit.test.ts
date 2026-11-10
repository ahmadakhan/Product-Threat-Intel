import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { loadConfig } from '../server/config.ts';
import { encrypt } from '../server/secrets.ts';
import { ingestFeed } from '../server/ingestion.ts';
import { createPool, migrate, put, get } from '../server/db.ts';
import { WorkerLeadership } from '../server/leadership.ts';
import { queueConsolidatedFindingNotifications } from '../server/delivery.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { reconcileFindings } from '../src/engine/reconcileFindings.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { ThreatFeed, Finding, WatchListItem, NormalizedCVE } from '../src/types/index.ts';

const config = loadConfig({NODE_ENV:'test',DATABASE_URL:'postgres://unused',APP_ORIGIN:'http://localhost',ENCRYPTION_KEY:randomBytes(32).toString('base64')});
const date = new Date().toISOString();
const cpe = 'cpe:2.3:a:acme:gateway:1.5:*:*:*:*:*:*:*';
const feed = {id:'vc',name:'VC',type:'VULNCHECK_NVD',url:'https://api.vulncheck.com/v3/index/nist-nvd2',enabled:true,authType:'BEARER',authSecretKey:encrypt('audit-token',[config.ENCRYPTION_KEY],'feed:vc'),rateLimitPerMin:1000} as ThreatFeed;
const raw = {id:'CVE-2026-98001',vulnStatus:'Analyzed',published:date,lastModified:date,descriptions:[{lang:'en',value:'Acme Gateway flaw'}],configurations:[],metrics:{},references:[],weaknesses:[]};
const cve = {cveId:raw.id,title:'Acme Gateway flaw',description:'Acme Gateway flaw',publishedDate:date,modifiedDate:date,cvss:{version:'3.1',score:9.8,severity:'CRITICAL',vector:''},exploitStatus:'None',cwe:[],cpeMatches:[cpe],sourceFeeds:['vc'],remediation:{immediateActions:[],vendorAdvisoryRef:'',patchUrl:'',workarounds:[],rollbackPlan:'',stepByStep:[]},cisaKev:{isKev:false},epss:{score:0,percentile:0}} as NormalizedCVE;
const asset = {id:'a1',assetTag:'gateway',vendor:'acme',product:'gateway',version:'1.5',cpes:[cpe],purls:[],ownerGroup:'SOC',active:true,createdAt:date} as WatchListItem;
const settings = {...DEFAULT_SETTINGS,scopeHours:0,maxFindingsPerRun:1,maxDispatchesPerRunPerFeed:1,maxTotalFindingsPerRun:1};

test('VulnCheck ingestion accepts its actual v3 envelope and cursor continuation', async () => {
  let calls = 0;
  const result = await ingestFeed(feed,24,async (url,options) => {
    assert.equal(options?.headers?.Authorization,'Bearer audit-token');
    calls++;
    const second = new URL(url).searchParams.has('cursor');
    return {status:200,headers:{},body:JSON.stringify({_meta:{next_cursor:second ? undefined : 'page2'},data:[{...raw,id:second ? 'CVE-2026-98002' : raw.id}]})};
  },config,async()=>{});
  assert.equal(calls,2);
  assert.deepEqual(result.cves.map(c=>c.cveId),[raw.id,'CVE-2026-98002']);
});

test('NVD incremental windows request modifications to previously published records', async () => {
  const result = await ingestFeed({...feed,type:'NVD_API',authType:'NONE',url:'https://services.nvd.nist.gov/rest/json/cves/2.0'},24,async(url)=>{
    const query = new URL(url).searchParams;
    assert.ok(query.has('lastModStartDate') && query.has('lastModEndDate'));
    assert.equal(query.has('pubStartDate'),false);
    return {status:200,headers:{},body:JSON.stringify({totalResults:1,vulnerabilities:[{cve:{...raw,published:'2020-01-01T00:00:00Z',vulnStatus:'Rejected'}}]})};
  },config,async()=>{});
  assert.equal(result.withdrawals?.[0].cveId,raw.id);
});

test('breaker deferral is separate from confidence and reconciliation clears it',()=>{
  const findings=runVulnerabilityPipeline([feed],[cve,{...cve,cveId:'CVE-2026-98002'}],[asset],[],[],settings).newFindings;
  assert.equal(findings[1].dispatchDeferred,true);
  const refreshed=reconcileFindings([findings[1]],[{...findings[1],dispatchDeferred:false}]);
  assert.equal(refreshed[0].dispatchDeferred,false);
});

test('retained leadership and queue quotas work against PostgreSQL',{skip:!process.env.TEST_DATABASE_URL},async()=>{
  const control=createPool(process.env.TEST_DATABASE_URL!);
  const schema=`production_audit_${randomBytes(8).toString('hex')}`;
  await control.query(`CREATE SCHEMA ${schema}`);
  const url=new URL(process.env.TEST_DATABASE_URL!);
  url.searchParams.set('options',`-c search_path=${schema}`);
  const pool=createPool(url.href);
  const a=new WorkerLeadership(pool,'replica-a'),b=new WorkerLeadership(pool,'replica-b');
  try{
    await migrate(pool);
    await Promise.all([a.check(),b.check()]);
    assert.equal(Number(a.isLeader)+Number(b.isLeader),1);
    const winner=a.isLeader ? a : b, follower=a.isLeader ? b : a;
    const before=await get<any>(pool,'systemState','leader-election');
    assert.ok(['replica-a','replica-b'].includes(before.leaderId));
    await winner.close();
    await follower.check();
    assert.equal(follower.isLeader,true);
    await put(pool,'settings','main',settings);
    await put(pool,'recipients','r1',{id:'r1',email:'audit@example.invalid',name:'SOC',enabled:true,deliveryGroup:'SECURITY_TEAM',subscriptionTier:'ALL_SEVERITIES'});
    const findings=runVulnerabilityPipeline([feed],[cve,{...cve,cveId:'CVE-2026-98002'}],[asset],[],[],{...settings,maxFindingsPerRun:100,maxDispatchesPerRunPerFeed:100,maxTotalFindingsPerRun:100}).newFindings;
    // Exercise the final queue guard independently of matching-time flags.
    for (const finding of findings) finding.notificationStatus='REVIEW_REQUIRED';
    await queueConsolidatedFindingNotifications(pool,findings);
    const jobs=(await pool.query('SELECT payload FROM outbox')).rows;
    assert.equal(jobs.length,1);
    assert.equal(jobs[0].payload.includedFindingIds.length,1);
  }finally{
    await Promise.all([a.close(),b.close()]);
    await pool.end();
    await control.query(`DROP SCHEMA ${schema} CASCADE`);
    await control.end();
  }
});
