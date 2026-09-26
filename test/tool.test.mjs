import test from 'node:test';
import assert from 'node:assert/strict';
import { checkCostTags, validPolicy, TOOL_ID, LIMITS, RULES } from '../src/index.mjs';
import { runCli } from '../src/cli.mjs';
import { mkdtempSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const policy = { schemaVersion:'1', asOf:'2026-09-26T00:00:00Z', requiredTags:[{key:'cost-center',allowedValues:['CC-1']},{key:'owner',allowedValues:['team-a']},{key:'environment',allowedValues:['test']}], exceptions:[] };
const resource = { provider:'aws', resourceId:'synthetic-r1', tags:{'cost-center':'CC-1',owner:'team-a',environment:'test'} };
const inventory = { schemaVersion:'1', complete:true, resources:[resource] };
const check = data => checkCostTags(data,policy);

test('complete multi-provider inventory with allowed tags passes without echoing values', () => {
  const azure = { provider:'azure',resourceId:'synthetic-r2',tags:{'COST-CENTER':'CC-1',Owner:'team-a',ENVIRONMENT:'test'} };
  const gcp = { provider:'gcp',resourceId:'synthetic-r3',tags:{...resource.tags} };
  const report = check({ ...inventory, resources:[resource,azure,gcp] });
  assert.equal(TOOL_ID,'cloud-cost-tag-checker'); assert.equal(report.status,'pass'); assert.equal(report.summary.checked,3);
  assert.equal(JSON.stringify(report).includes('synthetic-r1'),false);
  assert.equal(JSON.stringify(report).includes('team-a'),false);
});

test('blank owner fails; provider tag-key case is deliberate; ambiguous Azure keys cannot pass', () => {
  const blank = check({ ...inventory,resources:[{...resource,tags:{...resource.tags,owner:'  '}}] });
  assert.equal(blank.status,'fail'); assert.ok(blank.findings.some(f=>f.ruleId==='blank-owner'));
  const awsCase = check({ ...inventory,resources:[{...resource,tags:{'cost-center':'CC-1',Owner:'team-a',environment:'test'}}] });
  assert.equal(awsCase.status,'fail'); assert.ok(awsCase.findings.some(f=>f.ruleId==='required-tag-missing'));
  const azureAlias = check({ ...inventory,resources:[{...resource,provider:'azure',tags:{...resource.tags,Owner:'team-a'}}] });
  assert.equal(azureAlias.status,'incomplete'); assert.ok(azureAlias.findings.some(f=>f.ruleId==='tag-ambiguous'));
});

test('only exact scoped live exclusions with reason and expiry are accepted', () => {
  const excluded = { provider:'aws',resourceId:'synthetic-r1',tags:{},excluded:true };
  const approved = { ...policy,exceptions:[{provider:'aws',resourceId:'synthetic-r1',reason:'synthetic migration',expiresAt:'2026-09-27T00:00:00Z'}] };
  assert.equal(checkCostTags({ ...inventory,resources:[excluded] },approved).status,'pass');
  const unapproved = check({ ...inventory,resources:[excluded] });
  assert.equal(unapproved.status,'fail'); assert.ok(unapproved.findings.some(f=>f.ruleId==='exclusion-unapproved'));
  const expired = checkCostTags({ ...inventory,resources:[excluded] },{ ...approved,exceptions:[{...approved.exceptions[0],expiresAt:'2026-09-26T00:00:00Z'}] });
  assert.equal(expired.status,'fail'); assert.ok(expired.findings.some(f=>f.ruleId==='exclusion-expired'));
  const badReason = checkCostTags({ ...inventory,resources:[excluded] },{ ...approved,exceptions:[{...approved.exceptions[0],reason:'  '}] });
  assert.equal(badReason.status,'incomplete');
  const wrongScope = checkCostTags({ ...inventory,resources:[excluded] },{ ...approved,exceptions:[{...approved.exceptions[0],resourceId:'other'}] });
  assert.equal(wrongScope.status,'fail');
});

test('partial inventory and unsupported provider are incomplete', () => {
  assert.equal(check({ ...inventory,complete:false }).status,'incomplete');
  assert.equal(check({ ...inventory,resources:[{...resource,provider:'unknown'}] }).status,'incomplete');
});

test('resource and depth N/N+1 and injected deadline are enforced', () => {
  const many = n => ({...inventory,resources:Array.from({length:n},(_,i)=>({...resource,resourceId:`synthetic-${i}`}))});
  assert.equal(check(many(LIMITS.resources)).findings.some(f=>f.ruleId==='limit-exceeded'),false);
  assert.ok(check(many(LIMITS.resources+1)).findings.some(f=>f.ruleId==='limit-exceeded'));
  const deep=n=>{const d=structuredClone(inventory);let x=d;for(let i=0;i<n;i++){x.extra={};x=x.extra;}return d;};
  assert.equal(check(deep(16)).findings.some(f=>f.ruleId==='limit-exceeded'),false);
  assert.ok(check(deep(17)).findings.some(f=>f.ruleId==='limit-exceeded'));
  assert.equal(checkCostTags(inventory,policy,{now:()=>5000,deadline:5000}).status,'pass');
  assert.equal(checkCostTags(inventory,policy,{now:()=>5001,deadline:5000}).status,'incomplete');
});

test('CLI has confined reads, duplicate-key refusal, and exact byte limits', () => {
  const root=mkdtempSync(join(tmpdir(),'cloud-tags-')),outside=mkdtempSync(join(tmpdir(),'cloud-tags-out-'));
  const args=['--root',root,'--policy','policy.json','--inventory','inventory.json'];
  const capture=()=>{let stdout='';return{io:{stdout:{write:s=>{stdout+=s;}},stderr:{write(){}}},get stdout(){return stdout;}};};
  try {
    writeFileSync(join(root,'policy.json'),JSON.stringify(policy));writeFileSync(join(root,'inventory.json'),JSON.stringify(inventory));
    let o=capture();assert.equal(runCli(args,o.io),0);assert.equal(JSON.parse(o.stdout).status,'pass');
    writeFileSync(join(root,'inventory.json'),JSON.stringify(inventory).replace('"complete":true','"compl\\u0065te":false,"complete":true'));
    o=capture();assert.equal(runCli(args,o.io),2);assert.equal(JSON.parse(o.stdout).status,'incomplete');
    writeFileSync(join(outside,'inventory.json'),JSON.stringify(inventory));symlinkSync(join(outside,'inventory.json'),join(root,'linked.json'));
    o=capture();assert.equal(runCli(['--root',root,'--policy','policy.json','--inventory','linked.json'],o.io),2);assert.equal(o.stdout,'');
    o=capture();assert.equal(runCli(['--root',join(root,'policy.json'),'--policy','policy.json','--inventory','inventory.json'],o.io),2);assert.equal(o.stdout,'');
    for(const [file,limit] of [['policy.json',LIMITS.policyBytes],['inventory.json',LIMITS.inventoryBytes]]){
      const raw=file==='policy.json'?JSON.stringify(policy):JSON.stringify(inventory);
      for(const delta of [0,1]){writeFileSync(join(root,'policy.json'),JSON.stringify(policy));writeFileSync(join(root,'inventory.json'),JSON.stringify(inventory));writeFileSync(join(root,file),raw+' '.repeat(limit+delta-Buffer.byteLength(raw)));o=capture();runCli(args,o.io);if(file==='policy.json')assert.equal(o.stdout==='',delta===1);else assert.equal(JSON.parse(o.stdout).findings.some(f=>f.ruleId==='limit-exceeded'),delta===1);}
    }
  } finally {rmSync(root,{recursive:true,force:true});rmSync(outside,{recursive:true,force:true});}
});

test('severity catalog is pinned', () => {
  assert.deepEqual(RULES,{'policy-invalid':'warning','inventory-invalid':'warning','inventory-incomplete':'warning','provider-unsupported':'warning','tag-ambiguous':'warning','limit-exceeded':'warning','input-unreadable':'warning','required-tag-missing':'error','blank-owner':'error','tag-value-not-allowed':'error','exclusion-unapproved':'error','exclusion-expired':'error'});
});

test('exception and tag count N/N+1 are enforced', () => {
  const exceptions=n=>({...policy,exceptions:Array.from({length:n},(_,i)=>({provider:'aws',resourceId:`synthetic-${i}`,reason:'test-only',expiresAt:'2026-09-27T00:00:00Z'}))});
  assert.equal(validPolicy(exceptions(LIMITS.exceptions)),true);
  assert.equal(validPolicy(exceptions(LIMITS.exceptions+1)),false);
  const tagged=n=>{const tags={...resource.tags};for(let i=0;i<n-3;i++)tags[`tag-${i}`]='x';return {...inventory,resources:[{...resource,tags}]};};
  assert.equal(check(tagged(LIMITS.tags)).status,'pass');
  assert.ok(check(tagged(LIMITS.tags+1)).findings.some(f=>f.ruleId==='limit-exceeded'));
});

test('canaries in identifiers, values and exception reasons are not reported', () => {
  const canary='SECRET-CANARY-999';
  const bad={...resource,resourceId:canary,tags:{...resource.tags,owner:canary}};
  const result=check({...inventory,resources:[bad]});
  assert.equal(result.status,'fail');
  assert.equal(JSON.stringify(result).includes(canary),false);
  const e={...policy,exceptions:[{provider:'aws',resourceId:canary,reason:canary,expiresAt:'2026-09-26T00:00:00Z'}]};
  const excluded=checkCostTags({...inventory,resources:[{...bad,excluded:true}]},e);
  assert.equal(excluded.status,'fail');
  assert.equal(JSON.stringify(excluded).includes(canary),false);
});

test('visually blank format-only owner is never approved, while ordinary owner still passes', () => {
  assert.equal(check(inventory).status,'pass');
  const invisible='\u200e';
  const altered={...inventory,resources:[{...resource,tags:{...resource.tags,owner:invisible}}]};
  const result=check(altered);
  assert.equal(result.status,'fail');
  assert.ok(result.findings.some(f=>f.ruleId==='blank-owner'));
  assert.equal(JSON.stringify(result).includes(invisible),false);
  const unsafePolicy={...policy,requiredTags:policy.requiredTags.map(t=>t.key==='owner'?{...t,allowedValues:[invisible]}:t)};
  assert.equal(checkCostTags(altered,unsafePolicy).status,'incomplete');
  assert.equal(validPolicy(unsafePolicy),false);
});
