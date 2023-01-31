export const TOOL_ID='cloud-cost-tag-checker';
export const LIMITS=Object.freeze({policyBytes:65536,inventoryBytes:1048576,resources:1000,exceptions:100,tags:100,depth:16,milliseconds:5000});
export const RULES=Object.freeze({'policy-invalid':'warning','inventory-invalid':'warning','inventory-incomplete':'warning','provider-unsupported':'warning','tag-ambiguous':'warning','limit-exceeded':'warning','input-unreadable':'warning','required-tag-missing':'error','blank-owner':'error','tag-value-not-allowed':'error','exclusion-unapproved':'error','exclusion-expired':'error'});
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const only=(x,keys)=>Object.keys(x).every(k=>keys.includes(k));
const cmp=(a,b)=>a<b?-1:a>b?1:0;
const id=x=>typeof x==='string'&&x.length>0&&x.length<=256&&!/[\u0000-\u001f\u007f-\u009f]/u.test(x);
const provider=x=>['aws','azure','gcp'].includes(x);
const clean=x=>typeof x==='string'&&x.trim().length>0&&x.length<=256&&!/[\u0000-\u001f\u007f-\u009f]/u.test(x);
const instant=x=>typeof x==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString().slice(0,19)===x.slice(0,19);
function depth(x){const stack=[[x,0,new Set()]];while(stack.length){const [v,n,a]=stack.pop();if(n>LIMITS.depth)return n;if(v&&typeof v==='object'){if(a.has(v))return LIMITS.depth+1;const next=new Set(a);next.add(v);for(const c of Object.values(v))stack.push([c,n+1,next]);}}return 0;}
export function validPolicy(p){
  if(!obj(p)||!only(p,['schemaVersion','asOf','requiredTags','exceptions'])||p.schemaVersion!=='1'||!instant(p.asOf)||!Array.isArray(p.requiredTags)||p.requiredTags.length!==3||!Array.isArray(p.exceptions)||p.exceptions.length>LIMITS.exceptions)return false;
  if(!p.requiredTags.every(t=>obj(t)&&only(t,['key','allowedValues'])&&['cost-center','owner','environment'].includes(t.key)&&Array.isArray(t.allowedValues)&&t.allowedValues.length>0&&t.allowedValues.length<=100&&t.allowedValues.every(clean)&&new Set(t.allowedValues).size===t.allowedValues.length)||new Set(p.requiredTags.map(t=>t.key)).size!==3)return false;
  return p.exceptions.every(e=>obj(e)&&only(e,['provider','resourceId','reason','expiresAt'])&&provider(e.provider)&&id(e.resourceId)&&clean(e.reason)&&instant(e.expiresAt))&&new Set(p.exceptions.map(e=>`${e.provider}\0${e.resourceId}`)).size===p.exceptions.length;
}
export function checkCostTags(inventory,policy,{now=Date.now,deadline=now()+LIMITS.milliseconds}={}){
  const findings=[];
  const add=(ruleId,pointer,message,file='@inventory')=>{if(!Object.hasOwn(RULES,ruleId))throw new Error('Unknown rule');findings.push({ruleId,severity:RULES[ruleId],message,location:{file,pointer}});};
  const finish=checked=>{findings.sort((a,b)=>cmp(a.location.file,b.location.file)||cmp(a.location.pointer,b.location.pointer)||cmp(a.ruleId,b.ruleId));return{schemaVersion:'1',tool:TOOL_ID,status:findings.some(f=>f.severity==='warning')?'incomplete':findings.length?'fail':checked?'pass':'incomplete',summary:{checked,errors:findings.filter(f=>f.severity==='error').length,warnings:findings.filter(f=>f.severity==='warning').length},findings};};
  if(!validPolicy(policy)){add('policy-invalid','','Cost tag policy is invalid.','@policy');return finish(0);}
  if(depth(inventory)>LIMITS.depth){add('limit-exceeded','','Inventory JSON depth limit exceeded.');return finish(0);}
  if(!obj(inventory)||!only(inventory,['schemaVersion','complete','resources'])||inventory.schemaVersion!=='1'||typeof inventory.complete!=='boolean'||!Array.isArray(inventory.resources)){add('inventory-invalid','','Inventory shape is invalid.');return finish(0);}
  if(inventory.resources.length>LIMITS.resources){add('limit-exceeded','/resources','Resource record limit exceeded.');return finish(0);}
  if(!inventory.complete)add('inventory-incomplete','/complete','Inventory declares partial coverage.');
  if(!inventory.resources.length){add('inventory-invalid','/resources','No resource evidence was supplied.');return finish(0);}
  const seen=new Set();
  for(let i=0;i<inventory.resources.length;i++){
    if(now()>deadline){add('limit-exceeded','','Evaluation deadline exceeded.');return finish(i);}
    const r=inventory.resources[i],at=`/resources/${i}`;
    if(!obj(r)||!only(r,['provider','resourceId','tags','excluded'])||!id(r.resourceId)||(r.excluded!==undefined&&typeof r.excluded!=='boolean')||!obj(r.tags)){add('inventory-invalid',at,'Resource identity, tags, or exclusion flag is invalid.');continue;}
    if(!provider(r.provider)){add('provider-unsupported',`${at}/provider`,'Resource provider is unsupported.');continue;}
    const scope=`${r.provider}\0${r.resourceId}`;
    if(seen.has(scope)){add('inventory-invalid',at,'Resource identity is duplicated.');continue;}seen.add(scope);
    if(Object.keys(r.tags).length>LIMITS.tags){add('limit-exceeded',`${at}/tags`,'Tag count exceeds limit.');continue;}
    if(!Object.entries(r.tags).every(([key,value])=>typeof key==='string'&&/^[A-Za-z0-9][A-Za-z0-9-]{0,127}$/.test(key)&&typeof value==='string'&&value.length<=256&&!/[\u0000-\u001f\u007f-\u009f]/u.test(value))){add('inventory-invalid',`${at}/tags`,'Tag map contains unsupported key or value.');continue;}
    if(r.excluded){
      const e=policy.exceptions.find(x=>x.provider===r.provider&&x.resourceId===r.resourceId);
      if(!e)add('exclusion-unapproved',`${at}/excluded`,'Excluded resource lacks a scoped policy exception.');
      else if(Date.parse(e.expiresAt)<=Date.parse(policy.asOf))add('exclusion-expired',`${at}/excluded`,'Scoped exclusion has expired.');
      continue;
    }
    const entries=Object.entries(r.tags), normalized=new Map();let ambiguous=false;
    for(const [key,value] of entries){const canonical=r.provider==='azure'?key.toLowerCase():key;if(normalized.has(canonical)){ambiguous=true;break;}normalized.set(canonical,value);}
    if(ambiguous){add('tag-ambiguous',`${at}/tags`,'Tag names collide under provider case rules.');continue;}
    for(const required of policy.requiredTags){const key=r.provider==='azure'?required.key.toLowerCase():required.key;const value=normalized.get(key),ptr=`${at}/tags`;
      if(value===undefined)add('required-tag-missing',ptr,'Required cost allocation tag is missing.');
      else if(required.key==='owner'&&!value.trim())add('blank-owner',ptr,'Owner tag is blank.');
      else if(!required.allowedValues.includes(value))add('tag-value-not-allowed',ptr,'Required tag value is outside policy allowlist.');
    }
  }
  return finish(inventory.resources.length);
}
