import {readFileSync,realpathSync,statSync} from 'node:fs';
import {resolve,relative,isAbsolute} from 'node:path';
import {inspectJsonKeys} from './json-keys.mjs';
import {checkCostTags,validPolicy,TOOL_ID,RULES,LIMITS} from './index.mjs';
const decode=bytes=>new TextDecoder('utf-8',{fatal:true}).decode(bytes);
const inside=(root,path)=>{const rel=relative(root,path);return rel!=='..'&&!rel.startsWith('../')&&!isAbsolute(rel);};
const incomplete=(ruleId,message)=>({schemaVersion:'1',tool:TOOL_ID,status:'incomplete',summary:{checked:0,errors:0,warnings:1},findings:[{ruleId,severity:RULES[ruleId],message,location:{file:'@inventory',pointer:''}}]});
export function runCli(args,{stdout=process.stdout,stderr=process.stderr,now=Date.now}={}){
  const invalid=message=>{stderr.write(`${message}\n`);return 2;};
  if(args.length!==6||args.some((v,i)=>i%2===0&&!['--root','--policy','--inventory'].includes(v)))return invalid('Usage: --root DIR --policy FILE --inventory FILE');
  const flags=new Map();for(let i=0;i<args.length;i+=2){if(flags.has(args[i]))return invalid('Duplicate option');flags.set(args[i],args[i+1]);}
  if(flags.size!==3||[...flags.values()].some(v=>typeof v!=='string'||!v))return invalid('Missing option value');
  let root;try{root=realpathSync(flags.get('--root'));if(!statSync(root).isDirectory())return invalid('Root must be a directory');}catch{return invalid('Invalid root directory');}
  const paths=new Map();for(const key of ['--policy','--inventory']){const value=flags.get(key);if(isAbsolute(value)||value.split('/').some(x=>x==='.'||x==='..')||/[\u0000-\u001f\u007f-\u009f\\]/u.test(value))return invalid('Input path must be relative and confined');const lexical=resolve(root,value);if(!inside(root,lexical))return invalid('Input path escapes root');try{const actual=realpathSync(lexical);if(!inside(root,actual))return invalid('Input path escapes root');paths.set(key,actual);}catch(error){if(error.code!=='ENOENT')return invalid('Invalid input path');paths.set(key,lexical);}}
  let policy;try{const bytes=readFileSync(paths.get('--policy'));if(bytes.length>LIMITS.policyBytes)return invalid('Policy byte limit exceeded');const raw=decode(bytes);policy=JSON.parse(raw);if(inspectJsonKeys(raw,LIMITS.depth)||!validPolicy(policy))return invalid('Invalid cost tag policy');}catch{return invalid('Policy could not be read, decoded, or parsed');}
  let report;try{const bytes=readFileSync(paths.get('--inventory'));if(bytes.length>LIMITS.inventoryBytes)report=incomplete('limit-exceeded','Inventory byte limit exceeded.');else{const raw=decode(bytes),data=JSON.parse(raw),problem=inspectJsonKeys(raw,LIMITS.depth);report=problem?incomplete(problem==='duplicate'?'inventory-invalid':'limit-exceeded',problem==='duplicate'?'Inventory contains duplicate JSON keys.':'Inventory JSON depth limit exceeded.'):checkCostTags(data,policy,{now,deadline:now()+LIMITS.milliseconds});}}catch{report=incomplete('input-unreadable','Inventory could not be read, decoded, or parsed.');}
  stdout.write(`${JSON.stringify(report)}\n`);return report.status==='pass'?0:report.status==='fail'?1:2;
}
