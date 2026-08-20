const phases=[
 {n:'01',title:'Establish trust',desc:'Run MeowResolver and FilelessBypassDetection in report-only mode. Capture tamper indicators before parsing.',link:'MeowResolver / FilelessBypassDetection'},
 {n:'02',title:'Build the timeline',desc:'Cross-check Prefetch, BAM, UserAssist, Amcache, USN Journal, and USB history for execution and deletion traces.',link:'PrefetchView / BAMReveal / JournalParser'},
 {n:'03',title:'Inspect the client',desc:'Inventory mods and jars. Use static analysis, strings, signatures, imports, and obfuscation signals.',link:'MeowModAnalyzer / StringsParser'},
 {n:'04',title:'Test hypotheses',desc:'Apply YARA and client-specific detectors only after recording hashes, paths, timestamps, and rule names.',link:'YARA / MeowClientFucker'},
 {n:'05',title:'Escalate carefully',desc:'Use memory collection last, when historical evidence gives a reason to test what is currently loaded.',link:'Memory scans / correlation'}
];
const tools=[
 ['MeowResolver','anti','Anti-forensic','Tamper checks across registry, event logs, filesystem, hosts, IFEO, and USN indicators.','https://github.com/MeowTonynoh/MeowResolver'],
 ['FilelessBypassDetection','anti','Anti-forensic','Looks for fileless execution, in-memory loaders, and reflection-based injection traces.','https://github.com/l4rpsucks/Scripts'],
 ['PrefetchView','artifact','Artifacts','Parses Prefetch, checks signatures/imports, runs YARA, and surfaces unresolved paths and security-change flags.','https://github.com/Orbdiff/PrefetchView/releases/latest'],
 ['BAMReveal','artifact','Artifacts','Independent execution evidence from Background Activity Moderator. Useful when Prefetch is absent or cleared.','https://github.com/Orbdiff/BAMReveal/releases/latest'],
 ['JournalParser','artifact','Artifacts','Reads the USN Journal $J stream to confirm deletion and rename activity.','https://github.com/Orbdiff/JournalParser/releases/latest'],
 ['UserAssistView','artifact','Artifacts','Execution counts, timestamps, focus metrics, signatures, and generic YARA hits. Build from source.','https://github.com/Orbdiff/UserAssistView/releases/latest'],
 ['USBDetector','artifact','Artifacts','USB connection history for removable-media and device-swap correlation.','https://github.com/Orbdiff/USBDetector/releases/latest'],
 ['StringsParser','artifact','Artifacts','Extract and match strings in binaries or memory dumps against known signatures.','https://github.com/Orbdiff/StringsParser/releases/latest'],
 ['MeowModAnalyzer','mods','Mods & jars','Static .minecraft/mods review for obfuscation, Runtime.exec, network behavior, and known module names.','https://github.com/MeowTonynoh/MeowModAnalyzer'],
 ['zeezyparser / catchmacro','mods','Mods & jars','Parse jars and scan macro behavior; point at versions or mods folders as prompted.','https://github.com/zeezyexe/zeezy-jar-parser'],
 ['MeowClientFucker','client','Client detectors','General client detector for a focused hypothesis test after artifact collection.','https://github.com/MeowTonynoh/MeowClientFucker/releases/latest'],
 ['MeowDoomsdayFucker','client','Client detectors','Doomsday-specific memory and Prefetch trace analysis.','https://github.com/MeowTonynoh/MeowDoomsdayFucker/releases/latest'],
 ['MeowNovowareFucker','client','Client detectors','Novoware-specific detector with historical and live investigation modes.','https://github.com/MeowTonynoh/MeowNovowareFucker/releases/latest'],
 ['KernelLiveDumpTool','memory','Memory','Kernel/live dump collection. Keep last: invasive, slow, and hypothesis-driven.','https://github.com/spokwn/KernelLiveDumpTool/releases/latest'],
 ['Velociraptor','memory','Memory','Endpoint collection and triage platform for broader evidence acquisition.','https://github.com/Velocidex/velociraptor/releases/latest'],
 ['Hayabusa','artifact','Artifacts','Windows event-log timeline and threat hunting support for corroboration.','https://github.com/Yamato-Security/hayabusa/releases/latest']
];
const timeline=document.querySelector('#timeline'); timeline.innerHTML=phases.map(p=>`<article class="phase"><span class="phase-num">${p.n}</span><h3>${p.title}</h3><p>${p.desc}</p><a href="#toolkit">${p.link} ↗</a></article>`).join('');
const grid=document.querySelector('#toolGrid'); const search=document.querySelector('#toolSearch'); const filter=document.querySelector('#categoryFilter');
const toolUse={
 'MeowResolver':'Open the release build, select report-only during an active case, and preserve the finding list before remediation.',
 'FilelessBypassDetection':'Run only after recording the host state; retain its console output with the case notes.',
 'PrefetchView':'Open the Prefetch directory, filter recent execution, then export or record unresolved-path and signature findings.',
 'BAMReveal':'Review BAM entries as an independent execution lane; compare the executable path and time with Prefetch.',
 'JournalParser':'Review relevant create, rename, and delete activity around a lead; correlate the path with other artifact sources.',
 'UserAssistView':'Build from source when needed, then review execution counts and timestamps as corroboration rather than proof alone.',
 'USBDetector':'Review connected-device history around the relevant time window and preserve identifiers and timestamps.',
 'StringsParser':'Choose the target file or approved dump, record the source hash, then document matched strings with surrounding context.',
 'MeowModAnalyzer':'Point it at the intended mods directory; review unknown, obfuscated, and suspicious results against the jar contents.',
 'zeezyparser / catchmacro':'Choose the versions or mods directory and review parsed jar content or macro findings with their source paths.',
 'MeowClientFucker':'Use after the artifact review gives a client hypothesis; capture version, result, and supporting artifacts.',
 'MeowDoomsdayFucker':'Choose the mode that matches the evidence: historical Prefetch traces first, then live memory only when justified.',
 'MeowNovowareFucker':'Run against the relevant host state and retain the result together with supporting timeline evidence.',
 'KernelLiveDumpTool':'Collect only when earlier evidence establishes a live-memory question; preserve collection metadata and hashes.',
 'Velociraptor':'Use targeted collections to gather the specific artifact lanes needed for correlation and subsequent review.',
 'Hayabusa':'Parse the relevant event-log export, filter to the time window, and correlate events with artifact timestamps.'
};
function renderTools(){const q=search.value.toLowerCase(), f=filter.value; grid.innerHTML=tools.filter(t=>(f==='all'||t[1]===f)&&(!q||t[0].toLowerCase().includes(q)||t[2].toLowerCase().includes(q)||t[3].toLowerCase().includes(q))).map(t=>`<article class="tool-card"><span class="tag">${t[2]}</span><h3>${t[0]}</h3><p>${t[3]}</p><details><summary>How to use</summary><p class="tool-use">${toolUse[t[0]]||'Review the tool documentation, record the input and output, and correlate findings with another evidence lane.'}</p></details><div class="tool-foot"><span class="mono">REFERENCE</span><a href="${t[4]}" target="_blank" rel="noreferrer">Open release ↗</a></div></article>`).join('')||'<p class="body-copy">No tools match this filter.</p>'}
search.addEventListener('input',renderTools); filter.addEventListener('change',renderTools); renderTools();
document.querySelectorAll('[data-save]').forEach(el=>{const k='blocktrace_'+el.dataset.save; const old=localStorage.getItem(k); if(old!==null){if(el.type==='checkbox')el.checked=old==='true';else el.value=old} el.addEventListener('input',()=>localStorage.setItem(k,el.type==='checkbox'?el.checked:el.value));});
const clearBtn=document.querySelector('#clearBtn'); if(clearBtn){clearBtn.addEventListener('click',()=>{document.querySelectorAll('[data-save]').forEach(el=>{localStorage.removeItem('blocktrace_'+el.dataset.save); if(el.type==='checkbox')el.checked=false; else el.value='';});});} document.querySelector('#printBtn').addEventListener('click',()=>window.print());

// Screenshare-inspired reference controls
const guideTabs=document.querySelectorAll('.guide-tab');
guideTabs.forEach(tab=>tab.addEventListener('click',()=>{guideTabs.forEach(t=>t.classList.remove('active'));document.querySelectorAll('.guide-panel').forEach(p=>p.classList.remove('active'));tab.classList.add('active');document.querySelector(`#${tab.dataset.guide}-panel`).classList.add('active');}));
const targetPlayer=document.querySelector('#targetPlayer'); const playerAvatar=document.querySelector('#playerAvatar');
function syncTarget(){const name=(targetPlayer.value.trim()||'BT').replace(/[^a-zA-Z0-9_ -]/g,'');playerAvatar.textContent=name.slice(0,2).toUpperCase();document.querySelectorAll('.dynamic-copy').forEach(btn=>btn.dataset.copy=btn.dataset.copy.replace(/Subject: .*?(?=\n|$)/,'Subject: '+name));}
if(targetPlayer){targetPlayer.addEventListener('input',syncTarget);syncTarget();}
document.querySelectorAll('.copy-btn').forEach(btn=>btn.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(btn.dataset.copy);const toast=document.querySelector('#toast');toast.textContent='Copied to clipboard.';toast.classList.add('show');setTimeout(()=>toast.classList.remove('show'),1800);}catch{}}));

// Signature console: parses only rule text supplied in the browser.
const scannerIndicators=['dnscache','lsass.exe','javaw.exe','dcom','SysMain','PcaSvc','Bam','Schedule','EventLog','DusmSvc','DPS','CDPSvc'];
const enabledIndicators=new Set(scannerIndicators.map(value=>value.toLowerCase()));
const byId=id=>document.getElementById(id);
const ruleText=byId('ruleText'), ruleFile=byId('ruleFile'), ruleSource=byId('ruleSource');
const escapeRuleHtml=value=>value.replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
function setSource(text,label){ruleText.value=text;ruleSource.textContent=label;byId('sourceState').textContent=text?'LOADED':'NOT LOADED';byId('sourceDetail').textContent=text?label:'Choose readable rule text';}
function setQueue(state,detail,progress){byId('queueState').textContent=state;byId('queueDetail').textContent=detail;byId('progressLabel').textContent=state+' / '+detail;byId('progressBar').style.width=progress+'%';}
function renderTargets(){const root=byId('indicatorChips');if(!root)return;root.innerHTML=scannerIndicators.map(value=>`<button class="indicator-chip ${enabledIndicators.has(value.toLowerCase())?'active':''}" type="button" data-indicator="${value}">${value}</button>`).join('');root.querySelectorAll('button').forEach(button=>button.addEventListener('click',()=>{const key=button.dataset.indicator.toLowerCase();enabledIndicators.has(key)?enabledIndicators.delete(key):enabledIndicators.add(key);renderTargets();byId('targetProfile').textContent=enabledIndicators.size+' ACTIVE TARGET'+(enabledIndicators.size===1?'':'S');}));}
function parseRuleText(text){const rules=[...text.matchAll(/^\s*(?:private\s+|global\s+)?rule\s+([A-Za-z0-9_]+)/gmi)].map(match=>match[1]);const strings=[...text.matchAll(/^\s*(\$[A-Za-z0-9_]+)\s*=/gmi)].map(match=>match[1]);const lower=text.toLowerCase();const hits=[...enabledIndicators].map(value=>({value,count:(lower.match(new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'g'))||[]).length})).filter(hit=>hit.count);return{rules,strings,hits};}
function renderFindings(data){const rulesHtml=data.rules.length?data.rules.map(name=>`<div class="result-item"><b>${escapeRuleHtml(name)}</b><em>RULE</em></div>`).join(''):'<p>No YARA rule declarations found in the loaded text.</p>';const hitHtml=data.hits.length?`<div class="hit-list"><strong>ACTIVE TARGET MATCHES</strong><div>${data.hits.map(hit=>`<span class="hit">${escapeRuleHtml(hit.value)} × ${hit.count}</span>`).join('')}</div></div>`:'<div class="hit-list"><strong>ACTIVE TARGET MATCHES</strong><p>No configured indicators were found.</p></div>';byId('ruleResults').innerHTML=rulesHtml+hitHtml;}
renderTargets();
ruleFile?.addEventListener('change',async event=>{const file=event.target.files[0];if(!file)return;setSource(await file.text(),file.name);setQueue('READY','source loaded',0);});
byId('loadBundledRules')?.addEventListener('click',async()=>{try{const response=await fetch('rules/minecraft-dfir-rules.md');if(!response.ok)throw new Error('missing');setSource(await response.text(),'rules/minecraft-dfir-rules.md');setQueue('READY','included rules loaded',0);}catch{setSource('','Select rules/minecraft-dfir-rules.md manually when using file:// preview.');setQueue('WAITING','manual source required',0);}});
byId('clearRules')?.addEventListener('click',()=>{setSource('','NO SOURCE');byId('ruleCount').textContent='0';byId('indicatorCount').textContent='0';byId('stringCount').textContent='0';byId('ruleResults').innerHTML='<p>Load a signature source, then run the queue. Findings stay local to this browser tab.</p>';byId('scanState').textContent='WAITING';setQueue('IDLE','awaiting a scan',0);});
byId('scanRules')?.addEventListener('click',()=>{const text=ruleText.value;if(!text.trim()){setQueue('WAITING','load a source first',0);return;}setQueue('RUNNING','parsing declarations',35);byId('scanState').textContent='RUNNING';window.setTimeout(()=>{const data=parseRuleText(text);byId('ruleCount').textContent=data.rules.length;byId('indicatorCount').textContent=data.hits.reduce((total,hit)=>total+hit.count,0);byId('stringCount').textContent=data.strings.length;renderFindings(data);byId('scanState').textContent='COMPLETE';setQueue('COMPLETE',data.rules.length+' rules parsed',100);},180);});
