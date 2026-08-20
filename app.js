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
