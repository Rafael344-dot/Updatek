// ==================== CONFIGURAÇÃO ANTICHEAT EXTREMA ====================
const CONFIG = {
    SUSPECT_PROCESSES: [
        "frida", "cycript", "substrate", "substitute", "gdb", "lldb",
        "debugserver", "ptrace", "dylib", "inject", "hook", "theos",
        "unc0ver", "checkra1n", "odyssey", "taurine", "palera1n"
    ],
    SUSPECT_FRAMEWORKS: [
        "FridaGadget.dylib", "CydiaSubstrate", "SubstrateInserter",
        "libhooker", "PreferenceLoader", "RocketBootstrap"
    ],
    FORBIDDEN_URLS: [
        "cydia://", "sileo://", "zbra://", "installer://"
    ],
    PROXY_PATTERNS: [
        "http-proxy", "socks", "mitm", "charles", "burp", "fiddler",
        "proxyman", "ssl-kill-switch"
    ]
};

// ==================== FUNÇÕES DE LEITURA ====================
async function readFile(path) {
    let fm = FileManager.local();
    if (!fm.fileExists(path)) return null;
    return fm.readString(path);
}

function looksLikePrivacyReport(content) {
    try {
        let lines = content.trim().split("\n");
        for (let i = 0; i < Math.min(5, lines.length); i++) {
            let obj = JSON.parse(lines[i]);
            if (obj.appID || obj.appVersion || obj.domain || obj.firstTimeStamp) return true;
        }
    } catch(e) {}
    return false;
}

function looksLikeUsageFile(content) {
    return content.includes("xp_amp_app_usage") || 
           (content.includes("bundleID") && content.includes("usageSeconds"));
}

// ==================== PARSING .NDJSON ====================
function parseNdjson(content) {
    let entries = [];
    let lines = content.trim().split("\n");
    for (let line of lines) {
        if (!line.trim()) continue;
        try {
            entries.push(JSON.parse(line));
        } catch(e) {}
    }
    return entries;
}

// ==================== ANÁLISE IPS ====================
function parseIpsFile(content) {
    let result = { header: null, records: [] };
    let lines = content.split("\n");
    for (let line of lines) {
        line = line.trim();
        if (!line) continue;
        if (line.startsWith("{") && !result.header) {
            try { result.header = JSON.parse(line); } catch(e) {}
        } else if (line.startsWith("{") && line.includes("usageSeconds")) {
            try { result.records.push(JSON.parse(line)); } catch(e) {}
        }
    }
    return result;
}

function analyzeIps(data) {
    let findings = [];
    if (!data.records.length) return findings;
    
    let appUsage = {};
    for (let record of data.records) {
        let bundle = record.bundleID || "unknown";
        let seconds = record.usageSeconds || 0;
        appUsage[bundle] = (appUsage[bundle] || 0) + seconds;
        
        if (CONFIG.SUSPECT_PROCESSES.some(p => bundle.toLowerCase().includes(p))) {
            findings.push(`⚠️ Processo suspeito detectado: ${bundle} (${seconds}s)`);
        }
    }
    
    let totalTime = Object.values(appUsage).reduce((a,b) => a+b, 0);
    if (totalTime > 0) {
        for (let [bundle, time] of Object.entries(appUsage)) {
            if (time / totalTime > 0.8 && time > 3600) {
                findings.push(`⚠️ Uso excessivo de ${bundle}: ${Math.round(time/60)}min (${Math.round(time/totalTime*100)}% do total)`);
            }
        }
    }
    
    return findings;
}

// ==================== VALIDAÇÃO DO RELATÓRIO ====================
function validateReport(entries) {
    if (!entries || entries.length === 0) return { ok: false, reason: "Arquivo vazio ou corrompido" };
    
    let hasTime = entries.some(e => e.firstTimeStamp || e.lastTimeStamp);
    let hasDomain = entries.some(e => e.domain);
    let hasApp = entries.some(e => e.appID);
    
    if (!hasTime && !hasDomain && !hasApp) return { ok: false, reason: "Estrutura inválida – campos obrigatórios ausentes" };
    
    let firstTimestamp = null;
    for (let e of entries) {
        let ts = e.firstTimeStamp || e.lastTimeStamp;
        if (ts && typeof ts === "number" && ts > 1000000000000) {
            firstTimestamp = ts;
            break;
        }
    }
    if (!firstTimestamp) return { ok: false, reason: "Timestamp inválido – parece arquivo corrompido" };
    
    return { ok: true, reason: "" };
}

// ==================== ANÁLISE PRINCIPAL ====================
async function analyze(entries) {
    let findings = [];
    let netEntries = [];
    let cheatAppFindings = [];
    let knownCheatFindings = [];
    let ghostAppFindings = [];
    let proxyLoginFindings = [];
    
    let suspiciousDomains = [];
    let vpnDetected = false;
    let proxyDetected = false;
    
    // Mapeamento de apps conhecidos por trapaça
    let knownCheatApps = {
        "gameguardian": "Game Guardian",
        "lucky.patcher": "Lucky Patcher",
        "freedom.apk": "Freedom",
        "sbgamehacker": "SB Game Hacker",
        "xmodgames": "Xmodgames",
        "creehack": "CreeHack",
        "leo.play.card": "Leo Play Card",
        "frida": "Frida",
        "cycript": "Cycript"
    };
    
    // Apps fantasmas (que tentam se esconder)
    let ghostApps = [
        "com.apple.springboard", "com.apple.Preferences",
        "com.apple.mobilesafari", "com.apple.MobileSMS",
        "com.apple.mobilephone", "com.apple.AppStore"
    ];
    
    for (let entry of entries) {
        if (entry.domain) {
            netEntries.push(entry);
            let domain = entry.domain.toLowerCase();
            
            // Proxy e VPN
            if (domain.includes("proxy") || domain.includes("vpn") || domain.includes("tunnel")) {
                proxyDetected = true;
                findings.push(`🌐 Proxy/VPN detectado: ${entry.domain}`);
            }
            
            // IP interno
            if (domain.match(/^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/)) {
                findings.push(`🏠 Conexão com IP local: ${entry.domain} (possível proxy local)`);
            }
            
            // Domínios suspeitos
            if (domain.includes("mitm") || domain.includes("charles") || domain.includes("burp")) {
                suspiciousDomains.push(domain);
                proxyLoginFindings.push(`🔍 Proxy MITM detectado: ${entry.domain}`);
            }
        }
        
        if (entry.appID) {
            let app = entry.appID.toLowerCase();
            
            // Apps de trapaça conhecidos
            for (let [key, name] of Object.entries(knownCheatApps)) {
                if (app.includes(key)) {
                    knownCheatFindings.push(`🎮 App de trapaça detectado: ${name} (${entry.appID})`);
                }
            }
            
            // Apps fantasmas
            if (ghostApps.includes(app)) {
                ghostAppFindings.push(`👻 App fantasma tentando se camuflar: ${entry.appID}`);
            }
            
            // Framework de hook
            if (CONFIG.SUSPECT_FRAMEWORKS.some(fw => app.includes(fw.toLowerCase()))) {
                cheatAppFindings.push(`🔧 Framework de hook detectado: ${entry.appID}`);
            }
            
            // Processo de debug
            if (CONFIG.SUSPECT_PROCESSES.some(p => app.includes(p))) {
                cheatAppFindings.push(`🐛 Processo de debug detectado: ${entry.appID}`);
            }
            
            // Assinatura inválida
            if (entry.appVersion && (entry.appVersion.includes("debug") || entry.appVersion.includes("test"))) {
                cheatAppFindings.push(`⚠️ Versão debug/teste: ${entry.appID} ${entry.appVersion}`);
            }
        }
    }
    
    // Verificação de integridade temporal
    let timestamps = [];
    for (let e of entries) {
        if (e.firstTimeStamp) timestamps.push(e.firstTimeStamp);
        if (e.lastTimeStamp) timestamps.push(e.lastTimeStamp);
    }
    timestamps.sort();
    if (timestamps.length > 1) {
        let gaps = [];
        for (let i = 1; i < timestamps.length; i++) {
            let gap = timestamps[i] - timestamps[i-1];
            if (gap > 3600000 && gap < 86400000) gaps.push(Math.round(gap/60000));
        }
        if (gaps.length > 3) {
            findings.push(`⏱️ Possível manipulação de tempo: ${gaps.length} lacunas >1h no log`);
        }
    }
    
    return {
        findings: [...new Set(findings)],
        netEntries,
        cheatAppFindings: [...new Set(cheatAppFindings)],
        knownCheatFindings: [...new Set(knownCheatFindings)],
        ghostAppFindings: [...new Set(ghostAppFindings)],
        proxyLoginFindings: [...new Set(proxyLoginFindings)]
    };
}

// ==================== BUILD HTML ====================
function buildHTML(findings, netEntries, cheatAppFindings, knownCheatFindings, ipsFindings, ipsMeta, cheatList, ghostAppFindings, proxyLoginFindings, filename) {
    let total = netEntries.length;
    let uniqueDomains = new Set(netEntries.map(e => e.domain)).size;
    
    let allCheatDetections = [
        ...knownCheatFindings,
        ...cheatAppFindings,
        ...ghostAppFindings,
        ...proxyLoginFindings,
        ...findings.filter(f => f.includes("trapaça") || f.includes("hook") || f.includes("debug")),
        ...ipsFindings
    ];
    
    let isCheating = allCheatDetections.length > 0;
    let cheatLevel = allCheatDetections.length === 0 ? "Nenhum" :
                     allCheatDetections.length <= 2 ? "Baixo" :
                     allCheatDetections.length <= 5 ? "Médio" : "Alto";
    
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #f5f5f7; padding: 20px; color: #1c1c1e; }
            .container { max-width: 800px; margin: 0 auto; }
            .card { background: white; border-radius: 20px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
            .header { text-align: center; margin-bottom: 24px; }
            .title { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
            .badge { display: inline-block; padding: 6px 14px; border-radius: 30px; font-size: 14px; font-weight: 600; margin-top: 8px; }
            .safe { background: #34c75920; color: #248a3d; }
            .cheat-low { background: #ff950020; color: #c45a00; }
            .cheat-medium { background: #ff3b3020; color: #d70015; }
            .cheat-high { background: #ff3b30; color: white; }
            .section { margin-top: 20px; }
            .section-title { font-size: 20px; font-weight: 600; margin-bottom: 12px; border-left: 4px solid #007aff; padding-left: 12px; }
            .detection { background: #fff5f0; border-left: 4px solid #ff3b30; padding: 12px; border-radius: 12px; margin-bottom: 8px; font-size: 14px; }
            .warning { background: #fff9e6; border-left: 4px solid #ff9500; padding: 12px; border-radius: 12px; margin-bottom: 8px; }
            .info { background: #e9f0ff; border-left: 4px solid #007aff; padding: 12px; border-radius: 12px; margin-bottom: 8px; }
            .stat { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #e9e9ef; }
            .stat-label { font-weight: 500; color: #6c6c70; }
            .stat-value { font-weight: 600; }
            .filename { font-size: 12px; color: #8e8e93; text-align: center; margin-top: 20px; padding-top: 16px; border-top: 1px solid #e9e9ef; }
            @media (prefers-color-scheme: dark) {
                body { background: #000000; color: #ffffff; }
                .card { background: #1c1c1e; }
                .info { background: #1a2a4a; }
                .warning { background: #3a2e1a; }
                .detection { background: #3a1a1a; }
                .stat { border-bottom-color: #2c2c2e; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card header">
                <div class="title">🛡️ Relatório Anti-Cheat</div>
                <div class="badge ${isCheating ? (cheatLevel === 'Alto' ? 'cheat-high' : (cheatLevel === 'Médio' ? 'cheat-medium' : 'cheat-low')) : 'safe'}">
                    ${isCheating ? `⚠️ RISCO DE TRAPAÇA - Nível ${cheatLevel}` : "✅ SISTEMA LIMPO"}
                </div>
                <div style="margin-top: 12px; font-size: 14px; color: #8e8e93;">Arquivo: ${filename}</div>
            </div>
            
            ${allCheatDetections.length > 0 ? `
            <div class="card">
                <div class="section-title">🚨 DETECÇÕES DE TRAPAÇA (${allCheatDetections.length})</div>
                ${allCheatDetections.map(d => `<div class="detection">${d}</div>`).join('')}
            </div>
            ` : ''}
            
            <div class="card">
                <div class="section-title">📊 Estatísticas do Relatório</div>
                <div class="stat"><span class="stat-label">Total de requisições</span><span class="stat-value">${total}</span></div>
                <div class="stat"><span class="stat-label">Domínios únicos</span><span class="stat-value">${uniqueDomains}</span></div>
                <div class="stat"><span class="stat-label">Apps detectados</span><span class="stat-value">${new Set(netEntries.map(e => e.appID).filter(Boolean)).size}</span></div>
                ${ipsMeta.iosVersion ? `<div class="stat"><span class="stat-label">iOS Version</span><span class="stat-value">${ipsMeta.iosVersion}</span></div>` : ''}
            </div>
            
            ${findings.filter(f => !f.includes("trapaça") && !f.includes("hook") && !f.includes("debug")).length > 0 ? `
            <div class="card">
                <div class="section-title">⚠️ Alertas de Segurança</div>
                ${findings.filter(f => !f.includes("trapaça") && !f.includes("hook") && !f.includes("debug")).map(f => `<div class="warning">${f}</div>`).join('')}
            </div>
            ` : ''}
            
            <div class="filename">
                🔐 Relatório gerado em ${new Date().toLocaleString()}<br>
                Verificação anti-trapaça nível extremo ativada
            </div>
        </div>
    </body>
    </html>
    `;
}

async function showResult(html) {
    let wv = new WebView();
    await wv.loadHTML(html);
    await wv.present(true);
}

// ==================== SPEECH ====================
const S = {
    start: "Análise anti-cheat concluída. Verifique o relatório."
};

// ==================== FLUXO PRINCIPAL ====================
async function main() {
    let step1 = new Alert();
    step1.title = "📋 Passo 1 de 3 — Relatório de Privacidade";
    step1.message = "Vá em:\n\nAjustes → Privacidade e Segurança → Relatório de Privacidade de Apps\n\nRole até o final e toque em\n\"Ativar Relatório de Privacidade de Apps\"\n\nDepois toque em\n\"Exportar Relatório de Privacidade de Apps\"\ne salve o arquivo .ndjson em qualquer lugar (Arquivos, iCloud, etc).";
    step1.addAction("Entendido, próximo →");
    step1.addCancelAction("Cancelar");
    if (await step1.present() === -1) { Script.complete(); return; }
    
    let step2 = new Alert();
    step2.title = "📊 Passo 2 de 3 — Dados de Análise";
    step2.message = "Vá em:\n\nAjustes → Privacidade e Segurança → Análise e Melhorias\n\nAtive as opções:\n• Compartilhar análise do iPhone\n• Compartilhar análise do iCloud\n• Compartilhar com desenvolvedores de app\n\nDepois volte e toque em\n\"Dados de Análise\"\nRole até o final e selecione o arquivo mais recente começando com\n\"xp_amp_app_usage_dnu\"\n\nToque no arquivo → toque no ícone de compartilhar → Salvar em Arquivos.";
    step2.addAction("Entendido, próximo →");
    step2.addCancelAction("Cancelar");
    if (await step2.present() === -1) { Script.complete(); return; }
    
    let step3 = new Alert();
    step3.title = "✅ Passo 3 de 3 — Selecionar arquivos";
    step3.message = "Agora selecione os 2 arquivos salvos.\n\nVocê pode selecioná-los em qualquer ordem — o sistema identifica automaticamente cada um.\n\n📋 App_Privacy_Report.ndjson\n📊 xp_amp_app_usage_dnu*.ips";
    step3.addAction("Selecionar arquivo 1");
    step3.addCancelAction("Cancelar");
    if (await step3.present() === -1) { Script.complete(); return; }
    
    let path1 = await DocumentPicker.openFile();
    if (!path1) { Script.complete(); return; }
    let content1 = await readFile(path1);
    if (!content1) {
        let a = new Alert();
        a.title = "Erro";
        a.message = "Não foi possível ler o arquivo 1.";
        a.addAction("OK");
        await a.present();
        return;
    }
    
    let notice2 = new Alert();
    notice2.title = "Arquivo 2";
    notice2.message = "Selecione o segundo arquivo (ou pule para analisar somente o primeiro).";
    notice2.addAction("Selecionar arquivo 2");
    notice2.addCancelAction("Pular");
    let path2 = null;
    let content2 = null;
    if (await notice2.present() !== -1) {
        path2 = await DocumentPicker.openFile();
        if (path2) content2 = await readFile(path2);
    }
    
    let ndjsonContent = null, ndjsonPath = null;
    let ipsContent = null;
    
    function classifyContent(content, path) {
        if (looksLikePrivacyReport(content)) return "ndjson";
        if (looksLikeUsageFile(content)) return "ips";
        let name = (path || "").split("/").pop().toLowerCase();
        if (name.endsWith(".ndjson") || name.includes("privacy")) return "ndjson";
        if (name.endsWith(".ips") || name.includes("xp_amp")) return "ips";
        return "unknown";
    }
    
    let type1 = classifyContent(content1, path1);
    let type2 = content2 ? classifyContent(content2, path2) : null;
    
    if (type2 && type1 === type2) {
        let a = new Alert();
        a.title = "Arquivos do mesmo tipo";
        a.message = type1 === "ndjson" ? "Os 2 arquivos parecem ser App Privacy Reports. Selecione um xp_amp_app_usage_dnu*.ips como segundo arquivo." : "Os 2 arquivos parecem ser dados de análise. Selecione um App_Privacy_Report.ndjson como primeiro arquivo.";
        a.addAction("OK");
        await a.present();
        return;
    }
    
    if (type1 === "ndjson" || type2 === "ips") {
        ndjsonContent = content1; ndjsonPath = path1;
        ipsContent = content2;
    } else if (type1 === "ips" || type2 === "ndjson") {
        ipsContent = content1;
        ndjsonContent = content2; ndjsonPath = path2;
    } else {
        let a = new Alert();
        a.title = "Arquivo não reconhecido";
        a.message = "Não foi possível identificar o tipo dos arquivos.\n\nVerifique se selecionou:\n• App_Privacy_Report.ndjson\n• xp_amp_app_usage_dnu*.ips";
        a.addAction("OK");
        await a.present();
        return;
    }
    
    if (!ndjsonContent) {
        let a = new Alert();
        a.title = "App Privacy Report ausente";
        a.message = "O arquivo App_Privacy_Report.ndjson é obrigatório.\n\nAjustes → Privacidade → Relatório de Privacidade de Apps → Exportar";
        a.addAction("OK");
        await a.present();
        return;
    }
    
    let entries = parseNdjson(ndjsonContent);
    let validation = validateReport(entries);
    if (!validation.ok) {
        let a = new Alert();
        a.title = "App Privacy Report inválido";
        a.message = validation.reason + "\n\nExporte em: Ajustes → Privacidade → Relatório de Privacidade de Apps → Exportar";
        a.addAction("OK");
        await a.present();
        return;
    }
    
    let ipsFindings = [];
    let ipsMeta = { iosVersion: null, rootsInstalled: 0 };
    if (ipsContent) {
        let parsed = parseIpsFile(ipsContent);
        ipsFindings = analyzeIps(parsed);
        if (parsed.header) {
            let osMatch = (parsed.header.os_version || "").match(/iPhone OS ([\d.]+)/);
            ipsMeta.iosVersion = osMatch ? osMatch[1] : parsed.header.os_version || null;
            ipsMeta.rootsInstalled = parsed.header.roots_installed || 0;
        }
    }
    
    let filename = (ndjsonPath || "arquivo").split("/").pop();
    Speech.speak(S.start);
    let { findings, netEntries, cheatAppFindings, knownCheatFindings, ghostAppFindings, proxyLoginFindings } = await analyze(entries);
    let html = buildHTML(findings, netEntries, cheatAppFindings, knownCheatFindings, ipsFindings, ipsMeta, [], ghostAppFindings, proxyLoginFindings, filename);
    await showResult(html);
}

main();
