// Extension Abuse Analyzer - Popup Script
// Stage 1: Retrieve installed extensions metadata using chrome.management API
// Stage 2: Analyze permissions and risk assessment

document.addEventListener('DOMContentLoaded', function() {
    const scanBtn = document.getElementById('scanBtn');
    const refreshBtn = document.getElementById('refreshBtn');
    const riskFilter = document.getElementById('riskFilter');
    const statusDiv = document.getElementById('status');
    const summaryDiv = document.getElementById('summary');
    const filtersDiv = document.getElementById('filters');
    const extensionsListDiv = document.getElementById('extensionsList');
    
    let allExtensions = [];
    
    // Permission risk definitions
    const HIGH_RISK_PERMS = [
        'debugger',
        'management',
        'system.memory',
        'system.storage',
        'system.cpu',
        'privacy',
        'enterprise',
        'nativeMessaging'
    ];
    
    const MEDIUM_RISK_PERMS = [
        'tabs',
        'cookies',
        'webRequest',
        'webRequestBlocking',
        'webRequestAuthProvider',
        'scripting',
        'contentSettings',
        'downloads',
        'bookmarks',
        'history',
        'topSites',
        'pageCapture',
        'proxy',
        'notifications',
        'clipboardWrite',
        'unlimitedStorage'
    ];
    
    const BROAD_HOST_PERMS = [
        '<all_urls>',
        '*://*/*',
        'http://*/*',
        'https://*/*'
    ];
    
    scanBtn.addEventListener('click', scanExtensions);
    refreshBtn.addEventListener('click', scanExtensions);
    riskFilter.addEventListener('change', filterExtensions);
    
    async function scanExtensions() {
        statusDiv.textContent = 'Scanning extensions...';
        statusDiv.className = 'status loading';
        scanBtn.disabled = true;
        
        try {
            // Stage 1: Retrieve all installed extensions
            const extensions = await chrome.management.getAll();
            
            // Filter out the analyzer itself and system apps
            allExtensions = extensions
                .filter(ext => ext.id !== chrome.runtime.id)
                .filter(ext => ext.type !== 'theme')
                .map(analyzeExtension);
            
            // Sort by risk level (high to low)
            allExtensions.sort((a, b) => {
                const riskOrder = { high: 3, medium: 2, low: 1 };
                return riskOrder[b.riskLevel] - riskOrder[a.riskLevel];
            });
            
            displaySummary(allExtensions);
            displayExtensions(allExtensions);
            
            statusDiv.textContent = `Found ${allExtensions.length} extensions`;
            statusDiv.className = 'status success';
            summaryDiv.style.display = 'block';
            filtersDiv.style.display = 'block';
        } catch (error) {
            statusDiv.textContent = 'Error scanning extensions: ' + error.message;
            statusDiv.className = 'status error';
            console.error('Scan error:', error);
        } finally {
            scanBtn.disabled = false;
        }
    }
    
    function analyzeExtension(extension) {
        const permissions = extension.permissions || [];
        const hostPermissions = extension.hostPermissions || [];
        const allPerms = [...permissions, ...hostPermissions];
        
        let riskScore = 0;
        let riskLevel = 'low';
        let riskFactors = [];
        
        // Analyze high risk permissions
        HIGH_RISK_PERMS.forEach(perm => {
            if (permissions.includes(perm)) {
                riskScore += 3;
                riskFactors.push(`High-risk permission: ${perm}`);
            }
        });
        
        // Analyze medium risk permissions
        MEDIUM_RISK_PERMS.forEach(perm => {
            if (permissions.includes(perm) && !HIGH_RISK_PERMS.includes(perm)) {
                riskScore += 2;
                riskFactors.push(`Medium-risk permission: ${perm}`);
            }
        });
        
        // Analyze broad host permissions
        BROAD_HOST_PERMS.forEach(perm => {
            if (hostPermissions.includes(perm) || permissions.includes(perm)) {
                riskScore += 2;
                riskFactors.push(`Broad host access: ${perm} (can access data on many sites)`);
            }
        });
        
        // Check for dangerous combinations
        if (permissions.includes('scripting') && 
            (hostPermissions.includes('<all_urls>') || hostPermissions.includes('*://*/*'))) {
            riskScore += 2;
            riskFactors.push('Dangerous combo: scripting + broad host access');
        }
        
        if (permissions.includes('webRequest') && 
            (hostPermissions.includes('<all_urls>') || hostPermissions.includes('*://*/*'))) {
            riskScore += 1;
            riskFactors.push('Observes network requests across sites');
        }
        
        if (permissions.includes('debugger')) {
            riskScore += 4;
            riskFactors.push('EXTREMELY HIGH RISK: debugger access to browser targets');
        }
        
        // Determine risk level
        if (riskScore >= 6) {
            riskLevel = 'high';
        } else if (riskScore >= 3) {
            riskLevel = 'medium';
        } else {
            riskLevel = 'low';
        }
        
        // Add general information
        if (riskFactors.length === 0) {
            riskFactors.push('No notable high-risk permissions detected');
        }
        
        return {
            ...extension,
            riskScore,
            riskLevel,
            riskFactors,
            allPermissions: allPerms
        };
    }
    
    function displaySummary(extensions) {
        const total = extensions.length;
        const highRisk = extensions.filter(e => e.riskLevel === 'high').length;
        const mediumRisk = extensions.filter(e => e.riskLevel === 'medium').length;
        const lowRisk = extensions.filter(e => e.riskLevel === 'low').length;
        
        document.getElementById('totalCount').textContent = total;
        document.getElementById('highRiskCount').textContent = highRisk;
        document.getElementById('mediumRiskCount').textContent = mediumRisk;
        document.getElementById('lowRiskCount').textContent = lowRisk;
    }
    
    function displayExtensions(extensions) {
        const filter = riskFilter.value;
        const filtered = filter === 'all' 
            ? extensions 
            : extensions.filter(e => e.riskLevel === filter);
        
        if (filtered.length === 0) {
            extensionsListDiv.innerHTML = `
                <div class="empty-state">
                    <p>No extensions match the selected filter</p>
                </div>
            `;
            return;
        }
        
        extensionsListDiv.innerHTML = filtered.map(ext => createExtensionCard(ext)).join('');
    }
    
    function createExtensionCard(extension) {
        const iconUrl = extension.icons && extension.icons.length > 0 
            ? extension.icons[extension.icons.length - 1].url 
            : 'icons/icon48.png';
        
        const enabledStatus = extension.enabled ? 'Enabled' : 'Disabled';
        const enabledClass = extension.enabled ? 'enabled' : 'disabled';
        
        let permissionsHtml = '';
        if (extension.permissions && extension.permissions.length > 0) {
            permissionsHtml += '<div class="perm-section"><strong>Permissions:</strong> ' + 
                extension.permissions.map(p => `<span class="perm-tag">${escapeHtml(p)}</span>`).join('') + 
                '</div>';
        }
        if (extension.hostPermissions && extension.hostPermissions.length > 0) {
            permissionsHtml += '<div class="perm-section"><strong>Host Permissions:</strong> ' + 
                extension.hostPermissions.map(p => `<span class="perm-tag host-perm">${escapeHtml(p)}</span>`).join('') + 
                '</div>';
        }
        
        let riskFactorsHtml = '<div class="risk-factors"><strong>Risk Analysis:</strong><ul>' + 
            extension.riskFactors.map(f => `<li>${escapeHtml(f)}</li>`).join('') + 
            '</ul></div>';
        
        return `
            <div class="extension-card ${extension.riskLevel}-border">
                <div class="extension-header">
                    <img src="${escapeHtml(iconUrl)}" alt="${escapeHtml(extension.name)}" class="extension-icon" onerror="this.src='icons/icon48.png'">
                    <div class="extension-info">
                        <h3 class="extension-name">${escapeHtml(extension.name)}</h3>
                        <div class="extension-meta">
                            <span class="risk-badge risk-${extension.riskLevel}">${extension.riskLevel.toUpperCase()} RISK</span>
                            <span class="meta-item">v${escapeHtml(extension.version)}</span>
                            <span class="meta-item ${enabledClass}">${enabledStatus}</span>
                            <span class="meta-item">ID: ${escapeHtml(extension.id)}</span>
                        </div>
                    </div>
                </div>
                ${extension.description ? `<div class="extension-desc">${escapeHtml(extension.description)}</div>` : ''}
                ${permissionsHtml}
                ${riskFactorsHtml}
                <div class="extension-details">
                    <small>Type: ${extension.type} | Install Type: ${extension.installType || 'unknown'}</small>
                </div>
            </div>
        `;
    }
    
    function filterExtensions() {
        displayExtensions(allExtensions);
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
});
