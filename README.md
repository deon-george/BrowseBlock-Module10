# Extension Abuse Analyzer

A Chrome Extension that analyzes installed Chrome extensions for permission risks and potential abuse vectors. This tool leverages the `chrome.management` API to discover installed extensions and performs risk assessment based on requested permissions.

## Overview

This extension provides:
- **Stage 1:** Discovery and enumeration of all installed Chrome extensions (excluding themes and self)
- **Stage 2:** Permission analysis and risk classification based on dangerous permission patterns

## Features

### Permission Risk Analysis

The analyzer evaluates extensions against known high-risk permissions and capability patterns:

| Permission/Capability | Why it deserves review | Risk Level |
|------------------------|------------------------|------------|
| `tabs` | Can expose information about browser tabs and their URLs | Medium |
| `cookies` | Can access cookies for permitted domains | Medium |
| `webRequest` | Can observe certain network-request information, subject to API restrictions | Medium |
| `scripting` | Can inject scripts into permitted pages | Medium |
| `debugger` | Grants powerful debugging access to browser targets | Very High |
| Broad host permissions (`<all_urls>`, `*://*/*`, etc.) | May allow access to data on many websites | Medium |
| Scripting + Broad host access | Dangerous combination enabling script injection across sites | High |

### Additional Risk Factors Detected

- High-risk permissions: `debugger`, `management`, `system.memory`, `system.storage`, `system.cpu`, `privacy`, `enterprise`, `nativeMessaging`
- Dangerous combinations (scripting with broad host access, webRequest with broad host access)
- Extensions requesting debugger access are flagged as extremely high risk

### User Interface

- Clean, intuitive popup interface
- Risk summary dashboard (High/Medium/Low risk counts)
- Filter by risk level
- Detailed extension cards showing:
  - Extension name, version, ID, type
  - Description
  - Permissions and host permissions (color-coded)
  - Risk analysis breakdown
  - Enabled/Disabled status
  - Install type

## Installation (Development)

1. Clone or download this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" (toggle in top right)
4. Click "Load unpacked"
5. Select the directory containing this extension
6. The Extension Abuse Analyzer icon will appear in your browser toolbar

## Usage

1. Click the Extension Abuse Analyzer icon in the toolbar
2. Click "Scan Installed Extensions" to discover and analyze all installed extensions
3. Review the summary dashboard for overall risk distribution
4. Use the risk filter to focus on high-risk extensions
5. Examine individual extension cards for detailed permission breakdown and risk factors

## Files

- `manifest.json` - Extension manifest (Manifest V3)
- `popup.html` - Main UI
- `popup.js` - Core logic for scanning and analysis
- `styles.css` - Styling
- `background.js` - Service worker
- `icons/` - Extension icons (placeholder files)
- `README.md` - Documentation
- `requirements.txt` - Dependencies (none, uses Chrome APIs)
- `.gitignore` - Git ignore rules

## Important Notes

- This extension requires the `management` permission to read installed extension metadata
- It excludes itself from analysis to avoid self-reporting
- Themes are excluded from analysis as they don't pose the same permission risks
- Analysis is performed locally in the browser - no data is transmitted externally
- Results depend on what Chrome's management API exposes and may be subject to browser restrictions

## Limitations

- Cannot analyze extensions that are force-installed by policy in some enterprise environments
- Cannot detect runtime behavior, only static permission declarations
- Some extensions may have permissions that are context-dependent
- The `management` API permission means this extension itself has elevated access (necessary for its function)

## Security Considerations

This is a security analysis tool. Be cautious when installing and using it. The tool itself requests the `management` permission - only use versions from trusted sources.

## License

Open source - feel free to modify and distribute.
