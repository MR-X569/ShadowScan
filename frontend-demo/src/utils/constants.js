export const FEATURES = [
  {
    id: 'website-scan',
    icon: 'scan',
    title: 'Website Scan',
    description: 'Deep crawl your entire web application. Discover hidden endpoints, subdomains, and attack surfaces automatically.',
    color: '#00DCE5',
    tag: 'CORE',
  },
  {
    id: 'owasp-detection',
    icon: 'shield-alert',
    title: 'OWASP Detection',
    description: 'Detect all OWASP Top 10 vulnerabilities including SQL Injection, XSS, CSRF, IDOR, and more — with precise location data.',
    color: '#B600F8',
    tag: 'SECURITY',
  },
  {
    id: 'tech-detection',
    icon: 'cpu',
    title: 'Technology Detection',
    description: 'Fingerprint your entire stack — frameworks, CMS, libraries, server software — and flag outdated or vulnerable components.',
    color: '#00DCE5',
    tag: 'INTELLIGENCE',
  },
  {
    id: 'security-score',
    icon: 'gauge',
    title: 'Security Score',
    description: 'Get an AI-computed security score from 0–100. Understand your risk posture at a glance with actionable breakdown.',
    color: '#00F5FF',
    tag: 'AI',
  },
  {
    id: 'pdf-reports',
    icon: 'file-text',
    title: 'Download Reports',
    description: 'Export professional-grade PDF reports with executive summaries, technical details, and remediation guidance.',
    color: '#B600F8',
    tag: 'EXPORT',
  },
  {
    id: 'scan-history',
    icon: 'history',
    title: 'Scan History',
    description: 'Track your security posture over time. Compare scans, monitor fixed vulnerabilities, and prove compliance.',
    color: '#00DCE5',
    tag: 'ANALYTICS',
  },
]

export const HOW_IT_WORKS_STEPS = [
  {
    step: '01',
    title: 'Submit URL',
    description: 'Enter the target website URL into ShadowScan\'s command interface.',
    icon: 'link',
    log: '[INIT] Target acquired: {url}',
  },
  {
    step: '02',
    title: 'Web Crawler',
    description: 'Our AI crawler maps every page, endpoint, form, and parameter.',
    icon: 'globe',
    log: '[CRAWL] Discovered 247 endpoints, 83 forms, 1,204 parameters',
  },
  {
    step: '03',
    title: 'Fingerprint Engine',
    description: 'Technology stack detected — frameworks, libraries, CMS, server software.',
    icon: 'fingerprint',
    log: '[FINGERPRINT] React 18.2 | Node 20.x | Nginx 1.24 | PostgreSQL 15',
  },
  {
    step: '04',
    title: 'Scanner Engine',
    description: 'Multi-vector attack simulation across all OWASP Top 10 categories.',
    icon: 'zap',
    log: '[SCAN] Testing 3,847 payloads across 247 endpoints...',
  },
  {
    step: '05',
    title: 'Analysis Engine',
    description: 'AI correlates findings, eliminates false positives, assigns severity.',
    icon: 'brain',
    log: '[ANALYSIS] 23 confirmed vulnerabilities | 4 Critical | 7 High',
  },
  {
    step: '06',
    title: 'Risk Calculator',
    description: 'CVSS-based risk scoring combined with business impact assessment.',
    icon: 'calculator',
    log: '[RISK] Security Score: 34/100 | Risk Level: CRITICAL',
  },
  {
    step: '07',
    title: 'PDF Report',
    description: 'Professional report generated with executive summary and remediation.',
    icon: 'file-text',
    log: '[REPORT] Generated: shadowscan-report-2024-01-15.pdf (2.4 MB)',
  },
]

export const TESTIMONIALS = [
  {
    name: 'Alex Chen',
    role: 'CISO @ TechCorp',
    avatar: 'AC',
    color: '#00DCE5',
    quote: 'ShadowScan found 12 critical vulnerabilities in our production environment that our internal team missed. The AI analysis is next level.',
    rating: 5,
  },
  {
    name: 'Sarah Mitchell',
    role: 'Security Engineer @ FinanceHub',
    avatar: 'SM',
    color: '#B600F8',
    quote: 'The OWASP detection accuracy is unreal. 99% precision means no alert fatigue — only real threats that need attention.',
    rating: 5,
  },
  {
    name: 'Marcus Rodriguez',
    role: 'Lead Developer @ StartupX',
    avatar: 'MR',
    color: '#00F5FF',
    quote: 'We run ShadowScan before every production deployment. It\'s become an essential part of our CI/CD pipeline. Absolute game-changer.',
    rating: 5,
  },
  {
    name: 'Priya Sharma',
    role: 'Founder @ SecureBase',
    avatar: 'PS',
    color: '#00DCE5',
    quote: 'The PDF reports are boardroom-ready. My clients are impressed and our security practice has grown 3x since using ShadowScan.',
    rating: 5,
  },
  {
    name: 'James Wilson',
    role: 'Penetration Tester',
    avatar: 'JW',
    color: '#B600F8',
    quote: 'As a professional pentester, I was skeptical of AI scanners. ShadowScan changed my mind completely. It\'s faster than I am.',
    rating: 5,
  },
  {
    name: 'Emma Thompson',
    role: 'CTO @ CloudScale',
    avatar: 'ET',
    color: '#00F5FF',
    quote: 'Replaced 3 separate security tools with ShadowScan. The unified dashboard alone saves us hours every week.',
    rating: 5,
  },
]

export const FAQS = [
  {
    q: 'How accurate is ShadowScan\'s vulnerability detection?',
    a: 'ShadowScan achieves 99% precision with less than 1% false positive rate. Our AI engine is trained on millions of real-world vulnerabilities and continuously updated with the latest CVE database.',
  },
  {
    q: 'How long does a full website scan take?',
    a: 'Most websites complete a full scan in under 2 minutes. Complex applications with thousands of endpoints may take up to 10 minutes. You\'ll receive real-time progress updates throughout.',
  },
  {
    q: 'Which OWASP Top 10 vulnerabilities does ShadowScan detect?',
    a: 'ShadowScan detects all OWASP Top 10 categories: Broken Access Control, Cryptographic Failures, Injection (SQL, XSS, SSTI, etc.), Insecure Design, Security Misconfiguration, Vulnerable Components, Authentication Failures, SSRF, and more.',
  },
  {
    q: 'Is ShadowScan legal to use on any website?',
    a: 'ShadowScan is designed for authorized security testing only. You must own the website or have explicit written permission from the owner. Unauthorized scanning is illegal and against our Terms of Service.',
  },
  {
    q: 'Can I integrate ShadowScan into my CI/CD pipeline?',
    a: 'Yes. ShadowScan provides a REST API and native integrations for GitHub Actions, GitLab CI, Jenkins, and more. Block deployments automatically when critical vulnerabilities are found.',
  },
  {
    q: 'What format are the security reports in?',
    a: 'Reports are generated as professional PDF documents with an executive summary, detailed technical findings, CVSS scores, evidence screenshots, and step-by-step remediation guidance.',
  },
]

export const FAKE_VULNERABILITIES = [
  { severity: 'CRITICAL', name: 'SQL Injection', location: '/api/search?q=', cve: 'CWE-89', score: 9.8 },
  { severity: 'HIGH', name: 'Cross-Site Scripting (XSS)', location: '/comments/new', cve: 'CWE-79', score: 7.4 },
  { severity: 'HIGH', name: 'Broken Authentication', location: '/api/auth/login', cve: 'CWE-287', score: 8.1 },
  { severity: 'MEDIUM', name: 'Outdated jQuery 1.8.3', location: '/assets/jquery.min.js', cve: 'CVE-2019-11358', score: 6.1 },
  { severity: 'MEDIUM', name: 'Missing CSRF Protection', location: '/account/settings', cve: 'CWE-352', score: 5.9 },
  { severity: 'LOW', name: 'Information Disclosure', location: '/server-status', cve: 'CWE-200', score: 3.1 },
]

export const SCAN_PHASES = [
  { label: 'Initializing crawler...', duration: 800 },
  { label: 'Mapping endpoints...', duration: 1200 },
  { label: 'Fingerprinting technology stack...', duration: 1000 },
  { label: 'Running OWASP test suite...', duration: 2000 },
  { label: 'Testing injection payloads...', duration: 1800 },
  { label: 'Analyzing authentication flows...', duration: 1200 },
  { label: 'Calculating risk scores...', duration: 800 },
  { label: 'Generating report...', duration: 600 },
]

export const STATS = [
  { value: 10000, suffix: '+', label: 'Websites Scanned', prefix: '' },
  { value: 200, suffix: '+', label: 'CVE Detections', prefix: '' },
  { value: 99, suffix: '%', label: 'Detection Accuracy', prefix: '' },
  { value: 2, suffix: 'min', label: 'Avg Scan Time', prefix: '<' },
]

export const NAV_LINKS = [
  { label: 'Features', href: '#features' },
  { label: 'How It Works', href: '#how-it-works' },
  { label: 'Demo', href: '#demo' },
  { label: 'Dashboard', href: '#dashboard' },
  { label: 'FAQ', href: '#faq' },
]
