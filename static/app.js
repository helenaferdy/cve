document.addEventListener('alpine:init', () => {
    Alpine.data('cveApp', () => ({
        allCVEs: [],
        filteredCVEs: [],
        syncStatus: {
            last_sync: 'Loading...',
            next_sync_in: 'Loading...'
        },
        sortBy: 'latest',
        relativeSyncText: 'Loading...',

        // Individual vendor open/closed flags
        vOpenFortinet: false,
        vOpenCheckpoint: false,
        vOpenPaloalto: false,
        vOpenCisco: false,
        // Product collapse: array of collapsed product keys
        collapsedProducts: [],

        // Selected products (all selected by default)
        selectedProducts: [],

        // Vendor → Product hierarchy (releases info kept for CVE card display only)
        vendors: [
            {
                id: 'fortinet',
                name: 'Fortinet',
                products: [
                    { name: 'FortiOS', key: 'fortios', releases: ['FortiOS 7.6', 'FortiOS 7.4', 'FortiOS 7.2', 'FortiOS 7.0'] },
                    { name: 'FortiManager', key: 'fortimanager', releases: ['FortiManager 7.6', 'FortiManager 7.4', 'FortiManager 7.2', 'FortiManager 7.0'] },
                    { name: 'FortiAnalyzer', key: 'fortianalyzer', releases: ['FortiAnalyzer 7.6', 'FortiAnalyzer 7.4', 'FortiAnalyzer 7.2', 'FortiAnalyzer 7.0'] },
                    { name: 'FortiProxy', key: 'fortiproxy', releases: ['FortiProxy 7.6', 'FortiProxy 7.4', 'FortiProxy 7.2', 'FortiProxy 7.0'] },
                    { name: 'FortiWeb', key: 'fortiweb', releases: ['FortiWeb 7.6', 'FortiWeb 7.4', 'FortiWeb 7.2'] },
                    { name: 'FortiClientEMS', key: 'forticlientems', releases: ['FortiClientEMS 7.4', 'FortiClientEMS 7.2'] },
                    { name: 'FortiAuthenticator', key: 'fortiauthenticator', releases: ['FortiAuthenticator 8.0'] },
                    { name: 'FortiSwitch', key: 'fortiswitch', releases: ['FortiSwitch 7.6', 'FortiSwitch 7.4', 'FortiSwitch 7.2'] },
                    { name: 'FortiAP', key: 'fortiap', releases: ['FortiAP 7.6', 'FortiAP 7.4', 'FortiAP 7.2'] },
                    { name: 'FortiNDR', key: 'fortindr', releases: ['FortiNDR 7.4', 'FortiNDR 7.2'] },
                    { name: 'FortiMail', key: 'fortimail', releases: ['FortiMail 7.6', 'FortiMail 7.4'] },
                    { name: 'FortiVoice', key: 'fortivoice', releases: ['FortiVoice 7.2', 'FortiVoice 7.0'] },
                    { name: 'FortiSOAR', key: 'fortisoar', releases: ['FortiSOAR 7.6', 'FortiSOAR 7.4'] },
                ]
            },
            {
                id: 'checkpoint',
                name: 'Check Point',
                products: [
                    { name: 'Gaia OS', key: 'gaia', releases: ['Gaia OS R82.10', 'Gaia OS R82', 'Gaia OS R81.20', 'Gaia OS R81.10', 'Gaia OS R81', 'Gaia OS R80.40', 'Gaia OS R80.30', 'Gaia OS R80.20', 'Gaia OS R80.10', 'Gaia OS R80'] },
                ]
            },
            {
                id: 'paloalto',
                name: 'Palo Alto Networks',
                products: [
                    { name: 'PAN-OS', key: 'pan-os', releases: ['PAN-OS 12.1', 'PAN-OS 11.2', 'PAN-OS 11.1', 'PAN-OS 11.0', 'PAN-OS 10.2', 'PAN-OS 10.1', 'PAN-OS 10.0', 'PAN-OS 9.1', 'PAN-OS 9.0', 'PAN-OS 8.1'] },
                    { name: 'GlobalProtect App', key: 'globalprotect', releases: ['GlobalProtect App 6.3', 'GlobalProtect App 6.2'] },
                ]
            },
            {
                id: 'cisco',
                name: 'Cisco',
                products: [
                    { name: 'FTD', key: 'ftd', releases: ['FTD 10.x', 'FTD 7.7', 'FTD 7.6', 'FTD 7.4', 'FTD 7.3', 'FTD 7.2', 'FTD 7.1', 'FTD 7.0', 'FTD 6.7', 'FTD 6.6'] },
                    { name: 'ASA', key: 'asa', releases: ['ASA 9.20', 'ASA 9.18', 'ASA 9.16'] },
                    { name: 'ISE', key: 'ise', releases: ['ISE 3.4', 'ISE 3.3'] },
                ]
            }
        ],

        searchQuery: '',
        selectedCVE: null,
        selectedCVEValidation: null,
        isLoading: true,
        isSyncing: false,
        cveCountsByVendor: {},
        productCounts: {},

        // Impacted releases display limit
        releasesLimit: 5,
        expandedCards: [],

        init() {
            // Build the default selectedProducts list (all products)
            this.selectedProducts = [];
            this.vendors.forEach(v => {
                v.products.forEach(p => {
                    this.selectedProducts.push(p.key);
                });
            });

            this.fetchInitialCounts();
            this.fetchSyncStatus();

            this.$watch('selectedProducts', () => this.fetchFilteredCVEs());
            this.$watch('searchQuery', () => this.fetchFilteredCVEs());
            this.$watch('sortBy', () => this.sortCVEs());
            this.$watch('selectedCVE', async (cve) => {
                if (cve) {
                    this.selectedCVEValidation = null;
                    try {
                        const response = await fetch(`/api/cves/${cve.cve_id}/validation`);
                        if (response.ok) {
                            this.selectedCVEValidation = await response.json();
                        }
                    } catch (err) {
                        console.error("Failed to fetch validation log:", err);
                    }
                } else {
                    this.selectedCVEValidation = null;
                }
            });

            setInterval(() => this.fetchSyncStatus(), 30000);
            setInterval(() => {
                this.relativeSyncText = this.getRelativeSyncTime();
            }, 10000);
        },

        // --- Collapse/expand ---

        toggleVendor(id) {
            if (id === 'fortinet') this.vOpenFortinet = !this.vOpenFortinet;
            else if (id === 'checkpoint') this.vOpenCheckpoint = !this.vOpenCheckpoint;
            else if (id === 'paloalto') this.vOpenPaloalto = !this.vOpenPaloalto;
            else if (id === 'cisco') this.vOpenCisco = !this.vOpenCisco;
        },

        isOpen(id) {
            if (id === 'fortinet') return this.vOpenFortinet;
            if (id === 'checkpoint') return this.vOpenCheckpoint;
            if (id === 'paloalto') return this.vOpenPaloalto;
            if (id === 'cisco') return this.vOpenCisco;
            return false;
        },

        isProductCollapsed(vendorId, productName) {
            return this.collapsedProducts.includes(vendorId + '_' + productName);
        },

        toggleProductCollapse(vendorId, productName) {
            const key = vendorId + '_' + productName;
            if (this.collapsedProducts.includes(key)) {
                this.collapsedProducts = this.collapsedProducts.filter(k => k !== key);
            } else {
                this.collapsedProducts = [...this.collapsedProducts, key];
            }
        },

        // --- Product filter selection ---

        isProductSelected(key) {
            return this.selectedProducts.includes(key);
        },

        toggleProduct(key) {
            if (this.selectedProducts.includes(key)) {
                this.selectedProducts = this.selectedProducts.filter(k => k !== key);
            } else {
                this.selectedProducts = [...this.selectedProducts, key];
            }
        },

        isVendorSelected(vendor) {
            return vendor.products.every(p => this.selectedProducts.includes(p.key));
        },

        isVendorIndeterminate(vendor) {
            const sel = vendor.products.filter(p => this.selectedProducts.includes(p.key)).length;
            return sel > 0 && sel < vendor.products.length;
        },

        toggleVendorProducts(vendor) {
            if (this.isVendorSelected(vendor)) {
                vendor.products.forEach(p => {
                    this.selectedProducts = this.selectedProducts.filter(k => k !== p.key);
                });
            } else {
                vendor.products.forEach(p => {
                    if (!this.selectedProducts.includes(p.key)) {
                        this.selectedProducts = [...this.selectedProducts, p.key];
                    }
                });
            }
        },

        selectAllProducts() {
            const all = [];
            this.vendors.forEach(v => {
                v.products.forEach(p => {
                    if (!all.includes(p.key)) all.push(p.key);
                });
            });
            this.selectedProducts = all;
        },

        deselectAllProducts() {
            this.selectedProducts = [];
        },

        // --- Data fetching ---

        async fetchInitialCounts() {
            try {
                const response = await fetch('/api/cves');
                if (response.ok) {
                    this.allCVEs = await response.json();
                    this.calculateCounts();
                    this.fetchFilteredCVEs();
                }
            } catch (err) {
                console.error("Failed to load baseline counts:", err);
                this.isLoading = false;
            }
        },

        calculateCounts() {
            const counts = {};
            const prods = {};
            this.vendors.forEach(v => {
                counts[v.id] = this.allCVEs.filter(c => c.vendor === v.id).length;
                v.products.forEach(p => {
                    prods[p.key] = this.allCVEs.filter(c => c.vendor === v.id && c.product === p.key).length;
                });
            });
            this.cveCountsByVendor = counts;
            this.productCounts = prods;
        },

        async fetchSyncStatus() {
            try {
                const response = await fetch('/api/status');
                if (response.ok) {
                    this.syncStatus = await response.json();
                    this.relativeSyncText = this.getRelativeSyncTime();
                }
            } catch (err) {
                console.error("Failed to fetch sync status:", err);
            }
        },

        getRelativeSyncTime() {
            if (!this.syncStatus || !this.syncStatus.last_sync || this.syncStatus.last_sync === 'Loading...' || this.syncStatus.last_sync === 'Never') {
                return this.syncStatus.last_sync || 'Loading...';
            }
            try {
                const timeStr = this.syncStatus.last_sync;
                const parts = timeStr.replace(" UTC", "").split(/[- :]/);
                if (parts.length < 5) return timeStr;
                const utcDate = new Date(Date.UTC(
                    parseInt(parts[0]), parseInt(parts[1]) - 1, parseInt(parts[2]),
                    parseInt(parts[3]), parseInt(parts[4]), parts[5] ? parseInt(parts[5]) : 0
                ));
                const now = new Date();
                const diffMs = now.getTime() - utcDate.getTime();
                const diffMins = Math.floor(diffMs / 60000);
                if (diffMins < 0) return "last updated just now";
                const hours = Math.floor(diffMins / 60);
                const mins = diffMins % 60;
                if (hours === 0) return `last updated ${mins} mins ago`;
                return `last updated ${hours} hours ${mins} mins ago`;
            } catch (e) {
                console.error("Error parsing sync time:", e);
                return this.syncStatus.last_sync;
            }
        },

        async fetchFilteredCVEs() {
            if (!this.selectedProducts || this.selectedProducts.length === 0) {
                this.filteredCVEs = [];
                this.isLoading = false;
                return;
            }
            this.isLoading = true;
            try {
                const params = new URLSearchParams();

                // Determine active vendors from selected products
                const activeVendors = [];
                this.vendors.forEach(v => {
                    const hasSel = v.products.some(p => this.selectedProducts.includes(p.key));
                    if (hasSel) activeVendors.push(v.id);
                });

                // Only vendor-filter if not all vendors are active
                if (activeVendors.length > 0 && activeVendors.length < this.vendors.length) {
                    activeVendors.forEach(v => params.append('vendor', v));
                }

                // Product filter: only if not all products are selected
                const allKeys = []; this.vendors.forEach(v => v.products.forEach(p => allKeys.push(p.key)));
                const allSelected = allKeys.every(k => this.selectedProducts.includes(k));
                if (!allSelected && this.selectedProducts.length > 0) {
                    this.selectedProducts.forEach(k => params.append('product', k));
                }

                if (this.searchQuery.trim()) {
                    params.append('search', this.searchQuery.trim());
                }

                const response = await fetch(`/api/cves?${params.toString()}`);
                if (response.ok) {
                    this.filteredCVEs = await response.json();
                    this.sortCVEs();
                }
            } catch (err) {
                console.error("Failed to fetch filtered CVE list:", err);
            } finally {
                this.isLoading = false;
            }
        },

        sortCVEs() {
            if (!this.filteredCVEs || this.filteredCVEs.length === 0) return;
            let sorted = [...this.filteredCVEs];
            if (this.sortBy === 'latest') {
                sorted.sort((a, b) => {
                    const dateA = a.publish_date ? new Date(a.publish_date).getTime() : 0;
                    const dateB = b.publish_date ? new Date(b.publish_date).getTime() : 0;
                    return dateB - dateA;
                });
            } else if (this.sortBy === 'cvss') {
                sorted.sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0));
            } else if (this.sortBy === 'epss') {
                sorted.sort((a, b) => (b.epss_score || 0) - (a.epss_score || 0));
            }
            this.filteredCVEs = sorted;
        },

        // --- Impacted releases expand/collapse ---

        isExpanded(cve) {
            return this.expandedCards.includes(cve.cve_id);
        },

        toggleReleases(cve) {
            const idx = this.expandedCards.indexOf(cve.cve_id);
            if (idx === -1) {
                this.expandedCards.push(cve.cve_id);
            } else {
                this.expandedCards.splice(idx, 1);
            }
        },

        // --- Display helpers ---

        conditionMap: {
            pre_auth_exploit: 'Pre-Authentication Exploit',
            post_auth_required: 'Post-Authentication Required',
            mgmt_interface_exposed: 'Management exposed',
            api_enabled: 'API / Automation Enabled',
            telemetry_active: 'Telemetry & Analytics Active',
            ssl_vpn_enabled: 'SSL VPN Enabled',
            captive_portal_active: 'Captive Portal Active',
            ike_v2_processing: 'IKEv2 VPN Active',
            saml_sso_configured: 'SAML SSO Configured',
            ssl_decryption_active: 'SSL/TLS Decryption Active',
            ips_enabled: 'IPS / Threat Prevention Enabled',
            file_inspection_active: 'File Inspection / Sandboxing',
            dynamic_routing_active: 'Dynamic Routing Active (BGP/OSPF)',
            ha_clustering_enabled: 'HA Clustering Enabled'
        },

        getSeverityClass(severity) {
            switch (severity.toLowerCase()) {
                case 'critical':
                    return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
                case 'high':
                    return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
                case 'medium':
                    return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
                default:
                    return 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30';
            }
        },

        getCVSSColor(score) {
            if (score >= 9.0) return 'text-rose-500';
            if (score >= 7.0) return 'text-amber-500';
            if (score >= 4.0) return 'text-blue-400';
            return 'text-zinc-500';
        },

        getEPSSColor(score) {
            if (score >= 0.50) return 'text-rose-500 font-extrabold';
            if (score >= 0.10) return 'text-amber-500 font-bold';
            return 'text-emerald-400 font-semibold';
        },

        getEPSSBgColor(score) {
            if (score >= 0.50) return 'bg-rose-500';
            if (score >= 0.10) return 'bg-amber-500';
            return 'bg-emerald-500';
        },

        formatDate(dateStr) {
            if (!dateStr) return '';
            try {
                const date = new Date(dateStr);
                return date.toISOString().slice(0, 10);
            } catch (e) {
                return dateStr;
            }
        },

        renderMarkdown(text) {
            if (!text) return '';
            let escaped = text
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
            const codeBlocks = [];
            escaped = escaped.replace(/```(cli|bash|json)?\n([\s\S]*?)\n```/g, (match, lang, code) => {
                const placeholder = `__CODE_BLOCK_PLACEHOLDER_${codeBlocks.length}__`;
                codeBlocks.push(`<div class="bg-zinc-950 border border-zinc-800 rounded-xl p-4 font-mono text-[11px] text-zinc-300 overflow-x-auto my-3"><span class="text-[10px] text-zinc-600 block uppercase font-bold tracking-wider mb-2">${lang || 'code'}</span>${code}</div>`);
                return placeholder;
            });
            escaped = escaped.replace(/`([^`]+)`/g, '<code class="bg-zinc-900 text-amber-500 font-mono px-1.5 py-0.5 rounded text-[11px] border border-zinc-800">$1</code>');
            escaped = escaped.replace(/\*\*([^*]+)\*\*/g, '<strong class="text-white font-semibold">$1</strong>');
            escaped = escaped.replace(/^###\s+(.+)$/gm, '<h3 class="text-xs font-bold text-white uppercase tracking-wider mt-4 mb-2">$1</h3>');
            escaped = escaped.replace(/^\s*(?:\d+\.|\-)\s+(.+)$/gm, '<div class="flex items-start space-x-2 my-2"><span class="text-amber-500 font-bold shrink-0 text-xs">•</span><span class="text-zinc-400 font-normal leading-relaxed">$1</span></div>');
            escaped = escaped.split('\n').map(line => {
                const trimmed = line.trim();
                if (!trimmed) return '';
                if (trimmed.startsWith('<h3') || trimmed.startsWith('<div') || trimmed.startsWith('__CODE_')) {
                    return line;
                }
                return `<p class="my-2 text-zinc-400 font-normal leading-relaxed text-xs">${line}</p>`;
            }).join('');
            codeBlocks.forEach((html, index) => {
                escaped = escaped.replace(`__CODE_BLOCK_PLACEHOLDER_${index}__`, html);
            });
            return escaped;
        }
    }));
});
