#!/usr/bin/env python3
"""
Apache Analyzer & Monitoring - Live & Offline Mode
Fully asynchronous architecture with background workers, responsive layout,
and support for live real-time monitoring and files (-r/--read) or pipe (|) input.

Author: Petr Palacky
AI Collaboration: DeepSeek, Gemini
Date: 2026
Version: 0.1

Project page: https://github.com/p3t3r50n-cz/apache-server-status-analyzer-monitoring
"""

import requests
import re
from bs4 import BeautifulSoup
from collections import defaultdict
import psutil
import time
import sys
import os
import signal
from datetime import datetime
import socket
import threading
import queue
import tty
import termios

# Disable warnings for unverified HTTPS certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    HEADER = '\033[95;40m'
    BLUE = '\033[94;40m'
    CYAN = '\033[96;40m'
    GREEN = '\033[92;40m'
    YELLOW = '\033[93;40m'
    RED = '\033[91;40m'
    MAGENTA = '\033[35;40m'
    BOLD = '\033[1;40m'
    DIM = '\033[2;40m'
    RESET = '\033[0m'
    
    GOTO_TOP = '\033[H'
    CLEAR_LINE = '\033[0m\033[K'
    CURSOR_HIDE = '\033[?25l'
    CURSOR_SHOW = '\033[?25h'
    
    SOFT_RESET = '\033[!p\033[2J\033[H'
    
    CPU_LOW = '\033[38;5;82;40m'
    CPU_MED = '\033[38;5;226;40m'
    CPU_HIGH = '\033[38;5;208;40m'
    CPU_CRIT = '\033[38;5;196;40m'
    
    MEM_LOW = '\033[38;5;82;40m'
    MEM_MED = '\033[38;5;226;40m'
    MEM_HIGH = '\033[38;5;208;40m'
    MEM_CRIT = '\033[38;5;196;40m'
    
    GRAPH_BG = '\033[38;5;236;40m'
    TAB_ACTIVE = '\033[1;30;106m'

class ApacheAnalyzerPro:
    def __init__(self, hosts=["localhost"], port=80, ssl=False, status_path="/server-status", refresh_interval=3, offline_html=None):
        self.hosts = hosts
        self.current_host_idx = 0
        self.port = port
        self.ssl = ssl
        self.status_path = status_path
        self.refresh_interval = refresh_interval
        
        # Offline mode detection
        self.offline_mode = offline_html is not None
        self.offline_html = offline_html
        
        self.running = True
        self.terminal_width = 120
        self.terminal_height = 30
        
        self.hosts_data = {h: None for h in self.hosts}
        
        self.dns_cache = {}
        self.dns_queue = queue.Queue()
        
        self.orig_settings = None
        self.input_thread = threading.Thread(target=self._keyboard_listener, daemon=True)
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGWINCH, self.handle_resize)
        
        self.update_terminal_size()
        
        if not self.offline_mode:
            self.resolver_thread = threading.Thread(target=self._dns_resolver_worker, daemon=True)
            self.resolver_thread.start()
    
    def _dns_resolver_worker(self):
        while self.running:
            try:
                ip = self.dns_queue.get(timeout=1)
                if ip not in self.dns_cache or self.dns_cache[ip] == "[resolving...]":
                    try:
                        hostname, _, _ = socket.gethostbyaddr(ip)
                        self.dns_cache[ip] = hostname
                    except Exception:
                        self.dns_cache[ip] = "[no hostname]"
                self.dns_queue.task_done()
            except queue.Empty:
                continue
            except Exception:
                continue

    def get_hostname(self, ip):
        if self.offline_mode:
            return "[offline]"
        if ip not in self.dns_cache:
            self.dns_cache[ip] = "[resolving...]"
            self.dns_queue.put(ip)
        return self.dns_cache[ip]
    
    def _keyboard_listener(self):
        try:
            self.orig_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
            while self.running:
                ch = sys.stdin.read(1)
                if ch == '\x1b':  
                    ch2 = sys.stdin.read(1)
                    if ch2 == '[':
                        ch3 = sys.stdin.read(1)
                        if ch3 == 'D' and not self.offline_mode:  
                            self.current_host_idx = (self.current_host_idx - 1) % len(self.hosts)
                        elif ch3 == 'C' and not self.offline_mode:  
                            self.current_host_idx = (self.current_host_idx + 1) % len(self.hosts)
                elif ch in ['q', 'Q']:
                    self.running = False
                    break
                elif ch.isdigit() and not self.offline_mode:
                    idx = int(ch) - 1
                    if 0 <= idx < len(self.hosts):
                        self.current_host_idx = idx
        except Exception:
            pass

    def update_terminal_size(self):
        try:
            size = os.get_terminal_size()
            self.terminal_width = max(110, size.columns)
            self.terminal_height = size.lines
        except:
            self.terminal_width = 120
            self.terminal_height = 30
    
    def handle_resize(self, sig, frame):
        self.update_terminal_size()
    
    def signal_handler(self, sig, frame):
        self.running = False
        self.cleanup_terminal()
        sys.exit(0)
        
    def cleanup_terminal(self):
        if self.orig_settings:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.orig_settings)
            except:
                pass
        sys.stdout.write('\033[?1049l')
        sys.stdout.write(Colors.RESET + Colors.SOFT_RESET + Colors.CURSOR_SHOW + "\n")
        sys.stdout.flush()

    def strip_ansi(self, text):
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def pad_line(self, text, width):
        visible_len = len(self.strip_ansi(text))
        padding = max(0, width - visible_len)
        return text + (" " * padding)
    
    def get_cpu_color(self, cpu_percent):
        if cpu_percent < 10: return Colors.CPU_LOW
        elif cpu_percent < 30: return Colors.CPU_MED
        elif cpu_percent < 60: return Colors.CPU_HIGH
        else: return Colors.CPU_CRIT
    
    def get_mem_color(self, mem_percent):
        if mem_percent < 5: return Colors.MEM_LOW
        elif mem_percent < 15: return Colors.MEM_MED
        elif mem_percent < 30: return Colors.MEM_HIGH
        else: return Colors.MEM_CRIT
    
    def format_bar(self, percent, width=12, color_func=None):
        filled = int(width * min(percent, 100) / 100)
        empty = width - filled
        color = color_func(percent) if color_func else (Colors.CPU_LOW if percent < 30 else Colors.CPU_MED)
        
        filled_part = color + "█" * filled + Colors.RESET
        empty_part = Colors.GRAPH_BG + "█" * empty + Colors.RESET
        return filled_part + empty_part
    
    def parse_html_content(self, html_text):
        try:
            sys_procs = {}
            if not self.offline_mode:
                for p in psutil.process_iter(['pid', 'memory_percent']):
                    try:
                        sys_procs[p.info['pid']] = p.info['memory_percent'] or 0
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

            soup = BeautifulSoup(html_text, 'html.parser')
            processes = []
            domains_stats = defaultdict(lambda: {
                'cpu': 0, 'mem': 0, 'count': 0, 'urls': defaultdict(int),
                'ips': defaultdict(int), 'modes': defaultdict(int), 'total_dur': 0,
                'max_cpu_pid': '-', 'max_cpu_val': -1
            })
            
            ip_stats = defaultdict(int)
            subnet_16_stats = defaultdict(int)
            subnet_8_stats = defaultdict(int)
            
            rows = soup.find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                if len(cells) < 15:
                    continue
                
                pid_text = cells[1].get_text(strip=True)
                if not pid_text.isdigit():
                    continue
                
                pid = int(pid_text)
                mode = cells[3].get_text(strip=True)
                if mode not in ['R', 'W', 'K', 'C']:
                    continue
                
                cpu_text = cells[4].get_text(strip=True)
                dur_text = cells[7].get_text(strip=True) if len(cells) > 7 else "0"
                try:
                    cpu = float(cpu_text)
                    dur = float(dur_text)
                except:
                    cpu, dur = 0, 0
                
                vhost = cells[13].get_text(strip=True) if len(cells) > 13 else "unknown"
                request = cells[14].get_text(strip=True) if len(cells) > 14 else ""
                client = cells[11].get_text(strip=True) if len(cells) > 11 else ""
                
                url_match = re.search(r'(GET|POST|HEAD|OPTIONS)\s+(\S+)', request)
                url = url_match.group(2) if url_match else request[:50]
                real_mem = sys_procs.get(pid, 0)
                
                process = {
                    'pid': pid, 'cpu': cpu, 'mem': real_mem, 'dur': dur,
                    'domain': vhost, 'url': url, 'mode': mode, 'client': client
                }
                processes.append(process)
                
                domains_stats[vhost]['cpu'] += cpu
                domains_stats[vhost]['mem'] += real_mem
                domains_stats[vhost]['count'] += 1
                domains_stats[vhost]['total_dur'] += dur
                domains_stats[vhost]['urls'][url] += 1
                
                if client:
                    domains_stats[vhost]['ips'][client] += 1
                    ip_stats[client] += 1
                    
                    if ":" in client:
                        ipv6_parts = client.split(':')
                        sub_16 = ":".join(ipv6_parts[:2]) + "::/32"
                        sub_8 = ipv6_parts[0] + "::/16"
                    else:
                        ipv4_parts = client.split('.')
                        if len(ipv4_parts) >= 1:
                            sub_8 = f"{ipv4_parts[0]}.0.0.0/8"
                            sub_16 = f"{ipv4_parts[0]}.{ipv4_parts[1]}.0.0/16" if len(ipv4_parts) >= 2 else client
                        else:
                            sub_8, sub_16 = client, client
                            
                    subnet_16_stats[sub_16] += 1
                    subnet_8_stats[sub_8] += 1
                
                domains_stats[vhost]['modes'][mode] += 1
                if cpu > domains_stats[vhost]['max_cpu_val']:
                    domains_stats[vhost]['max_cpu_val'] = cpu
                    domains_stats[vhost]['max_cpu_pid'] = pid
            
            return processes, domains_stats, ip_stats, subnet_16_stats, subnet_8_stats
        except Exception:
            return None

    def fetch_single_host(self, host):
        try:
            protocol = "https" if self.ssl else "http"
            if ":" in host and not host.startswith("["):
                url = f"{protocol}://{host}{self.status_path}"
            else:
                url = f"{protocol}://{host}:{self.port}{self.status_path}"
                
            response = requests.get(url, timeout=2.0, verify=False)
            if response.status_code != 200:
                return None
            return self.parse_html_content(response.text)
        except Exception:
            return None

    def _host_worker(self, host):
        while self.running:
            result = self.fetch_single_host(host)
            if result is not None:
                self.hosts_data[host] = result
            for _ in range(int(self.refresh_interval * 10)):
                if not self.running:
                    break
                time.sleep(0.1)

    def start_background_workers(self):
        """Initializes and runs asynchronous scraping workers for all listed hosts."""
        for host in self.hosts:
            t = threading.Thread(target=self._host_worker, args=(host,), daemon=True)
            t.start()

    def render_left_column(self, processes, domains_stats, width):
        lines = []
        total_cpu = sum(p['cpu'] for p in processes) if processes else 0
        total_mem = sum(p['mem'] for p in processes) if processes else 0
        active_count = len(processes) if processes else 0
        unique_domains = len(domains_stats) if domains_stats else 0
        
        lines.append(self.pad_line(Colors.BOLD + Colors.CYAN + " SUMMARY ".ljust(width, '─') + Colors.RESET, width))
        lines.append(self.pad_line(f" Active processes:  {active_count}", width))
        lines.append(self.pad_line(f" Unique domains:   {unique_domains}", width))
        lines.append(self.pad_line(f" Total CPU inst.:   {total_cpu:.1f} %", width))
        
        if self.offline_mode:
            lines.append(self.pad_line(f" Total RAM inst.:   [N/A offline]", width))
            lines.append(self.pad_line(f" System Load AVG:   [N/A offline]", width))
        else:
            lines.append(self.pad_line(f" Total RAM inst.:   {total_mem:.1f} %", width))
            try:
                load_avg = os.getloadavg()
                load_color = Colors.GREEN if load_avg[0] < 2 else Colors.YELLOW if load_avg[0] < 5 else Colors.RED
                load_str = f"{load_color}{load_avg[0]:.2f} {load_avg[1]:.2f} {load_avg[2]:.2f}{Colors.RESET}"
                lines.append(self.pad_line(f" System Load AVG:   {load_str}", width))
            except:
                lines.append(self.pad_line(" System Load AVG:   --", width))
        
        lines.append(self.pad_line(Colors.BOLD + Colors.CYAN + "─" * width + Colors.RESET, width))
        lines.append(self.pad_line(Colors.BOLD + Colors.RED + " SUSPICIOUS PATTERNS" + Colors.RESET, width))
        
        found = False
        max_dom_len = max(15, width - 17)
        if domains_stats:
            for domain, stats in domains_stats.items():
                for url, count in stats['urls'].items():
                    url_lower = url.lower()
                    if 'wp-login' in url_lower:
                        dom_str = domain[:max_dom_len] + "..." if len(domain) > max_dom_len else domain
                        lines.append(self.pad_line(f"  {Colors.RED} [!] BRUTEFORCE{Colors.RESET} {dom_str}", width))
                        found = True
                    elif 'xmlrpc' in url_lower:
                        dom_str = domain[:max_dom_len] + "..." if len(domain) > max_dom_len else domain
                        lines.append(self.pad_line(f"  {Colors.RED} [!] XML-RPC{Colors.RESET}    {dom_str}", width))
                        found = True
                    elif 'admin-ajax' in url_lower and count > 20:
                        dom_str = domain[:max_dom_len] + "..." if len(domain) > max_dom_len else domain
                        lines.append(self.pad_line(f"  {Colors.YELLOW} [#] HIGH AJAX{Colors.RESET} {dom_str}", width))
                        found = True
        
        if not found:
            lines.append(self.pad_line(f"  {Colors.GREEN}[*] No problems detected{Colors.RESET}", width))
        
        while len(lines) < 9:
            lines.append(self.pad_line("", width))

        lines.append(self.pad_line(Colors.BOLD + Colors.CYAN + "─" * width + Colors.RESET, width))
        lines.append(self.pad_line(Colors.BOLD + Colors.CYAN + " PROCESS STATUS" + Colors.RESET, width))
        
        mode_stats = defaultdict(int)
        if domains_stats:
            for stats in domains_stats.values():
                for mode, count in stats['modes'].items():
                    mode_stats[mode] += count
        
        mode_names = {'R': 'Reading', 'W': 'Sending', 'K': 'Keepalive', 'C': 'Closing'}
        mode_colors = {'R': Colors.YELLOW, 'W': Colors.GREEN, 'K': Colors.CYAN, 'C': Colors.MAGENTA}
        
        total_modes = max(1, sum(mode_stats.values()))
        bar_width = max(10, width - 20)
        
        for mode in ['R', 'W', 'K', 'C']:
            count = mode_stats.get(mode, 0)
            color = mode_colors.get(mode, Colors.RESET)
            bar = self.format_bar((count / total_modes) * 100, bar_width)
            mode_name = mode_names[mode]
            lines.append(self.pad_line(f"  {color}{mode_name:<9}{Colors.RESET} {count:<4} {bar}", width))
        
        return lines
    
    def render_right_column(self, processes, domains_stats, ip_stats, subnet_16_stats, subnet_8_stats, width):
        lines = []
        stats_width = 30
        pid_col_width = 8
        available_for_text = width - stats_width - pid_col_width - 7
        
        domain_width = int(available_for_text * 0.35)
        url_width = available_for_text - domain_width
        
        # --- TOP 10 DOMAINS BY CPU ---
        lines.append(self.pad_line(Colors.BOLD + Colors.YELLOW + " TOP 10 DOMAINS BY CPU ".ljust(width, '─') + Colors.RESET, width))
        sorted_domains = sorted(domains_stats.items(), key=lambda x: x[1]['cpu'], reverse=True)[:10] if domains_stats else []
        
        for i in range(1, 11):
            if i <= len(sorted_domains):
                domain, stats = sorted_domains[i-1]
                cpu_color = self.get_cpu_color(stats['cpu'])
                mem_color = self.get_mem_color(stats['mem'])
                bar = self.format_bar(stats['cpu'], 12, self.get_cpu_color)
                
                suspicious = " "
                if any('wp-login' in u or 'xmlrpc' in u for u in stats['urls']):
                    suspicious = Colors.RED + "!" + Colors.RESET
                elif any('admin-ajax' in u for u in stats['urls']):
                    suspicious = Colors.YELLOW + "#" + Colors.RESET
                
                dom_raw = domain[:domain_width-3] + "..." if len(domain) > domain_width else domain
                domain_display = f"{Colors.BOLD}{dom_raw:<{domain_width}}{Colors.RESET}"
                
                pid_str = str(stats['max_cpu_pid'])
                pid_display = f"{Colors.CYAN}{pid_str:<{pid_col_width}}{Colors.RESET}"
                
                top_urls = sorted(stats['urls'].items(), key=lambda x: x[1], reverse=True)[:1]
                if top_urls:
                    url, count = top_urls[0]
                    raw_url_string = f"[{count}x] {url}"
                    url_raw = raw_url_string[:url_width-3] + "..." if len(raw_url_string) > url_width else raw_url_string
                    url_display = f"{Colors.DIM}{url_raw}{Colors.RESET}"
                else:
                    url_display = ""
                
                mem_str = f"{stats['mem']:4.1f}%" if not self.offline_mode else " -- "
                line_dom = f" {i:>2}. {cpu_color}{stats['cpu']:5.1f}%{Colors.RESET} {bar} {mem_color}{mem_str}{Colors.RESET} │ {pid_display} │ {domain_display} {suspicious} │ {url_display}"
                lines.append(self.pad_line(line_dom, width))
            else:
                lines.append(self.pad_line(f" {i:>2}. {Colors.DIM}-- . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . --{Colors.RESET}", width))
        
        # --- TOP 10 INDIVIDUAL REQUESTS ---
        lines.append(self.pad_line(Colors.BOLD + Colors.GREEN + "─" * width + Colors.RESET, width))
        lines.append(self.pad_line(Colors.BOLD + Colors.GREEN + " TOP 10 INDIVIDUAL REQUESTS (CPU) ".ljust(width, '─') + Colors.RESET, width))
        
        sorted_procs = sorted(processes, key=lambda x: x['cpu'], reverse=True) if processes else []
        active_procs = [p for p in sorted_procs if p['cpu'] >= 0.1][:10]
        
        for i in range(1, 11):
            if i <= len(active_procs):
                proc = active_procs[i-1]
                cpu_color = self.get_cpu_color(proc['cpu'])
                mem_color = self.get_mem_color(proc['mem'])
                mode_color = Colors.GREEN if proc['mode'] == 'K' else Colors.YELLOW if proc['mode'] == 'R' else Colors.RED
                
                pid_str = str(proc['pid'])
                pid_display = f"{Colors.CYAN}{pid_str:<{pid_col_width}}{Colors.RESET}"
                
                dom_raw = proc['domain'][:domain_width-3] + "..." if len(proc['domain']) > domain_width else proc['domain']
                domain_display = f"{dom_raw:<{domain_width-4}} [{mode_color}{proc['mode']}{Colors.RESET}]"
                url_raw = proc['url'][:url_width-3] + "..." if len(proc['url']) > url_width else proc['url']
                
                dummy_bar = self.format_bar(proc['cpu'], 12, self.get_cpu_color)
                mem_str = f"{proc['mem']:4.1f}%" if not self.offline_mode else " -- "
                line_proc = f" {i:>2}. {cpu_color}{proc['cpu']:5.1f}%{Colors.RESET} {dummy_bar} {mem_color}{mem_str}{Colors.RESET} │ {pid_display} │ {domain_display}   │ {url_raw}"
                lines.append(self.pad_line(line_proc, width))
            else:
                lines.append(self.pad_line(f" {i:>2}. {Colors.DIM}-- . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . --{Colors.RESET}", width))
        
        # --- TOP 5 SLOW REQUESTS ---
        lines.append(self.pad_line(Colors.BOLD + Colors.MAGENTA + "─" * width + Colors.RESET, width))
        lines.append(self.pad_line(Colors.BOLD + Colors.MAGENTA + " TOP 5 SLOW REQUESTS (duration) ".ljust(width, '─') + Colors.RESET, width))
        
        sorted_by_dur = sorted(processes, key=lambda x: x['dur'], reverse=True) if processes else []
        slow_procs = [p for p in sorted_by_dur if p['dur'] >= 100][:5]
        
        for i in range(1, 6):
            if i <= len(slow_procs):
                proc = slow_procs[i-1]
                dur_color = Colors.YELLOW if proc['dur'] < 500 else Colors.RED
                
                pid_str = str(proc['pid'])
                pid_display = f"{Colors.CYAN}{pid_str:<{pid_col_width}}{Colors.RESET}"
                
                dom_raw = proc['domain'][:domain_width-3] + "..." if len(proc['domain']) > domain_width else proc['domain']
                domain_display = f"{dom_raw:<{domain_width}}"
                url_raw = proc['url'][:url_width-3] + "..." if len(proc['url']) > url_width else proc['url']
                
                dur_str = f" {i:>2}. {dur_color}{proc['dur']:7.0f} ms ({proc['dur']/1000:.1f} s){Colors.RESET}"
                dur_padded = self.pad_line(dur_str, stats_width)
                
                line_slow = f"{dur_padded} │ {pid_display} │ {domain_display}   │ {url_raw}"
                lines.append(self.pad_line(line_slow, width))
            else:
                dur_padded = self.pad_line(f" {i:>2}. {Colors.DIM}--{Colors.RESET}", stats_width)
                lines.append(self.pad_line(f"{dur_padded} │ {Colors.DIM}{' ':<{pid_col_width}} │ {' ':<{domain_width}}   │ --{Colors.RESET}", width))

        # --- TOP 5 NETWORK CONNECTIONS ---
        lines.append(self.pad_line(Colors.BOLD + Colors.CYAN + "─" * width + Colors.RESET, width))
        lines.append(self.pad_line(Colors.BOLD + Colors.CYAN + " NETWORK CONNECTION ANALYSIS (TOP 5 BY MASK) ".ljust(width, '─') + Colors.RESET, width))
        
        sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:5] if ip_stats else []
        sorted_subnets_16 = sorted(subnet_16_stats.items(), key=lambda x: x[1], reverse=True)[:5] if subnet_16_stats else []
        sorted_subnets_8 = sorted(subnet_8_stats.items(), key=lambda x: x[1], reverse=True)[:5] if subnet_8_stats else []
        
        w_net16 = 28
        w_net8 = 25
        w_ip_column = max(40, width - w_net16 - w_net8 - 6)
        
        for idx in range(5):
            if idx < len(sorted_ips):
                ip, count = sorted_ips[idx]
                ip_color = Colors.RED if count > 50 else Colors.YELLOW if count > 20 else Colors.RESET
                hname = self.get_hostname(ip)
                
                padded_ip = f"{ip:<15}"
                prefix_str = f" {idx+1}. {padded_ip} ({count:>2}x) "
                
                max_hname_len = w_ip_column - len(prefix_str)
                if max_hname_len > 4 and not self.offline_mode:
                    if len(hname) > max_hname_len:
                        hname = hname[:max_hname_len - 3] + "..."
                    ip_content = f" {idx+1}. {ip_color}{padded_ip}{Colors.RESET} ({count:>2}x) {Colors.DIM}{hname}{Colors.RESET}"
                else:
                    ip_content = f" {idx+1}. {ip_color}{padded_ip}{Colors.RESET} ({count:>2}x)"
                ip_str = self.pad_line(ip_content, w_ip_column)
            else:
                ip_str = self.pad_line(f" {idx+1}. {Colors.DIM}--{Colors.RESET}", w_ip_column)
                
            if idx < len(sorted_subnets_16):
                net, count = sorted_subnets_16[idx]
                net_color = Colors.RED if count > 100 else Colors.YELLOW if count > 40 else Colors.RESET
                raw_net = f" {idx+1}. {net:<15} ({count:>2}x)"
                colored_net = raw_net.replace(net, f"{net_color}{net}{Colors.RESET}")
                net_str = self.pad_line(colored_net, w_net16)
            else:
                net_str = self.pad_line(f" {idx+1}. {Colors.DIM}--{Colors.RESET}", w_net16)
                
            if idx < len(sorted_subnets_8):
                net8, count = sorted_subnets_8[idx]
                net8_color = Colors.RED if count > 200 else Colors.YELLOW if count > 80 else Colors.RESET
                raw_net8 = f" {idx+1}. {net8:<12} ({count:>2}x)"
                colored_net8 = raw_net8.replace(net8, f"{net8_color}{net8}{Colors.RESET}")
                net8_str = self.pad_line(colored_net8, w_net8)
            else:
                net8_str = self.pad_line(f" {idx+1}. {Colors.DIM}--{Colors.RESET}", w_net8)
                
            full_line = f"{ip_str} │ {net_str} │ {net8_str}"
            lines.append(self.pad_line(full_line, width))
            
        return lines
    
    def generate_tabs_header(self, box_width):
        if self.offline_mode:
            return self.pad_line(" " + Colors.TAB_ACTIVE + " [i] OFFLINE FILE / PIPE ANALYSIS " + Colors.RESET, box_width)
            
        tab_line = " "
        for i, host in enumerate(self.hosts):
            tab_label = f" {i+1}: {host} "
            if i == self.current_host_idx:
                tab_line += f"{Colors.TAB_ACTIVE}{tab_label}{Colors.RESET} "
            else:
                tab_line += f"\033[44;37m{tab_label}{Colors.RESET} "
        return self.pad_line(tab_line, box_width)

    def render_frame(self):
        total_inner_width = self.terminal_width - 3
        left_width = int(total_inner_width * 0.28)
        right_width = total_inner_width - left_width
        box_width = left_width + 1 + right_width
        
        if self.offline_mode:
            data = self.hosts_data.get("offline")
        else:
            current_host = self.hosts[self.current_host_idx]
            data = self.hosts_data.get(current_host)
        
        if data is None:
            left_col = self.render_left_column(None, None, left_width)
            right_col = [self.pad_line(" Fetching and parsing data...", right_width)]
        else:
            processes, domains_stats, ip_stats, subnet_16_stats, subnet_8_stats = data
            left_col = self.render_left_column(processes, domains_stats, left_width)
            right_col = self.render_right_column(processes, domains_stats, ip_stats, subnet_16_stats, subnet_8_stats, right_width)
        
        max_height = max(len(left_col), len(right_col))
        left_col += [" " * left_width] * (max_height - len(left_col))
        right_col += [" " * right_width] * (max_height - len(right_col))
        
        lines = []
        lines.append(Colors.BOLD + Colors.CYAN + "┌" + "─" * box_width + "┐" + Colors.RESET)
        
        time_str = datetime.now().strftime('%H:%M:%S') if not self.offline_mode else "[ OFFLINE MODE ]"
        title = f"  [RUN] APACHE ANALYZER PRO   │   Status: {time_str}"
        padding = box_width - len(title)
        lines.append(Colors.BOLD + Colors.CYAN + "│" + Colors.RESET + title + " " * max(0, padding) + Colors.BOLD + Colors.CYAN + "│" + Colors.RESET)
        
        tabs_row = self.generate_tabs_header(box_width)
        lines.append(Colors.BOLD + Colors.CYAN + "│" + Colors.RESET + tabs_row + Colors.BOLD + Colors.CYAN + "│" + Colors.RESET)
        
        lines.append(Colors.BOLD + Colors.CYAN + "├" + "─" * left_width + "┬" + "─" * right_width + "┤" + Colors.RESET)
        
        for left_line, right_line in zip(left_col, right_col):
            lines.append(
                Colors.BOLD + Colors.CYAN + "│" + Colors.RESET + left_line + 
                Colors.BOLD + Colors.CYAN + "│" + Colors.RESET + right_line + 
                Colors.BOLD + Colors.CYAN + "│" + Colors.CLEAR_LINE
            )
        
        lines.append(Colors.BOLD + Colors.CYAN + "└" + "─" * left_width + "┴" + "─" * right_width + "┘" + Colors.RESET)
        lines.append(Colors.CLEAR_LINE)
        
        if self.offline_mode:
            legend = f"  [*] Size: {self.terminal_width}x{self.terminal_height}  │  Static Data  │  Keys: [ Q ] Exit viewer"
        else:
            legend = f"  [*] Size: {self.terminal_width}x{self.terminal_height}  │  Keys: [ <- ] [ -> ] Switch hosts  │  [ 1-{len(self.hosts)} ] Direct select  │  [ Q ] Exit"
        lines.append(Colors.DIM + legend + Colors.RESET + Colors.CLEAR_LINE)
        
        return "\n".join(lines)
    
    def run(self):
        sys.stdout.write(Colors.CURSOR_HIDE)
        sys.stdout.write('\033[?1049h')
        sys.stdout.write('\033[2J')
        sys.stdout.flush()
        
        self.input_thread.start()
        
        if self.offline_mode:
            self.hosts_data["offline"] = self.parse_html_content(self.offline_html)
            
            while self.running:
                new_frame = self.render_frame()
                sys.stdout.write(Colors.GOTO_TOP)
                sys.stdout.write(new_frame)
                sys.stdout.flush()
                time.sleep(0.2)
        else:
            self.start_background_workers()
            while self.running:
                start_time = time.time()
                new_frame = self.render_frame()
                
                sys.stdout.write(Colors.GOTO_TOP)
                sys.stdout.write(new_frame)
                sys.stdout.flush()
                
                elapsed = time.time() - start_time
                sleep_time = max(0.1, self.refresh_interval - elapsed)
                steps = int(sleep_time / 0.1)
                for _ in range(steps):
                    if not self.running:
                        break
                    time.sleep(0.1)
        
        self.cleanup_terminal()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Apache Analyzer PRO - Live & Offline Mode')
    parser.add_argument('--host', default='localhost', help='Comma-separated list of live hosts.')
    parser.add_argument('--port', type=int, default=80)
    parser.add_argument('--ssl', action='store_true', help='Use HTTPS instead of HTTP.')
    parser.add_argument('--status-path', default='/server-status', help='Path to server-status.')
    parser.add_argument('--interval', type=int, default=3, help='Refresh interval in seconds.')
    parser.add_argument('-r', '--read', type=str, default=None, help='Path to saved server-status HTML file for offline analysis.')
    
    args = parser.parse_args()
    
    offline_html = None
    
    if not sys.stdin.isatty():
        offline_html = sys.stdin.read()
        sys.stdin = open('/dev/tty')
        
    elif args.read:
        if os.path.exists(args.read):
            with open(args.read, 'r', encoding='utf-8', errors='ignore') as f:
                offline_html = f.read()
        else:
            print(f"Error: File '{args.read}' does not exist.")
            sys.exit(1)
            
    if offline_html:
        app = ApacheAnalyzerPro(offline_html=offline_html)
    else:
        hosts_list = [h.strip() for h in args.host.split(',') if h.strip()]
        if not hosts_list:
            hosts_list = ['localhost']
        app = ApacheAnalyzerPro(hosts=hosts_list, port=args.port, ssl=args.ssl, status_path=args.status_path, refresh_interval=args.interval)
    
    try:
        app.run()
    except KeyboardInterrupt:
        app.cleanup_terminal()
        print("Offline analysis terminated.")
        sys.exit(0)

if __name__ == "__main__":
    main()
