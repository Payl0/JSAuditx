import re
import os
import json
import requests
from urllib.parse  import urlparse, urljoin
from concurrent.futures  import ThreadPoolExecutor
import argparse
import logging
from tqdm import tqdm
import sys
from colorama import init, Fore, Style
import warnings
import time
import psutil
import chardet
import base64
from typing import Dict, List, Set, Union

class EnhancedJSONEncoder(json.JSONEncoder):
    """处理set类型的JSON序列化"""
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)

# 初始化 colorama
init(autoreset=True)
 
# 设置日志
logging.basicConfig(level=logging.INFO,  format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
warnings.filterwarnings("ignore")
 
BANNER = f"""
{Fore.RED}
 ██╗███████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗██╗  ██╗ 
████╗╚══███╔╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝╚██╗██╔╝ 
██╔██╗  ███╔╝ ███████║██║   ██║██████╔╝██║   ██║    ╚███╔╝ 
██║╚██╗ ███╔╝ ██╔══██║██║   ██║██╔═══╝ ██║   ██║    ██╔██╗ 
██║ ╚████╔╝  ██║  ██║╚██████╔╝██║     ██║   ██║   ██╔╝ ██╗ 
╚═╝  ╚═══╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝   ╚═╝   ╚═╝  ╚═╝ 
                                                            
{Fore.BLUE}  Advanced JavaScript Security Auditor | v1.1 | By 故态复萌{Style.RESET_ALL}
"""


class JSAuditX:
    def __init__(self, output=None, threads=5, wordlist=None, passive=False, max_memory=512, quiet=False):
        """
        初始化JSAuditX
        
        参数:
            output (str): 输出文件路径 
            threads (int): 线程数
            wordlist (str): 自定义敏感关键词文件路径 
            passive (bool): 是否被动模式(仅分析不发送请求)
            max_memory (int): 最大内存使用(MB)
            quiet (bool): 静默模式(不显示输出)
        """
        self.output  = output
        self.threads  = threads
        self.passive  = passive
        self.quiet  = quiet
        self.max_memory  = max_memory * 1024 * 1024
        self.sensitive_keywords  = self.load_sensitive_keywords(wordlist)
        self.vulnerability_patterns  = self._compile_vulnerability_patterns()
        self.api_patterns  = self._compile_api_patterns()
        
        # 结果存储
        self.results  = {
            'targets': {},
            'stats': {
                'total_files': 0,
                'processed_files': 0,
                'total_lines': 0,
                'vulnerabilities_found': 0,
                'secrets_found': 0,
                'start_time': time.time(),
                'end_time': None
            }
        }

    def load_sensitive_keywords(self, wordlist_path=None):
        """加载敏感关键词"""
        default_keywords = {
            'admin', 'api', 'auth', 'login', 'register', 'user',
            'account', 'config', 'secret', 'token', 'password',
            'oauth', 'session', 'jwt', 'reset', 'forgot', 'debug',
            'test', 'internal', 'private', 'backup', 'restore',
            'database', 'credential', 'endpoint', 'key', 'security',
            'vulnerability', 'bypass', 'token', 'secret', 'auth', 'id', ''
        }
        
        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r') as f:
                    custom_keywords = {line.strip() for line in f if line.strip()}
                return default_keywords.union(custom_keywords)
            except Exception as e:
                if not self.quiet:
                    logger.warning(f" 无法加载自定义关键词列表: {e}")
        
        return default_keywords

        return default_keywords

    def _enhanced_vulnerability_scan(self, content: str, source: str, lines: List[str], target_result: Dict):
        """增强的漏洞扫描"""
        found_vulns = False
        
        # 扫描所有漏洞类型
        # 对已知库降低检测敏感度
        if self._is_known_library(source):
            self._scan_vulnerabilities(content, source, lines, target_result, sensitivity='low')
        else:
            self._scan_vulnerabilities(content, source, lines, target_result, sensitivity='high')
        found_vulns = len(target_result['vulnerabilities']) > 0
        
        if found_vulns and not self.quiet:
            logger.info(f"{Fore.CYAN}[+] 在 {source} 中发现 {len(target_result['vulnerabilities'])}个潜在漏洞{Style.RESET_ALL}")

    @staticmethod
    def _compile_vulnerability_patterns():
        """编译漏洞检测正则表达式模式
        
        返回:
            dict: 包含各类型漏洞检测模式的字典
        """
        import re
        return {
            'xss': [re.compile(r'document\.write\(\s*[^,]+?\+\s*[^)]+\)'), re.compile(r'<script.*?src=.*?javascript:|eval\(\s*[^,]+?\+\s*[^)]+\)')],
            'sql_injection': [re.compile(r'SELECT.*?FROM.*?WHERE.*?(\+|\|\||\&\&|AND|OR).*?=.*?\$')],
            'command_injection': [re.compile(r'exec\(|system\(|shell_exec\(|`|\$\(.*?\)')],
            'csrf': [re.compile(r'csrf_token|anti_csrf|xsrf_token', re.IGNORECASE)],
            'insecure_cookie': [re.compile(r'document\.cookie.*?=.*?(;|$)', re.IGNORECASE)],
            'unvalidated_redirect': [re.compile(r'window\.location\.href.*?=.*?(\+|blockurl)|location\.replace\(.*?blockurl\)'), re.compile(r'location\.href\s*=\s*[^;]+?blockurl', re.IGNORECASE)],
            'ssrf': [re.compile(r'(fetch|XMLHttpRequest|axios|request|get|post|http|https)\(.*?\$\{.*?\}', re.IGNORECASE), re.compile(r'(url|src|href)\s*[:=]\s*[^"\']*\$\{.*?\}', re.IGNORECASE)],
            'insecure_cookies': [
                re.compile(r'document\.cookie\s*=\s*([^;]+)',  re.IGNORECASE),
                re.compile(r'(?:secure |httponly)\s*:\s*false', re.IGNORECASE)
            ],
            'dom_xss': [
                re.compile(r'(?:document |window)\.(?:URL|documentURI|baseURI|referrer)\s*[^=]=[^=]\s*([^;]+)', re.IGNORECASE),
                re.compile(r'\.(?:appendChild |insertBefore|replaceChild)\s*\(([^)]+)\)', re.IGNORECASE),
                re.compile(r'(?:location\.(?:href|replace|assign)|window\.open)\s*=\s*[^;]*?(\+|=)\s*[^;]*?(document\.|window\.|location\.)', re.IGNORECASE)
            ]
        }
 
    @staticmethod
    def _compile_api_patterns():
        """编译API正则表达式模式"""
        return {
            'api_endpoints': re.compile(
                r'(?:fetch|axios|XMLHttpRequest|\.get|\.post|\.put|\.delete|\.patch|\.ajax)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                re.IGNORECASE
            ),
            'url_strings': re.compile(
                r'(?:https?|ftp):\/\/[^\s\'\"]+|\'[^\'\"\s]+\'|\"[^\'\"\s]+\"',
                re.IGNORECASE
            ),
            'api_keys': re.compile(
                r'(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
                re.IGNORECASE
            ),
            'jwt_tokens': re.compile(
                r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
                re.IGNORECASE
            ),
            'hardcoded_creds': re.compile(
                r'(?:user|username|password|passwd|pwd|auth)\s*[=:]\s*[\'"`][^\'"`]+[\'"`]',
                re.IGNORECASE
            ),
            'base64_data': re.compile(
                r'data:image\/[^;]+;base64,[a-zA-Z0-9+/=]+',
                re.IGNORECASE
            ),
            'sensitive_comments': re.compile(
                r'\/\/.*(TODO|FIXME|HACK|SECURITY|VULNERABLE|BUG).*$',
                re.IGNORECASE | re.MULTILINE
            )
        }
 
    def load_sensitive_keywords(self, wordlist_path=None):
        """加载敏感关键词"""
        default_keywords = {
            'admin', 'api', 'auth', 'login', 'register', 'user',
            'account', 'config', 'secret', 'token', 'password',
            'oauth', 'session', 'jwt', 'reset', 'forgot', 'debug',
            'test', 'internal', 'private', 'backup', 'restore',
            'database', 'credential', 'endpoint', 'key', 'security',
            'vulnerability', 'bypass', 'token', 'secret', 'auth', 'id', ''
        }
        
        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r') as f:
                    custom_keywords = {line.strip()  for line in f if line.strip()}
                return default_keywords.union(custom_keywords)
            except Exception as e:
                if not self.quiet:
                    logger.warning(f" 无法加载自定义关键词列表: {e}")
        
        return default_keywords
    
    def analyze_targets(self, targets):
        """分析多个目标"""
        if not isinstance(targets, list):
            targets = [targets]
 
        self.results['stats']['total_files']  = len(targets)
        
        with ThreadPoolExecutor(max_workers=self.threads)  as executor:
            list(tqdm(
                executor.map(self._process_single_target,  targets),
                total=len(targets),
                desc="分析目标" if not self.quiet  else None,
                unit="目标",
                disable=self.quiet
            ))
 
    def _process_single_target(self, target):
        """处理单个目标"""
        if not target or target.strip()  == "":
            return
 
        target = target.strip()
        target_result = {
            'apis': [],
            'secrets': [],
            'vulnerabilities': [],
            'domains': set(),
            'stats': {
                'lines_processed': 0,
                'status': 'success',
                'error': None
            }
        }
        
        try:
            if target.startswith(('http://',  'https://')):
                content = self._fetch_url_content(target)
                if content:
                    self._analyze_js_content(content, target, target_result)
            elif os.path.isfile(target):
                with open(target, 'r', encoding='utf-8') as f:
                    content = f.read()
                self._analyze_js_content(content, target, target_result)
            elif os.path.isdir(target):
                self._analyze_directory(target, target_result)
            else:
                target_result['stats']['status'] = 'skipped'
                target_result['stats']['error'] = 'Invalid target'
            
            self.results['targets'][target] = target_result
            if 'stats' not in self.results:
                self.results['stats'] = {'processed_files': 0}
            self.results['stats']['processed_files'] += 1
        except Exception as e:
            target_result['stats']['status'] = 'failed'
            target_result['stats']['error'] = str(e)
            self.results['targets'][target]  = target_result
            if not self.quiet:
                logger.error(f" 处理目标 {target} 时出错: {e}")
 
    def _fetch_url_content(self, url):
        """获取URL内容"""
        try:
            requests.packages.urllib3.disable_warnings()
            response = requests.get(
                url,
                timeout=30,
                verify=False,
                headers={'User-Agent': 'JSAuditX/2.1'}
            )
            
            if response.status_code  == 200:
                return response.text
            else:
                if not self.quiet:
                    logger.warning(f"{url}  返回状态码: {response.status_code}")
                raise Exception(f"HTTP状态码 {response.status_code}")
        except Exception as e:
            if not self.quiet:
                logger.error(f" 获取 {url} 内容时出错: {str(e)}")
            raise
 
    def _analyze_directory(self, directory, target_result):
        """分析目录"""
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower().endswith('.js'):
                    file_path = os.path.join(root,  file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        self._analyze_js_content(content, file_path, target_result)
                    except Exception as e:
                        if not self.quiet:
                            logger.error(f" 处理文件 {file_path} 时出错: {e}")
 
    def _analyze_js_content(self, content, source, target_result):
        """分析JS内容"""
        # 检查内存使用
        self._check_memory_usage()
 
        # 分割内容为行
        lines = content.split('\n')
        target_result['stats']['lines_processed'] += len(lines)
        self.results['stats']['total_lines']  += len(lines)
 
        # 过滤掉base64图片数据
        content = self.api_patterns['base64_data'].sub('',  content)
 
        # 漏洞扫描
        self._enhanced_vulnerability_scan(content, source, lines, target_result)
 
        # 提取API端点
        self._extract_apis(content, source, target_result)
 
        # 查找敏感数据
        self._find_secrets(content, source, target_result)
 
        # 提取外部域名
        self._extract_domains(content, target_result)
 
        # 查找敏感注释
        self._find_sensitive_comments(content, source, lines, target_result)
 
    def _is_known_library(self, source):
        """检测是否为已知安全库"""
        known_libraries = ['jquery', 'react', 'vue', 'angular', 'bootstrap', 'lodash']
        return any(lib in source.lower() for lib in known_libraries)

    def _scan_vulnerabilities(self, content, source, lines, target_result, sensitivity='high'):
        """漏洞扫描, 支持不同敏感度级别"""
        
        """扫描漏洞"""
        # XSS检测
        if sensitivity == 'high':
            xss_patterns = self.vulnerability_patterns['xss']
        else:
            xss_patterns = [self.vulnerability_patterns['xss'][0], self.vulnerability_patterns['xss'][1]]
        
        for pattern in xss_patterns:
            for match in pattern.finditer(content):
                line_num = self._get_line_number(content, match.start(),  lines)
                self._add_vulnerability(
                    target_result,
                    'XSS',
                    match.group(0),
                    source,
                    line_num,
                    f"潜在的跨站脚本(XSS)漏洞: {match.group(0)}"
                )
 
        # 开放重定向检测
        for pattern in self.vulnerability_patterns['unvalidated_redirect']:
            for match in pattern.finditer(content):
                line_num = self._get_line_number(content, match.start(),  lines)
                self._add_vulnerability(
                    target_result,
                    'Open Redirect',
                    match.group(0),
                    source,
                    line_num,
                    f"潜在的开放重定向漏洞: {match.group(0)}"
                )
 
 
        # SSRF检测
        for pattern in self.vulnerability_patterns['ssrf']:
            for match in pattern.finditer(content):
                line_num = self._get_line_number(content, match.start(),  lines)
                self._add_vulnerability(
                    target_result,
                    'SSRF',
                    match.group(0),
                    source,
                    line_num,
                    f"潜在的服务器端请求伪造(SSRF)漏洞: {match.group(0)}"
                )

        # 不安全Cookie检测
        for pattern in self.vulnerability_patterns['insecure_cookies']:
            for match in pattern.finditer(content):
                line_num = self._get_line_number(content, match.start(),  lines)
                self._add_vulnerability(
                    target_result,
                    'Insecure Cookie',
                    match.group(0),
                    source,
                    line_num,
                    f"潜在的不安全Cookie设置: {match.group(0)}"
                )
 
    def _find_sensitive_comments(self, content, source, lines, target_result):
        """查找敏感注释"""
        for match in self.api_patterns['sensitive_comments'].finditer(content):
            line_num = self._get_line_number(content, match.start(),  lines)
            self._add_vulnerability(
                target_result,
                'Sensitive Comment',
                match.group(0),
                source,
                line_num,
                f"敏感的代码注释: {match.group(0)}"
            )
 
    def _extract_apis(self, content, source, target_result):
        """提取API端点"""
        for match in self.api_patterns['api_endpoints'].finditer(content):
            api = match.group(1)
            if not api.startswith(('http://',  'https://')):
                api = urljoin(source if source.startswith(('http://',  'https://')) else '', api)
            self._add_result(target_result, 'apis', {
                'url': api,
                'source': source,
                'type': 'API Endpoint'
            })
        
        for match in self.api_patterns['url_strings'].finditer(content):
            url = match.group(0).strip('\'"`')
            if url.startswith(('http://',  'https://')):
                self._add_result(target_result, 'apis', {
                    'url': url,
                    'source': source,
                    'type': 'URL String'
                })
 
    def _find_secrets(self, content, source, target_result):
        """查找敏感数据"""
        for match in self.api_patterns['api_keys'].finditer(content):
            self._add_result(target_result, 'secrets', {
                'value': match.group(0),
                'source': source,
                'type': 'API Key',
                'severity': 'high'
            })
        
        for match in self.api_patterns['jwt_tokens'].finditer(content):
            self._add_result(target_result, 'secrets', {
                'value': match.group(0),
                'source': source,
                'type': 'JWT Token',
                'severity': 'medium'
            })
        
        for match in self.api_patterns['hardcoded_creds'].finditer(content):
            self._add_result(target_result, 'secrets', {
                'value': match.group(0),
                'source': source,
                'type': 'Hardcoded Credential',
                'severity': 'high'
            })
 
    def _extract_domains(self, content, target_result):
        """提取外部域名"""
        for match in self.api_patterns['url_strings'].finditer(content):
            url = match.group(0).strip('\'"`')
            if url.startswith(('http://',  'https://')):
                domain = urlparse(url).netloc
                if domain and domain not in target_result['domains']:
                    target_result['domains'].add(domain)
 
    def _add_vulnerability(self, target_result, vuln_type, code, source, line_num, description):
        """添加漏洞到结果"""
        self._add_result(target_result, 'vulnerabilities', {
            'type': vuln_type,
            'code': code,
            'source': source,
            'line': line_num,
            'description': description,
            'severity': self._get_severity_level(vuln_type)
        })
 
    def _add_result(self, target_result, category, item):
        """添加结果到对应分类"""
        # 过滤掉过大的内容
        if isinstance(item, (dict, str)) and len(str(item)) > 10000:
            return
        
        target_result[category].append(item)
 
    def _get_line_number(self, content, pos, lines=None):
        """获取匹配项的行号"""
        if lines is None:
            lines = content.split('\n')
        
        current_pos = 0
        for i, line in enumerate(lines):
            current_pos += len(line) + 1  # +1 for newline
            if current_pos >= pos:
                return i + 1
        return 0
 
    def _get_severity_level(self, vuln_type):
        """获取漏洞严重级别"""
        severity_map = {
            'XSS': 'high',
            'Code Execution': 'critical',
            'SSRF': 'high',
            'Open Redirect': 'medium',
            'SSRF': 'high',
            'Insecure Cookie': 'medium',
            'Sensitive Comment': 'low',
            'Hardcoded Credential': 'high',
            'API Key': 'high',
            'JWT Token': 'medium'
        }
        return severity_map.get(vuln_type,  'low')
 
    def _check_memory_usage(self):
        """检查内存使用情况"""
        mem_usage = psutil.Process().memory_info().rss
        if mem_usage > self.max_memory:
            raise MemoryError(f"内存使用超过限制: {mem_usage/1024/1024:.2f}MB > {self.max_memory/1024/1024:.2f}MB")
 
    def _post_process_results(self):
        """后处理结果"""
        # 统计总漏洞和秘密数量
        for target, result in self.results['targets'].items():
            self.results['stats']['vulnerabilities_found']  += len(result.get('vulnerabilities',  []))
            self.results['stats']['secrets_found']  += len(result.get('secrets',  []))
 
        # 按严重性排序漏洞
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        for target in self.results['targets'].values():
            if 'vulnerabilities' in target:
                target['vulnerabilities'].sort(
                    key=lambda x: severity_order.get(x.get('severity',  'low'), 3)
                )
 
        # 添加结束时间
        self.results['stats']['end_time']  = time.time()
        self.results['stats']['duration']  = round(
            self.results['stats']['end_time']  - self.results['stats']['start_time'],  2
        )
 
    def save_results(self):
        if not self.output:
            return False
 
        os.makedirs(os.path.dirname(self.output)  or '.', exist_ok=True)
    
        try:
            self._post_process_results()
            results = {
                'targets': self.results['targets'],
                'stats': self.results['stats'],
                'summary': {
                    'total_targets': self.results['stats']['total_files'],
                    'processed_targets': self.results['stats']['processed_files'],
                    'vulnerabilities_found': self.results['stats']['vulnerabilities_found'],
                    'secrets_found': self.results['stats']['secrets_found'],
                    'execution_time': f"{self.results['stats']['duration']:.2f}  seconds"
                },
                'metadata': {
                    'timestamp': time.strftime("%Y-%m-%d  %H:%M:%S"),
                    'version': '2.2',
                    'tool': 'JSAuditX'
                }
            }
 
            with open(self.output,  'w', encoding='utf-8') as f:
                json.dump(results,  f, indent=2, ensure_ascii=False, cls=EnhancedJSONEncoder)
        
            if not self.quiet:
                logger.info(f" 结果已保存到 {self.output}")
            return True
        except Exception as e:
            if not self.quiet:
                logger.error(f" 保存结果时出错: {e}")
            return False
 
def read_targets_from_file(file_path):
    """从文件读取目标列表"""
    targets = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        return targets
    except Exception as e:
        logger.error(f" 读取目标文件时出错: {e}")
        return []
 
def print_banner():
    """打印横幅"""
    print(BANNER)
    print(f"{Fore.CYAN}高级JavaScript安全审计工具 v1.1{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}\n")
 
def main():
    # 打印横幅
    if len(sys.argv)  > 1 and '--quiet' not in sys.argv:
        print_banner()
 
    parser = argparse.ArgumentParser(description='JSAuditX - 高级JavaScript安全审计工具', add_help=False)
    parser.add_argument('-h',  '--help', action='help', default=argparse.SUPPRESS, help='显示帮助信息并退出')
    parser.add_argument('-t',  '--target', help='目标URL/文件/目录路径或包含目标的文本文件', required=True)
    parser.add_argument('-o',  '--output', help='输出JSON文件路径', required=True)
    parser.add_argument('-w',  '--wordlist', help='自定义敏感关键词文件路径')
    parser.add_argument('--threads',  type=int, default=5, help='线程数 (默认: 5)')
    parser.add_argument('--passive',  action='store_true', help='被动模式(仅分析不发送请求)')
    parser.add_argument('--max-memory',  type=int, default=512, help='最大内存使用(MB) (默认: 512)')
    parser.add_argument('--quiet',  action='store_true', help='静默模式(不显示输出)')
    
    if len(sys.argv)  == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
 
    auditor = JSAuditX(
        output=args.output,
        threads=args.threads,
        wordlist=args.wordlist,
        passive=args.passive,
        max_memory=args.max_memory,
        quiet=args.quiet
    )
 
    try:
        # 检查是否是文本文件
        if os.path.isfile(args.target)  and not (args.target.lower().endswith('.js')  or os.path.isdir(args.target)):
            targets = read_targets_from_file(args.target)
            if not targets:
                if not args.quiet:
                    logger.error(" 未找到有效目标")
                sys.exit(1)
            
            if not args.quiet:
                logger.info(f" 从文件 {args.target}  中读取到 {len(targets)} 个目标")
            
            auditor.analyze_targets(targets)
        else:
            auditor.analyze_targets([args.target])
        
        if auditor.save_results():
            sys.exit(0)
        else:
            sys.exit(1)
    except KeyboardInterrupt:
        if not args.quiet:
            print(f"\n{Fore.YELLOW}[!] 用户中断操作{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        if not args.quiet:
            logger.error(f"{Fore.RED} 发生致命错误: {e}{Style.RESET_ALL}")
        sys.exit(1)

def _enhanced_vulnerability_scan(self, content: str, source: str, lines: List[str], target_result: Dict):
        """增强的漏洞扫描"""
        found_vulns = False
        
        # 检测XSS漏洞
        xss_vulns = self._detect_xss(content, source, lines)
        if xss_vulns:
            found_vulns = True
            target_result['vulnerabilities'].extend(xss_vulns)
        
        # 检测开放重定向
        redirect_vulns = self._detect_open_redirect(content, source, lines)
        if redirect_vulns:
            found_vulns = True
            target_result['vulnerabilities'].extend(redirect_vulns)
        
        # 检测SSRF漏洞
        ssrf_vulns = self._detect_ssrf(content, source, lines)
        if ssrf_vulns:
            found_vulns = True
            target_result['vulnerabilities'].extend(ssrf_vulns)
        
        
        if found_vulns and not self.quiet:
            logger.info(f"{Fore.CYAN}[+] 在 {source} 中发现 {len(target_result['vulnerabilities'])} 个潜在漏洞{Style.RESET_ALL}")

def _detect_specific_redirects(self, content: str, source: str, lines: List[str]) -> List[Dict]:
        vulns = []
        
        # 检测 location.replace( 参数) 模式
        replace_pattern = re.compile(r'location\.replace\s*\(([^)]+)\)')
        for match in replace_pattern.finditer(content):
            param = match.group(1)
            if 'location.search' in param or 'URLSearchParams' in param:
                line_num = self._get_line_number(content, match.start(),  lines)
                vulns.append({
                    'type': 'Unvalidated Redirect',
                    'source': source,
                    'line': line_num,
                    'code': match.group(0),
                    'description': "未经验证的重定向: 直接使用URL参数进行页面跳转",
                    'severity': 'high'
                })
        
        return vulns
        
        # 检测 location.replace( 参数) 模式
        replace_pattern = re.compile(r'location\.replace\s*\(([^)]+)\)')
        for match in replace_pattern.finditer(content):
            param = match.group(1)
            if 'location.search' in param or 'URLSearchParams' in param:
                line_num = self._get_line_number(content, match.start(),  lines)
                vulns.append({
                    'type': 'Unvalidated Redirect',
                    'source': source,
                    'line': line_num,
                    'code': match.group(0),
                    'description': "未经验证的重定向: 直接使用URL参数进行页面跳转",
                    'severity': 'high'
                })
        
        return vulns
    
        # 检测 location.replace( 参数) 模式
        replace_pattern = re.compile(r'location\.replace\s*\(([^)]+)\)')
        for match in replace_pattern.finditer(content):
            param = match.group(1)
            if 'location.search' in param or 'URLSearchParams' in param:
                line_num = self._get_line_number(content, match.start(),  lines)
                vulns.append({
                    'type': 'Unvalidated Redirect',
                    'source': source,
                    'line': line_num,
                    'code': match.group(0),
                    'description': "未经验证的重定向: 直接使用URL参数进行页面跳转",
                    'severity': 'high'
                })
    
        return vulns
 
if __name__ == '__main__':
    main()
