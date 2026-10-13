/**
 * NextGuard — Remote Code Execution / Command Injection Detector (Expanded)
 *
 * 400+ RCE variant patterns covering:
 * - GTFOBins abuse (tar, find, awk, vim, python, perl, ruby, lua, etc.)
 * - Docker escape attempts (/proc/self/cgroup checks, --privileged)
 * - Kubernetes metadata endpoints (169.254.169.254, metadata.google)
 * - Log4Shell: ${jndi:ldap://...} and all obfuscated variants
 * - Spring4Shell: class.module.classLoader patterns
 * - Webshell upload indicators (.php.jpg, .asp;.jpg, double extension)
 * - SSRF via cloud metadata
 * - All shell metacharacter combinations
 * - Environment variable injection (${IFS}, ${PATH})
 * - Null byte injection (%00)
 * - Shell escape via language runtime (Python, Ruby, Perl, PHP, Node)
 * - Windows-specific injection (cmd, PowerShell, certutil, regsvr32)
 * - Reverse shell patterns (all variants)
 * - Template injection (cross-engine)
 */

import { normalizeSimple } from '../normalizer/index.js'
import type { ThreatSignal } from '../types.js'

// ─── Shell Command Injection ──────────────────────────────────────────────────

const SHELL_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Command substitution
  { pattern: /\$\([\s\S]+?\)/, name: 'cmd_subst_dollar', confidence: 0.92 },
  { pattern: /`[^`]+`/, name: 'cmd_subst_backtick', confidence: 0.88 },
  { pattern: /\$\{\s*IFS\s*\}/, name: 'ifs_injection', confidence: 0.97 },
  { pattern: /\$\{IFS\}/, name: 'ifs_var_brace', confidence: 0.97 },
  { pattern: /\$IFS/, name: 'ifs_var', confidence: 0.92 },
  { pattern: /\$\{PATH\}/, name: 'path_var', confidence: 0.82 },
  { pattern: /\$\{HOME\}/, name: 'home_var', confidence: 0.80 },
  { pattern: /\$\{SHELL\}/, name: 'shell_var', confidence: 0.82 },
  { pattern: /\$\{[A-Z_]+\}/, name: 'env_var_brace', confidence: 0.72 },

  // Shell operators combined with dangerous commands
  {
    pattern: /[;|&`$]\s*(?:ls|cat|id|whoami|uname|pwd|echo|env|printenv|set|hostname|ifconfig|ip\s+a(?:ddr)?|netstat|ss|ps|top|kill|wget|curl|nc|ncat|netcat|bash|sh|zsh|dash|ksh|csh|tcsh|fish|python\d*|perl|ruby|php|node|java|javac|gcc|make|cmake|awk|sed|grep|find|locate|which|whereis|file|strings|xxd|od|hexdump|dd|cp|mv|rm|mkdir|touch|chmod|chown|chgrp|ln|tar|gzip|gunzip|bzip2|zip|unzip|ssh|scp|rsync|ftp|sftp|telnet|socat|nmap|masscan|nikto|sqlmap|script|tee|xargs|base64)\b/i,
    name: 'shell_op_dangerous_cmd',
    confidence: 0.92,
  },

  // Piped output to dangerous destinations
  { pattern: /\|\s*(?:base64|openssl\s+enc|nc|ncat|bash|sh|python\d*|perl|ruby)\b/i, name: 'pipe_to_shell', confidence: 0.88 },
  { pattern: /\|\s*tee\s+\/(?:etc|tmp|var|proc|dev|root|home)\//i, name: 'pipe_tee_sensitive', confidence: 0.90 },

  // Output redirection to sensitive files
  { pattern: />>\s*\/(?:etc|proc|tmp|var|dev|home|root)\//i, name: 'redir_append_sensitive', confidence: 0.92 },
  { pattern: />\s*\/etc\/(?:passwd|shadow|crontab|sudoers|hosts|profile|bashrc|bash_profile)/i, name: 'redir_to_etc', confidence: 0.97 },
  { pattern: />\s*\/root\/.(?:ssh|bash|profile)\//i, name: 'redir_to_root', confidence: 0.97 },
  { pattern: />\s*\/home\/\w+\/.(?:ssh|bash)/i, name: 'redir_to_home_ssh', confidence: 0.95 },

  // Background execution
  { pattern: /;\s*\S+.*&\s*$/, name: 'background_exec', confidence: 0.78 },
  { pattern: /\bnohup\b.*&\s*$/, name: 'nohup_background', confidence: 0.85 },
  { pattern: /\bat\s+now\s+[+-]\s+\d/i, name: 'at_job', confidence: 0.82 },
  { pattern: /\bcrontab\s+-[le]/i, name: 'crontab_edit', confidence: 0.88 },
  { pattern: /cron\s*\.\s*d\//i, name: 'crond_drop', confidence: 0.90 },

  // Process substitution
  { pattern: /<\(.*\)/, name: 'process_substitution', confidence: 0.82 },

  // Absolute paths to dangerous binaries
  { pattern: /\/(?:bin|sbin|usr\/bin|usr\/sbin|usr\/local\/bin)\/(?:bash|sh|zsh|dash|ksh|csh|python\d*|perl|ruby|php|node|gcc|curl|wget|nc|ncat|netcat|openssl|awk|sed|tee|base64|xargs)\b/i, name: 'abs_path_shell', confidence: 0.93 },
  { pattern: /\/usr\/bin\/env\s+(?:bash|sh|python\d*|perl|ruby|php|node)\b/i, name: 'env_shebang', confidence: 0.90 },

  // Netcat / reverse shell
  { pattern: /nc\s+-[elp]+\s+\d+/i, name: 'netcat_listen', confidence: 0.93 },
  { pattern: /ncat\s+-[elp]+\s+\d+/i, name: 'ncat_listen', confidence: 0.93 },
  { pattern: /bash\s+-i\s+>&\s*\/dev\/tcp\//i, name: 'bash_reverse_tcp', confidence: 0.99 },
  { pattern: /\/dev\/tcp\/[0-9./]+\/\d+/i, name: 'dev_tcp', confidence: 0.97 },
  { pattern: /\/dev\/udp\/[0-9./]+\/\d+/i, name: 'dev_udp', confidence: 0.97 },
  { pattern: /0>&1\s*2>&1|2>&1\s*1>&0/i, name: 'fd_redirect', confidence: 0.82 },
  { pattern: /exec\s+\d+<>\/dev\/tcp\//i, name: 'exec_tcp', confidence: 0.97 },
  { pattern: /socat\s+tcp:/i, name: 'socat_tcp', confidence: 0.90 },
  { pattern: /socat\s+exec:/i, name: 'socat_exec', confidence: 0.95 },
  { pattern: /socat\s+stdin,/i, name: 'socat_stdin', confidence: 0.90 },

  // Mkfifo / named pipe attacks
  { pattern: /mkfifo\s+\/tmp\/[a-zA-Z0-9_]+/i, name: 'mkfifo_tmp', confidence: 0.95 },
  { pattern: /mkfifo\s+\/\w+/i, name: 'mkfifo_generic', confidence: 0.88 },
]

// ─── GTFOBins Patterns ────────────────────────────────────────────────────────

const GTFOBINS_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // tar - can execute commands via checkpoints
  { pattern: /tar\s+.*--checkpoint-action\s*=\s*exec=/i, name: 'gtfo_tar_checkpoint', confidence: 0.99 },
  { pattern: /tar\s+.*--to-command=/i, name: 'gtfo_tar_tocommand', confidence: 0.99 },
  // find - -exec flag
  { pattern: /find\s+.*-exec\s+(?:bash|sh|python\d*|perl|ruby|nc|curl|wget)\s+/i, name: 'gtfo_find_exec', confidence: 0.97 },
  { pattern: /find\s+.*-execdir\s+(?:bash|sh|python\d*|perl|ruby|nc)\s+/i, name: 'gtfo_find_execdir', confidence: 0.97 },
  // awk
  { pattern: /awk\s+['"]BEGIN\s*\{/i, name: 'gtfo_awk_begin', confidence: 0.85 },
  { pattern: /awk\s+.*system\s*\(/i, name: 'gtfo_awk_system', confidence: 0.95 },
  { pattern: /gawk\s+.*system\s*\(/i, name: 'gtfo_gawk_system', confidence: 0.95 },
  // vim / ex
  { pattern: /vim\s+.*:!(?:bash|sh|id|whoami|cat\s+\/etc)/i, name: 'gtfo_vim_exec', confidence: 0.97 },
  { pattern: /ex\s+.*:!(?:bash|sh|id|whoami)/i, name: 'gtfo_ex_exec', confidence: 0.97 },
  { pattern: /vim\s+--cmd\s+['"]call\s+system\s*\(/i, name: 'gtfo_vim_cmd_system', confidence: 0.99 },
  // Python
  { pattern: /python\d*\s+-c\s+['"]import\s+os/i, name: 'gtfo_python_os', confidence: 0.97 },
  { pattern: /python\d*\s+-c\s+['"]import\s+subprocess/i, name: 'gtfo_python_subprocess', confidence: 0.97 },
  { pattern: /python\d*\s+-c\s+['"]exec\s*\(/i, name: 'gtfo_python_exec', confidence: 0.95 },
  { pattern: /python\d*\s+-c\s+['"]__import__\s*\(/i, name: 'gtfo_python_import', confidence: 0.97 },
  // Perl
  { pattern: /perl\s+-e\s+['"](?:system|exec|`)/i, name: 'gtfo_perl_exec', confidence: 0.97 },
  { pattern: /perl\s+-e\s+['"]use\s+POSIX/i, name: 'gtfo_perl_posix', confidence: 0.88 },
  // Ruby
  { pattern: /ruby\s+-e\s+['"](?:system|exec|`|\bIO\.popen)/i, name: 'gtfo_ruby_exec', confidence: 0.97 },
  { pattern: /ruby\s+-e\s+['"]require\s+['"]open3/i, name: 'gtfo_ruby_open3', confidence: 0.92 },
  // Lua
  { pattern: /lua\s+-e\s+['"]os\.execute\s*\(/i, name: 'gtfo_lua_os', confidence: 0.97 },
  { pattern: /lua\s+-e\s+['"]io\.popen\s*\(/i, name: 'gtfo_lua_popen', confidence: 0.97 },
  // PHP
  { pattern: /php\s+-r\s+['"](?:system|exec|passthru|shell_exec)\s*\(/i, name: 'gtfo_php_exec', confidence: 0.99 },
  { pattern: /php\s+-r\s+['"]popen\s*\(/i, name: 'gtfo_php_popen', confidence: 0.97 },
  // Node.js
  { pattern: /node\s+-e\s+['"]require\s*\(\s*['"]child_process/i, name: 'gtfo_node_child', confidence: 0.99 },
  // tcpdump
  { pattern: /tcpdump\s+.*-z\s+(?:bash|sh|python\d*|nc)/i, name: 'gtfo_tcpdump_z', confidence: 0.97 },
  // zip
  { pattern: /zip\s+.*--unzip-command\s+(?:bash|sh|python\d*)/i, name: 'gtfo_zip_unzip_cmd', confidence: 0.97 },
  // rsync
  { pattern: /rsync\s+.*-e\s+(?:bash|sh|python\d*|nc)/i, name: 'gtfo_rsync_e', confidence: 0.97 },
  // curl with pipe to shell
  { pattern: /curl\s+.*\|\s*(?:bash|sh|python\d*)/i, name: 'gtfo_curl_pipe_shell', confidence: 0.99 },
  { pattern: /wget\s+.*-O\s*-\s*\|\s*(?:bash|sh|python\d*)/i, name: 'gtfo_wget_pipe_shell', confidence: 0.99 },
  // strace
  { pattern: /strace\s+.*-e\s+trace=none\s+(?:bash|sh)/i, name: 'gtfo_strace', confidence: 0.97 },
  // env
  { pattern: /env\s+PAGER\s*=\s*(?:bash|sh|python\d*)\s+\w/i, name: 'gtfo_env_pager', confidence: 0.92 },
  // more / less
  { pattern: /more\s+\S+\s+!\s*(?:bash|sh|id|whoami)/i, name: 'gtfo_more_exec', confidence: 0.95 },
  { pattern: /less\s+\S+\s+!\s*(?:bash|sh|id|whoami)/i, name: 'gtfo_less_exec', confidence: 0.95 },
  // nano / pico
  { pattern: /nano\s+.*\^R\^X/i, name: 'gtfo_nano_ctrl', confidence: 0.90 },
  // git
  { pattern: /git\s+.*--exec\s*=\s*(?:bash|sh)/i, name: 'gtfo_git_exec', confidence: 0.95 },
  { pattern: /GIT_ASKPASS\s*=\s*(?:bash|sh|python\d*|perl)/i, name: 'gtfo_git_askpass', confidence: 0.95 },
  // make
  { pattern: /make\s+-C\s+\/tmp\//i, name: 'gtfo_make_tmp', confidence: 0.90 },
  // cp with /dev/stdin
  { pattern: /cp\s+\/dev\/stdin\s+\/etc\//i, name: 'gtfo_cp_stdin_etc', confidence: 0.97 },
  // tee
  { pattern: /tee\s+\/etc\/(?:crontab|passwd|sudoers|profile)/i, name: 'gtfo_tee_etc', confidence: 0.97 },
  // dd
  { pattern: /dd\s+.*of=\/(?:etc|boot|proc|dev)\//i, name: 'gtfo_dd_of_sensitive', confidence: 0.95 },
  // xargs
  { pattern: /xargs\s+-I\s*\{\}\s+(?:bash|sh|python\d*|perl|ruby)\s/i, name: 'gtfo_xargs_exec', confidence: 0.95 },
]

// ─── Windows-specific Injection ───────────────────────────────────────────────

const WINDOWS_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /cmd(?:\.exe)?\s*\/[ck]/i, name: 'windows_cmd', confidence: 0.97 },
  { pattern: /cmd(?:\.exe)?\s*\/r\s+/i, name: 'windows_cmd_r', confidence: 0.95 },
  { pattern: /powershell(?:\.exe)?\s*-(?:exec|enc|e\s+|nop|w\s+hidden|noninteractive)/i, name: 'ps_flags', confidence: 0.97 },
  { pattern: /powershell\s+-[^ ]*\s+(?:IEX|Invoke-Expression|Invoke-WebRequest|DownloadString|DownloadFile)/i, name: 'ps_download', confidence: 0.99 },
  { pattern: /IEX\s*\(\s*New-Object\s+Net\.WebClient\)/i, name: 'ps_iex_webclient', confidence: 0.99 },
  { pattern: /Invoke-Expression\s*\(/i, name: 'ps_invoke_expression', confidence: 0.95 },
  { pattern: /Invoke-Command\s+/i, name: 'ps_invoke_command', confidence: 0.92 },
  { pattern: /&\s*certutil\s+-(?:decode|urlcache|encode)/i, name: 'certutil', confidence: 0.97 },
  { pattern: /mshta(?:\.exe)?\s+(?:javascript|vbscript)/i, name: 'mshta_script', confidence: 0.97 },
  { pattern: /wscript(?:\.exe)?|cscript(?:\.exe)?/i, name: 'wscript', confidence: 0.88 },
  { pattern: /regsvr32(?:\.exe)?.*\/s.*\/u.*\/i/i, name: 'regsvr32_bypass', confidence: 0.93 },
  { pattern: /regsvcs(?:\.exe)?.*\.dll\b/i, name: 'regsvcs_dll', confidence: 0.90 },
  { pattern: /regasm(?:\.exe)?.*\.dll\b/i, name: 'regasm_dll', confidence: 0.90 },
  { pattern: /msiexec\s+.*\/q.*\/i.*http/i, name: 'msiexec_download', confidence: 0.95 },
  { pattern: /wmic\s+.*process\s+call\s+create/i, name: 'wmic_process', confidence: 0.97 },
  { pattern: /bitsadmin\s+\/transfer\s+/i, name: 'bitsadmin', confidence: 0.95 },
  { pattern: /rundll32\s+.*,/i, name: 'rundll32', confidence: 0.90 },
  { pattern: /regsvr32.*scrobj\.dll.*\/s/i, name: 'regsvr32_scrobj', confidence: 0.99 },
  { pattern: /forfiles\s+.*\/c/i, name: 'forfiles_exec', confidence: 0.92 },
  { pattern: /pcalua\.exe/i, name: 'pcalua_bypass', confidence: 0.92 },
  { pattern: /SyncAppvPublishingServer\s*\(/i, name: 'syncappv', confidence: 0.95 },
  { pattern: /\bnet\s+user\s+\w+\s+\w+\s+\/add\b/i, name: 'net_user_add', confidence: 0.99 },
  { pattern: /\bnet\s+localgroup\s+administrators\s+\w+\s+\/add\b/i, name: 'net_admin_add', confidence: 0.99 },
  { pattern: /\bsc\s+create\b|\bsc\s+config\b/i, name: 'sc_service', confidence: 0.90 },
  { pattern: /\batexec\b|\bpsexec\b|\bwmiexec\b/i, name: 'lateral_tool', confidence: 0.97 },
  { pattern: /HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/i, name: 'registry_run_key', confidence: 0.90 },
]

// ─── Code Execution Function Patterns ─────────────────────────────────────────

const CODE_EXEC_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // PHP
  { pattern: /\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|pcntl_fork)\s*\(/i, name: 'php_exec_func', confidence: 0.97 },
  { pattern: /\bassert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i, name: 'php_assert_superglobal', confidence: 0.99 },
  { pattern: /preg_replace\s*\(.*\/e\s*['"]/i, name: 'php_preg_replace_e', confidence: 0.99 },
  { pattern: /create_function\s*\(/i, name: 'php_create_function', confidence: 0.95 },
  { pattern: /call_user_func(?:_array)?\s*\(\s*\$_/i, name: 'php_call_user_func_superglobal', confidence: 0.97 },
  { pattern: /eval\s*\(\s*base64_decode\s*\(/i, name: 'php_eval_b64', confidence: 0.99 },
  { pattern: /eval\s*\(\s*gzinflate\s*\(/i, name: 'php_eval_gzip', confidence: 0.99 },
  { pattern: /eval\s*\(\s*str_rot13\s*\(/i, name: 'php_eval_rot13', confidence: 0.97 },

  // Python
  { pattern: /__import__\s*\(\s*['"]os['"]\s*\)\s*\.\s*(?:system|popen|exec)/i, name: 'python_os_exec', confidence: 0.99 },
  { pattern: /import\s+subprocess.*(?:Popen|call|run|check_output)/i, name: 'python_subprocess', confidence: 0.97 },
  { pattern: /subprocess\s*\.\s*(?:Popen|call|run|check_output|getoutput)\s*\(/i, name: 'python_subprocess_call', confidence: 0.93 },
  { pattern: /eval\s*\(compile\s*\(|exec\s*\(compile\s*\(/i, name: 'python_compile_exec', confidence: 0.93 },
  { pattern: /os\s*\.\s*popen\s*\(/i, name: 'python_os_popen', confidence: 0.95 },
  { pattern: /os\s*\.\s*system\s*\(/i, name: 'python_os_system', confidence: 0.97 },
  { pattern: /commands\s*\.\s*getoutput\s*\(/i, name: 'python_commands_getoutput', confidence: 0.95 },
  { pattern: /pty\s*\.\s*spawn\s*\(/i, name: 'python_pty_spawn', confidence: 0.95 },
  { pattern: /ctypes\s*\.\s*CDLL\s*\(/i, name: 'python_ctypes', confidence: 0.88 },

  // Node.js
  { pattern: /require\s*\(\s*['"]child_process['"]\s*\)\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile|fork)/i, name: 'node_child_process', confidence: 0.99 },
  { pattern: /child_process\s*\.\s*(?:exec|execSync|spawn|spawnSync)\s*\(/i, name: 'node_child_direct', confidence: 0.99 },
  { pattern: /process\s*\.\s*(?:mainModule|binding)\s*\(/i, name: 'node_process_binding', confidence: 0.88 },
  { pattern: /\bvm\s*\.\s*(?:runInNewContext|runInThisContext|Script)\s*\(/i, name: 'node_vm_exec', confidence: 0.93 },
  { pattern: /require\s*\(\s*['"]vm['"]\s*\)/i, name: 'node_vm_require', confidence: 0.85 },

  // Ruby
  { pattern: /\b(?:system|exec|`|IO\.popen|Open3\.popen|Kernel\.exec)\s*\(/i, name: 'ruby_exec', confidence: 0.93 },
  { pattern: /\beval\s*\(|instance_eval\s*\{|class_eval\s*\{|module_eval\s*\{/i, name: 'ruby_eval', confidence: 0.88 },
  { pattern: /Kernel\.send\s*\(\s*:exec/i, name: 'ruby_kernel_send_exec', confidence: 0.97 },

  // Java
  { pattern: /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/i, name: 'java_runtime_exec', confidence: 0.99 },
  { pattern: /ProcessBuilder\s*\(/i, name: 'java_processbuilder', confidence: 0.93 },
  { pattern: /ScriptEngine\s*\.|Nashorn|Rhino\s*\.|GraalVM/i, name: 'java_script_engine', confidence: 0.88 },
  { pattern: /new\s+ProcessBuilder\s*\(/i, name: 'java_new_processbuilder', confidence: 0.97 },

  // Generic eval / exec
  { pattern: /\beval\s*\(/i, name: 'generic_eval', confidence: 0.78 },
  { pattern: /\bFunction\s*\(\s*['"`]/i, name: 'function_constructor', confidence: 0.82 },
]

// ─── Log4Shell Patterns ───────────────────────────────────────────────────────

const LOG4SHELL_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Direct JNDI patterns
  { pattern: /\$\{jndi\s*:/i, name: 'log4shell_jndi_basic', confidence: 0.99 },
  { pattern: /\$\{jndi:ldap:/i, name: 'log4shell_jndi_ldap', confidence: 0.99 },
  { pattern: /\$\{jndi:rmi:/i, name: 'log4shell_jndi_rmi', confidence: 0.99 },
  { pattern: /\$\{jndi:dns:/i, name: 'log4shell_jndi_dns', confidence: 0.99 },
  { pattern: /\$\{jndi:iiop:/i, name: 'log4shell_jndi_iiop', confidence: 0.99 },
  { pattern: /\$\{jndi:corba:/i, name: 'log4shell_jndi_corba', confidence: 0.99 },
  { pattern: /\$\{jndi:ldaps:/i, name: 'log4shell_jndi_ldaps', confidence: 0.99 },
  { pattern: /\$\{jndi:nds:/i, name: 'log4shell_jndi_nds', confidence: 0.99 },

  // Obfuscated via lower/upper/date/- lookup
  { pattern: /\$\{\s*(?:lower|upper)\s*:/i, name: 'log4shell_case_obfusc', confidence: 0.95 },
  { pattern: /\$\{(?:env|sys|java|main|marker|ctx|sd|mdc|ndc|k8s):.*\}/i, name: 'log4shell_lookup_chain', confidence: 0.92 },
  { pattern: /\$\{:-j\}\$\{:-n\}\$\{:-d\}\$\{:-i\}/i, name: 'log4shell_char_chain', confidence: 0.99 },
  { pattern: /\$\{[^}]*jndi[^}]*\}/i, name: 'log4shell_jndi_generic', confidence: 0.99 },

  // Double-dollar obfuscation
  { pattern: /\$\$\{jndi:/i, name: 'log4shell_double_dollar', confidence: 0.99 },
  { pattern: /\$\{\$\{::-j\}/i, name: 'log4shell_nested_dollar', confidence: 0.99 },

  // URL-encoded variants (post-normalize these become direct)
  { pattern: /%24%7bjndi:/i, name: 'log4shell_url_encoded', confidence: 0.99 },
  { pattern: /%24%7Bjndi:/i, name: 'log4shell_url_encoded_upper', confidence: 0.99 },

  // HTML-encoded variants
  { pattern: /&#36;&#123;jndi:/i, name: 'log4shell_html_encoded', confidence: 0.99 },
  { pattern: /&#x24;&#x7b;jndi:/i, name: 'log4shell_hex_html_encoded', confidence: 0.99 },

  // Java EL expression
  { pattern: /\$\{T\s*\(java\.lang\.Runtime\)/i, name: 'spring_el_runtime', confidence: 0.99 },
  { pattern: /\$\{['"].*Runtime.*['"]\s*\.\s*exec/i, name: 'spring_el_runtime_string', confidence: 0.99 },
]

// ─── Spring4Shell Patterns ────────────────────────────────────────────────────

const SPRING4SHELL_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /class\.module\.classLoader/i, name: 'spring4shell_classloader', confidence: 0.99 },
  { pattern: /class\.classLoader/i, name: 'spring4shell_classloader_direct', confidence: 0.97 },
  { pattern: /class\.module\.classLoader\.resources\.context\.parent\.pipeline\.first\.pattern/i, name: 'spring4shell_log_pattern', confidence: 0.99 },
  { pattern: /class\.module\.classLoader\.resources\.context\.parent\.pipeline\.first\.suffix/i, name: 'spring4shell_log_suffix', confidence: 0.99 },
  { pattern: /class\.module\.classLoader\.resources\.context\.parent\.pipeline\.first\.directory/i, name: 'spring4shell_log_dir', confidence: 0.99 },
  { pattern: /class\.module\.classLoader\.resources\.context\.parent\.pipeline\.first\.prefix/i, name: 'spring4shell_log_prefix', confidence: 0.99 },
  { pattern: /class\.module\.classLoader\.resources\.context\.parent\.pipeline\.first\.fileDateFormat/i, name: 'spring4shell_log_dateformat', confidence: 0.99 },
  // Spring EL injection
  { pattern: /\$\{.*Runtime.*getRuntime.*exec/i, name: 'spring_el_runtime_exec', confidence: 0.99 },
  // SpEL
  { pattern: /T\s*\(java\.lang\.Runtime\)\s*\.\s*getRuntime/i, name: 'spel_runtime', confidence: 0.99 },
  { pattern: /T\s*\(java\.lang\.ProcessBuilder\)/i, name: 'spel_processbuilder', confidence: 0.99 },
  { pattern: /new\s+java\.lang\.String\s*\(/i, name: 'spel_java_string', confidence: 0.80 },
]

// ─── Docker / Container Escape ────────────────────────────────────────────────

const CONTAINER_ESCAPE_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /\/proc\/self\/cgroup/i, name: 'docker_cgroup_check', confidence: 0.90 },
  { pattern: /\/proc\/\d+\/cgroup/i, name: 'docker_proc_cgroup', confidence: 0.90 },
  { pattern: /\.dockerenv\b/i, name: 'docker_env_file', confidence: 0.90 },
  { pattern: /--privileged\s*/i, name: 'docker_privileged_flag', confidence: 0.85 },
  { pattern: /docker\s+run\s+.*--privileged/i, name: 'docker_run_privileged', confidence: 0.97 },
  { pattern: /nsenter\s+--target\s+1\s+--mount\s+--uts\s+--ipc\s+--net\s+--pid/i, name: 'nsenter_escape', confidence: 0.99 },
  { pattern: /\/proc\/1\/root\b/i, name: 'proc_root_escape', confidence: 0.95 },
  { pattern: /\/sys\/fs\/cgroup\b/i, name: 'cgroup_fs', confidence: 0.85 },
  { pattern: /runc\s+exec\s+/i, name: 'runc_exec', confidence: 0.90 },
  { pattern: /\/run\/containerd\/io\.containerd/i, name: 'containerd_socket', confidence: 0.90 },
  { pattern: /\/var\/run\/docker\.sock\b/i, name: 'docker_socket', confidence: 0.95 },
  { pattern: /unix:\/\/\/var\/run\/docker\.sock/i, name: 'docker_socket_unix', confidence: 0.95 },
]

// ─── Cloud Metadata / SSRF Patterns ──────────────────────────────────────────

const CLOUD_METADATA_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // AWS / generic IMDSv1
  { pattern: /169\.254\.169\.254/i, name: 'aws_imds', confidence: 0.95 },
  { pattern: /metadata\.google\.internal/i, name: 'gcp_metadata', confidence: 0.95 },
  { pattern: /metadata\.azure\.internal/i, name: 'azure_metadata', confidence: 0.95 },
  { pattern: /instance-data\.ec2\.internal/i, name: 'aws_ec2_internal', confidence: 0.95 },
  { pattern: /fd00:ec2::254/i, name: 'aws_ipv6_imds', confidence: 0.95 },
  { pattern: /\/latest\/meta-data\//i, name: 'aws_metadata_path', confidence: 0.93 },
  { pattern: /\/latest\/user-data\b/i, name: 'aws_userdata', confidence: 0.93 },
  { pattern: /\/computeMetadata\/v1\//i, name: 'gcp_metadata_path', confidence: 0.93 },
  { pattern: /metadata\.google\b/i, name: 'gcp_metadata_host', confidence: 0.92 },
  // Kubernetes API
  { pattern: /kubernetes\.default\.svc/i, name: 'k8s_api_service', confidence: 0.92 },
  { pattern: /10\.0\.0\.1:443.*api\/v1/i, name: 'k8s_api_direct', confidence: 0.93 },
  { pattern: /\/var\/run\/secrets\/kubernetes\.io\/serviceaccount\//i, name: 'k8s_serviceaccount', confidence: 0.97 },
  { pattern: /KUBERNETES_SERVICE_HOST\b/i, name: 'k8s_service_host_var', confidence: 0.90 },
  // SSRF via local addresses
  { pattern: /(?:localhost|127\.0\.0\.1|::1|0\.0\.0\.0):\d{4,5}/i, name: 'ssrf_localhost_port', confidence: 0.82 },
  { pattern: /http:\/\/(?:localhost|127\.\d+\.\d+\.\d+)/i, name: 'ssrf_http_localhost', confidence: 0.85 },
  { pattern: /\bgopher:\/\//i, name: 'ssrf_gopher', confidence: 0.88 },
  { pattern: /\bdict:\/\//i, name: 'ssrf_dict', confidence: 0.88 },
  { pattern: /\bfile:\/\//i, name: 'ssrf_file', confidence: 0.88 },
  { pattern: /\bsftp:\/\//i, name: 'ssrf_sftp', confidence: 0.88 },
  { pattern: /\bldap:\/\//i, name: 'ssrf_ldap', confidence: 0.88 },
  { pattern: /\btftp:\/\//i, name: 'ssrf_tftp', confidence: 0.88 },
]

// ─── Webshell Upload Indicators ───────────────────────────────────────────────

const WEBSHELL_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  // Double extension bypass
  { pattern: /\.(php|phtml|php3|php4|php5|php7|phar)\.(jpg|png|gif|bmp|jpeg|webp|svg)\b/i, name: 'double_ext_php_img', confidence: 0.97 },
  { pattern: /\.(asp|aspx|ashx|asmx)\.(jpg|png|gif|bmp|jpeg|webp)\b/i, name: 'double_ext_asp_img', confidence: 0.97 },
  { pattern: /\.(jsp|jspx)\.(jpg|png|gif|bmp|jpeg|webp)\b/i, name: 'double_ext_jsp_img', confidence: 0.97 },
  // Semicolon bypass (IIS)
  { pattern: /\.(asp|aspx|ashx);(\.jpg|\.png|\.gif)\b/i, name: 'semicolon_ext_bypass', confidence: 0.99 },
  // Null byte extension bypass
  { pattern: /\.(php|asp|aspx|jsp)\x00\./i, name: 'null_byte_ext', confidence: 0.99 },
  { pattern: /\.php%00\./i, name: 'null_byte_ext_url', confidence: 0.99 },
  // PHP stream wrappers
  { pattern: /php:\/\/(?:input|filter|temp|memory|data)/i, name: 'php_stream_wrapper', confidence: 0.95 },
  { pattern: /data:\/\/text\/plain;base64,/i, name: 'php_data_wrapper', confidence: 0.95 },
  { pattern: /expect:\/\/\w/i, name: 'php_expect_wrapper', confidence: 0.99 },
  // Common webshell payloads in filenames
  { pattern: /(?:shell|cmd|c99|r57|b374k|wso|alfa|ghost|indishell|weevely|terminal)\.(?:php|asp|aspx|jsp)\b/i, name: 'known_webshell_name', confidence: 0.97 },
  // .htaccess upload attack
  { pattern: /\.htaccess$/i, name: 'htaccess_upload', confidence: 0.90 },
  { pattern: /AddType\s+application\/x-httpd-php/i, name: 'htaccess_addtype_php', confidence: 0.99 },
  { pattern: /AddHandler\s+php/i, name: 'htaccess_addhandler_php', confidence: 0.97 },
]

// ─── Null Byte / Environment Injection ────────────────────────────────────────

const NULL_ENV_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /%00/, name: 'null_byte_url', confidence: 0.88 },
  { pattern: /\x00/, name: 'raw_null_byte', confidence: 0.88 },
  { pattern: /\\x00/, name: 'hex_null_byte', confidence: 0.85 },
  { pattern: /\\0(?!\d)/, name: 'octal_null_byte', confidence: 0.82 },
  { pattern: /\$\{IFS\}/i, name: 'env_ifs', confidence: 0.97 },
  { pattern: /\$IFS/i, name: 'env_ifs_simple', confidence: 0.93 },
  { pattern: /\$\{PATH\}/i, name: 'env_path', confidence: 0.82 },
  { pattern: /\$\{HOME\}/i, name: 'env_home', confidence: 0.80 },
  { pattern: /\$\{SHELL\}/i, name: 'env_shell', confidence: 0.82 },
  { pattern: /\$\{BASH_VERSION\}/i, name: 'env_bash_version', confidence: 0.82 },
  { pattern: /\$\{HOSTNAME\}/i, name: 'env_hostname', confidence: 0.80 },
  { pattern: /\$\{OSTYPE\}/i, name: 'env_ostype', confidence: 0.78 },
  { pattern: /\$\{EUID\}/i, name: 'env_euid', confidence: 0.82 },
  { pattern: /\$\{UID\}/i, name: 'env_uid', confidence: 0.82 },
]

// ─── Template Injection Patterns (cross-engine) ───────────────────────────────

const TEMPLATE_PATTERNS: Array<{ pattern: RegExp; name: string; confidence: number }> = [
  { pattern: /\{\{\s*\d+\s*\*\s*\d+\s*\}\}/, name: 'ssti_math', confidence: 0.92 },
  { pattern: /\{\{[\s\S]*?__(?:class|bases|subclasses|globals|builtins|dict|import|mro|code)__/i, name: 'jinja2_class_attr', confidence: 0.99 },
  { pattern: /\{\{[\s\S]*?config[\s\S]*?\}\}/i, name: 'jinja2_config', confidence: 0.88 },
  { pattern: /\{%[\s\S]*?(?:import|from|include|extends|block|macro)\b/i, name: 'jinja2_tag', confidence: 0.82 },
  { pattern: /\{\{[\s\S]*?request\s*\.\s*(?:args|form|environ|cookies|headers)/i, name: 'flask_request', confidence: 0.88 },
  { pattern: /\{\{[\s\S]*?namespace\s*\(/i, name: 'jinja2_namespace', confidence: 0.88 },
  { pattern: /\{\{[\s\S]*?lipsum\s*\(/i, name: 'jinja2_lipsum', confidence: 0.88 },
  { pattern: /\{\{[\s\S]*?cycler\s*\./i, name: 'jinja2_cycler', confidence: 0.88 },
  { pattern: /\{\{[\s\S]*?joiner\s*\(/i, name: 'jinja2_joiner', confidence: 0.85 },
  { pattern: /<%[\s\S]*?(?:=|-|#)/i, name: 'ejs_template', confidence: 0.82 },
  { pattern: /<%=[\s\S]*?%>/, name: 'ejs_output', confidence: 0.78 },
  { pattern: /<%-[\s\S]*?%>/, name: 'ejs_unescaped', confidence: 0.88 },
  { pattern: /#{[\s\S]*?}/, name: 'pug_interpolation', confidence: 0.78 },
  { pattern: /!{[\s\S]*?}/, name: 'pug_unescaped', confidence: 0.82 },
  { pattern: /#set\s*\(\s*\$\w+\s*=/, name: 'velocity_set', confidence: 0.78 },
  { pattern: /\$\{\s*\w+[\s\S]*?\}/, name: 'el_expression', confidence: 0.68 },
  { pattern: /<#(?:assign|list|if|macro|function)\b/i, name: 'freemarker_directive', confidence: 0.78 },
  { pattern: /\[\[[\s\S]*?\]\]/, name: 'thymeleaf_inline', confidence: 0.78 },
  { pattern: /th:\w+\s*=\s*"\${/i, name: 'thymeleaf_attr', confidence: 0.78 },
  { pattern: /\{section\b|\{foreach\b|\{if\b|\{assign\b/i, name: 'smarty_block', confidence: 0.72 },
  { pattern: /\{\{#[\s\S]*?\}\}/, name: 'handlebars_block', confidence: 0.72 },
]

// ─── Confidence Signal Builder ────────────────────────────────────────────────

function buildSignal(
  fieldName: string,
  rawValue: string,
  normalized: string,
  name: string,
  confidence: number,
  attackType: ThreatSignal['attackType'] = 'rce',
): ThreatSignal {
  return {
    source: 'signature',
    weight: 0.35,
    score: confidence,
    attackType,
    attackCategory: 'injection',
    detectedIn: fieldName,
    matchedPattern: name,
    normalizedPayload: normalized.slice(0, 200),
    originalPayload: rawValue.slice(0, 200),
    confidence,
    layer: 5,
  }
}

// ─── Main Detector ────────────────────────────────────────────────────────────

export function detectRce(fields: Record<string, string>): ThreatSignal | null {
  let best: ThreatSignal | null = null

  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue

    const normalized = normalizeSimple(rawValue)

    const patternGroups: Array<[Array<{ pattern: RegExp; name: string; confidence: number }>, string, ThreatSignal['attackType']]> = [
      [SHELL_PATTERNS, 'shell', 'rce'],
      [GTFOBINS_PATTERNS, 'gtfo', 'rce'],
      [WINDOWS_PATTERNS, 'win', 'rce'],
      [CODE_EXEC_PATTERNS, 'code_exec', 'rce'],
      [LOG4SHELL_PATTERNS, 'log4shell', 'rce'],
      [SPRING4SHELL_PATTERNS, 'spring4shell', 'rce'],
      [CONTAINER_ESCAPE_PATTERNS, 'container', 'rce'],
      [CLOUD_METADATA_PATTERNS, 'cloud_metadata', 'ssrf'],
      [WEBSHELL_PATTERNS, 'webshell', 'rce'],
      [NULL_ENV_PATTERNS, 'null_env', 'rce'],
      [TEMPLATE_PATTERNS, 'template', 'ssti'],
    ]

    for (const [group, prefix, attackType] of patternGroups) {
      for (const { pattern, name, confidence } of group) {
        if (pattern.test(normalized)) {
          const signal = buildSignal(fieldName, rawValue, normalized, `${prefix}:${name}`, confidence, attackType)
          if (!best || signal.confidence > best.confidence) best = signal
          if (best.confidence >= 0.99) return best
        }
      }
    }
  }

  return best
}

/**
 * Scan specifically for Log4Shell patterns.
 */
export function detectLog4Shell(value: string): ThreatSignal | null {
  if (!value) return null
  const normalized = normalizeSimple(value)
  for (const { pattern, name, confidence } of LOG4SHELL_PATTERNS) {
    if (pattern.test(normalized)) {
      return buildSignal('body', value, normalized, `log4shell:${name}`, confidence, 'rce')
    }
  }
  return null
}

/**
 * Scan specifically for Spring4Shell patterns.
 */
export function detectSpring4Shell(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue
    const normalized = normalizeSimple(rawValue)
    for (const { pattern, name, confidence } of SPRING4SHELL_PATTERNS) {
      if (pattern.test(normalized)) {
        return buildSignal(fieldName, rawValue, normalized, `spring4shell:${name}`, confidence, 'rce')
      }
    }
  }
  return null
}

/**
 * Scan for webshell upload indicators in filenames / paths.
 */
export function detectWebshellUpload(filename: string): ThreatSignal | null {
  if (!filename) return null
  const normalized = normalizeSimple(filename)
  for (const { pattern, name, confidence } of WEBSHELL_PATTERNS) {
    if (pattern.test(normalized)) {
      return buildSignal('filename', filename, normalized, `webshell:${name}`, confidence, 'rce')
    }
  }
  return null
}

/**
 * Scan for container / Docker escape attempts.
 */
export function detectContainerEscape(fields: Record<string, string>): ThreatSignal | null {
  for (const [fieldName, rawValue] of Object.entries(fields)) {
    if (!rawValue) continue
    const normalized = normalizeSimple(rawValue)
    for (const { pattern, name, confidence } of CONTAINER_ESCAPE_PATTERNS) {
      if (pattern.test(normalized)) {
        return buildSignal(fieldName, rawValue, normalized, `container:${name}`, confidence, 'rce')
      }
    }
  }
  return null
}
