#!/usr/bin/env python3
"""andork — OSINT recon for external pen tests.

Two modes:
  - metadata: dork search engines for documents on the target domain,
    download them, run exiftool, harvest authors/companies/paths.
  - dork: 174 curated dorks across 14 categories (auth, config,
    secrets, api, admin_tools, backups, errors, ...) — searches only,
    no downloads.

Two search backends (DuckDuckGo via ddgs + Selenium-driven Chrome on
Google), parallel per-engine rate limits. Non-intrusive: only fetches
files that public search engines have already indexed; never crawls
the target.
"""

from __future__ import annotations

import argparse
import hashlib
import html as html_mod
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse as up
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

MIN_SEARCH_DELAY = 30
MIN_DOWNLOAD_DELAY = 30
_CURRENT_YEAR = datetime.now().year

DEFAULT_EXTS = ("pdf", "docx", "xlsx", "pptx", "csv", "zip", "doc")

EXT_PRESETS = {
    "default":   ("pdf", "docx", "xlsx", "pptx", "csv", "zip", "doc"),
    "office":    ("doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp"),
    "sensitive": ("bak", "backup", "old", "swp", "sql", "dump", "db", "sqlite",
                  "env", "conf", "cfg", "ini", "yaml", "yml", "log"),
    "all":       ("pdf", "docx", "xlsx", "pptx", "csv", "zip", "doc", "xls",
                  "ppt", "odt", "ods", "odp", "bak", "old", "sql", "dump",
                  "env", "conf", "cfg", "ini", "yaml", "log"),
}

# Curated dorks for dork mode. Each template uses:
#   {site}   → "site:DOMAIN"
#   {domain} → bare domain (used when target appears in the BODY, not
#              as a site: filter — e.g. cloud-bucket scans)
DORKS_DB = {
    "auth": [
        ("login_pages",       '{site} (inurl:login OR inurl:signin OR inurl:logon OR inurl:auth)'),
        ("admin_panels",      '{site} inurl:admin'),
        ("dashboards",        '{site} (intitle:dashboard OR inurl:dashboard)'),
        ("phpmyadmin",        '{site} (inurl:phpmyadmin OR intitle:phpmyadmin)'),
        ("control_panels",    '{site} (inurl:cpanel OR inurl:webmin OR inurl:plesk)'),
        ("portals",           '{site} (inurl:portal OR intitle:"employee portal")'),
        ("citrix",            '{site} (inurl:Citrix OR intitle:"Citrix Receiver")'),
        ("sso_pages",         '{site} (inurl:sso OR inurl:saml OR inurl:oauth)'),
        ("owa",               '{site} (inurl:owa/auth OR intitle:"Outlook Web")'),
        ("exchange",          '{site} (inurl:ews OR inurl:autodiscover OR intitle:"Exchange")'),
        ("netscaler",         '{site} (inurl:vpn/index.html OR intitle:"NetScaler")'),
        ("anyconnect",        '{site} (inurl:+CSCOE+ OR intitle:"Cisco AnyConnect")'),
        ("watchguard",        '{site} intitle:"WatchGuard Firebox"'),
        ("juniper",           '{site} (inurl:dana/home OR intitle:"Juniper")'),
        ("citrix_storefront", '{site} inurl:Citrix/StoreWeb'),
        ("password_reset",    '{site} (inurl:reset-password OR inurl:forgot-password OR inurl:resetpassword)'),
    ],
    "listings": [
        ("index_of",          '{site} intitle:"index of"'),
        ("dir_listing",       '{site} intitle:"index of" "parent directory"'),
        ("apache_listing",    '{site} intitle:"index of" Apache'),
        ("nginx_listing",     '{site} intitle:"index of" nginx'),
        ("iis_listing",       '{site} intitle:"index of" IIS'),
        ("tomcat_listing",    '{site} intitle:"directory listing" Tomcat'),
        ("docs_listing",      '{site} intitle:"index of" (docs OR documents OR files)'),
        ("ftp_listing",       '{site} (intitle:"index of /pub" OR intitle:"index of /ftp")'),
        ("archive_listing",   '{site} intitle:"index of" (".tar.gz" OR ".zip" OR ".tar")'),
        ("private_listing",   '{site} intitle:"index of" (private OR secret OR confidential)'),
    ],
    "config": [
        ("dotenv",            '{site} (inurl:".env" OR ext:env)'),
        ("git_exposed",       '{site} (inurl:".git/config" OR inurl:".git/HEAD")'),
        ("svn_exposed",       '{site} inurl:".svn"'),
        ("web_config",        '{site} (filetype:config web.config OR inurl:web.config)'),
        ("htaccess",          '{site} inurl:".htaccess"'),
        ("dotfiles",          '{site} (inurl:".bash_history" OR inurl:".ssh" OR inurl:".bashrc")'),
        ("config_files",      '{site} (filetype:cfg OR filetype:conf OR filetype:ini)'),
        ("yaml_secrets",      '{site} (filetype:yaml OR filetype:yml) (secret OR password OR apikey)'),
        ("docker_compose",    '{site} (filetype:yml docker-compose OR inurl:docker-compose.yml)'),
        ("k8s_configs",       '{site} (filetype:yaml kubernetes OR filetype:yml kind:)'),
        ("xml_configs",       '{site} filetype:xml (inurl:config OR inurl:settings)'),
        ("json_secrets",      '{site} filetype:json (apikey OR api_key OR secret OR password)'),
        ("web_xml",           '{site} (inurl:WEB-INF/web.xml OR filetype:xml inurl:WEB-INF)'),
        ("app_properties",    '{site} (inurl:application.properties OR filetype:properties)'),
        ("terraform",         '{site} (filetype:tf OR filetype:tfvars OR inurl:terraform.tfstate)'),
        ("ansible",           '{site} (filetype:yml inurl:group_vars OR filetype:yml inurl:host_vars)'),
        ("npmrc",             '{site} inurl:".npmrc"'),
        ("composer",          '{site} (filetype:json inurl:composer.json OR filetype:lock inurl:composer.lock)'),
        ("php_config",        '{site} (filetype:php inurl:config OR inurl:wp-config.php)'),
        ("rails_secrets",     '{site} (filetype:yml inurl:secrets.yml OR filetype:yml inurl:database.yml)'),
        ("django_settings",   '{site} (filetype:py inurl:settings.py OR filetype:py inurl:local_settings)'),
    ],
    "backups": [
        ("bak_files",         '{site} (filetype:bak OR ext:bak OR ext:old OR ext:backup)'),
        ("sql_dumps",         '{site} (filetype:sql OR ext:sql OR ext:dump)'),
        ("db_files",          '{site} (filetype:db OR ext:sqlite)'),
        ("zip_archives",      '{site} (filetype:zip OR filetype:tar OR filetype:gz) (backup OR dump)'),
        ("swap_files",        '{site} (ext:swp OR ext:swo OR ext:tmp)'),
        ("rar_archives",      '{site} (filetype:rar OR filetype:7z OR filetype:bz2) (backup OR dump)'),
        ("dated_archives",    '{site} (intitle:"index of" "' + str(_CURRENT_YEAR) + '" OR intitle:"index of" "' + str(_CURRENT_YEAR - 1) + '") (.zip OR .tar)'),
        ("rsync_paths",       '{site} (inurl:rsync OR intext:"rsync://")'),
        ("mysql_dumps",       '{site} (intext:"-- MySQL dump" OR intext:"-- Server version")'),
        ("postgres_dumps",    '{site} (intext:"-- PostgreSQL database dump")'),
    ],
    "errors": [
        ("phpinfo",           '{site} (intitle:phpinfo OR "PHP Version" "phpinfo()")'),
        ("stack_traces",      '{site} (intext:"Traceback (most recent call last)" OR intext:"Stack trace:")'),
        ("sql_errors",        '{site} (intext:"sql syntax near" OR intext:"You have an error in your SQL syntax")'),
        ("debug_pages",       '{site} (intitle:debug OR inurl:debug=true OR inurl:debug=1)'),
        ("warning_messages",  '{site} (intext:"Warning: include" OR intext:"Warning: require")'),
        ("server_status",     '{site} (intitle:"Apache Status" OR inurl:server-status)'),
        ("django_debug",      '{site} (intitle:"DisallowedHost" OR intext:"DEBUG = True")'),
        ("rails_errors",      '{site} (intext:"ActionController" OR intext:"NoMethodError")'),
        ("dotnet_errors",     '{site} (intext:"Server Error in" OR intext:"System.Web.HttpException")'),
        ("java_exceptions",   '{site} (intext:"java.lang." intext:Exception OR intext:"at org.springframework")'),
        ("nodejs_errors",     '{site} (intext:"Error: Cannot find module" OR intext:"at Object.<anonymous>")'),
        ("struts_errors",     '{site} intext:"struts.devMode"'),
        ("tomcat_errors",     '{site} (intitle:"Apache Tomcat" intext:"HTTP Status")'),
    ],
    "internal": [
        ("confluence",        '{site} (inurl:confluence OR intitle:"Confluence")'),
        ("jira",              '{site} (inurl:jira OR intitle:"Issue Navigator")'),
        ("wiki",              '{site} (inurl:wiki OR intitle:"MediaWiki")'),
        ("sharepoint",        '{site} (inurl:sharepoint OR intitle:"SharePoint")'),
        ("intranet",          '{site} (inurl:intranet OR intitle:intranet)'),
        ("crm",               '{site} (inurl:salesforce OR inurl:crm OR inurl:dynamics)'),
        ("ticketing",         '{site} (inurl:helpdesk OR inurl:zendesk OR inurl:freshdesk)'),
        ("internal_docs",     '{site} (inurl:internal-docs OR intitle:"internal documentation")'),
        ("notion",            '(site:notion.so OR site:notion.site) "{domain}"'),
        ("slack",             'site:slack.com inurl:archives "{domain}"'),
        ("trello",            'site:trello.com inurl:/b/ "{domain}"'),
        ("monday",            'site:monday.com "{domain}"'),
        ("asana",             'site:asana.com "{domain}"'),
        ("basecamp",          'site:basecamp.com "{domain}"'),
        ("mattermost",        '{site} (inurl:mattermost OR intitle:"Mattermost")'),
    ],
    "devops": [
        ("jenkins",           '{site} (inurl:jenkins OR intitle:"Dashboard [Jenkins]")'),
        ("gitlab",            '{site} (inurl:gitlab OR intitle:"GitLab")'),
        ("travis",            '{site} (filetype:yml inurl:.travis.yml)'),
        ("circleci",          '{site} (inurl:.circleci OR filetype:yml inurl:config.yml)'),
        ("dockerfile",        '{site} (filetype:dockerfile OR inurl:Dockerfile)'),
        ("ci_logs",           '{site} (inurl:build/console OR intitle:"build log")'),
        ("gitlab_ci",         '{site} inurl:.gitlab-ci.yml'),
        ("bb_pipelines",      '{site} inurl:bitbucket-pipelines.yml'),
        ("argo",              '{site} (inurl:argo OR intitle:"Argo CD")'),
        ("vault",             '{site} (inurl:vault OR intitle:"Vault UI")'),
        ("consul",            '{site} (inurl:consul OR intitle:"Consul")'),
        ("prometheus",        '{site} (inurl:prometheus OR intitle:"Prometheus")'),
        ("grafana",           '{site} (inurl:grafana OR intitle:"Grafana")'),
        ("kibana",            '{site} (inurl:kibana OR intitle:"Kibana")'),
        ("nexus",             '{site} (inurl:nexus OR intitle:"Sonatype Nexus")'),
        ("artifactory",       '{site} (inurl:artifactory OR intitle:"JFrog")'),
        ("github_actions",    '{site} inurl:.github/workflows'),
    ],
    "cloud": [
        ("s3_buckets",        'site:s3.amazonaws.com "{domain}"'),
        ("gcs_buckets",       'site:storage.googleapis.com "{domain}"'),
        ("azure_blobs",       'site:blob.core.windows.net "{domain}"'),
        ("public_drive",      '(site:drive.google.com OR site:docs.google.com) "{domain}"'),
        ("digitalocean",      'site:digitaloceanspaces.com "{domain}"'),
        ("backblaze",         'site:b2.backblazeb2.com "{domain}"'),
        ("wasabi",            'site:s3.wasabisys.com "{domain}"'),
        ("aliyun_oss",        'site:aliyuncs.com "{domain}"'),
        ("dropbox_share",     'site:dropbox.com "{domain}"'),
        ("onedrive_share",    'site:1drv.ms "{domain}"'),
    ],
    "vpn": [
        ("ssl_vpn",           '{site} (inurl:vpn OR inurl:remote intitle:"login")'),
        ("fortinet",          '{site} (inurl:remote/login OR intitle:"FortiGate")'),
        ("pulse",             '{site} (inurl:dana-na/auth OR intitle:"Pulse Connect")'),
        ("sonicwall",         '{site} (inurl:sonicwall OR intitle:"SonicWall - Authentication")'),
        ("openvpn",           '{site} (inurl:openvpn OR intitle:"OpenVPN")'),
        ("globalprotect",     '{site} (inurl:global-protect OR intitle:"GlobalProtect")'),
        ("anyconnect_portal", '{site} (inurl:CSCOSSLC OR intext:"Cisco Secure Desktop")'),
        ("checkpoint",        '{site} (inurl:sslvpn OR intitle:"Check Point")'),
    ],
    "secrets": [
        ("api_keys",          '{site} (intext:"api_key" OR intext:"apikey" OR intext:"x-api-key")'),
        ("passwords_in_text", '{site} intext:password (filetype:txt OR filetype:log)'),
        ("aws_keys",          '{site} (intext:"AKIA" OR intext:"aws_access_key_id")'),
        ("private_keys",      '{site} (intext:"-----BEGIN RSA PRIVATE KEY-----" OR ext:pem)'),
        ("ssh_keys",          '{site} (intext:"BEGIN OPENSSH PRIVATE KEY")'),
        ("oauth_tokens",      '{site} (intext:"access_token" OR intext:"client_secret")'),
        ("connection_strings",'{site} (intext:"jdbc:" OR intext:"mongodb://" OR intext:"postgres://")'),
        ("env_secrets",       '{site} filetype:env (intext:secret OR intext:password)'),
        ("stripe_keys",       '{site} (intext:"sk_live_" OR intext:"pk_live_")'),
        ("twilio_keys",       '{site} (intext:"twilio_sid" OR intext:"twilio_auth_token")'),
        ("sendgrid_keys",     '{site} (intext:"SG." intext:"apikey" OR intext:"SENDGRID_API_KEY")'),
        ("github_tokens",     '{site} (intext:"ghp_" OR intext:"github_token")'),
        ("slack_tokens",      '{site} (intext:"xoxb-" OR intext:"xoxp-")'),
        ("jwt_tokens",        '{site} (intext:"eyJhbGciOi" OR (intext:"eyJ" intext:"Bearer"))'),
        ("google_keys",       '{site} (intext:"AIza" OR intext:"google_api_key")'),
        ("mongo_uri",         '{site} intext:"mongodb+srv://"'),
    ],
    "media": [
        ("cameras",           '{site} (inurl:viewerframe OR intitle:"Live View" OR inurl:axis-cgi)'),
        ("axis_cameras",      '{site} (intitle:"AXIS" inurl:view/index)'),
        ("hikvision",         '{site} (inurl:doc/page OR intitle:"Hikvision")'),
        ("dahua",             '{site} intitle:"WEB SERVICE" Dahua'),
        ("printers",          '{site} (intitle:"HP Officejet" OR intitle:"network printer")'),
        ("printers_brother",  '{site} intitle:"Brother" intext:"network configuration"'),
        ("printers_konica",   '{site} intitle:"Konica Minolta"'),
        ("media_uploads",     '{site} (inurl:wp-content/uploads OR inurl:assets/uploads)'),
    ],
    "users": [
        ("employee_dir",      '{site} (intitle:"directory" OR intitle:"staff" OR intitle:"employees")'),
        ("contacts",          '{site} (intitle:"contact us" OR inurl:contact)'),
        ("linkedin_refs",     '"linkedin.com/in" "{domain}"'),
        ("email_lists",       '"@{domain}" (filetype:txt OR filetype:csv)'),
        ("leadership",        '{site} (intitle:"leadership" OR intitle:"our team" OR intitle:"about us")'),
        ("board_members",     '{site} (intitle:"board of directors" OR intitle:"executives")'),
        ("alumni",            '{site} (intitle:"alumni" OR intitle:"former employees")'),
        ("press_releases",    '{site} (intitle:"press release" OR inurl:press)'),
    ],
    "api": [
        ("swagger_ui",        '{site} (inurl:swagger OR inurl:api-docs OR intitle:"Swagger UI")'),
        ("graphql",           '{site} (inurl:graphql OR inurl:graphiql OR intitle:"GraphQL")'),
        ("api_versions",      '{site} (inurl:/api/v1 OR inurl:/api/v2 OR inurl:/api/v3)'),
        ("openapi_spec",      '{site} (filetype:json inurl:openapi OR filetype:yaml inurl:openapi)'),
        ("postman",           '{site} (filetype:json intext:"postman_collection" OR inurl:postman)'),
        ("api_debug",         '{site} inurl:api (intext:"error" OR intext:"stack trace")'),
        ("wsdl",              '{site} (filetype:wsdl OR inurl:"?wsdl")'),
        ("rest_docs",         '{site} (inurl:redoc OR inurl:api/docs OR intitle:"API Documentation")'),
        ("api_keys_exposed",  '{site} inurl:api (filetype:json OR filetype:xml) (intext:"key" OR intext:"token")'),
        ("actuator",          '{site} (inurl:actuator OR inurl:actuator/health OR inurl:actuator/env)'),
    ],
    "admin_tools": [
        ("adminer",           '{site} (inurl:adminer OR intitle:"Login - Adminer")'),
        ("redis_commander",   '{site} (inurl:redis-commander OR intitle:"Redis Commander")'),
        ("mongo_express",     '{site} (inurl:mongo-express OR intitle:"Mongo Express")'),
        ("elasticsearch",     '{site} (inurl:_cluster/health OR inurl:_cat/indices)'),
        ("rabbitmq",          '{site} (inurl:rabbitmq OR intitle:"RabbitMQ Management")'),
        ("solr",              '{site} (inurl:solr/admin OR intitle:"Solr Admin")'),
        ("pgadmin",           '{site} (inurl:pgadmin OR intitle:"pgAdmin")'),
        ("portainer",         '{site} (inurl:portainer OR intitle:"Portainer")'),
        ("cockpit",           '{site} (inurl:cockpit OR intitle:"Web Console")'),
        ("flower",            '{site} (inurl:flower OR intitle:"Celery Flower")'),
        ("mailhog",           '{site} (inurl:mailhog OR intitle:"MailHog")'),
        ("phpldapadmin",      '{site} (inurl:phpldapadmin OR intitle:"phpLDAPadmin")'),
    ],
}
CATEGORY_SEVERITY = {
    "secrets":     "critical",
    "config":      "high",
    "backups":     "high",
    "admin_tools": "high",
    "auth":        "medium",
    "errors":      "medium",
    "devops":      "medium",
    "vpn":         "medium",
    "api":         "medium",
    "cloud":       "medium",
    "internal":    "low",
    "listings":    "low",
    "media":       "info",
    "users":       "info",
}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)

EXT_MAGIC = {
    "pdf":  (b"%PDF",),
    "doc":  (b"\xD0\xCF\x11\xE0",),
    "xls":  (b"\xD0\xCF\x11\xE0",),
    "ppt":  (b"\xD0\xCF\x11\xE0",),
    "docx": (b"PK\x03\x04",),
    "xlsx": (b"PK\x03\x04",),
    "pptx": (b"PK\x03\x04",),
    "zip":  (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
}

log = logging.getLogger("andork")


# --------------------------- color / formatting ---------------------------

class C:
    """ANSI color codes. Set to '' if stdout isn't a TTY or NO_COLOR is set."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    GREY    = "\033[90m"

    @classmethod
    def disable(cls) -> None:
        for k in list(vars(cls)):
            if k.isupper() and isinstance(getattr(cls, k), str) and k != "RESET":
                setattr(cls, k, "")
            elif k == "RESET":
                setattr(cls, k, "")


if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C.disable()


class ColorFormatter(logging.Formatter):
    LEVEL_COLOR = {
        logging.DEBUG:    C.GREY,
        logging.INFO:     "",
        logging.WARNING:  C.YELLOW,
        logging.ERROR:    C.RED,
        logging.CRITICAL: C.RED + C.BOLD,
    }

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        color = self.LEVEL_COLOR.get(record.levelno, "")
        if color:
            return f"{color}{msg}{C.RESET}"
        return msg


def section(title: str) -> None:
    """Print a visual section banner. Always logged at INFO."""
    bar = "─" * max(0, 70 - len(title) - 4)
    log.info(f"{C.BOLD}{C.CYAN}━━ {title} {bar}{C.RESET}")


def subsection(title: str) -> None:
    log.info(f"{C.BOLD}{title}{C.RESET}")


# --------------------------- rate limiter ---------------------------

class RateLimiter:
    def __init__(self, delay: float, name: str):
        self.delay = delay
        self.name = name
        self.last = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            rem = self.delay - (time.time() - self.last)
            if rem > 0:
                log.info("rate-limit[%s]: sleeping %.0fs", self.name, rem)
                time.sleep(rem)
            self.last = time.time()


# --------------------------- url helpers ---------------------------

def in_scope(host: str, domain: str) -> bool:
    if not host:
        return False
    h = host.lower().split(":")[0]
    d = domain.lower()
    return h == d or h.endswith("." + d)


# Tracking/affiliate params we strip before dedupe — Google's srsltid was
# the worst offender (8x dupes of the same about-us page on the GNC run).
_TRACKING_PARAMS = {
    "srsltid", "gclid", "gclsrc", "dclid", "fbclid", "msclkid", "yclid",
    "mc_cid", "mc_eid", "_hsenc", "_hsmi", "_ga", "_gl",
    "ref", "ref_", "ref_src", "referrer",
}
_TRACKING_PARAM_PREFIXES = ("utm_",)


def _strip_tracking(query: str) -> str:
    if not query:
        return query
    kept = [
        (k, v) for k, v in up.parse_qsl(query, keep_blank_values=True)
        if k.lower() not in _TRACKING_PARAMS
        and not any(k.lower().startswith(p) for p in _TRACKING_PARAM_PREFIXES)
    ]
    return up.urlencode(kept, doseq=True)


def normalize_url(url: str) -> str:
    p = up.urlsplit(url)
    host = (p.hostname or "").lower()
    netloc = host
    if p.port and not (
        (p.scheme == "http" and p.port == 80)
        or (p.scheme == "https" and p.port == 443)
    ):
        netloc = f"{host}:{p.port}"
    return up.urlunsplit(
        (p.scheme.lower(), netloc, p.path, _strip_tracking(p.query), "")
    )


# Hosts/path-patterns that the gnc.com run made obvious are noise:
# coupon-spam buckets that stuff the target domain into URL fragments,
# adblock/filter-list dumps, alexa-rank dumps, and code-archive mirrors
# that incidentally contain the target domain in big lists.
_NOISE_HOST_PATTERNS = (
    re.compile(r"^verifiedcoupons[a-z0-9]*\.s3\.amazonaws\.com$"),
    re.compile(r"^hotcoupondiscount[a-z0-9]*\.blob\.core\.windows\.net$"),
    re.compile(r"^(?:[a-z0-9-]+\.)*offer\.love$"),
    re.compile(r"^easylist(?:-downloads)?\.(?:to|adblockplus\.org)$"),
    re.compile(r"^filters\.adtidy\.org$"),
    re.compile(r"^blokada\.org$"),
    re.compile(r"^chromium\.googlesource\.com$"),
    re.compile(r"^patentimages\.storage\.googleapis\.com$"),
    re.compile(r"^fossies\.org$"),
    re.compile(r"^sources\.debian\.org$"),
    re.compile(r"^gitlab\.developers\.cam\.ac\.uk$"),
    re.compile(r"^perso\.crans\.org$"),
    re.compile(r"^svn(?:-us)?\.apache\.org$"),
)
_NOISE_PATH_PATTERNS = (
    # GitHub-hosted blocklists / hosts files / alexa dumps
    re.compile(r"raw\.githubusercontent\.com/.*/(BlockLists|hosts|filter|alexa)",
               re.IGNORECASE),
    re.compile(r"cdn\.jsdelivr\.net/gh/(blackmatrix7|badmojr|1hosts)/",
               re.IGNORECASE),
    re.compile(r"github\.com/.*/(blocklist|hosts|filter|alexa|top-domains)",
               re.IGNORECASE),
    # Generic "alexa top sites" data files
    re.compile(r"alexa[-_]?(?:domains|top|1m|10000)", re.IGNORECASE),
    re.compile(r"top[-_]?domains", re.IGNORECASE),
)


def is_noise_host(url: str) -> bool:
    """True if a result URL is known low-signal junk (coupon spam, adblock
    list dumps, alexa-rank lists, etc.) that just happens to contain the
    target domain as a substring."""
    p = up.urlsplit(url)
    host = (p.hostname or "").lower()
    if any(rx.match(host) for rx in _NOISE_HOST_PATTERNS):
        return True
    full = f"{host}{p.path}"
    return any(rx.search(full) for rx in _NOISE_PATH_PATTERNS)


def extract_ext(url: str) -> Optional[str]:
    path = up.urlsplit(url).path.lower()
    if "." not in path:
        return None
    ext = path.rsplit(".", 1)[1]
    return ext if ext.isalnum() else None


def _fmt_dur(seconds: float) -> str:
    s = int(seconds)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def atomic_write_json(path: Path, obj) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2))
    tmp.replace(path)


@dataclass
class SearchResult:
    items: dict[str, list]
    failed_engines: set[str]


def search_engines_parallel(engines: list, dork: str) -> SearchResult:
    """Run a list of (name, engine) pairs against the same dork concurrently.

    Each engine has its own rate limiter, so DDG and Google run in parallel
    without blocking each other. Returns a SearchResult with per-engine
    items and a set of engines that encountered errors.

    Selenium itself isn't thread-safe, but we only ever have one Google
    search inflight per call, so a single thread per engine is fine.
    """
    out: dict[str, list] = {name: [] for name, _ in engines}
    failed: set[str] = set()
    if not engines:
        return SearchResult(items=out, failed_engines=failed)

    def run_one(name: str, engine) -> None:
        try:
            for item in engine.search(dork):
                out[name].append(item)
        except Exception as e:
            log.warning("%s: search error on %r: %s", name, dork, e)
            failed.add(name)

    with ThreadPoolExecutor(max_workers=len(engines)) as ex:
        futures = [ex.submit(run_one, name, eng) for name, eng in engines]
        for f in futures:
            f.result()
    return SearchResult(items=out, failed_engines=failed)


# --------------------------- DuckDuckGo ---------------------------

class DDGSearch:
    """Wraps the `ddgs` library. One call per dork — ddgs handles internal
    pagination and rotation across multiple backends. We only enforce our
    own rate limit *between* dorks, not between ddgs's internal requests.
    """

    def __init__(self, rate: RateLimiter, max_per_call: int, debug_dir: Path):
        self.rate = rate
        self.max_per_call = max_per_call
        self.debug_dir = debug_dir

    def search(self, dork: str) -> Iterator[dict]:
        """Yields {href, title, body} dicts. ddgs handles its own pagination."""
        try:
            from ddgs import DDGS
        except ImportError as e:
            log.error("ddgs library not installed: %s", e)
            return

        self.rate.wait()
        try:
            with DDGS() as d:
                # Pin to DuckDuckGo only — by default ddgs rotates across
                # DDG/Yahoo/Yandex/Bing and hits flaky ones. We just want
                # the DDG index.
                results = list(d.text(
                    query=dork,
                    region="us-en",
                    safesearch="off",
                    backend="duckduckgo",
                    max_results=self.max_per_call,
                ))
        except Exception as e:
            # ddgs raises an exception on zero results — that's a normal
            # outcome for many dorks, not an error.
            msg = str(e)
            if "no results" in msg.lower():
                log.info("ddgs: no results for %r", dork)
            else:
                log.warning("ddgs: error on %r: %s", dork, e)
            return

        if not results:
            log.info("ddgs: 0 raw results for %r", dork)
            self._dump(dork, [])
            return
        log.info("%sddgs: %d raw results for %r%s",
                 C.GREEN, len(results), dork, C.RESET)
        for item in results:
            href = (
                item.get("href")
                or item.get("url")
                or item.get("link")
            )
            if href and href.startswith(("http://", "https://")):
                yield {
                    "href": href,
                    "title": item.get("title") or "",
                    "body": item.get("body") or "",
                }

    def _dump(self, dork: str, results: list) -> None:
        try:
            self.debug_dir.mkdir(parents=True, exist_ok=True)
            p = self.debug_dir / f"ddgs-empty-{int(time.time())}.json"
            p.write_text(json.dumps({"dork": dork, "results": results}, indent=2))
            log.info("ddgs: dumped %s", p)
        except Exception:
            pass


# --------------------------- Google / Selenium ---------------------------

BROWSER_CANDIDATES = (
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/snap/bin/chromium",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
)
DRIVER_CANDIDATES = (
    "/usr/bin/chromedriver",
    "/usr/local/bin/chromedriver",
    "/snap/bin/chromium.chromedriver",
)


def _binary_version(path: str) -> Optional[tuple[int, ...]]:
    try:
        out = subprocess.check_output(
            [path, "--version"], stderr=subprocess.STDOUT, timeout=5,
        ).decode("utf-8", "replace")
    except Exception:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(x) for x in m.groups()) if m else None


def detect_browser_and_driver(
    browser_override: Optional[str],
    driver_override: Optional[str],
) -> tuple[Optional[str], Optional[str]]:
    """Pick a (browser, chromedriver) pair whose major versions match.

    Falls back to (browser, None) so webdriver_manager can download a
    matching driver. Returns (None, None) if no browser is found at all.
    """
    if browser_override and driver_override:
        return browser_override, driver_override

    browsers = (
        [browser_override] if browser_override
        else [b for b in BROWSER_CANDIDATES if Path(b).exists()]
    )
    drivers = (
        [driver_override] if driver_override
        else [d for d in DRIVER_CANDIDATES if Path(d).exists()]
    )

    if not browsers:
        return None, None

    if drivers:
        for d in drivers:
            dv = _binary_version(d)
            if not dv:
                continue
            for b in browsers:
                bv = _binary_version(b)
                if bv and bv[0] == dv[0]:
                    log.info("selenium: matched %s (%s) with %s (%s)",
                             b, ".".join(map(str, bv)),
                             d, ".".join(map(str, dv)))
                    return b, d

    log.info("selenium: no version-matched driver; "
             "will let webdriver_manager fetch one for %s", browsers[0])
    return browsers[0], None


class GoogleSelenium:
    def __init__(self, rate: RateLimiter, max_pages: int, headed: bool,
                 proxy: Optional[str], browser_path: Optional[str],
                 driver_path: Optional[str], debug_dir: Path,
                 user_data_dir: Optional[str], captcha_timeout: int,
                 wait_for_captcha: bool = False):
        self.rate = rate
        self.max_pages = max_pages
        self.headed = headed
        self.proxy = proxy
        self.browser_path = browser_path
        self.driver_path = driver_path
        self.debug_dir = debug_dir
        self.user_data_dir = user_data_dir
        self.captcha_timeout = captcha_timeout
        self.wait_for_captcha = wait_for_captcha
        self.driver = None
        self.captcha_seen = False

    def _dump(self, tag: str) -> None:
        if not self.driver:
            return
        try:
            self.debug_dir.mkdir(parents=True, exist_ok=True)
            ts = int(time.time())
            stem = self.debug_dir / f"google-{tag}-{ts}"
            try:
                self.driver.save_screenshot(str(stem) + ".png")
            except Exception:
                pass
            try:
                (Path(str(stem) + ".html")).write_text(
                    self.driver.page_source or ""
                )
            except Exception:
                pass
            log.warning("google: dumped %s.{png,html} (current_url=%s)",
                        stem, self.driver.current_url)
        except Exception as e:
            log.warning("google: dump failed: %s", e)

    def _ensure_driver(self):
        if self.driver:
            return

        browser, driver = detect_browser_and_driver(
            self.browser_path, self.driver_path,
        )
        if not browser:
            raise RuntimeError(
                "no Chrome/Chromium binary found; install one or "
                "pass --browser-path"
            )

        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        opts = Options()
        opts.binary_location = browser
        if not self.headed:
            opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--window-size=1280,900")
        # 'eager' returns from .get() once DOMContentLoaded fires, instead
        # of waiting for every tracker/image/iframe — Google's SERP has
        # tons of those and 'normal' load can hang for minutes.
        opts.page_load_strategy = "eager"
        # Anti-automation tells: don't spoof UA (mismatched UA is more
        # suspicious than the real one), strip the "Chrome is being
        # controlled" banner switches, and patch navigator.webdriver below.
        opts.add_argument("--disable-blink-features=AutomationControlled")
        opts.add_experimental_option("excludeSwitches", ["enable-automation"])
        opts.add_experimental_option("useAutomationExtension", False)
        if self.user_data_dir:
            Path(self.user_data_dir).mkdir(parents=True, exist_ok=True)
            opts.add_argument(f"--user-data-dir={self.user_data_dir}")
        if self.proxy:
            opts.add_argument(f"--proxy-server={self.proxy}")

        from selenium.webdriver.chrome.service import Service
        if driver:
            svc = Service(driver)
        else:
            try:
                from webdriver_manager.chrome import ChromeDriverManager
                svc = Service(ChromeDriverManager().install())
            except Exception:
                svc = Service()

        self.driver = webdriver.Chrome(service=svc, options=opts)
        # Fail fast on hung pages instead of letting selenium block on its
        # default 120s HTTP read timeout to chromedriver.
        try:
            self.driver.set_page_load_timeout(30)
            self.driver.set_script_timeout(15)
        except Exception:
            pass
        try:
            self.driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {"source": "Object.defineProperty(navigator, 'webdriver', "
                           "{get: () => undefined});"},
            )
        except Exception:
            pass
        log.info("selenium: driver up (browser=%s, headed=%s)",
                 browser, self.headed)

    def _wait_for_human(self) -> bool:
        """Block until the operator finishes the CAPTCHA flow.

        Polls every 2s; returns True if we've left the /sorry/ page within
        the timeout, False otherwise.
        """
        from selenium.common.exceptions import WebDriverException
        if self.wait_for_captcha:
            log.warning(
                "google: CAPTCHA detected — solve it in the browser window. "
                "Will resume automatically. Waiting indefinitely "
                "(--wait-for-captcha).",
            )
            deadline = None
        else:
            log.warning(
                "google: CAPTCHA detected — solve it in the browser window. "
                "Will resume automatically. Timeout: %ds.",
                self.captcha_timeout,
            )
            deadline = time.time() + self.captcha_timeout
        last_log = 0
        while deadline is None or time.time() < deadline:
            try:
                cur = self.driver.current_url
            except WebDriverException:
                return False
            if "/sorry/" not in cur and "consent.google.com" not in cur:
                log.info("google: human cleared the challenge, resuming")
                time.sleep(2)
                return True
            now = time.time()
            if now - last_log > 30:
                log.info("google: still on %s — waiting...", cur)
                last_log = now
            time.sleep(2)
        return False

    def _looks_dead(self, exc) -> bool:
        s = str(exc).lower()
        return any(k in s for k in (
            "no such window", "target window already closed",
            "no such session", "invalid session id",
            "chrome not reachable", "session deleted",
            "browser has closed", "disconnected",
        ))

    def _ensure_alive(self) -> None:
        """If the existing driver's session is dead (window closed, browser
        crashed mid-run), reset self.driver so _ensure_driver() recreates it.
        With --user-data-dir, the persisted profile keeps captcha cookies."""
        if not self.driver:
            return
        try:
            _ = self.driver.title
        except Exception as e:
            msg = str(e).splitlines()[0] if str(e) else "?"
            log.warning("google: existing browser session looks dead "
                        "(%s) — will recreate driver", msg)
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None

    def search(self, dork: str) -> Iterator[dict]:
        """Yields {href, title, body} dicts. Title/body are best-effort
        via container-based extraction; falls back to URL-only if the
        Google DOM layout doesn't match known selectors."""
        if self.captcha_seen:
            return
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.common.exceptions import (
            TimeoutException,
            WebDriverException,
        )

        self._ensure_alive()
        try:
            self._ensure_driver()
        except Exception as e:
            log.error("google: driver init failed: %s", e)
            self.captcha_seen = True
            return

        base = "https://www.google.com/search?" + up.urlencode(
            {"q": dork, "hl": "en", "gl": "us", "pws": "0"}
        )
        # Google now defaults to ~10 results per page and ignores num=100
        # for most users, so we count pages of 10.
        per_page = 10
        for page in range(1, self.max_pages + 1):
            self.rate.wait()
            # Phase 1: navigate. On page-load timeout (Google trackers
            # hanging), halt the load and try to extract anyway.
            try:
                if page == 1:
                    self.driver.get(base)
                else:
                    if not self._click_next():
                        start = (page - 1) * per_page
                        self.driver.get(base + f"&start={start}")
            except TimeoutException:
                log.warning("google page %d: page load timed out, "
                            "calling window.stop() and trying to scrape", page)
                try:
                    self.driver.execute_script("window.stop();")
                except Exception:
                    pass
            except WebDriverException as e:
                msg = str(e).splitlines()[0] if str(e) else "(no message)"
                log.warning("google page %d driver error: %s", page, msg)
                if self._looks_dead(e):
                    try:
                        self.driver.quit()
                    except Exception:
                        pass
                    self.driver = None
                else:
                    self._dump(f"driver-fail-p{page}")
                return

            # Phase 2: wait for body to have something useful in it.
            try:
                WebDriverWait(self.driver, 15).until(
                    lambda d: len(d.find_element(By.TAG_NAME, "body").text) > 50
                )
            except (TimeoutException, WebDriverException) as e:
                msg = str(e).splitlines()[0] if str(e) else "(no message)"
                log.warning("google page %d body wait failed: %s", page, msg)
                if isinstance(e, WebDriverException) and self._looks_dead(e):
                    try:
                        self.driver.quit()
                    except Exception:
                        pass
                    self.driver = None
                else:
                    self._dump(f"wait-fail-p{page}")
                return

            cur = self.driver.current_url
            page_src = self.driver.page_source or ""

            captcha = (
                "/sorry/" in cur
                or "unusual traffic" in page_src.lower()
                or bool(self.driver.find_elements(
                    By.CSS_SELECTOR, "form[action*='sorry']"
                ))
            )
            consent = (
                "consent.google.com" in cur
                or "before you continue" in page_src.lower()
            )

            if captcha or consent:
                tag = "captcha" if captcha else "consent"
                self._dump(f"{tag}-p{page}")
                if self.headed and self._wait_for_human():
                    # human cleared it; wait for the SERP to actually render
                    try:
                        WebDriverWait(self.driver, 20).until(
                            lambda d: "/search" in d.current_url
                            and self._has_results_container(d)
                        )
                    except TimeoutException:
                        log.warning("google: SERP didn't render after CAPTCHA clear")
                        self._dump(f"post-captcha-empty-p{page}")
                        return
                    page_src = self.driver.page_source or ""
                else:
                    log.warning(
                        "google: %s blocking and %s — disabling backend",
                        tag,
                        "timeout exceeded" if self.headed
                        else "headless can't solve (re-run with --headed)",
                    )
                    self.captcha_seen = True
                    return

            # No-results page
            if "did not match any documents" in page_src or \
               "No results found" in page_src:
                log.info("google page %d: no results for dork", page)
                return

            # Give JS a beat to populate result divs (some Google layouts
            # hydrate after initial render).
            time.sleep(1.5)
            items = self._extract_results()
            if items:
                log.info("%sgoogle page %d: %d raw results%s",
                         C.GREEN, page, len(items), C.RESET)
            else:
                log.info("google page %d: 0 raw results", page)
            yield from items
            if not items:
                self._dump(f"empty-p{page}")
                return

    def _has_results_container(self, d) -> bool:
        from selenium.webdriver.common.by import By
        return bool(
            d.find_elements(By.CSS_SELECTOR, "div#search, div#rso, div#main")
        )

    def _click_next(self) -> bool:
        """Try every known 'Next' selector. Returns True if click landed."""
        from selenium.webdriver.common.by import By
        from selenium.common.exceptions import (
            ElementClickInterceptedException, WebDriverException,
        )
        selectors = (
            "a#pnnext",
            "td#pnnext > a",
            "a[aria-label='Next page']",
            "a[aria-label='More results']",
            "a[id^='pnnext']",
        )
        for sel in selectors:
            els = self.driver.find_elements(By.CSS_SELECTOR, sel)
            if not els:
                continue
            try:
                self.driver.execute_script(
                    "arguments[0].scrollIntoView({block:'center'});", els[0]
                )
                els[0].click()
                return True
            except (ElementClickInterceptedException, WebDriverException):
                continue
        return False

    def _extract_results(self) -> list[dict]:
        """Pull results with best-effort title/snippet extraction.

        Tries container-based extraction first (find each result block,
        then extract URL + title + snippet from within it). Falls back
        to the broad anchor-scan if no containers match.
        """
        from selenium.webdriver.common.by import By
        container_selectors = ("div.g", "div.tF2Cxc", "div.MjjYud")
        title_selectors = ("h3", "a h3", "div[role='heading']")
        snippet_selectors = (
            "div.VwiC3b", "span.aCOpRe", "div[data-sncf]",
            "div.IsZvec", "div[style*='line-clamp']",
        )

        seen: set[str] = set()
        out: list[dict] = []

        for csel in container_selectors:
            for container in self.driver.find_elements(By.CSS_SELECTOR, csel):
                try:
                    anchors = container.find_elements(By.CSS_SELECTOR, "a[href]")
                    href = ""
                    for a in anchors:
                        h = a.get_attribute("href") or ""
                        real = self._unwrap_url_q(h)
                        if real and real.startswith(("http://", "https://")):
                            host = up.urlsplit(real).hostname or ""
                            if not host.endswith(("google.com", "gstatic.com")):
                                href = real
                                break
                    if not href or href in seen:
                        continue

                    title = ""
                    for tsel in title_selectors:
                        try:
                            el = container.find_element(By.CSS_SELECTOR, tsel)
                            title = (el.text or "").strip()
                            if title:
                                break
                        except Exception:
                            pass

                    snippet = ""
                    for ssel in snippet_selectors:
                        try:
                            el = container.find_element(By.CSS_SELECTOR, ssel)
                            snippet = (el.text or "").strip()
                            if snippet:
                                break
                        except Exception:
                            pass

                    seen.add(href)
                    out.append({"href": href, "title": title, "body": snippet})
                except Exception:
                    continue

        if out:
            return out

        # Fallback: broad anchor scan (no title/snippet)
        fallback_selectors = (
            "div#search a[href]", "div#rso a[href]", "div#main a[href]",
            "div[data-async-context] a[href]", "div.MjjYud a[href]",
            "div.tF2Cxc a[href]", "div.g a[href]",
        )
        for sel in fallback_selectors:
            for a in self.driver.find_elements(By.CSS_SELECTOR, sel):
                try:
                    href = a.get_attribute("href") or ""
                except Exception:
                    continue
                real = self._unwrap_url_q(href)
                if not real or not real.startswith(("http://", "https://")):
                    continue
                host = up.urlsplit(real).hostname or ""
                if host.endswith(("google.com", "gstatic.com")):
                    continue
                if real in seen:
                    continue
                seen.add(real)
                out.append({"href": real, "title": "", "body": ""})
        return out

    @staticmethod
    def _unwrap_url_q(href: str) -> Optional[str]:
        if not href:
            return None
        if "/url?" in href:
            qs = up.urlsplit(href).query
            q = up.parse_qs(qs).get("q", [None])[0]
            if q:
                return q
        return href

    def close(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None


# --------------------------- downloader ---------------------------

@dataclass
class DownloadRecord:
    sha1: str
    url: str
    ext: str
    size: int
    engines: list
    downloaded_at: str
    http_status: int


def download_one(
    session,
    url: str,
    ext: str,
    files_dir: Path,
    max_size_mb: int,
    ua: str,
    proxy: Optional[str],
) -> Optional[DownloadRecord]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        r = session.get(
            url,
            stream=True,
            timeout=30,
            allow_redirects=True,
            headers={"User-Agent": ua},
            proxies=proxies,
        )
    except Exception as e:
        log.warning("download error %s: %s", url, e)
        return None

    if r.status_code != 200:
        log.info("download skip %s: HTTP %d", url, r.status_code)
        r.close()
        return None

    cl = r.headers.get("Content-Length")
    cap = max_size_mb * 1024 * 1024
    if cl and cl.isdigit() and int(cl) > cap:
        log.info("download skip %s: %s bytes > %dMB cap", url, cl, max_size_mb)
        r.close()
        return None

    h = hashlib.sha1()
    size = 0
    tf = tempfile.NamedTemporaryFile(delete=False, dir=str(files_dir))
    try:
        for chunk in r.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            size += len(chunk)
            if size > cap:
                log.info("download skip %s: streamed > %dMB cap", url, max_size_mb)
                tf.close()
                os.unlink(tf.name)
                return None
            h.update(chunk)
            tf.write(chunk)
        tf.close()
    except Exception as e:
        log.warning("download stream error %s: %s", url, e)
        try:
            tf.close()
            os.unlink(tf.name)
        except Exception:
            pass
        return None

    sha1 = h.hexdigest()
    final = files_dir / f"{sha1}.{ext}"
    if final.exists():
        os.unlink(tf.name)
    else:
        try:
            with open(tf.name, "rb") as fh:
                head = fh.read(8)
            magic = EXT_MAGIC.get(ext, ())
            if magic and not any(head.startswith(m) for m in magic):
                log.warning("magic mismatch %s: head=%r — skipping", url, head[:8])
                os.unlink(tf.name)
                return None
        except Exception:
            pass
        shutil.move(tf.name, str(final))

    return DownloadRecord(
        sha1=sha1,
        url=url,
        ext=ext,
        size=size,
        engines=[],
        downloaded_at=datetime.now(timezone.utc).isoformat(),
        http_status=200,
    )


# --------------------------- exiftool ---------------------------

def run_exiftool(files: list[Path]) -> dict[str, dict]:
    if not files:
        return {}
    cmd = [
        "exiftool", "-j", "-G", "-n",
        "-api", "largefilesupport=1",
    ] + [str(f) for f in files]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.PIPE, timeout=600)
    except subprocess.CalledProcessError as e:
        log.warning("exiftool returned %d, parsing partial output", e.returncode)
        out = e.output or b""
    except Exception as e:
        log.error("exiftool failed: %s", e)
        return {}
    try:
        arr = json.loads(out.decode("utf-8", errors="replace"))
    except Exception as e:
        log.error("exiftool json parse failed: %s", e)
        return {}
    by_sha: dict[str, dict] = {}
    for entry in arr:
        src = entry.get("SourceFile") or ""
        stem = Path(src).stem
        by_sha[stem] = entry
    return by_sha


# --------------------------- summary ---------------------------

INTERESTING_FIELDS = (
    "Author", "LastModifiedBy", "Creator", "Company",
    "Producer", "Application", "Software", "Title",
)
WIN_PATH_RE = re.compile(r"[A-Z]:\\\\?[^\"\s<>|*?]+", re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def print_metadata_summary(metadata: list[dict]) -> None:
    by_ext = Counter(m["ext"] for m in metadata)
    log.info("--- summary ---")
    for ext, c in by_ext.most_common():
        log.info("  %s: %d", ext, c)

    field_vals: dict[str, Counter] = defaultdict(Counter)
    paths = Counter()
    emails = Counter()
    for m in metadata:
        exif = m.get("exif") or {}
        for k, v in exif.items():
            short = k.split(":")[-1]
            if short in INTERESTING_FIELDS and v not in (None, ""):
                field_vals[short][str(v)] += 1
        blob = json.dumps(exif)
        for p in WIN_PATH_RE.findall(blob):
            paths[p] += 1
        for e in EMAIL_RE.findall(blob):
            emails[e] += 1

    for f in INTERESTING_FIELDS:
        if not field_vals[f]:
            continue
        log.info("--- %s (top 20) ---", f)
        for v, c in field_vals[f].most_common(20):
            log.info("  %dx  %s", c, v)
    if paths:
        log.info("--- Windows paths (top 20) ---")
        for p, c in paths.most_common(20):
            log.info("  %dx  %s", c, p)
    if emails:
        log.info("--- emails (top 20) ---")
        for e, c in emails.most_common(20):
            log.info("  %dx  %s", c, e)


# --------------------------- argparse ---------------------------

def _add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-d", "--domain", default=None,
                   help="Target domain(s), comma-separated "
                        "(subdomains auto-included)")
    p.add_argument("--domain-file", default=None,
                   help="Path to file with one domain per line "
                        "(blank lines and #comments ignored)")
    p.add_argument("-o", "--output", default="./output")
    p.add_argument("--max-per-dork", type=int, default=100,
                   help="Max URLs to keep per dork (per engine)")
    p.add_argument("--max-pages", type=int, default=None,
                   help="Max Google result pages per dork (1 page = 1 search). "
                        "ddgs handles its own pagination internally. "
                        "Default: 5 for metadata, 1 for curated dork, "
                        "3 for custom dork-file.")
    p.add_argument("--search-delay", type=int, default=30,
                   help=f"Seconds between searches per engine "
                        f"(min {MIN_SEARCH_DELAY}; engines run in parallel)")
    p.add_argument("--google-delay", type=int, default=60,
                   help="Seconds between Google searches (default 60 — "
                        "Google triggers CAPTCHAs faster than DDG, so we "
                        "throttle it harder than --search-delay)")
    p.add_argument("--no-ddg", action="store_true")
    p.add_argument("--no-google", action="store_true")
    p.add_argument("--headed", action="store_true",
                   help="Run Chrome non-headless (lets you solve CAPTCHAs)")
    p.add_argument("--user-agent", default=None,
                   help="Override download User-Agent")
    p.add_argument("--proxy", default=None,
                   help="http://host:port (applied to search and download)")
    p.add_argument("--browser-path", default=None,
                   help="Path to Chrome/Chromium binary (auto-detected)")
    p.add_argument("--driver-path", default=None,
                   help="Path to chromedriver (auto-detected)")
    p.add_argument("--user-data-dir", default=None,
                   help="Persistent Chrome profile dir; cookies / "
                        "captcha-solved state survive across runs")
    p.add_argument("--captcha-timeout", type=int, default=300,
                   help="In --headed mode, seconds to wait for human "
                        "to solve a CAPTCHA before giving up")
    p.add_argument("--wait-for-captcha", action="store_true",
                   help="In --headed mode, block forever waiting for a "
                        "human to clear the CAPTCHA (overrides "
                        "--captcha-timeout). Use this when stepping away.")
    p.add_argument("--allow-root", action="store_true",
                   help="Bypass the 'not root' preflight check. Chrome with "
                        "--no-sandbox running as root is brittle; create a "
                        "regular user instead unless you really need this.")
    p.add_argument("--skip-preflight", action="store_true",
                   help="Skip startup preflight checks (deps, browser, "
                        "exiftool, root). For unusual environments only.")
    p.add_argument("--show-urls", action="store_true",
                   help="Print each discovered URL to console as it is found")


def parse_args():
    top_epilog = (
        "examples:\n"
        "  # full metadata sweep (default exts, headed Chrome, persistent profile)\n"
        "  andork metadata -d domain.com --headed --wait-for-captcha \\\n"
        "      --user-data-dir ~/chrome_profile --allow-root\n"
        "\n"
        "  # full dork sweep across all 174 dorks (~2.5h with 60s Google delay)\n"
        "  andork dork -d domain.com --headed --wait-for-captcha \\\n"
        "      --user-data-dir ~/chrome_profile --allow-root\n"
        "\n"
        "  # focused dork sweep — high-signal categories only (~30-45m)\n"
        "  andork dork -d domain.com --categories auth,config,secrets,backups \\\n"
        "      --headed --wait-for-captcha --user-data-dir ~/chrome_profile\n"
        "\n"
        "  # unattended DDG-only run (no Chrome, no CAPTCHA risk, weaker results)\n"
        "  andork dork -d domain.com --no-google\n"
        "\n"
        "  # multiple domains (comma-separated or from file)\n"
        "  andork dork -d domain1.com,domain2.com --no-google\n"
        "  andork metadata --domain-file targets.txt --headed --allow-root\n"
        "\n"
        "see 'andork metadata --help' or 'andork dork --help' for per-mode flags."
    )
    parser = argparse.ArgumentParser(
        prog="andork",
        description="OSINT recon for external pen tests. Two modes: "
                    "'metadata' (find docs, download, exiftool) and "
                    "'dork' (curated dork sweep, record findings).",
        epilog=top_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subs = parser.add_subparsers(dest="mode", required=True,
                                 metavar="{metadata,dork}")

    # --- metadata mode ---
    pm_epilog = (
        "examples:\n"
        "  # default extensions (pdf,docx,xlsx,pptx,csv,zip,doc), headed run\n"
        "  andork metadata -d domain.com --headed --wait-for-captcha \\\n"
        "      --user-data-dir ~/chrome_profile --allow-root\n"
        "\n"
        "  # PDF-only, fast and unattended via DDG (often weak for filetype:)\n"
        "  andork metadata -d domain.com -e pdf --no-google\n"
        "\n"
        "  # sensitive files (bak/sql/env/conf/...) preset, headed\n"
        "  andork metadata -d domain.com --ext-preset sensitive --headed \\\n"
        "      --wait-for-captcha --user-data-dir ~/chrome_profile\n"
        "\n"
        "output:\n"
        "  ./output/<domain>/metadata/report.html  (browse this)\n"
        "  ./output/<domain>/metadata/metadata.json\n"
        "  ./output/<domain>/metadata/files/<sha1>.<ext>"
    )
    pm = subs.add_parser(
        "metadata",
        help="Find documents, download them, run exiftool",
        epilog=pm_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_args(pm)
    pm.add_argument("-e", "--exts", default=None,
                    help=f"Comma list of extensions (overrides --ext-preset). "
                         f"Default preset: 'default' = {','.join(EXT_PRESETS['default'])}")
    pm.add_argument("--ext-preset",
                    choices=tuple(EXT_PRESETS.keys()), default="default",
                    help="Predefined extension set; ignored if -e is given")
    pm.add_argument("--download-delay", type=int, default=30,
                    help=f"Seconds between downloads (min {MIN_DOWNLOAD_DELAY})")
    pm.add_argument("--max-size-mb", type=int, default=50)
    pm.add_argument("--download-all", action="store_true",
                    help="Download all search results regardless of scope "
                         "(skip in_scope filtering)")
    pm.add_argument("--resume", dest="resume",
                    action="store_true", default=True)
    pm.add_argument("--no-resume", dest="resume", action="store_false")

    # --- dork mode ---
    pd_epilog = (
        "examples:\n"
        "  # full sweep (174 dorks, ~2.5h, headed for CAPTCHA solving)\n"
        "  andork dork -d domain.com --headed --wait-for-captcha \\\n"
        "      --user-data-dir ~/chrome_profile --allow-root\n"
        "\n"
        "  # high-signal categories only (~60 dorks, ~30-45m)\n"
        "  andork dork -d domain.com --categories auth,config,secrets,backups \\\n"
        "      --headed --wait-for-captcha --user-data-dir ~/chrome_profile\n"
        "\n"
        "  # see what would run without actually searching\n"
        "  andork dork -d domain.com --list-dorks\n"
        "\n"
        "  # run a custom dork list file (one dork per line)\n"
        "  andork dork -d domain.com --dork-file ./dorks/simple_high_signal_70.dorks\n"
        "\n"
        "  # DDG-only (no Chrome required, no CAPTCHA, fewer results)\n"
        "  andork dork -d domain.com --no-google\n"
        "\n"
        "categories: " + ", ".join(DORKS_DB.keys()) + "\n"
        "output:    ./output/<domain>/dork/report.html  (browse this)"
    )
    pd = subs.add_parser(
        "dork",
        help="Curated dork sweep — searches only, no downloads",
        epilog=pd_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_args(pd)
    pd.add_argument("--categories", default="all",
                    help=f"Comma list of categories or 'all'. "
                         f"Available: {','.join(DORKS_DB.keys())}")
    pd.add_argument("--dork-file", default=None,
                    help="Path to custom dork file (one dork per line). "
                         "If set, uses this file instead of curated --categories. "
                         "Supports {site} and {domain} placeholders.")
    pd.add_argument("--list-dorks", action="store_true",
                    help="Print every dork that would run and exit")
    pd.add_argument("--no-strict", action="store_true",
                    help="Disable post-filter that drops results lacking "
                         "literal evidence of the dork's operators "
                         "(inurl/filetype/intitle/intext). Strict is on by "
                         "default — most search-engine fuzzy false positives "
                         "are caught here.")
    pd.add_argument("--resume", dest="resume",
                    action="store_true", default=True,
                    help="Resume from previous run (skip completed dorks)")
    pd.add_argument("--no-resume", dest="resume", action="store_false")

    args = parser.parse_args()
    return args


def preflight(args) -> None:
    """Fail fast on missing deps, missing binaries, or unsafe environment.

    Each lazy-import / lazy-discovery point in the tool currently fails 30+
    minutes into a run. Run all of those checks once at startup with clear,
    actionable error messages before any rate-limit sleep or browser launch.
    """
    # Bootstrap a console handler so preflight messages surface before
    # setup_logging runs inside cmd_metadata / cmd_dork. setup_logging
    # clears handlers, so this is replaced cleanly later.
    if not log.handlers:
        log.setLevel(logging.INFO)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(ColorFormatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        log.addHandler(sh)

    if getattr(args, "skip_preflight", False):
        log.warning("preflight skipped (--skip-preflight)")
        return

    # 1. Not root
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        if not args.allow_root:
            raise SystemExit(
                "running as root is unsafe for headless Chrome and is not "
                "recommended; create a regular user, or pass --allow-root "
                "to override"
            )
        log.warning("%srunning as root (--allow-root); Chrome under "
                    "--no-sandbox in this configuration is brittle%s",
                    C.YELLOW, C.RESET)

    summary: list[str] = []

    user = os.environ.get("USER") or os.environ.get("LOGNAME") or "?"
    summary.append(f"user={user}")

    # 2. Python deps
    def _need(modname: str, label: str) -> None:
        try:
            __import__(modname)
        except ImportError:
            raise SystemExit(
                f"missing dependency {label!r}.\n"
                f"Install with one of:\n"
                f"  uv tool install --force .   (recommended; from repo root)\n"
                f"  pipx reinstall andork\n"
                f"  pip install {label}         (into the active venv/python)\n"
                f"  pip install -r requirements.txt"
            )
        summary.append(f"{label}=ok")

    _need("requests", "requests")
    if not args.no_ddg:
        _need("ddgs", "ddgs")
    else:
        summary.append("ddgs=skipped (--no-ddg)")
    if not args.no_google:
        _need("selenium", "selenium")
    else:
        summary.append("selenium=skipped (--no-google)")

    # 3. System binaries
    if args.mode == "metadata":
        if shutil.which("exiftool") is None:
            raise SystemExit(
                "exiftool not found in PATH.\n"
                "Install with one of:\n"
                "  Debian/Ubuntu/Kali:  sudo apt install libimage-exiftool-perl\n"
                "  Fedora/RHEL:         sudo dnf install perl-Image-ExifTool\n"
                "  macOS (homebrew):    brew install exiftool\n"
                "Or run dork mode (no exiftool dependency)."
            )
        summary.append("exiftool=ok")

    if not args.no_google:
        browser, _driver = detect_browser_and_driver(
            args.browser_path, args.driver_path,
        )
        if not browser or not Path(browser).exists():
            raise SystemExit(
                f"no Chrome/Chromium binary found "
                + (f"at {browser!r}.\n" if browser
                   else "at any of:\n  " + "\n  ".join(BROWSER_CANDIDATES) + "\n")
                + "Install one with one of:\n"
                "  Debian/Ubuntu/Kali:  sudo apt install chromium-browser chromium-driver\n"
                "  Fedora/RHEL:         sudo dnf install chromium chromedriver\n"
                "  macOS (homebrew):    brew install --cask chromium && brew install chromedriver\n"
                "Or pass --browser-path /path/to/chrome, or skip Google with --no-google."
            )
        summary.append(f"chrome={browser}")
    else:
        summary.append("chrome=skipped (--no-google)")

    # 4. Output dir writable
    try:
        out = Path(args.output)
        out.mkdir(parents=True, exist_ok=True)
        probe = out / ".preflight_write_test"
        probe.write_text("ok")
        probe.unlink()
    except OSError as e:
        raise SystemExit(f"output dir {args.output!r} not writable: {e}")
    summary.append(f"output={args.output}")

    log.info("%spreflight ok: %s%s",
             C.CYAN, " | ".join(summary), C.RESET)


def validate_domain(d: str) -> str:
    if not d:
        raise SystemExit("domain required")
    if d.startswith("*."):
        sys.stderr.write(
            "[note] stripping leading '*.' — subdomains are auto-included\n"
        )
        d = d[2:]
    if "/" in d or ":" in d or "*" in d:
        raise SystemExit("domain must be a bare host (no scheme/path/port/wildcard)")
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", d):
        raise SystemExit("IP addresses not accepted; use a hostname")
    if "." not in d:
        raise SystemExit(f"domain {d!r} doesn't look like a hostname")
    return d.lower()


def resolve_domains(args) -> list[str]:
    domains: list[str] = []
    if args.domain:
        for d in args.domain.split(","):
            d = d.strip()
            if d:
                domains.append(validate_domain(d))
    if args.domain_file:
        p = Path(args.domain_file).expanduser()
        if not p.exists():
            raise SystemExit(f"domain file not found: {p}")
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            domains.append(validate_domain(s))
    seen: set[str] = set()
    deduped: list[str] = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            deduped.append(d)
    if not deduped:
        raise SystemExit(
            "no domains specified — use -d DOMAIN or --domain-file FILE"
        )
    return deduped


def setup_logging(target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    log.setLevel(logging.INFO)
    datefmt = "%Y-%m-%d %H:%M:%S"
    plain_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                  datefmt=datefmt)
    color_fmt = ColorFormatter("%(asctime)s [%(levelname)s] %(message)s",
                               datefmt=datefmt)
    # Avoid duplicate handlers if setup_logging is called twice (rare).
    log.handlers.clear()
    fh = logging.FileHandler(target_dir / "run.log")
    fh.setFormatter(plain_fmt)
    log.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(color_fmt)
    log.addHandler(sh)


def cmd_metadata(args) -> int:
    domains = resolve_domains(args)
    if args.max_pages is None:
        args.max_pages = 5

    sd = max(args.search_delay, MIN_SEARCH_DELAY)
    dd = max(args.download_delay, MIN_DOWNLOAD_DELAY)

    if args.exts:
        exts = [e.strip().lower().lstrip(".")
                for e in args.exts.split(",") if e.strip()]
    else:
        exts = list(EXT_PRESETS[args.ext_preset])
    if not exts:
        raise SystemExit("no extensions specified")

    gd = max(args.google_delay or sd, MIN_SEARCH_DELAY)
    ddg_rate = RateLimiter(sd, "ddg")
    google_rate = RateLimiter(gd, "google")
    download_rate = RateLimiter(dd, "download")

    import requests
    sess_dl = requests.Session()

    ddg = (None if args.no_ddg
           else DDGSearch(ddg_rate, args.max_per_dork, None))
    google = (None if args.no_google
              else GoogleSelenium(google_rate, args.max_pages,
                                  args.headed, args.proxy,
                                  args.browser_path, args.driver_path,
                                  None, args.user_data_dir,
                                  args.captcha_timeout,
                                  args.wait_for_captcha))
    engines = [(n, e) for n, e in (("ddg", ddg), ("google", google)) if e]

    try:
        for di, domain in enumerate(domains, start=1):
            if len(domains) > 1:
                section(f"DOMAIN: {domain} ({di}/{len(domains)})")
            if google:
                google.captcha_seen = False

            target_dir = Path(args.output) / domain / "metadata"
            files_dir = target_dir / "files"
            debug_dir = target_dir / "debug"
            files_dir.mkdir(parents=True, exist_ok=True)
            setup_logging(target_dir)

            if ddg:
                ddg.debug_dir = debug_dir
            if google:
                google.debug_dir = debug_dir

            log.info("=== metadata mode: domain=%s ===", domain)
            log.info(
                "search_delay=%ds download_delay=%ds max_pages=%d max_per_dork=%d",
                sd, dd, args.max_pages, args.max_per_dork,
            )
            if args.download_all:
                log.warning("%s--download-all: scope filtering disabled — "
                            "downloading ALL search results regardless of host%s",
                            C.YELLOW, C.RESET)
            log.info("extensions: %s", ",".join(exts))

            state_path = target_dir / "search_results.json"
            state: dict = {"urls": {}, "downloads": {}}
            if state_path.exists() and args.resume:
                try:
                    state = json.loads(state_path.read_text())
                    state.setdefault("urls", {})
                    state.setdefault("downloads", {})
                    log.info(
                        "resumed: %d known URLs, %d downloads",
                        len(state["urls"]), len(state["downloads"]),
                    )
                except Exception as e:
                    log.warning("could not load state, starting fresh: %s", e)

            for ext in exts:
                dork = f"site:{domain} filetype:{ext}"
                section(f"DORK: {dork}")
                sr = search_engines_parallel(engines, dork)
                for engine_name, items in sr.items.items():
                    bucket = 0
                    for item in items:
                        if bucket >= args.max_per_dork:
                            break
                        raw = item["href"] if isinstance(item, dict) else item
                        if not raw or not raw.startswith(("http://", "https://")):
                            continue
                        host = up.urlsplit(raw).hostname or ""
                        if not args.download_all and not in_scope(host, domain):
                            continue
                        if extract_ext(raw) != ext:
                            continue
                        nu = normalize_url(raw)
                        if args.show_urls:
                            log.info("  %s-> %s%s", C.CYAN, nu, C.RESET)
                        rec = state["urls"].setdefault(nu, {
                            "engines": [],
                            "ext": ext,
                            "first_seen": datetime.now(timezone.utc).isoformat(),
                        })
                        if engine_name not in rec["engines"]:
                            rec["engines"].append(engine_name)
                        bucket += 1
                    scope_label = "total" if args.download_all else "in-scope"
                    if bucket:
                        log.info("%s%s: %d %s %s URLs%s",
                                 C.GREEN, engine_name, bucket, scope_label, ext, C.RESET)
                    else:
                        log.info("%s: 0 %s %s URLs", engine_name, scope_label, ext)
                atomic_write_json(state_path, state)

            log.info("=== download phase: %d unique URLs ===", len(state["urls"]))
            url_to_sha = {rec["url"]: sha
                          for sha, rec in state["downloads"].items()}
            for nu, meta in list(state["urls"].items()):
                ext = meta["ext"]
                existing = url_to_sha.get(nu)
                if existing and (files_dir / f"{existing}.{ext}").exists() and args.resume:
                    continue
                download_rate.wait()
                ua = args.user_agent or DEFAULT_UA
                rec = download_one(
                    sess_dl, nu, ext, files_dir, args.max_size_mb, ua, args.proxy,
                )
                if rec:
                    rec.engines = list(meta["engines"])
                    state["downloads"][rec.sha1] = asdict(rec)
                    url_to_sha[nu] = rec.sha1
                    atomic_write_json(state_path, state)
                    log.info("%sdownloaded %s -> %s.%s (%d bytes)%s",
                             C.GREEN, nu, rec.sha1[:12], ext, rec.size, C.RESET)

            log.info("=== exiftool phase ===")
            by_ext: dict[str, list[tuple[str, Path]]] = defaultdict(list)
            for sha, rec in state["downloads"].items():
                path = files_dir / f"{sha}.{rec['ext']}"
                if path.exists():
                    by_ext[rec["ext"]].append((sha, path))

            metadata: list[dict] = []
            for ext, items in by_ext.items():
                log.info("exiftool: %d %s files", len(items), ext)
                exif = run_exiftool([p for _, p in items])
                for sha, p in items:
                    rec = state["downloads"][sha]
                    metadata.append({**rec, "exif": exif.get(sha, {})})

            atomic_write_json(target_dir / "metadata.json", metadata)
            log.info("wrote metadata.json: %d entries", len(metadata))

            print_metadata_summary(metadata)
            render_metadata_report(metadata, domain, target_dir)
            section(f"done: {domain}")
    finally:
        if google:
            google.close()

    return 0


# --------------------------- dork mode ---------------------------

def _resolve_categories(spec: str) -> list[str]:
    if spec.strip().lower() == "all":
        return list(DORKS_DB.keys())
    cats = [c.strip() for c in spec.split(",") if c.strip()]
    unknown = [c for c in cats if c not in DORKS_DB]
    if unknown:
        raise SystemExit(
            f"unknown categories: {','.join(unknown)}. "
            f"Available: {','.join(DORKS_DB.keys())}"
        )
    return cats


def _build_dork_query(template: str, domain: str) -> str:
    return template.format(site=f"site:{domain}", domain=domain)


def _build_dork_query_loose(template: str, domain: str) -> str:
    """Render placeholders for custom-file dorks without requiring strict
    .format syntax. This avoids crashing on stray braces in raw GHDB lines."""
    return (template
            .replace("{site}", f"site:{domain}")
            .replace("{domain}", domain))


def _load_dork_file(path: str, domain: str) -> list[tuple[str, str, str]]:
    """Load custom dorks from a plain-text file.

    Format:
      - One query per line
      - Blank lines and lines starting with '#' are ignored
      - Optional placeholders: {site}, {domain}
    Returns list of (category, dork_id, query) tuples.
    """
    p = Path(path).expanduser()
    if not p.exists():
        raise SystemExit(f"dork file not found: {p}")
    if not p.is_file():
        raise SystemExit(f"dork path is not a file: {p}")

    try:
        raw = p.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise SystemExit(f"failed to read dork file {p}: {e}") from e

    seen: set[str] = set()
    out: list[tuple[str, str, str]] = []
    idx = 0
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        q = _build_dork_query_loose(s, domain).strip()
        if not q or q in seen:
            continue
        idx += 1
        seen.add(q)
        out.append(("custom", f"file_{idx:04d}", q))

    if not out:
        raise SystemExit(f"dork file {p} had no usable queries")
    return out


_DORK_CLAUSE_RE = re.compile(
    r'^(inurl|intitle|intext|filetype|ext|site):"?([^"]+)"?$',
    re.IGNORECASE,
)


def _tokenize_dork(query: str) -> list[str]:
    """Tokenize a dork query, preserving quoted phrases and paren grouping."""
    tokens: list[str] = []
    i = 0
    n = len(query)
    while i < n:
        c = query[i]
        if c.isspace():
            i += 1
            continue
        if c == "(" or c == ")":
            tokens.append(c)
            i += 1
            continue
        if c == '"':
            j = query.find('"', i + 1)
            if j < 0:
                tokens.append(query[i:])
                break
            tokens.append(query[i:j + 1])
            i = j + 1
            continue
        # bare or operator-prefixed token; may embed a quoted value
        j = i
        while j < n and not query[j].isspace() and query[j] not in "()":
            if query[j] == '"':
                k = query.find('"', j + 1)
                if k < 0:
                    j = n
                    break
                j = k + 1
            else:
                j += 1
        tokens.append(query[i:j])
        i = j
    return tokens


def _parse_clause(tok: str) -> Optional[tuple[str, str]]:
    m = _DORK_CLAUSE_RE.match(tok)
    if m:
        return (m.group(1).lower(), m.group(2))
    if tok.startswith('"') and tok.endswith('"') and len(tok) >= 2:
        v = tok[1:-1].strip()
        return ("text", v) if v else None
    if re.match(r"^[\w][\w.\-+/:]*$", tok):
        return ("text", tok)
    return None


def _parse_dork_groups(query: str) -> list:
    """Parse the dork into top-level AND groups. Each group is one of:
        ('clause', (op, val))                  — a single AND clause
        ('or',     [[(op, val), ...], ...])    — a parenthesized OR group;
                                                  each alt is itself an
                                                  AND list of clauses
    The whole dork matches iff every group matches.
    """
    tokens = _tokenize_dork(query)
    groups: list = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "(":
            depth = 1
            j = i + 1
            while j < len(tokens) and depth:
                if tokens[j] == "(":
                    depth += 1
                elif tokens[j] == ")":
                    depth -= 1
                if depth:
                    j += 1
            body = tokens[i + 1:j]
            alts: list[list[tuple[str, str]]] = []
            cur: list[tuple[str, str]] = []
            for t in body:
                if t.upper() == "OR":
                    if cur:
                        alts.append(cur)
                    cur = []
                else:
                    c = _parse_clause(t)
                    if c:
                        cur.append(c)
            if cur:
                alts.append(cur)
            if alts:
                groups.append(("or", alts))
            i = j + 1
            continue
        if tok.upper() == "OR":
            i += 1
            continue
        c = _parse_clause(tok)
        if c:
            groups.append(("clause", c))
        i += 1
    return groups


def _eval_clause(op: str, val: str,
                 url: str, title: str, snippet: str) -> Optional[bool]:
    """Evaluate one clause. Returns True/False, or None when the clause
    can't be checked from what we have (e.g. an intitle: clause when the
    engine didn't give us a title)."""
    vl = val.lower()
    u = url.lower()
    t = (title or "").lower()
    s = (snippet or "").lower()
    has_text = bool(t or s)
    if op == "inurl":
        return vl in u
    if op in ("filetype", "ext"):
        return bool(re.search(rf"\.{re.escape(vl)}(?:[?#/]|$)", u))
    if op == "site":
        host = up.urlsplit(url).netloc.lower()
        return host == vl or host.endswith("." + vl)
    if op == "intitle":
        return None if not has_text else (vl in t)
    if op == "intext":
        return None if not has_text else (vl in t or vl in s or vl in u)
    if op == "text":
        return None if not has_text else (vl in t or vl in s)
    return None


def _eval_alt(alt: list[tuple[str, str]],
              url: str, title: str, snippet: str) -> Optional[bool]:
    """An OR alternative is itself an AND of its clauses.
    Returns True (all verifiable clauses pass), False (some verifiable
    clause fails), or None (no clause was verifiable from the data we have).
    """
    results = [_eval_clause(op, v, url, title, snippet) for op, v in alt]
    verifiable = [r for r in results if r is not None]
    if not verifiable:
        return None
    return all(verifiable)


def _eval_group(group, url: str, title: str, snippet: str) -> bool:
    kind = group[0]
    if kind == "clause":
        op, val = group[1]
        r = _eval_clause(op, val, url, title, snippet)
        return True if r is None else r
    if kind == "or":
        # Pre-eval each alt as True/False/None.
        # - If any alt is definitively True → match.
        # - Else if at least one alt's verifiable clauses failed AND no alt
        #   is purely unverifiable → all-fail, drop. This catches the FP
        #   shape where the only "winning" alt is an intitle:/intext: with
        #   empty title+snippet (e.g. site:gnc.com inurl:ews OR
        #   intitle:"Exchange" matching stores.gnc.com/.../main-exchange).
        # - Else (all alts None, or mix of False+None) → trust the engine.
        alts = [_eval_alt(alt, url, title, snippet) for alt in group[1]]
        if any(r is True for r in alts):
            return True
        if any(r is False for r in alts) and not any(r is None for r in alts):
            return False
        if all(r is None for r in alts):
            return True
        # Mixed False + None: one alt definitively didn't match by URL/etc.,
        # another is text-based with no title/snippet. Be skeptical.
        return False
    return True


def validate_dork_match(query: str, url: str,
                        title: str, snippet: str) -> bool:
    """Re-validate a search hit against the dork's literal AND/OR
    structure. Drop hits that don't match all top-level AND groups.

    - Bare top-level clauses (operator-prefixed or quoted phrases) are
      conjuncted: every one must match.
    - A parenthesized OR group matches iff at least one alternative
      matches (each alternative is itself an AND of its own clauses).
    - Text-based clauses (intitle/intext/quoted) are unverifiable when
      the engine didn't give us title/snippet (Google's extractor).
      Unverifiable clauses are treated as 'trust the engine' to avoid
      dropping all Google results.
    """
    groups = _parse_dork_groups(query)
    if not groups:
        return True
    return all(_eval_group(g, url, title, snippet) for g in groups)


def cmd_dork(args) -> int:
    domains = resolve_domains(args)
    if args.max_pages is None:
        args.max_pages = 3 if args.dork_file else 1

    sd = max(args.search_delay, MIN_SEARCH_DELAY)
    strict = not args.no_strict

    gd = max(args.google_delay or sd, MIN_SEARCH_DELAY)
    ddg_rate = RateLimiter(sd, "ddg")
    google_rate = RateLimiter(gd, "google")

    ddg = (None if args.no_ddg
           else DDGSearch(ddg_rate, args.max_per_dork, None))
    google = (None if args.no_google
              else GoogleSelenium(google_rate, args.max_pages,
                                  args.headed, args.proxy,
                                  args.browser_path, args.driver_path,
                                  None, args.user_data_dir,
                                  args.captcha_timeout,
                                  args.wait_for_captcha))
    engines = [(n, e) for n, e in (("ddg", ddg), ("google", google)) if e]

    # --list-dorks: show dorks for first domain and exit
    if args.list_dorks:
        domain = domains[0]
        source_label = "curated"
        if args.dork_file:
            dorks = _load_dork_file(args.dork_file, domain)
            categories = sorted({c for c, _, _ in dorks})
            source_label = f"file:{args.dork_file}"
        else:
            categories = _resolve_categories(args.categories)
            dorks: list[tuple[str, str, str]] = []
            for cat in categories:
                for dork_id, template in DORKS_DB[cat]:
                    dorks.append(
                        (cat, dork_id, _build_dork_query(template, domain))
                    )
        for cat, dork_id, q in dorks:
            print(f"{cat:10s}  {dork_id:22s}  {q}")
        print(f"\n{len(dorks)} dorks across {len(categories)} categories "
              f"(source={source_label})")
        if len(domains) > 1:
            print(f"(showing dorks for {domain}; "
                  f"{len(domains) - 1} more domain(s) will use the same set)")
        return 0

    try:
        for di, domain in enumerate(domains, start=1):
            if len(domains) > 1:
                section(f"DOMAIN: {domain} ({di}/{len(domains)})")
            if google:
                google.captcha_seen = False

            source_label = "curated"
            if args.dork_file:
                dorks = _load_dork_file(args.dork_file, domain)
                categories = sorted({c for c, _, _ in dorks})
                source_label = f"file:{args.dork_file}"
            else:
                categories = _resolve_categories(args.categories)
                dorks: list[tuple[str, str, str]] = []
                for cat in categories:
                    for dork_id, template in DORKS_DB[cat]:
                        dorks.append(
                            (cat, dork_id, _build_dork_query(template, domain))
                        )

            target_dir = Path(args.output) / domain / "dork"
            debug_dir = target_dir / "debug"
            target_dir.mkdir(parents=True, exist_ok=True)
            setup_logging(target_dir)

            if ddg:
                ddg.debug_dir = debug_dir
            if google:
                google.debug_dir = debug_dir

            log.info("=== dork mode: domain=%s ===", domain)
            log.info("source=%s | categories=%s | %d dorks total | "
                     "search_delay=%ds | google_pages=%d",
                     source_label, ",".join(categories), len(dorks), sd, args.max_pages)

            findings_path = target_dir / "findings.json"
            progress_path = target_dir / "progress.json"
            findings: list[dict] = []
            seen: set[tuple[str, str]] = set()
            completed_dorks: set[str] = set()

            run_fingerprint = hashlib.sha256(json.dumps({
                "domain": domain,
                "source": source_label,
                "dorks": [(c, d, q) for c, d, q in dorks],
                "engines": [n for n, _ in engines],
                "strict": strict,
                "max_pages": args.max_pages,
                "max_per_dork": args.max_per_dork,
            }, sort_keys=True).encode()).hexdigest()[:16]

            if args.resume and progress_path.exists():
                try:
                    progress = json.loads(progress_path.read_text())
                    if isinstance(progress, dict) and progress.get("fingerprint") == run_fingerprint:
                        completed_dorks = set(progress.get("completed", []))
                        log.info("resumed: %d completed dorks (fingerprint match)",
                                 len(completed_dorks))
                    elif isinstance(progress, dict):
                        log.warning("progress fingerprint mismatch — previous run "
                                    "used different config; starting fresh")
                    else:
                        log.warning("progress file has old format; starting fresh")
                except Exception as e:
                    log.warning("could not load progress for resume: %s", e)

            if args.resume and completed_dorks and findings_path.exists():
                try:
                    prev_findings = json.loads(findings_path.read_text())
                    for f in prev_findings:
                        if f.get("dork_id") in completed_dorks:
                            findings.append(f)
                            seen.add((f["dork_id"], f["url"]))
                    log.info("resumed: %d findings from completed dorks", len(findings))
                except Exception as e:
                    log.warning("could not load findings for resume: %s", e)
                    findings = []

            total_dropped = 0
            total = len(dorks)
            skipped = 0
            run_started = time.time()
            for idx, (cat, dork_id, query) in enumerate(dorks, start=1):
                if dork_id in completed_dorks:
                    skipped += 1
                    log.info("[%d/%d] %s/%s: skipped (resume)", idx, total, cat, dork_id)
                    continue
                section(f"[{idx}/{total}] {cat}/{dork_id}: {query}")
                sr = search_engines_parallel(engines, query)
                engine_failures = set(sr.failed_engines)
                if google and google.captcha_seen:
                    engine_failures.add("google")
                for engine_name, items in sr.items.items():
                    hits = 0
                    dropped = 0
                    for item in items:
                        if hits >= args.max_per_dork:
                            break
                        href = (item.get("href") if isinstance(item, dict)
                                else item) or ""
                        if not href.startswith(("http://", "https://")):
                            continue
                        nu = normalize_url(href)
                        key = (dork_id, nu)
                        if key in seen:
                            continue
                        if strict and is_noise_host(nu):
                            dropped += 1
                            continue
                        title = item.get("title", "") if isinstance(item, dict) else ""
                        snippet = item.get("body", "") if isinstance(item, dict) else ""
                        if strict and not validate_dork_match(query, nu, title, snippet):
                            dropped += 1
                            continue
                        seen.add(key)
                        if args.show_urls:
                            if title:
                                log.info("  %s-> %s%s  %s%s%s",
                                         C.CYAN, nu, C.RESET, C.DIM, title, C.RESET)
                            else:
                                log.info("  %s-> %s%s", C.CYAN, nu, C.RESET)
                        findings.append({
                            "category": cat,
                            "dork_id": dork_id,
                            "dork_query": query,
                            "url": nu,
                            "title": title,
                            "snippet": snippet,
                            "engine": engine_name,
                            "found_at": datetime.now(timezone.utc).isoformat(),
                        })
                        hits += 1
                    if dropped:
                        total_dropped += dropped
                        log.info("%s%s: dropped %d false-positive(s) for %s/%s%s",
                                 C.YELLOW, engine_name, dropped, cat, dork_id, C.RESET)
                    if hits:
                        log.info("%s%s: %d hits for %s/%s%s",
                                 C.GREEN, engine_name, hits, cat, dork_id, C.RESET)
                    else:
                        log.info("%s: 0 hits for %s/%s",
                                 engine_name, cat, dork_id)
                if engine_failures:
                    log.warning("dork %s/%s: not marking complete — "
                                "engine(s) failed: %s",
                                cat, dork_id, ", ".join(sorted(engine_failures)))
                else:
                    completed_dorks.add(dork_id)
                atomic_write_json(findings_path, findings)
                atomic_write_json(progress_path, {
                    "fingerprint": run_fingerprint,
                    "completed": sorted(completed_dorks),
                })
                elapsed = time.time() - run_started
                done = idx - skipped
                avg = elapsed / max(done, 1)
                remaining = avg * (total - idx)
                log.info("progress: %d/%d (%d%%) | elapsed %s | eta %s",
                         idx, total, int(idx * 100 / total),
                         _fmt_dur(elapsed), _fmt_dur(remaining))

            log.info("wrote findings.json: %d entries", len(findings))
            if strict and total_dropped:
                log.info("strict-mode dropped %d fuzzy-match false-positives "
                         "(use --no-strict to keep them)", total_dropped)
            print_dork_summary(findings, dorks)
            render_dork_report(findings, domain, dorks, target_dir)
            section(f"done: {domain}")
    finally:
        if google:
            google.close()

    return 0


def print_dork_summary(findings: list[dict],
                       all_dorks: list[tuple[str, str, str]]) -> None:
    by_cat: dict[str, int] = defaultdict(int)
    by_dork: dict[str, int] = defaultdict(int)
    for f in findings:
        by_cat[f["category"]] += 1
        by_dork[f"{f['category']}/{f['dork_id']}"] += 1

    log.info("--- dork summary ---")
    log.info("total findings: %d (across %d unique dork hits)",
             len(findings), len(by_dork))
    log.info("--- by category ---")
    for cat, c in sorted(by_cat.items(), key=lambda x: -x[1]):
        log.info("  %3d  %s", c, cat)
    log.info("--- top dorks (top 20) ---")
    for d, c in sorted(by_dork.items(), key=lambda x: -x[1])[:20]:
        log.info("  %3d  %s", c, d)
    # zero-result dorks worth flagging so the operator can spot misfires
    hit_keys = {f"{c}/{d}" for c, d, _ in all_dorks if by_dork.get(f"{c}/{d}")}
    miss = [f"{c}/{d}" for c, d, _ in all_dorks
            if f"{c}/{d}" not in hit_keys]
    if miss:
        log.info("--- %d dorks returned 0 hits ---", len(miss))


# --------------------------- HTML reports ---------------------------

_HTML_CSS = """
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;
     max-width:1200px;margin:2em auto;padding:0 1em;color:#222;line-height:1.5;
     background:#fff}
h1{border-bottom:3px solid #2563eb;padding-bottom:.3em;color:#1e3a8a}
h2{margin-top:2em;color:#1e3a8a;border-bottom:1px solid #e5e7eb;padding-bottom:.2em}
h3{color:#374151}
.meta{color:#6b7280;font-size:.9em}
.kv{display:grid;grid-template-columns:200px 1fr;gap:.3em 1em;margin:1em 0}
.kv dt{font-weight:600;color:#4b5563}
.kv dd{margin:0}
table{border-collapse:collapse;width:100%;margin:1em 0;font-size:.92em}
th,td{padding:.5em .8em;text-align:left;border-bottom:1px solid #e5e7eb;vertical-align:top}
th{background:#f3f4f6;font-weight:600}
tr:hover td{background:#fafbfc}
code,pre{background:#f3f4f6;padding:.15em .3em;border-radius:3px;font-size:.9em;
         font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{padding:.8em;overflow:auto}
a{color:#2563eb;text-decoration:none;word-break:break-all}
a:hover{text-decoration:underline}
.tag{display:inline-block;padding:.1em .5em;background:#dbeafe;color:#1e3a8a;
     border-radius:3px;font-size:.8em;margin-right:.3em}
.tag.danger{background:#fee2e2;color:#991b1b}
.tag.engine{background:#f3f4f6;color:#4b5563}
.tag.sev-critical{background:#fee2e2;color:#991b1b}
.tag.sev-high{background:#ffedd5;color:#9a3412}
.tag.sev-medium{background:#fef9c3;color:#854d0e}
.tag.sev-low{background:#dbeafe;color:#1e3a8a}
.tag.sev-info{background:#f3f4f6;color:#4b5563}
details{margin:.5em 0}
summary{cursor:pointer;padding:.5em;background:#f3f4f6;border-radius:3px;font-weight:600}
summary:hover{background:#e5e7eb}
.snippet{color:#6b7280;font-size:.9em;margin-top:.3em}
.url-cell{max-width:500px;word-break:break-all}
.count{display:inline-block;min-width:2em;text-align:right;color:#1e3a8a;
       font-weight:600;font-family:ui-monospace,monospace}
.cat-section{border-left:4px solid #e5e7eb;padding-left:1em;margin-bottom:2em}
.cat-section.sev-critical{border-left-color:#dc2626}
.cat-section.sev-high{border-left-color:#f97316}
.cat-section.sev-medium{border-left-color:#eab308}
.cat-section.sev-low{border-left-color:#3b82f6}
.cat-section.sev-info{border-left-color:#6b7280}
.stat-row{display:flex;gap:1em;margin:1em 0;flex-wrap:wrap}
.stat-tile{padding:1em 1.5em;background:#f9fafb;border-radius:6px;text-align:center;
           min-width:100px;border-top:3px solid #e5e7eb}
.stat-tile .stat-num{font-size:2em;font-weight:700;color:#1e3a8a}
.stat-tile .stat-label{font-size:.85em;color:#6b7280;text-transform:uppercase}
.filter-bar{display:flex;gap:.8em;flex-wrap:wrap;align-items:center;
            padding:1em;background:#f9fafb;border-radius:6px;margin:1em 0;
            border:1px solid #e5e7eb}
.filter-bar input[type=text]{padding:.4em .6em;border:1px solid #d1d5db;border-radius:4px;
                             font-size:.9em;min-width:200px}
.filter-bar select{padding:.4em .6em;border:1px solid #d1d5db;border-radius:4px;
                   font-size:.9em;background:#fff}
.filter-bar button{padding:.4em .8em;border:1px solid #d1d5db;border-radius:4px;
                   font-size:.9em;background:#fff;cursor:pointer}
.filter-bar button:hover{background:#e5e7eb}
.filter-bar .filter-count{font-size:.85em;color:#6b7280}
.btn-copy{padding:.2em .5em;border:1px solid #d1d5db;border-radius:3px;font-size:.75em;
          background:#fff;cursor:pointer;color:#4b5563;margin-left:.5em}
.btn-copy:hover{background:#e5e7eb}
.multi-hit-count{font-weight:700;color:#dc2626}
@media (prefers-color-scheme:dark){
  body{background:#1a1a2e;color:#e0e0e0}
  h1{color:#93b5f5;border-bottom-color:#3b82f6}
  h2{color:#93b5f5;border-bottom-color:#374151}
  h3{color:#d1d5db}
  .meta{color:#9ca3af}
  .kv dt{color:#d1d5db}
  th{background:#1f2937}
  td{border-bottom-color:#374151}
  tr:hover td{background:#1f2937}
  code,pre{background:#1f2937}
  summary{background:#1f2937}
  summary:hover{background:#374151}
  a{color:#60a5fa}
  .tag{background:#1e3a5f;color:#93c5fd}
  .tag.danger,.tag.sev-critical{background:#7f1d1d;color:#fca5a5}
  .tag.sev-high{background:#7c2d12;color:#fdba74}
  .tag.sev-medium{background:#713f12;color:#fde68a}
  .tag.sev-low{background:#1e3a5f;color:#93c5fd}
  .tag.engine,.tag.sev-info{background:#374151;color:#d1d5db}
  .snippet{color:#9ca3af}
  .stat-tile{background:#1f2937;border-top-color:#374151}
  .stat-tile .stat-num{color:#93b5f5}
  .stat-tile .stat-label{color:#9ca3af}
  .filter-bar{background:#1f2937;border-color:#374151}
  .filter-bar input[type=text],.filter-bar select{background:#111827;color:#e0e0e0;
    border-color:#374151}
  .filter-bar button,.btn-copy{background:#1f2937;color:#d1d5db;border-color:#374151}
  .filter-bar button:hover,.btn-copy:hover{background:#374151}
  .count{color:#93b5f5}
  .cat-section{border-left-color:#374151}
  .cat-section.sev-critical{border-left-color:#ef4444}
  .cat-section.sev-high{border-left-color:#fb923c}
  .cat-section.sev-medium{border-left-color:#facc15}
  .cat-section.sev-low{border-left-color:#60a5fa}
  .cat-section.sev-info{border-left-color:#6b7280}
}
@media print{
  body{color:#000;max-width:none;background:#fff}
  a{text-decoration:underline;color:#000}
  .tag{border:1px solid #999;background:#f0f0f0;color:#000}
  summary{background:#eee}
  details{break-inside:avoid}
  .filter-bar,.btn-copy{display:none}
  .cat-section{border-left-width:3px}
  .stat-tile{border:1px solid #ccc}
}
"""


def _esc(s) -> str:
    return html_mod.escape(str(s) if s is not None else "")


def render_metadata_report(metadata: list[dict], domain: str,
                           target_dir: Path) -> None:
    if not metadata:
        return

    by_ext = Counter(m["ext"] for m in metadata)
    field_vals: dict[str, Counter] = defaultdict(Counter)
    paths = Counter()
    emails = Counter()
    for m in metadata:
        exif = m.get("exif") or {}
        for k, v in exif.items():
            short = k.split(":")[-1]
            if short in INTERESTING_FIELDS and v not in (None, ""):
                field_vals[short][str(v)] += 1
        blob = json.dumps(exif)
        for p in WIN_PATH_RE.findall(blob):
            paths[p] += 1
        for e in EMAIL_RE.findall(blob):
            emails[e] += 1

    parts: list[str] = []
    parts.append(f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                 f"<title>Metadata report — {_esc(domain)}</title>"
                 f"<style>{_HTML_CSS}</style></head><body>")
    parts.append(f"<h1>Metadata Recon — {_esc(domain)}</h1>")
    parts.append(f"<p class='meta'>Generated "
                 f"{datetime.now(timezone.utc).isoformat()} · "
                 f"{len(metadata)} files harvested</p>")

    parts.append("<h2>Summary</h2><dl class='kv'>")
    parts.append(f"<dt>Target</dt><dd>{_esc(domain)}</dd>")
    parts.append(f"<dt>Files</dt><dd>{len(metadata)}</dd>")
    parts.append(f"<dt>Extensions</dt><dd>" +
                 " ".join(f"<span class='tag'>{_esc(e)}: {c}</span>"
                          for e, c in by_ext.most_common()) + "</dd>")
    parts.append(f"<dt>Unique authors</dt>"
                 f"<dd>{len(field_vals.get('Author', {}))}</dd>")
    parts.append(f"<dt>Unique companies</dt>"
                 f"<dd>{len(field_vals.get('Company', {}))}</dd>")
    parts.append("</dl>")

    for f in INTERESTING_FIELDS:
        if not field_vals[f]:
            continue
        parts.append(f"<h2>{_esc(f)} <span class='meta'>"
                     f"({len(field_vals[f])} unique)</span></h2>")
        parts.append("<table><thead><tr><th style='width:80px'>Count</th>"
                     "<th>Value</th></tr></thead><tbody>")
        for v, c in field_vals[f].most_common(50):
            parts.append(f"<tr><td><span class='count'>{c}</span></td>"
                         f"<td>{_esc(v)}</td></tr>")
        parts.append("</tbody></table>")

    if paths:
        parts.append("<h2>Windows paths discovered</h2><table><thead><tr>"
                     "<th style='width:80px'>Count</th><th>Path</th>"
                     "</tr></thead><tbody>")
        for p, c in paths.most_common(30):
            parts.append(f"<tr><td><span class='count'>{c}</span></td>"
                         f"<td><code>{_esc(p)}</code></td></tr>")
        parts.append("</tbody></table>")

    if emails:
        parts.append("<h2>Email addresses</h2><table><thead><tr>"
                     "<th style='width:80px'>Count</th><th>Email</th>"
                     "</tr></thead><tbody>")
        for e, c in emails.most_common(50):
            parts.append(f"<tr><td><span class='count'>{c}</span></td>"
                         f"<td><code>{_esc(e)}</code></td></tr>")
        parts.append("</tbody></table>")

    parts.append("<h2>Files</h2><table><thead><tr><th>Type</th><th>Source URL</th>"
                 "<th>Author</th><th>Company</th><th>Producer</th>"
                 "<th style='width:80px'>Size</th></tr></thead><tbody>")
    for m in sorted(metadata, key=lambda x: x.get("ext", "")):
        exif = m.get("exif") or {}
        author = next((v for k, v in exif.items()
                       if k.endswith("Author") and v), "") or ""
        company = next((v for k, v in exif.items()
                        if k.endswith("Company") and v), "") or ""
        producer = next((v for k, v in exif.items()
                         if (k.endswith("Producer") or k.endswith("Application"))
                         and v), "") or ""
        size_kb = (m.get("size") or 0) // 1024
        url = m.get("url", "")
        parts.append(
            f"<tr><td><span class='tag'>{_esc(m.get('ext',''))}</span></td>"
            f"<td class='url-cell'><a href='{_esc(url)}' "
            f"target='_blank' rel='noopener'>{_esc(url)}</a></td>"
            f"<td>{_esc(author)}</td><td>{_esc(company)}</td>"
            f"<td>{_esc(producer)}</td><td>{size_kb} KB</td></tr>"
        )
    parts.append("</tbody></table>")

    parts.append("</body></html>")
    out = target_dir / "report.html"
    out.write_text("".join(parts))
    log.info("wrote %s", out)


def render_dork_report(findings: list[dict], domain: str,
                       all_dorks: list[tuple[str, str, str]],
                       target_dir: Path) -> None:
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_cat[f["category"]].append(f)

    cat_dorks_total: dict[str, int] = defaultdict(int)
    for c, _d, _q in all_dorks:
        cat_dorks_total[c] += 1

    sev_counts: Counter = Counter()
    for f in findings:
        sev_counts[CATEGORY_SEVERITY.get(f["category"], "info")] += 1

    unique_hosts: set[str] = set()
    engine_counts: Counter = Counter()
    for f in findings:
        host = up.urlsplit(f.get("url", "")).hostname or ""
        if host:
            unique_hosts.add(host)
        engine_counts[f.get("engine", "?")] += 1

    url_dorks: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        url_dorks[f["url"]].add(f["dork_id"])
    multi_hit = {u: dids for u, dids in url_dorks.items() if len(dids) > 1}

    hit_dork_ids = {f["dork_id"] for f in findings}
    zero_hit = [(c, d, q) for c, d, q in all_dorks if d not in hit_dork_ids]

    def _cat_sort_key(c: str) -> tuple:
        sev = CATEGORY_SEVERITY.get(c, "info")
        return (_SEV_ORDER.get(sev, 4), -len(by_cat.get(c, [])))

    parts: list[str] = []
    parts.append(f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                 f"<title>Dork report — {_esc(domain)}</title>"
                 f"<style>{_HTML_CSS}</style></head><body>")
    parts.append(f"<h1>Dork Sweep — {_esc(domain)}</h1>")
    parts.append(f"<p class='meta'>Generated "
                 f"{datetime.now(timezone.utc).isoformat()} · "
                 f"{len(findings)} findings across "
                 f"{len(by_cat)} categories · "
                 f"{len(all_dorks)} dorks executed</p>")

    # --- executive summary ---
    if findings:
        parts.append("<h2>Executive Summary</h2>")
        parts.append("<div class='stat-row'>")
        for sev_label, color in [("Critical", "#dc2626"), ("High", "#f97316"),
                                  ("Medium", "#eab308"), ("Low", "#3b82f6"),
                                  ("Info", "#6b7280")]:
            count = sev_counts.get(sev_label.lower(), 0)
            parts.append(
                f"<div class='stat-tile' style='border-top-color:{color}'>"
                f"<div class='stat-num'>{count}</div>"
                f"<div class='stat-label'>{sev_label}</div></div>")
        parts.append("</div>")
        parts.append("<div class='stat-row'>")
        parts.append(f"<div class='stat-tile'><div class='stat-num'>"
                     f"{len(unique_hosts)}</div>"
                     f"<div class='stat-label'>Unique Hosts</div></div>")
        parts.append(f"<div class='stat-tile'><div class='stat-num'>"
                     f"{len(multi_hit)}</div>"
                     f"<div class='stat-label'>Multi-Dork URLs</div></div>")
        for eng, cnt in engine_counts.most_common():
            parts.append(f"<div class='stat-tile'><div class='stat-num'>"
                         f"{cnt}</div>"
                         f"<div class='stat-label'>{_esc(eng)}</div></div>")
        parts.append("</div>")

    # --- filter bar ---
    if findings:
        cats_json = json.dumps(sorted(by_cat.keys(), key=_cat_sort_key))
        parts.append(
            "<div class='filter-bar' id='filterBar'>"
            "<input type='text' id='filterText' placeholder='Search URLs, titles, snippets...'>"
            f"<select id='filterCat'><option value=''>All categories</option></select>"
            "<select id='filterSev'><option value=''>All severities</option>"
            "<option value='critical'>Critical</option>"
            "<option value='high'>High</option>"
            "<option value='medium'>Medium</option>"
            "<option value='low'>Low</option>"
            "<option value='info'>Info</option></select>"
            "<select id='filterEngine'><option value=''>All engines</option>"
            "<option value='ddg'>DDG</option>"
            "<option value='google'>Google</option></select>"
            "<button onclick='clearFilters()'>Clear</button>"
            "<button onclick='copyVisibleUrls()'>Copy Visible URLs</button>"
            "<span class='filter-count' id='filterCount'></span>"
            "</div>")

    # --- summary by category ---
    parts.append("<h2>Summary by category</h2><table><thead><tr>"
                 "<th>Category</th><th style='width:100px'>Severity</th>"
                 "<th style='width:100px'>Findings</th>"
                 "<th style='width:100px'>Dorks</th></tr></thead><tbody>")
    for cat in sorted(by_cat.keys(), key=_cat_sort_key):
        sev = CATEGORY_SEVERITY.get(cat, "info")
        parts.append(
            f"<tr><td><strong>{_esc(cat)}</strong></td>"
            f"<td><span class='tag sev-{sev}'>{sev}</span></td>"
            f"<td><span class='count'>{len(by_cat[cat])}</span></td>"
            f"<td>{cat_dorks_total[cat]}</td></tr>"
        )
    parts.append("</tbody></table>")

    # --- per-category findings ---
    for cat in sorted(by_cat.keys(), key=_cat_sort_key):
        sev = CATEGORY_SEVERITY.get(cat, "info")
        parts.append(
            f"<div class='cat-section sev-{sev}' data-category='{_esc(cat)}' "
            f"data-severity='{sev}'>")
        parts.append(
            f"<h2>{_esc(cat)} "
            f"<span class='tag sev-{sev}'>{sev}</span> "
            f"<span class='meta'>({len(by_cat[cat])} findings)</span></h2>")
        by_dork: dict[str, list[dict]] = defaultdict(list)
        for f in by_cat[cat]:
            by_dork[f["dork_id"]].append(f)
        for dork_id, items in sorted(by_dork.items(),
                                     key=lambda x: -len(x[1])):
            query = items[0]["dork_query"]
            parts.append(
                f"<details open><summary>{_esc(dork_id)} "
                f"<span class='count'>{len(items)}</span></summary>"
                f"<p class='meta'><code>{_esc(query)}</code></p>"
                "<table><thead><tr><th>URL / Title</th>"
                "<th style='width:100px'>Engine</th></tr></thead><tbody>"
            )
            for it in items:
                title = it.get("title") or ""
                snippet = it.get("snippet") or ""
                url = it.get("url", "")
                engine = it.get("engine", "")
                parts.append(
                    f"<tr class='finding-row' data-category='{_esc(cat)}' "
                    f"data-severity='{sev}' data-engine='{_esc(engine)}' "
                    f"data-url='{_esc(url)}'>"
                    f"<td class='url-cell'>"
                    f"<a href='{_esc(url)}' target='_blank' "
                    f"rel='noopener'><strong>{_esc(title) if title else _esc(url)}"
                    f"</strong></a><br>"
                    f"<code style='font-size:.8em'>{_esc(url)}</code>"
                    + (f"<div class='snippet'>{_esc(snippet)}</div>"
                       if snippet else "") +
                    f"</td><td><span class='tag engine'>{_esc(engine)}</span></td></tr>"
                )
            parts.append("</tbody></table></details>")
        parts.append("</div>")

    # --- multi-dork URLs ---
    if multi_hit:
        parts.append(f"<h2>URLs flagged by multiple dorks "
                     f"<span class='meta'>({len(multi_hit)})</span></h2>")
        parts.append("<table><thead><tr><th>URL</th>"
                     "<th style='width:80px'>Dorks</th>"
                     "<th>Matched By</th></tr></thead><tbody>")
        for url, dork_ids in sorted(multi_hit.items(),
                                    key=lambda x: -len(x[1])):
            parts.append(
                f"<tr><td class='url-cell'><a href='{_esc(url)}' target='_blank' "
                f"rel='noopener'>{_esc(url)}</a></td>"
                f"<td><span class='multi-hit-count'>{len(dork_ids)}</span></td>"
                f"<td>{', '.join(_esc(d) for d in sorted(dork_ids))}</td></tr>")
        parts.append("</tbody></table>")

    # --- zero-hit dorks ---
    if zero_hit:
        parts.append(f"<details><summary>Dorks with 0 results "
                     f"<span class='count'>{len(zero_hit)}</span></summary>")
        parts.append("<table><thead><tr><th>Category</th><th>Dork ID</th>"
                     "<th>Query</th></tr></thead><tbody>")
        for c, d, q in zero_hit:
            parts.append(f"<tr><td>{_esc(c)}</td><td>{_esc(d)}</td>"
                         f"<td><code>{_esc(q)}</code></td></tr>")
        parts.append("</tbody></table></details>")

    if not findings:
        parts.append("<p>No findings. Try broader categories or "
                     "verify search engines are reaching the target.</p>")

    # --- inline JavaScript for filtering ---
    parts.append("""<script>
(function(){
  var rows=document.querySelectorAll('.finding-row');
  var sections=document.querySelectorAll('.cat-section');
  var tF=document.getElementById('filterText');
  var fC=document.getElementById('filterCat');
  var fS=document.getElementById('filterSev');
  var fE=document.getElementById('filterEngine');
  var fCount=document.getElementById('filterCount');
  if(!tF)return;
  var cats=new Set();
  sections.forEach(function(s){cats.add(s.dataset.category)});
  cats.forEach(function(c){
    var o=document.createElement('option');o.value=c;o.textContent=c;fC.appendChild(o);
  });
  function applyFilters(){
    var text=(tF.value||'').toLowerCase();
    var cat=fC.value;var sev=fS.value;var eng=fE.value;
    var visible=0;
    rows.forEach(function(r){
      var show=true;
      if(cat&&r.dataset.category!==cat)show=false;
      if(sev&&r.dataset.severity!==sev)show=false;
      if(eng&&r.dataset.engine!==eng)show=false;
      if(text&&r.textContent.toLowerCase().indexOf(text)<0)show=false;
      r.style.display=show?'':'none';
      if(show)visible++;
    });
    sections.forEach(function(s){
      var any=false;
      s.querySelectorAll('.finding-row').forEach(function(r){
        if(r.style.display!=='none')any=true;
      });
      s.style.display=any?'':'none';
    });
    fCount.textContent=visible+'/'+rows.length+' findings';
  }
  tF.addEventListener('input',applyFilters);
  fC.addEventListener('change',applyFilters);
  fS.addEventListener('change',applyFilters);
  fE.addEventListener('change',applyFilters);
  applyFilters();
  window.clearFilters=function(){tF.value='';fC.value='';fS.value='';fE.value='';applyFilters()};
  window.copyVisibleUrls=function(){
    var urls=[];
    rows.forEach(function(r){if(r.style.display!=='none')urls.push(r.dataset.url)});
    var unique=[...new Set(urls)];
    var text=unique.join('\\n');
    function fallback(){
      var ta=document.createElement('textarea');
      ta.value=text;ta.style.position='fixed';ta.style.opacity='0';
      document.body.appendChild(ta);ta.select();
      try{document.execCommand('copy');alert('Copied '+unique.length+' URLs')}
      catch(e){alert('Copy failed — select and copy manually:\\n'+text)}
      document.body.removeChild(ta);
    }
    if(navigator.clipboard&&window.isSecureContext){
      navigator.clipboard.writeText(text).then(function(){
        alert('Copied '+unique.length+' URLs');
      },fallback);
    }else{fallback()}
  };
})();
</script>""")

    parts.append("</body></html>")
    out = target_dir / "report.html"
    out.write_text("".join(parts))
    log.info("wrote %s", out)


# --------------------------- entry ---------------------------

def main() -> int:
    args = parse_args()
    # list-only mode should not require browser/dependency/exiftool checks
    # since no searches/downloads execute.
    if args.mode == "dork" and getattr(args, "list_dorks", False):
        return cmd_dork(args)
    preflight(args)
    if args.mode == "metadata":
        return cmd_metadata(args)
    if args.mode == "dork":
        return cmd_dork(args)
    raise SystemExit(f"unknown mode: {args.mode}")


if __name__ == "__main__":
    sys.exit(main())
