#!/usr/bin/env python3
"""`confluence-axis-scanner` — detection-only triage for Atlassian Confluence
Data Center `CVE-2026-90436` (Apache Axis 1.x unsafe reflection, unauthenticated
remote code execution, CVSS 9.8).

Confluence bundles Apache Axis 1.x for its XML-RPC and SOAP APIs. Axis parses
an inbound SOAP `<Fault>` before any per-service authentication runs, so a
`<detail><exceptionName>` element makes it load and instantiate an attacker
named class through its String constructor. Loading alone runs the class's
static initializer, and with a suitable class on the classpath that is remote
code execution. The flaw only bites when the `Remote API (XML-RPC & SOAP)`
setting is on — off by default for new installs since Confluence 3.0, removed
entirely in Confluence 10.0.

Rapid7 MDR detected exploitation against Confluence Data Center on
2026-11-13, and the same Axis flaw is the entry point of the 4EverAble2Shell
chain against N-able N-central (at least 21 production servers compromised).
Apache will not ship a fixed Axis 1.x release — the library is end of life —
so each vendor has to fix its own bundle. Atlassian's fix is Confluence
Data Center 9.2.28, released 2026-11-10.

This tool grades a Confluence install by its version, and — against a live
instance — probes the Remote API endpoint the way Atlassian's own advisory
tells you to validate the mitigation. It sends no SOAP body, no payloads,
no exploit traffic: one plain GET for the version, one plain GET for the
endpoint. Nothing that could trigger the flaw.

Fixed version, per the Atlassian advisory (2026-11-09, 22:00 PST):

    Confluence Data Center 9.2.28 (and later 9.2.x patch releases)

Confluence 10.x and later are not affected (the feature was removed).
Atlassian Cloud is not affected. Every other line — 9.0, 9.1, 9.3, 9.4,
9.5, 8.x and older — is listed affected with no fixed build named:
upgrade to 9.2.28 or 10.x+.

Usage:

    # against a live instance: version from the page + the endpoint probe
    python3 confluence_axis_scanner.py --url https://wiki.example.com/

    # a version string from inventory
    python3 confluence_axis_scanner.py --version "9.2.27"
    python3 confluence_axis_scanner.py --version "9.2.28"

    # a build number (CONFVERSION.BUILDNUMBER, or ajs-build-number)
    python3 confluence_axis_scanner.py --build-number 9117

    # on the Confluence box itself (reads the install jar + the log)
    python3 confluence_axis_scanner.py --local
    python3 confluence_axis_scanner.py --local --install-dir /opt/atlassian/confluence

    # saved page HTML, or any file holding a version string
    python3 confluence_axis_scanner.py --version-file /path/to/login.html

    # a whole fleet at once
    python3 confluence_axis_scanner.py --inventory-json fleet.json

    # the Remote API setting is off (the vendor mitigation)
    python3 confluence_axis_scanner.py --version "9.2.27" --no-remote-api

    # machine output / the fixed-version table
    python3 confluence_axis_scanner.py --version "9.2.28" --json
    python3 confluence_axis_scanner.py --list

Exit codes: 0 patched / not affected / not exposed, 1 vulnerable,
2 unknown, 3 usage error.
"""

import argparse
import glob
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

CVE_ID = "CVE-2026-90436"

# The only fixed build Atlassian names. 9.2.28, released 2026-11-10.
FIXED_VERSION = (9, 2, 28)

# Confluence 10.0 removed the Remote API feature entirely.
FIRST_UNAFFECTED_MAJOR = 10

# Build numbers, per Atlassian's Confluence build information page.
# 9117 spans 9.2.24 through 9.2.28: vulnerable and fixed share one build.
# 9304 is 10.0.0, the first build without the feature.
AMBIGUOUS_BUILD = 9117
FIRST_UNAFFECTED_BUILD = 9304

SOAP_PATH = "/plugins/servlet/soap-axis1/confluenceservice-v2"
LOGIN_PATH = "/login.action"

USER_AGENT = "confluence-axis-scanner/1.0 (detection-only version check)"

# Minor lines on the 9.x train with no fixed build named in the advisory.
NO_FIX_9X = (0, 1, 3, 4, 5)

DEFAULT_INSTALL_DIRS = (
    "/opt/atlassian/confluence",
    "/usr/local/confluence",
    "/opt/confluence",
)
DEFAULT_HOME_DIRS = (
    "/var/atlassian/application-data/confluence",
    "/var/atlassian/applicationdata/confluence",
)


def parse_version_tuple(text):
    """Parse `9.2.28`, `9.2` or `9` into a tuple of ints, or None."""
    if not text:
        return None
    parts = text.strip().split(".")
    if not all(p.isdigit() for p in parts):
        return None
    if len(parts) > 3:
        return None
    return tuple(int(p) for p in parts)


def parse_version(text):
    """Pull a Confluence version and build number out of free text.

    Anchored patterns first (page meta tags, jar filenames, install dir
    names, `Powered by` footers), then a bare version string as the last
    resort, so a stray date or port number in a log line is not mistaken
    for a version. Returns `(version, build)` with `version` a tuple of
    ints (1-3 parts) or None, and `build` an int or None.
    """
    if not text:
        return None, None
    version = None
    build = None

    m = re.search(
        r"ajs-version-number[\"']?\s+content=[\"'](\d+\.\d+(?:\.\d+)?)",
        text, re.IGNORECASE)
    if not m:
        m = re.search(r"confluence-(\d+\.\d+(?:\.\d+)?)\.jar", text,
                      re.IGNORECASE)
    if not m:
        m = re.search(r"atlassian-confluence-(\d+\.\d+(?:\.\d+)?)", text,
                      re.IGNORECASE)
    if not m:
        m = re.search(
            r"Powered by Atlassian Confluence\s+(\d+\.\d+(?:\.\d+)?)",
            text, re.IGNORECASE)
    if not m:
        m = re.search(r"\bConfluence\s+(\d+\.\d+(?:\.\d+)?)", text)
    if not m:
        # Bare version string, e.g. --version "9.2.28" or "9.2".
        m = re.search(r"^\s*(\d+\.\d+(?:\.\d+)?)\s*$", text)
    if m:
        version = parse_version_tuple(m.group(1))

    b = re.search(
        r"ajs-build-number[\"']?\s+content=[\"'](\d+)", text, re.IGNORECASE)
    if not b:
        b = re.search(r"buildNumber\s*[=:]\s*(\d+)", text, re.IGNORECASE)
    if not b:
        b = re.search(r"\bBUILDNUMBER\b[^0-9]{0,40}(\d+)", text,
                      re.IGNORECASE)
    if b:
        build = int(b.group(1))
    return version, build


def grade_version(version):
    """Grade a version tuple. Returns (verdict, reason)."""
    if not version:
        return "UNKNOWN", "no Confluence version found in the input"
    if len(version) == 1:
        if version[0] >= FIRST_UNAFFECTED_MAJOR:
            return "NOT-AFFECTED", (
                "Confluence %d.x: the Remote API (XML-RPC & SOAP) "
                "feature was removed in Confluence 10.0, so %s does "
                "not apply." % (version[0], CVE_ID)
            )
        return "UNKNOWN", (
            "bare major version %d says nothing about the patch level. "
            "The fix is 9.2.28, and 10.x is not affected. Give the full "
            "version, e.g. --version \"9.2.28\"." % version[0]
        )
    if len(version) == 2:
        major, minor = version
        if major >= FIRST_UNAFFECTED_MAJOR:
            return "NOT-AFFECTED", (
                "Confluence %d.%d.x: the Remote API (XML-RPC & SOAP) "
                "feature was removed in Confluence 10.0, so %s does "
                "not apply." % (major, minor, CVE_ID)
            )
        if (major, minor) == (9, 2):
            return "UNKNOWN", (
                "bare 9.2 says nothing about the patch level: 9.2.0 "
                "through 9.2.27 are vulnerable and the fix is 9.2.28. "
                "Give the full version, e.g. --version \"9.2.28\", or "
                "the build number with --build-number."
            )
        return "UNKNOWN", (
            "bare %d.%d says nothing about the patch level. Give the "
            "full version, e.g. --version \"%d.%d.0\"."
            % (major, minor, major, minor)
        )

    major, minor, patch = version
    if major >= FIRST_UNAFFECTED_MAJOR:
        return "NOT-AFFECTED", (
            "Confluence %d.%d.%d: the Remote API (XML-RPC & SOAP) "
            "feature was removed in Confluence 10.0, so %s does not "
            "apply. (Advisory: 10.x and above are not impacted.)"
            % (major, minor, patch, CVE_ID)
        )
    if major == 9 and minor == 2:
        if patch >= FIXED_VERSION[2]:
            return "PATCHED", (
                "Confluence 9.2.%d is at or above the fixed release "
                "9.2.28 (Atlassian advisory, 2026-11-10)." % patch
            )
        return "VULNERABLE", (
            "Confluence 9.2.%d is below the fixed release 9.2.28 "
            "(Atlassian advisory). Upgrade to 9.2.28 or later, or to "
            "10.x+. Until then, turn off Remote API (XML-RPC & SOAP)."
            % patch
        )
    if major == 9 and minor in NO_FIX_9X:
        return "VULNERABLE", (
            "Confluence 9.%d.%d is listed affected with no fixed build "
            "named for the 9.%d line. Atlassian's advisory names only "
            "9.2.28 as fixed: upgrade to 9.2.28 (LTS) or 10.x+."
            % (minor, patch, minor)
        )
    if major == 9:
        return "UNKNOWN", (
            "Confluence 9.%d.%d is not in the advisory's fixed-version "
            "table, which names only 9.2.28. Do not assume it is clean; "
            "check the advisory for your line." % (minor, patch)
        )
    if major >= 1:
        return "VULNERABLE", (
            "Confluence %d.%d.%d is listed affected (1.x.x through "
            "9.x.x) with no fixed build named for its line. Upgrade to "
            "9.2.28 or 10.x+." % (major, minor, patch)
        )
    return "UNKNOWN", "unrecognised version %s" % (version,)


def grade_build(build):
    """Grade a Confluence build number. Returns (verdict, reason).

    Build numbers repeat across versions, so this is coarser than the
    version string and only used when no version is available.
    """
    if build is None:
        return "UNKNOWN", "no build number given"
    if build <= 0:
        return "UNKNOWN", "build number %d is not a real Confluence build" % build
    if build >= FIRST_UNAFFECTED_BUILD:
        return "NOT-AFFECTED", (
            "Build %d is Confluence 10.0.0 or later (build %d is "
            "10.0.0), and the Remote API feature was removed in 10.0, "
            "so %s does not apply." % (build, FIRST_UNAFFECTED_BUILD,
                                        CVE_ID)
        )
    if build == AMBIGUOUS_BUILD:
        return "UNKNOWN", (
            "Build %d spans Confluence 9.2.24 through 9.2.28: 9.2.24–"
            "9.2.27 are vulnerable and 9.2.28 is the fix, and the build "
            "number alone cannot tell them apart. Give the version "
            "string instead, e.g. --version \"9.2.28\"."
            % AMBIGUOUS_BUILD
        )
    return "VULNERABLE", (
        "Build %d is a pre-10.0 build. Every pre-10.0 line is listed "
        "affected, and the only fixed version is 9.2.28 (build %d), so "
        "this build is vulnerable. Upgrade to 9.2.28 or 10.x+."
        % (build, AMBIGUOUS_BUILD)
    )


def triage(version, build, remote_api=None, remote_api_off=False,
           cloud=False):
    """Combine version/build grading with Remote API evidence.

    `remote_api` is `exposed`, `off`, or None (not probed). Returns a
    dict with verdict, reason, and a warnings list.
    """
    warnings = []
    if cloud:
        return {"verdict": "NOT-AFFECTED",
                "reason": "Atlassian Cloud is not affected by %s "
                          "(advisory). This check is for Confluence "
                          "Data Center." % CVE_ID,
                "warnings": warnings,
                "version": version, "build": build}

    if version is not None:
        verdict, reason = grade_version(version)
    elif build is not None:
        verdict, reason = grade_build(build)
    else:
        verdict, reason = "UNKNOWN", (
            "no Confluence version or build number found in the input. "
            "Give --version, --build-number, --url, or --local."
        )

    if remote_api == "exposed":
        if verdict == "UNKNOWN":
            # The endpoint only answers on pre-10.0 instances with the
            # feature on, and every such version is affected.
            verdict = "VULNERABLE"
            reason = (
                "The Remote API endpoint answers, which only happens on "
                "a pre-10.0 instance with Remote API (XML-RPC & SOAP) "
                "enabled — and every version on those lines is listed "
                "affected. The version itself could not be read, so "
                "confirm it and upgrade to 9.2.28 or 10.x+."
            )
        elif verdict == "VULNERABLE":
            warnings.append(
                "The Remote API endpoint answers, so the flaw is "
                "reachable from the network. Turn off Remote API "
                "(XML-RPC & SOAP) now if you cannot patch immediately."
            )
        elif verdict == "PATCHED":
            warnings.append(
                "The Remote API endpoint still answers. The Axis flaw "
                "is fixed in 9.2.28, but the API is live surface — "
                "disable it if nothing needs it."
            )
        elif verdict == "NOT-AFFECTED":
            warnings.append(
                "The Remote API endpoint answers on a 10.x+ instance, "
                "which should not have the feature at all. Re-check "
                "the version: something here does not add up."
            )

    if remote_api == "off":
        if verdict == "VULNERABLE":
            verdict = "NOT-EXPOSED"
            reason = (
                "The Remote API endpoint returns 403, which is "
                "Atlassian's own check that Remote API (XML-RPC & "
                "SOAP) is off — so the flaw cannot be reached. The "
                "version itself is still vulnerable (%s), so this is "
                "the mitigation, not a patch: upgrade to 9.2.28 or "
                "10.x+." % reason
            )
        elif verdict == "UNKNOWN":
            warnings.append(
                "The Remote API endpoint returns 403, which suggests "
                "the mitigation is on, but the version could not be "
                "graded, so this is not a clean verdict. Confirm the "
                "version."
            )
        elif verdict == "PATCHED":
            warnings.append(
                "The Remote API endpoint returns 403 (off). Good — "
                "patched and the API is off."
            )

    if remote_api_off:
        if verdict == "VULNERABLE":
            verdict = "NOT-EXPOSED"
            reason = (
                "Remote API (XML-RPC & SOAP) is off (per --no-remote-"
                "api), so the flaw cannot be reached. The version "
                "itself is still vulnerable (%s), so this is the "
                "mitigation, not a patch: upgrade to 9.2.28 or 10.x+."
                % reason
            )
        elif verdict == "UNKNOWN":
            warnings.append(
                "Remote API is reported off, but the version could not "
                "be graded, so this is not a clean verdict. Confirm "
                "the version."
            )

    return {"verdict": verdict, "reason": reason, "warnings": warnings,
            "version": version, "build": build}


def version_string(version, build):
    if version:
        text = ".".join(str(p) for p in version)
        if build is not None:
            text += " (build %d)" % build
        return text
    if build is not None:
        return "build %d (version unknown)" % build
    return "unknown"


def format_result(result, as_json=False):
    if as_json:
        return json.dumps(result, indent=2, sort_keys=True)
    lines = [
        "version: %s" % version_string(result.get("version"),
                                       result.get("build")),
        "verdict: %s" % result["verdict"],
        "reason: %s" % result["reason"],
    ]
    if result.get("remote_api"):
        lines.append("remote_api: %s" % result["remote_api"])
    if result.get("source"):
        lines.append("source: %s" % result["source"])
    if result.get("url"):
        lines.append("url: %s" % result["url"])
    for warning in result.get("warnings", []):
        lines.append("WARNING: %s" % warning)
    if result.get("ioc_hint"):
        lines.append("ioc: %s" % result["ioc_hint"])
    lines.append(
        "chain: the same Axis flaw is the entry point of the "
        "4EverAble2Shell chain against N-able N-central (Legacy API "
        "enabled, 2026.4 HF2 still exposed). If you run N-central too, "
        "disable Legacy API until HF3; this tool does not grade it."
    )
    return "\n".join(lines)


def fetch_url(url, timeout=20, insecure=False):
    """One plain GET. Returns (status, body_text). Raises RuntimeError
    with a human-readable cause on transport failure."""
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        # A 403/404 still tells us something; read the body if any.
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, body
    except urllib.error.URLError as exc:
        raise RuntimeError("could not reach %s: %s" % (url, exc.reason))
    except (ssl.SSLError, OSError) as exc:
        raise RuntimeError("could not reach %s: %s" % (url, exc))


def is_cloud_host(url):
    host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    host = host.split("/")[0].split("@")[-1].split(":")[0].lower()
    return host.endswith(".atlassian.net") or host.endswith(".jira.com")


def probe_remote_api(base_url, timeout=20, insecure=False):
    """The vendor's own validation step, as a plain GET.

    Returns `exposed` (endpoint answers with an AXIS service page),
    `off` (403, the advisory's mitigated signal), or `unknown`.
    No SOAP body is sent, so nothing here can trigger the flaw.
    """
    url = base_url.rstrip("/") + SOAP_PATH
    status, body = fetch_url(url, timeout=timeout, insecure=insecure)
    if status == 403:
        return "off", "HTTP 403 on %s" % SOAP_PATH
    if status == 200 and re.search(r"confluenceservice|axis",
                                   body, re.IGNORECASE):
        return "exposed", (
            "HTTP 200 on %s with an AXIS service page: Remote API is on"
            % SOAP_PATH)
    return "unknown", "HTTP %d on %s (no AXIS service page seen)" % (
        status, SOAP_PATH)


def probe_url(base_url, timeout=20, insecure=False):
    """Grade a live instance: version from the page, endpoint probe."""
    if is_cloud_host(base_url):
        result = triage(None, None, cloud=True)
        result["url"] = base_url
        return result

    version = None
    build = None
    try:
        _, body = fetch_url(base_url, timeout=timeout, insecure=insecure)
        version, build = parse_version(body)
        if version is None:
            # The login page carries the same meta tags.
            _, body = fetch_url(base_url.rstrip("/") + LOGIN_PATH,
                                timeout=timeout, insecure=insecure)
            version, build = parse_version(body)
    except RuntimeError as exc:
        raise
    remote_api, probe_detail = probe_remote_api(
        base_url, timeout=timeout, insecure=insecure)
    result = triage(version, build, remote_api=remote_api)
    result["remote_api"] = "%s (%s)" % (remote_api, probe_detail)
    result["url"] = base_url
    return result


def find_local_version(install_dir=None, home_dir=None):
    """Find the version on the Confluence box itself.

    Sources, in order: the `confluence-x.y.z.jar` filename in
    WEB-INF/lib, the install directory name, the last `Confluence x.y.z`
    line in atlassian-confluence.log. Returns (version, build, source).
    """
    install_dirs = []
    if install_dir:
        install_dirs.append(install_dir)
    install_dirs.extend(DEFAULT_INSTALL_DIRS)
    home_dirs = []
    if home_dir:
        home_dirs.append(home_dir)
    home_dirs.extend(DEFAULT_HOME_DIRS)

    for base in install_dirs:
        if not base or not os.path.isdir(base):
            continue
        jars = glob.glob(os.path.join(
            base, "confluence", "WEB-INF", "lib", "confluence-*.jar"))
        for jar in sorted(jars):
            version, _ = parse_version(os.path.basename(jar))
            if version:
                return version, None, "jar %s" % jar
        version, _ = parse_version(os.path.basename(
            os.path.normpath(base)))
        if version:
            return version, None, "install dir %s" % base

    for home in home_dirs:
        if not home:
            continue
        log = os.path.join(home, "logs", "atlassian-confluence.log")
        if not os.path.isfile(log):
            continue
        try:
            with open(log, "r", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        matches = re.findall(r"\bConfluence\s+(\d+\.\d+(?:\.\d+)?)", text)
        if matches:
            # The log accumulates across upgrades; the last startup
            # line is the running version.
            return (parse_version_tuple(matches[-1]), None,
                    "log %s (last startup line)" % log)
    return None, None, ""


def grade_entry(entry):
    """Grade one inventory entry dict. Returns a result dict."""
    host = entry.get("host", "unknown")
    version_text = entry.get("version", "")
    version = None
    build = entry.get("build")
    if "version_file" in entry:
        try:
            with open(entry["version_file"], "r", errors="replace") as fh:
                version_text = fh.read()
        except OSError as exc:
            return {"host": host, "verdict": "UNKNOWN",
                    "reason": "could not read %s: %s"
                    % (entry["version_file"], exc), "warnings": []}
    if version_text:
        version, parsed_build = parse_version(version_text)
        if build is None:
            build = parsed_build
    if entry.get("cloud"):
        result = triage(None, None, cloud=True)
    else:
        result = triage(version, build,
                        remote_api_off=bool(entry.get("remote_api_off")))
    result["host"] = host
    if version_text:
        result["version_text"] = version_text.strip()[:80]
    return result


def fixed_table():
    rows = [
        "Confluence Data Center — %s" % CVE_ID,
        "affected: 1.x.x through 9.x.x (Remote API enabled)",
        "fixed:    9.2.28 (released 2026-11-10, build 9117)",
        "not affected: 10.x and later (feature removed), Atlassian Cloud",
        "",
        "9.2.x at or above 9.2.28  -> PATCHED",
        "9.2.0 - 9.2.27             -> VULNERABLE",
        "9.0 / 9.1 / 9.3 / 9.4 / 9.5 -> VULNERABLE (no fix on the line)",
        "1.x - 8.x                 -> VULNERABLE (no fix, upgrade)",
        "bare 9.2 / bare 9         -> UNKNOWN (give the full version)",
        "",
        "build numbers (coarse; prefer the version string):",
        "build 9117                -> UNKNOWN (spans 9.2.24-9.2.28)",
        "build 9304 and later      -> NOT-AFFECTED (10.0.0+)",
        "any other pre-10.0 build  -> VULNERABLE",
    ]
    return "\n".join(rows)


EXIT_CODES = {"PATCHED": 0, "NOT-AFFECTED": 0, "NOT-EXPOSED": 0,
              "VULNERABLE": 1, "UNKNOWN": 2}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for Confluence Data Center "
                    "%s (Apache Axis 1.x RCE)." % CVE_ID)
    parser.add_argument("--local", action="store_true",
                        help="run on the Confluence box: install jar + log")
    parser.add_argument("--install-dir",
                        help="Confluence install directory (with --local)")
    parser.add_argument("--home-dir",
                        help="Confluence home directory (with --local)")
    parser.add_argument("--version",
                        help='Confluence version, e.g. "9.2.27"')
    parser.add_argument("--build-number", type=int,
                        help="build number, e.g. 9117 (CONFVERSION)")
    parser.add_argument("--version-file",
                        help="file holding page HTML or a version string")
    parser.add_argument("--url",
                        help="base URL of a Confluence instance, "
                             "e.g. https://wiki.example.com/")
    parser.add_argument("--inventory-json",
                        help="fleet file: list of {host, version[, build]}")
    parser.add_argument("--no-remote-api", action="store_true",
                        help="Remote API (XML-RPC & SOAP) is disabled "
                             "(the vendor mitigation)")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS verification (self-signed certs)")
    parser.add_argument("--list", action="store_true",
                        help="print the fixed-version table and exit")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    args = parser.parse_args(argv)

    if args.list:
        print(fixed_table())
        return 0

    if args.url:
        try:
            result = probe_url(args.url, insecure=args.insecure)
        except RuntimeError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 3
        result["ioc_hint"] = (
            "Rapid7 (2026-11-16) links these IPs to observed "
            "exploitation against Confluence Data Center: "
            "192.238.253.176, 5.133.47.243, 163.182.68.109, "
            "104.13.106.166. Check access logs; absence proves nothing."
        )
        print(format_result(result, args.json))
        return EXIT_CODES[result["verdict"]]

    if args.local:
        version, build, source = find_local_version(args.install_dir,
                                                    args.home_dir)
        if version is None and build is None:
            print("error: could not find a Confluence version in the "
                  "install dir or home dir. Pass --install-dir / "
                  "--home-dir, or use --version.", file=sys.stderr)
            return 3
        result = triage(version, build,
                        remote_api_off=args.no_remote_api)
        result["source"] = source
        print(format_result(result, args.json))
        return EXIT_CODES[result["verdict"]]

    if args.inventory_json:
        try:
            with open(args.inventory_json, "r") as fh:
                entries = json.load(fh)
        except (OSError, ValueError) as exc:
            print("error: could not read %s: %s"
                  % (args.inventory_json, exc), file=sys.stderr)
            return 3
        if not isinstance(entries, list):
            print("error: inventory file must hold a JSON list",
                  file=sys.stderr)
            return 3
        results = [grade_entry(e) for e in entries]
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        else:
            for result in results:
                print(format_result(result, False))
                print("---")
        return max(EXIT_CODES[r["verdict"]] for r in results)

    version_text = ""
    if args.version_file:
        try:
            with open(args.version_file, "r", errors="replace") as fh:
                version_text = fh.read()
        except OSError as exc:
            print("error: could not read %s: %s" % (args.version_file, exc),
                  file=sys.stderr)
            return 3
    elif args.version:
        version_text = args.version

    version = None
    build = args.build_number
    if version_text:
        version, parsed_build = parse_version(version_text)
        if build is None:
            build = parsed_build
    if version is None and build is None:
        parser.print_usage(sys.stderr)
        print("error: give --local, --url, --version, --build-number, "
              "--version-file, or --inventory-json", file=sys.stderr)
        return 3

    result = triage(version, build, remote_api_off=args.no_remote_api)
    print(format_result(result, args.json))
    return EXIT_CODES[result["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
