# `confluence-axis-scanner`

Detection-only triage for Atlassian Confluence Data Center `CVE-2026-90436` (Apache Axis 1.x unsafe reflection, unauthenticated remote code execution, `CVSS 9.8`). Grades your Confluence version against the fixed release, and against a live instance probes the Remote API endpoint the way Atlassian's own advisory tells you to validate the mitigation. No SOAP body, no payloads, no exploit traffic: two plain GETs, nothing that could trigger the flaw.

## `What it checks`

* `CVE-2026-90436` — Confluence bundles Apache Axis 1.x for its XML-RPC and SOAP APIs. Axis parses an inbound SOAP `<Fault>` before any per-service authentication runs, so a `<detail><exceptionName>` element makes it load and instantiate an attacker-named class through its String constructor. Loading alone runs the class's static initializer, and with a suitable class on the classpath that is remote code execution. `CVSS 9.8` (`CISA-ADP`, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), `CWE-470` unsafe reflection. Axis 1.x through 1.4 is affected and end of life; Apache will not ship a fixed Axis 1.x release.
* The flaw only bites when the `Remote API (XML-RPC & SOAP)` setting is on. It has been off by default for new installs since Confluence 3.0, and the feature was removed entirely in Confluence 10.0.
* Rapid7 MDR detected exploitation against Confluence Data Center on 2026-11-13, and the same Axis flaw is the entry point of the 4EverAble2Shell chain against N-able N-central, where at least 21 production servers were compromised (19 of them already on 2026.4 HF2) and a public proof-of-concept landed 2026-11-12. Rapid7 published its write-up 2026-11-16 and recommends patching on an emergency basis, outside the normal cycle.
* Rapid7 links these IPs to observed exploitation against Confluence Data Center: `192.238.253.176`, `5.133.47.243`, `163.182.68.109`, `104.13.106.166` (medium confidence, single-sourced to Rapid7 — verify before enforcing blocks). Check your access logs; absence of these addresses proves nothing.

Fixed version, per the Atlassian advisory (released 2026-11-09, 22:00 PST):

| `Confluence Data Center` | `Upgrade to` |
| --- | --- |
| `9.2.x` | `9.2.28` and later (released 2026-11-10, build `9117`) |

`10.x` and later are not affected (the feature was removed). Atlassian Cloud is not affected. Every other line — `9.0`, `9.1`, `9.3`, `9.4`, `9.5`, `8.x` and older — is listed affected with no fixed build named: upgrade to `9.2.28` or `10.x+`.

## `Usage`

```bash
# against a live instance: version from the page + the endpoint probe
python3 confluence_axis_scanner.py --url https://wiki.example.com/

# a version string from your inventory
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

# self-signed cert on the instance / machine output / the fix table
python3 confluence_axis_scanner.py --url https://wiki.example.com/ --insecure
python3 confluence_axis_scanner.py --version "9.2.28" --json
python3 confluence_axis_scanner.py --list
```

`--url` reads the version from the page's `ajs-version-number` meta tag (falling back to `/login.action` when the base page hides it), then GETs `/plugins/servlet/soap-axis1/confluenceservice-v2`: `403` means the Remote API is off (Atlassian's own validation step), a `200` with an AXIS service page means it is on and the flaw is reachable. `--local` reads the version from `confluence/WEB-INF/lib/confluence-x.y.z.jar`, the install directory name, or the last `Confluence x.y.z` line in `atlassian-confluence.log`.

`fleet.json` is a list of `{"host": "wiki-a", "version": "9.2.28"}` objects. Entries can use `"build"` instead of `"version"`, `"version_file"` to point at saved page HTML, `"remote_api_off": true` for the mitigation, and `"cloud": true` for Atlassian Cloud.

Exit codes: `0` patched / not affected / not exposed, `1` vulnerable, `2` unknown, `3` usage error.

## `The traps`

* `The 9.2.27 trap` — `9.2.27` shipped 2026-11-03, one week before the fix. One patch behind is still fully vulnerable. `9.2.28` is the fix, nothing earlier on the line is.
* `The build-number trap` — build `9117` spans `9.2.24` through `9.2.28`: vulnerable and fixed share one build number. A build number alone cannot tell `9.2.27` from `9.2.28`, so build `9117` grades `UNKNOWN`, never clean. Give the version string instead.
* `The no-fix-line trap` — the advisory names only `9.2.28` as fixed. `9.3.x`, `9.4.x`, `9.5.x`, `9.0.x`, `9.1.x` and `8.x` are all listed affected with no fixed build on their lines. There is no patch to install on those lines. Upgrade to `9.2.28` (LTS) or `10.x+`.
* `The bare-version trap` — `9.2` with no patch level says nothing: `9.2.0` through `9.2.27` are vulnerable and `9.2.28` is the fix. It grades `UNKNOWN`. Get the full version from the page meta tag, the install jar, or the log.
* `The mitigation trap` — turning off Remote API grades `NOT-EXPOSED` because the flaw cannot be reached, but the version is still vulnerable. It is the mitigation, not a patch. Upgrade anyway.
* `The 403 trap` — the endpoint probe treats `403` as "Remote API off" because that is Atlassian's own validation step. A `403` can also come from a WAF or reverse proxy in front of the instance. Confirm the setting in the admin UI (`General Configuration` → `Further Configuration`) before trusting it.
* `The N-central trap` — the same Axis flaw hits N-able N-central through its Legacy API, and `2026.4 HF2` is still exposed with Legacy API on. This tool does not grade N-central. If you run it too, disable Legacy API until HF3 ships.
* `The patched-but-live trap` — on a patched box the endpoint can still answer, because the fix is in the Axis library, not in the endpoint. The tool warns you instead of changing the verdict. Disable the API if nothing needs it.

## `Why version + endpoint probe`

Confluence hands its version to unauthenticated clients in the page meta tags, and the vendor's own advisory validates the mitigation with a plain GET to the SOAP endpoint. So this tool does exactly those two reads and nothing else. It never sends a SOAP envelope, a `<Fault>`, or any class name — the request that triggers the flaw is never constructed. Version grading is the verdict; the endpoint probe only tells you whether the flaw is reachable.

## `Sources and disagreements`

* Atlassian advisory `CVE-2026-90436` (released 2026-11-09, 22:00 PST): affected versions, the `9.2.28` fix, the mitigation and its `403` validation step. Primary source for everything graded here.
* Atlassian Confluence build information: `9.2.28` released 2026-11-10, build `9117`; `9.2.27` released 2026-11-03 on the same build; `10.0.0` is build `9304`. The build-number trap above comes straight from this table.
* Apache Axis security announcement (2026-11-06): the flaw, affected Axis 1.x through 1.4, EOL with no fixed release, patch commit `41f3b4e8d04e310ca81f86b92630ab2c11d608bd`.
* NVD: shows the CISA-ADP score `9.8` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`); NVD itself unscored as of 2026-11-17. Atlassian rates it `9.3` (`CVSS:4.0`) — lower because its vector scores the subsequent scope as none. The tool follows the `9.8`: the flaw is unauthenticated remote code execution, and CISA-ADP agrees.
* Rapid7 emergent threat response blog (2026-11-16): exploitation detected against Confluence Data Center 2026-11-13, the N-central exploitation the same day, the four Confluence IOC IPs above, emergency patching advice.
* N-able's incident update (2026-11-13) and Huntback's investigation (2026-11-12): the 21 compromised N-central servers, 19 on HF2, the `157.20.241.16` infrastructure. Those IOCs belong to N-central, not Confluence — do not transfer them across.
* CISA KEV: `CVE-2026-90436` is not listed as of 2026-11-17; EPSS sits at `1%`. The pick rests on confirmed exploitation, not a KEV entry.
* The CVE record itself is about Apache Axis 1.x, not Confluence versions — Confluence ranges come from the Atlassian advisory, not from NVD's affected-products table.
* No nuclei template exists for `CVE-2026-90436` (checked 2026-11-17: the canonical template path returns 404). The public proof-of-concepts are exploits for the Axis flaw and the N-central chain, not a Confluence version scanner. No dedicated public scanner for this CVE was found.

## `Thanks to`

* The Apache Axis team — disclosed the flaw and published the patch commit even though the line is EOL.
* Atlassian PSIRT — the advisory, the fixed version, and the endpoint validation step this tool is built on.
* Rapid7 MDR — detected the exploitation and published the IOCs.
* N-able and Huntback — the N-central investigation that showed what the chain does in the wild.

## `Disclaimer`

Detection only, for defenders checking their own instances. Educational use. If you are not supposed to be on the instance, do not run this against it.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
