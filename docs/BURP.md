# Burp Suite traffic in VAPT Lens

Burp Suite **Community has no built-in REST API**, so VAPT Lens cannot read its traffic
directly. There are three supported paths. All of them use **request metadata only** —
parameter values, cookies, auth headers and bodies are ignored or discarded.

> The bridge must be running for live streaming or AI analysis:
> `npm run bridge` from the project root. Verify with
> `curl http://127.0.0.1:8787/api/health` (expect `{"ok":true,...}`).

## Path A — live traffic with the Jython extension (recommended)

Install the optional extension `burp/burp_to_bridge.py`. It is community-safe and
never sends bodies or values.

**Version note (important in 2026):** current Burp releases bundle/require **Java 21+**
(2026.1 uses Java 25). The stable **Jython 2.7.4 only supports Java 8/11**, so it will
fail on modern Burp. Use **Jython 2.7.5rc1 standalone** (supports Java 8/11/17/25)
from https://www.jython.org/download.html, or run Burp with Java 11 and Jython 2.7.4.

1. Download `jython-standalone-2.7.5rc1.jar` from
   https://github.com/jython/jython/releases/download/v2.7.5rc1/jython-standalone-2.7.5rc1.jar
2. Burp: **Extensions > Extension settings > Python Environment** (older UI:
   **Extender > Options > Python Environment**) → select that JAR.
3. **Extensions > Installed > Add** (older UI: **Extender > Extensions > Add**) →
   Extension type: **Python** → select `burp/burp_to_bridge.py` → Next until loaded.
4. Check **Extensions > Installed**: `VAPT Lens Bridge Feeder` should be listed with
   no errors (inspect the Errors tab under Details if not).
5. With the bridge running, browse a target through the Proxy. Each request/response
   is posted to `http://127.0.0.1:8787/api/burp/stream`.

### CachyOS / Arch setup

CachyOS is Arch-based. Burp Suite Community is in the AUR, and Jython is just a JAR:

```sh
sudo pacman -Syu
sudo pacman -S jre-openjdk curl                 # Java runtime + downloader
yay -S burpsuite                                 # or: paru -S burpsuite

curl -L --fail -o ~/jython-standalone-2.7.5rc1.jar \
  https://github.com/jython/jython/releases/download/v2.7.5rc1/jython-standalone-2.7.5rc1.jar

java -version                                    # confirm >= 21 for current Burp
ls -lh ~/jython-standalone-2.7.5rc1.jar
```

Then in Burp, point **Python Environment** at
`/home/<your-user>/jython-standalone-2.7.5rc1.jar` and add the project's `burp/burp_to_bridge.py` (relative to wherever you cloned the repo).

If the extension errors with Java 25, install Java 11 (`yay -S jre11-openjdk`) and
launch Burp with `app_java_home=/usr/lib/jvm/java-11-openjdk burpsuite` using Jython
2.7.4 instead. On Wayland, use Xwayland for Burp if the UI renders incorrectly.

If your bridge is not on `127.0.0.1:8787`, edit `BRIDGE_URL` in the `.py` file and reload
the extension. The extension caps nothing — the bridge limits how many items it stores.

## Path B — export site map / proxy history as XML and paste it

No extension needed.

**Export the site map**

1. **Target > Site map**.
2. Right-click the host or folder → **Save selected items…** (or **Export site map**).
3. Choose **XML** as the format, pick a filename, and save.
4. Open the VAPT Lens panel → **Burp traffic** tab → paste the XML file contents →
   **Import**.

**Export proxy history**

1. **Proxy > HTTP history**.
2. Select one or more rows (Ctrl/Cmd-click for multiple).
3. Right-click → **Save selected items…** → choose **XML** → save the file.
4. Paste the file contents into the **Burp traffic** tab → **Import**.

The extension's importer reads Burp XML (`<item>` nodes with request/response data) and
keeps only method, host, path, parameter names, allowlisted header names, status,
content type and length. Values are discarded.

## Path C — copy as curl or save a HAR and paste it

Useful for a single request.

**Copy as curl**

1. **Proxy > HTTP history** or **Repeater**.
2. Right-click the request → **Copy as curl request** (older Burp: **Copy as curl**).
3. Paste the `curl …` command into the **Burp traffic** tab → **Import**.

**Save a HAR**

1. Export a HAR from Burp (**Save selected items…** → HAR) or from your browser's
   DevTools Network panel (**Save all as HAR**).
2. Paste the HAR JSON into the **Burp traffic** tab → **Import**.

As with XML, only metadata is used; any values present in the curl/HAR text are ignored.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Bridge offline / CORS errors | Run `npm run bridge`, then `curl http://127.0.0.1:8787/api/health`. The bridge allows `chrome-extension://*`, `moz-extension://*`, `http://localhost:*`, `http://127.0.0.1:*`. |
| Extension fails to load | Python Environment must be a Jython **standalone JAR** compatible with your Burp Java version — use 2.7.5rc1 for Java 17/21/25. Not CPython, not the installer JAR. Reload after setting it. |
| No live items arriving | Confirm the extension is enabled, the bridge is running, and traffic passes through Burp's Proxy (not just Repeater). Check Extender > Extensions > Errors. |
| Port mismatch | The extension POSTs to `127.0.0.1:8787`. If you changed the bridge port, update `BRIDGE_URL` in `burp_to_bridge.py` and reload. |
| Import shows zero items | Ensure you pasted raw XML/HAR/curl text, and that the file is not empty or binary. |
