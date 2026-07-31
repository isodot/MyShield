   
    # 🛡️ MyShield
    
    **A privacy & security hardening extension for Firefox** — blocks ads, malware domains, popups, tab hijacking, and dangerous downloads. Built for browsing the sketchy corners of the web safely.
    
    ![Firefox](https://img.shields.io/badge/Firefox-115%2B-FF7139?logo=firefoxbrowser&logoColor=white)
    
    ![Manifest](https://img.shields.io/badge/Manifest-V2-blue)
    
    ![License](https://img.shields.io/badge/License-MIT-green)
    
    ---
    
    ## ✨ Features
    
    ### 🚫 Ad & Malware Blocking
    
    - Blocks requests to known ad and malware domains using the full `webRequest` blocking API
    - Blocklists fetched automatically from [URLhaus](https://urlhaus.abuse.ch/) and [StevenBlack/hosts](https://github.com/StevenBlack/hosts)
    - Lists cached locally and refreshed every 6 hours — always up to date, zero maintenance
    - Matches parent domains (`sub.evil.com` is blocked if `evil.com` is listed)
    
    ### 🔒 Forced HTTPS
    
    - Automatically upgrades all `http://` requests to `https://`
    - Localhost and private IP ranges excluded
    
    ### 🪟 Popup & Popunder Protection
    
    - Blocks `window.open()` calls not triggered by a genuine user click
    - Defeats `mousedown`-based popunder tricks
    - Protection is tamper-resistant — pages cannot restore the original `window.open`
    
    ### 🗂️ Tab Hijack Protection
    
    - Detects and closes tabs auto-opened in the background by other tabs
    - Desktop notification shows which site attempted it
    - Per-site whitelist for sites you trust
    
    ### ⚔️ Strict Mode (per-site)
    
    Designed for streaming/movie sites that abuse clicks to open ad tabs. Off by default, enabled per domain from the popup:
    
    - Blocks **all** new tabs — even click-triggered ones
    - Blocks cross-domain link clicks and ad redirects (eTLD+1 comparison)
    - Removes invisible click-hijacking overlay elements
    - Strips `target="_blank"` so links open in the current tab
    - Blocks popunder chains triggered by mouse events
    - Video players and media subresources keep working — only navigations are blocked
    
    ### 📥 Download Protection
    
    - Cancels downloads originating from blocklisted domains
    - Blocks dangerous file types (`.exe`, `.scr`, `.bat`, `.msi`, …) from untrusted domains
    - Trusted-domain whitelist for sources you choose
    
    ### 📊 Dashboard
    
    - Popup UI with live counters: ads, malware, popups, auto-tabs, downloads blocked
    - Global on/off toggle
    - Per-site "Trust this site" and "Strict Mode" controls
    
    ---
    
    ## 🔐 Privacy
    
    **MyShield collects no data. Period.**
    
    - No analytics, no telemetry, no tracking
    - No user data ever leaves your browser
    - Network requests are made only to fetch public blocklists
    - Fully self-contained — no remote code execution
    
    ---
    
    ## 🚀 Installation
    
    ### From source (development)
    
        git clone https://github.com/YOUR-USERNAME/myshield.git
    
        cd myshield
    
        npm install -g web-ext
    
        web-ext run
    
    This launches a clean Firefox profile with MyShield loaded and hot-reloading enabled.
    
    ### Temporary install
    
    1. Open `about:debugging#/runtime/this-firefox`
    2. Click **Load Temporary Add-on**
    3. Select `manifest.json`
    
    ### Build for distribution
    
        web-ext lint
    
        web-ext build
    
    The packaged `.zip` appears in `web-ext-artifacts/`.
    
    ---
    
    ## 🧪 Manual Testing
    
    - **Ad/malware blocking:** visit a page that loads a blocklisted domain and confirm the request is cancelled
    - **HTTPS redirect:** open `http://example.com` and confirm it redirects to `https://example.com`
    - **Auto-tab protection:** trigger a script that opens a background tab and verify it is closed with a notification
    - **Popup blocking:** open a page that calls `window.open` without a user click and confirm it is blocked
    - **Download blocking:** attempt an `.exe` download from a non-trusted domain and verify it is cancelled
    - **Strict Mode:** enable it on a test site, then verify cross-site link blocking, overlay removal, and window-open blocking
    
    ---
    
    ## 🧰 Tech
    
    - Plain JavaScript — no frameworks, no external dependencies
    - Firefox WebExtensions API (`browser.*` namespace, Manifest V2 for full `webRequestBlocking` support)
    - APIs: `webRequest`, `tabs`, `downloads`, `storage`, `notifications`
    
    ---
    
    ## 🗺️ Roadmap
    
    - [ ] Custom user blocklist entries
    - [ ] Import/export settings
    - [ ] Element picker for manual overlay removal
    - [ ] AMO listing
    
    ---
    
    ## ❤️ Support
    
    If MyShield saves you from a sketchy ad or three, consider supporting development:
    
    **Bitcoin (BTC):**
    
        bc1q2fqyukqn4ggvv5qsamhxegrjjzzywpc30hl90r
    
    ---
    
    ## 📄 License
    
    [MIT](LICENSE) — free to use, modify, and distribute.
    
    ---
    
    ## ⚠️ Disclaimer
    
    MyShield is a defense-in-depth tool, not a replacement for common sense or OS-level antivirus. No blocker catches 100% of threats. Use alongside your system's built-in protections.
