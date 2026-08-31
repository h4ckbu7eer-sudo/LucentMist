# Local upstream references

Checked out on 2026-09-01 at the user's request. These independent checkouts are
gitignored, not vendored, bundled, executed at startup, or included in the image.

| Directory | Official upstream / pinned commit | Use and boundary |
|---|---|---|
| WhatWeb | https://github.com/urbanadventurer/WhatWeb · `d279d93042d034f3fd29d5a893d44ccc0595d3f8` | Reviewed `plugins/title.rb` and `plugins/zte-iad.rb`; independent title extraction, no GPL plugin/rule copy, no aggressive path enumeration |
| recog | https://github.com/rapid7/recog · `d3d20938da9f5f1e442c2419fe6c30cd651b6878` | BSD-2-Clause: three `xml/http_wwwauth.xml` ZTE realm rules adapted as executable C#; tests cover each; retained third-party notice |
| nmap | https://github.com/nmap/nmap · `b97fabd935362f85ad0575632e6d887f4d778b59` | Sparse `scripts/`, `nselib/`; reviewed `http-title.nse`, `http-server-header.nse`, `upnp-info.nse`. NPSL code not copied. Existing installed Nmap 7.95 used separately for a real authorized comparison |

Reproduce checkouts from the repository root (inspect licences before reuse):

```powershell
git clone https://github.com/urbanadventurer/WhatWeb.git tools/WhatWeb
git -C tools/WhatWeb checkout d279d93042d034f3fd29d5a893d44ccc0595d3f8
git clone https://github.com/rapid7/recog.git tools/recog
git -C tools/recog checkout d3d20938da9f5f1e442c2419fe6c30cd651b6878
git clone --filter=blob:none --sparse https://github.com/nmap/nmap.git tools/nmap
git -C tools/nmap sparse-checkout set scripts nselib
git -C tools/nmap checkout b97fabd935362f85ad0575632e6d887f4d778b59
```

Do not automatically execute upstream installers/plugins or submit network
fingerprints to public sites. Nmap's raw output may contain Set-Cookie/session
values: retain only parsed public service fields in app results and redact raw
comparison output before sharing. HTTP titles are unauthenticated device-name
clues, not hardware/firmware versions or proof of a CVE.
