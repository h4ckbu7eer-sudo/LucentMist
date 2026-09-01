# Third-party notices

## Rapid7 Recog

`Vulnerability/Data/recog-service-fingerprints.json` contains 950 service
fingerprints deterministically converted from the official `rapid7/recog`
datasets at commit `d3d20938da9f5f1e442c2419fe6c30cd651b6878`:
`http_servers.xml`, `http_xpoweredby.xml`, `ssh_banners.xml`,
`smtp_banners.xml`, `pop_banners.xml`, `imap_banners.xml`,
`dns_versionbind.xml`, `ftp_banners.xml`, and `mysql_banners.xml`.
`tools/fingerprint-import/convert_recog.py` is the reproducible converter. Oniguruma-only
patterns that cannot compile under .NET are retained in the generated source
for auditability but skipped at runtime. The Redis INFO and Windows RPC
evidence-only rules are independently implemented, not converted from Recog.
Consult `docs/fingerprint-sources.md`.

Three device realm rules in `HttpPageIdentity.cs` are adapted from
`xml/http_wwwauth.xml`: ZTE CPE (`cpe@zte.com`), ZXHN, and ZXV. No WhatWeb or
Nmap implementation code is copied into the application. Those GPL/NPSL source
checkouts remain separately licensed local references under `tools/`.

Copyright (c) 2014, Rapid7, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
