
# Android Mobile Pentesting Report – DIVA.apk

## 1. Introduction
This report presents a security assessment of **DIVA.apk (Damn Insecure and Vulnerable App)**, an intentionally vulnerable Android application designed for learning mobile app pentesting.  

The assessment included both **static** and **dynamic analysis** using tools like JADX, ADB, and Android Studio.  
The objective was to:
- Identify common mobile vulnerabilities.
- Demonstrate exploitation steps.
- Provide recommendations for mitigation.

---

## 2. Environment Setup

### 2.1 Tools Used
- **Android Studio** – Emulator setup and APK installation.
- **ADB (Android Debug Bridge)** – Interact with the device, access logs, and install APKs.
- **JADX-GUI** – Decompile APK for static analysis.

### 2.2 Emulator Setup
Open Android Studio and navigate to the **Device Manager**.  
Click the **"+"** button to create a new virtual device.

![Device Manager](images/device_manager.png)

Select a suitable device image and click **Next**.  
Once created, start the emulator.

![Environment Setup](images/intro_env_setup.png)

### 2.3 Installing the APK
The APK can be installed by:
- Drag and drop into the emulator, **or**
- Using ADB command:
```bash
adb install diva.apk
```

![APK Installation](images/apk_installation.png)

---

## 3. Static Analysis
Static analysis was performed to examine the application code and configurations **without execution**.

### Tools:
- **JADX-GUI** – Decompiled APK source code.
- **Apktool** – Review AndroidManifest.xml and resources.

Open the APK in JADX to view decompiled files.

![JADX Decompile](images/jadx_decompile.png)

---

### 3.1 Insecure Manifest Configuration
The `AndroidManifest.xml` contained insecure configurations:
- `android:debuggable="true"` enabled.
- Exported components without proper permission checks.

![Manifest Config](images/manifest_config.png)

**Impact:**
- Attackers can attach debuggers and modify app behavior.
- Exported components may be exploited by malicious apps.

**Recommendations:**
- Disable debugging in production builds.
- Set `android:exported="false"` for unnecessary components.
- Use proper permission enforcement.

---

### 3.2 Over-Privileged Permissions
The APK requested excessive permissions beyond core functionality.

![Permissions](images/permissions.png)

**Examples:**
- `WRITE_EXTERNAL_STORAGE`
- `READ_EXTERNAL_STORAGE`
- `ACCESS_FINE_LOCATION`

**Impact:**
- Increased attack surface.
- Privacy risks through sensitive data leakage.

**Recommendations:**
- Follow **least privilege principle**.
- Remove unused permissions.
- Request sensitive permissions only at runtime.

---

### 3.3 Hardcoded Secrets
Sensitive data such as **API keys**, **usernames**, and **passwords** were hardcoded.

![Hardcoded Secrets](images/hardcoded_secrets.png)
![API Credentials](images/api_creds.png)
![Database Name](images/database_exposed.png)

**Impact:**
- Easy extraction of secrets using static tools.
- May lead to unauthorized backend access.

**Recommendations:**
- Store secrets securely using Keystore or environment variables.
- Never hardcode sensitive information.

---

## 4. Dynamic Analysis
Dynamic analysis was conducted to monitor **runtime behavior**, identify insecure data storage, and detect logging issues.

### Tools:
- `adb logcat` – Capture logs.
- `adb shell` – Explore directories.
- Android Studio Emulator.

---

### 4.1 Hardcoded Vendor Key
The application validated vendor keys on the **client-side**, allowing attackers to bypass checks.

![Vendor Key](images/vendor_key.png)

**Exploitation:**
- Extract vendor key from source code.
- Enter the key directly to gain access.

---

### 4.2 Insecure Logging
Sensitive data such as **credit card numbers** were logged in plaintext.

![Insecure Logging](images/insecure_logging.png)
![Logcat Output](images/logcat_output.png)

**Impact:**
- Attackers can retrieve data by simply reading logs.
- Exposes users to fraud and privacy breaches.

**Recommendations:**
- Remove sensitive data from logs in production code.
- Use proper logging levels.

---

### 4.3 Insecure Data Storage
Credentials were stored in unencrypted **SharedPreferences**.

![Insecure Storage](images/insecure_storage.png)
![Shared Preferences](images/shared_prefs.png)

**Impact:**
- Easy data extraction on rooted/jailbroken devices.
- Violates data protection regulations.

**Recommendations:**
- Use **AES-256 encryption** for sensitive data.
- Store data securely using Android Keystore.

---

### 4.4 Input Validation Issues
The app failed to validate user inputs, leading to vulnerabilities like SQL Injection.

![Input Validation](images/input_validation.png)
![SQLi Payload](images/sqli_payload.png)

**Exploitation:**
- Supplying crafted SQLi payloads exposed sensitive information.

**Recommendations:**
- Implement proper server-side input validation and sanitization.

---

## 5. Key Findings

| Vulnerability              | Impact                  | Severity | Recommendation |
|----------------------------|-------------------------|----------|---------------|
| Insecure Manifest Config    | App exploitation via debuggers | High | Disable debugging, secure exported components |
| Over-Privileged Permissions | Increased attack surface | Medium | Remove unnecessary permissions |
| Hardcoded Secrets           | Unauthorized backend access | High | Securely store secrets |
| Insecure Logging            | Sensitive data leakage | High | Remove sensitive logs |
| Insecure Data Storage       | Credential theft | High | Encrypt data at rest |
| Input Validation Issues     | SQL Injection attacks | High | Validate and sanitize inputs |

---

## 6. Conclusion
The assessment of **DIVA.apk** revealed critical vulnerabilities including:
- Insecure data storage
- Hardcoded secrets
- Over-privileged permissions
- Insecure manifest configurations
- Insufficient input validation

**Final Recommendations:**
- Implement secure coding practices.
- Perform regular code reviews and security audits.
- Use encryption and secure storage mechanisms.
- Enforce the principle of least privilege.

By applying these measures, the overall security posture of the application will be greatly improved, reducing the risk of compromise.

---
