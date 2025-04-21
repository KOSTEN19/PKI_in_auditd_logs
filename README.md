# Secure Audit Logs with PKI for ALT Linux

This solution provides cryptographic protection for `auditd` logs using public-key infrastructure (PKI) with OpenSSL/GPG.

## 📜 Table of Contents
- [Key Generation](#-key-generation)
- [Installation](#-installation)
- [Usage](#-usage)
- [Verification](#-verification)
- [Security Notes](#-security-notes)

---

## 🔐 Key Generation

### OpenSSL Keys (RSA)
```bash
# Generate private key (protected with passphrase)
openssl genpkey -algorithm RSA -out /etc/audit/private/auditd_private_key.pem -aes256

# Extract public key
openssl rsa -pubout -in /etc/audit/private/auditd_private_key.pem -out /etc/audit/auditd_public_key.pem

# Set permissions
chown root:auditd /etc/audit/private/auditd_private_key.pem
chmod 640 /etc/audit/private/auditd_private_key.pem
```



## 📥 Installation
### Save the script to /usr/local/bin/auditd_secure_logs.sh:

```bash
#!/bin/bash
# OpenSSL Version
LOG_SOURCE="/var/log/audit/audit.log"
LOG_ENCRYPTED="/var/log/audit/secure/audit_$(date +%Y%m%d_%H%M%S).enc"
PRIVATE_KEY="/etc/audit/private/auditd_private_key.pem"
TEMP_FILE=$(mktemp)

# Sign and encrypt
openssl dgst -sha256 -sign "$PRIVATE_KEY" -out "${LOG_ENCRYPTED}.sig" "$LOG_SOURCE"
openssl rand -hex 32 > "$TEMP_FILE.key"
openssl enc -aes-256-cbc -salt -in "$LOG_SOURCE" -out "$TEMP_FILE.enc" -pass file:"$TEMP_FILE.key"
openssl rsautl -encrypt -pubin -inkey /etc/audit/auditd_public_key.pem -in "$TEMP_FILE.key" -out "$TEMP_FILE.key.enc"
cat "$TEMP_FILE.enc" "$TEMP_FILE.key.enc" > "$LOG_ENCRYPTED"
rm -f "$TEMP_FILE"*
gzip "$LOG_SOURCE"
```
