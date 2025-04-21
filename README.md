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
# Encrypts only high-priority logs (priority >= 4)
INPUT_LOG="$1"
OUTPUT_DIR="/var/log/audit/secure"
MIN_PRIORITY=4

[ "$(id -un)" = "auditd" ] || { echo "Must run as auditd" >&2; exit 1; }

process_line() {
  local line="$1"
  local pri=$(echo "$line" | grep -oP 'priority=\K\d+')
  
  if [ -n "$pri" ] && [ "$pri" -ge "$MIN_PRIORITY" ]; then
    # Encrypt high-priority entries
    TEMP_KEY=$(openssl rand -hex 32)
    echo "$line" | openssl enc -aes-256-cbc -salt -pass pass:"$TEMP_KEY" | \
      openssl rsautl -encrypt -pubin -inkey /etc/audit/auditd_public.pem > \
      "${OUTPUT_DIR}/$(date +%s).enc"
    echo "$TEMP_KEY" | openssl rsautl -sign -inkey /etc/audit/private/auditd_private.pem >> \
      "${OUTPUT_DIR}/$(date +%s).key"
  else
    # Pass through low-priority
    echo "$line"
  fi
}

mkdir -p "$OUTPUT_DIR"
while IFS= read -r line; do
  process_line "$line"
done < "$INPUT_LOG"
```


### Make executable:

```bash
chmod +x /usr/local/bin/auditd_secure_logs.sh
chown auditd:auditd /usr/local/bin/auditd_secure_logs.sh
```
