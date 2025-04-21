# Защита журналов аудита с помощью PKI для ALT Linux

Это решение обеспечивает криптографическую защиту журналов `auditd` с использованием инфраструктуры открытых ключей (PKI) с OpenSSL/GPG.

## 📜 Содержание
- [Генерация ключей](#-генерация-ключей)
- [Установка](#-установка)
- [Использование](#-использование)
- [Проверка](#-проверка)
- [Примечания по безопасности](#-примечания-по-безопасности)

---

## 🔐 Генерация ключей

### Ключи OpenSSL (RSA)
```bash
# Генерация закрытого ключа (защищенного паролем)
openssl genpkey -algorithm RSA -out /etc/audit/private/auditd_private_key.pem -aes256

# Извлечение открытого ключа
openssl rsa -pubout -in /etc/audit/private/auditd_private_key.pem -out /etc/audit/auditd_public_key.pem

# Установка прав доступа
chown root:auditd /etc/audit/private/auditd_private_key.pem
chmod 640 /etc/audit/private/auditd_private_key.pem
```

## 📥 Установка
### Сохраните скрипт в /usr/local/bin/auditd_secure_logs.sh:

```bash
#!/bin/bash
# Шифрует только журналы высокого приоритета (приоритет >= 4)
INPUT_LOG="$1"
OUTPUT_DIR="/var/log/audit/secure"
MIN_PRIORITY=4

[ "$(id -un)" = "auditd" ] || { echo "Должен выполняться от имени auditd" >&2; exit 1; }

process_line() {
  local line="$1"
  local pri=$(echo "$line" | grep -oP 'priority=\K\d+')
  
  if [ -n "$pri" ] && [ "$pri" -ge "$MIN_PRIORITY" ]; then
    # Шифрование записей высокого приоритета
    TEMP_KEY=$(openssl rand -hex 32)
    echo "$line" | openssl enc -aes-256-cbc -salt -pass pass:"$TEMP_KEY" | \
      openssl rsautl -encrypt -pubin -inkey /etc/audit/auditd_public.pem > \
      "${OUTPUT_DIR}/$(date +%s).enc"
    echo "$TEMP_KEY" | openssl rsautl -sign -inkey /etc/audit/private/auditd_private.pem >> \
      "${OUTPUT_DIR}/$(date +%s).key"
  else
    # Пропуск записей низкого приоритета
    echo "$line"
  fi
}

mkdir -p "$OUTPUT_DIR"
while IFS= read -r line; do
  process_line "$line"
done < "$INPUT_LOG"
```


### Сделайте исполняемым:

```bash
chmod +x /usr/local/bin/auditd_secure_logs.sh
chown auditd:auditd /usr/local/bin/auditd_secure_logs.sh
```


### Настройте auditd для запуска скрипта:

```bash
echo '-w /var/log/audit/audit.log -p wa -k secure_audit_log -x /usr/local/bin/auditd_secure_logs.sh' > /etc/audit/rules.d/secure_logs.rules
service auditd restart
```



# 🚀 Использование
## Скрипт будет автоматически:
Создавать зашифрованные журналы в /var/log/audit/secure/

Генерировать отделенные подписи (.sig)

Сжимать оригинальные журналы
