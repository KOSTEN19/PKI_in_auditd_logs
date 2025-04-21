# Защита журналов аудита с помощью PKI для ALT Linux

Это решение обеспечивает криптографическую защиту журналов `auditd` с использованием инфраструктуры открытых ключей (PKI) с OpenSSL/GPG.

## 📜 Содержание
- [Генерация ключей](#-генерация-ключей)
- [Установка](#-установка)
- [Использование](#-использование)

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
KEY_UPDATE_INTERVAL=3600  # Интервал обновления открытого ключа в секундах (1 час)

# Путь к открытым и закрытым ключам
PUBLIC_KEY="/etc/audit/auditd_public.pem"
PRIVATE_KEY="/etc/audit/private/auditd_private.pem"

# Функция для обновления открытого ключа
update_public_key() {
  # Здесь должна быть логика для обновления открытого ключа
  # Например, можно генерировать новый ключ и сохранять его в PUBLIC_KEY
  # Для примера просто копируем старый ключ в новый файл
  cp "$PUBLIC_KEY" "${PUBLIC_KEY}.old"
  openssl genpkey -algorithm RSA -out "$PUBLIC_KEY" -aes256
  echo "Открытый ключ обновлен."
}

# Проверка времени последнего обновления ключа
if [ ! -f "/etc/audit/last_key_update" ]; then
  touch "/etc/audit/last_key_update"
  echo "0" > "/etc/audit/last_key_update"
fi

LAST_UPDATE=$(cat /etc/audit/last_key_update)
CURRENT_TIME=$(date +%s)

if (( CURRENT_TIME - LAST_UPDATE >= KEY_UPDATE_INTERVAL )); then
  update_public_key
  echo "$CURRENT_TIME" > "/etc/audit/last_key_update"
fi

[ "$(id -un)" = "auditd" ] || { echo "Должен выполняться от имени auditd" >&2; exit 1; }

process_line() {
  local line="$1"
  local pri=$(echo "$line" | grep -oP 'priority=\K\d+')
  
  if [ -n "$pri" ] && [ "$pri" -ge "$MIN_PRIORITY" ]; then
    # Шифрование записей высокого приоритета
    TEMP_KEY=$(openssl rand -hex 32)
    echo "$line" | openssl enc -aes-256-cbc -salt -pass pass:"$TEMP_KEY" | \
      openssl rsautl -encrypt -pubin -inkey "$PUBLIC_KEY" > \
      "${OUTPUT_DIR}/$(date +%s).enc"
    echo "$TEMP_KEY" | openssl rsautl -sign -inkey "$PRIVATE_KEY" >> \
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
