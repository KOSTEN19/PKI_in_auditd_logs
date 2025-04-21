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
# Secure Log Encryptor (ECC+AES version)
# Шифрует только логи с priority >=4, используя:
# - ECC (prime256v1) для ключевой пары
# - AES-256-GCM для шифрования данных
# - Одноразовые сессионные ключи

INPUT_LOG="$1"
OUTPUT_FILE="/var/log/audit/secure/encrypted_logs.json"  # Один выходной файл
MIN_PRIORITY=4
PUBLIC_KEY="/etc/audit/keys/audit_public.pem"  # Только публичный ключ
TEMP_DIR=$(mktemp -d)                          # Безопасный временный каталог

# Проверки безопасности
[ "$(id -un)" = "auditd" ] || { echo "Must run as auditd" >&2; exit 1; }
[ -f "$PUBLIC_KEY" ] || { echo "Public key not found" >&2; exit 1; }
trap 'rm -rf "$TEMP_DIR"' EXIT                 # Удаление временных файлов при выходе

# Функция безопасного шифрования
encrypt_log_entry() {
    local plaintext="$1"
    local timestamp=$(date +%s)
    local iv_file="$TEMP_DIR/iv.$timestamp.bin"
    local key_file="$TEMP_DIR/key.$timestamp.bin"
    local tag_file="$TEMP_DIR/tag.$timestamp.bin"

    # 1. Генерация сессионного ключа и IV
    openssl rand -hex 32 > "$key_file"
    openssl rand -hex 12 > "$iv_file"  # 96-bit IV для GCM

    # 2. Шифрование данных AES-256-GCM
    local encrypted_data=$(echo -n "$plaintext" | openssl enc -aes-256-gcm \
        -K $(cat "$key_file") \
        -iv $(cat "$iv_file") \
        -a -A 2>"$tag_file")

    # 3. Шифрование сессионного ключа ECC
    local encrypted_key=$(openssl pkeyutl -encrypt \
        -pubin -inkey "$PUBLIC_KEY" \
        -in "$key_file" \
        -outform DER | base64 -w0)

    # 4. Формирование итоговой структуры
    local json_entry=$(jq -n \
        --arg iv $(base64 -w0 "$iv_file") \
        --arg tag $(base64 -w0 "$tag_file") \
        --arg data "$encrypted_data" \
        --arg key "$encrypted_key" \
        '{
            iv: $iv,
            tag: $tag,
            data: $data,
            key: $key,
            algo: "aes-256-gcm",
            key_algo: "prime256v1",
            timestamp: '$timestamp'
        }')

    # 5. Запись в выходной файл
    echo "$json_entry," >> "$OUTPUT_FILE"

    # 6. Очистка временных файлов
    shred -u "$key_file" "$iv_file" "$tag_file"
}

# Основной цикл обработки
mkdir -p "$(dirname "$OUTPUT_FILE")"
echo "[" > "$OUTPUT_FILE"  # Начало JSON массива

while IFS= read -r line; do
    pri=$(echo "$line" | grep -oP 'priority=\K\d+')
    if [ -n "$pri" ] && [ "$pri" -ge "$MIN_PRIORITY" ]; then
        encrypt_log_entry "$line"
    fi
done < "$INPUT_LOG"

# Удаление последней запятой и закрытие JSON массива
sed -i '$ s/,$//' "$OUTPUT_FILE"  # Удаление последней запятой
echo "]" >> "$OUTPUT_FILE"        # Закрытие JSON массива
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
# Раcшифровка

```bash
#!/bin/bash

INPUT_FILE="$1"
OUTPUT_FILE="$2"
PRIVATE_KEY="/etc/audit/private/auditd_private.pem"

# Проверка наличия входного файла
if [ ! -f "$INPUT_FILE" ]; then
  echo "Входной файл не найден!" >&2
  exit 1
fi

# Создание выходного файла
> "$OUTPUT_FILE"

while IFS= read -r line; do
  # Расшифровка зашифрованной строки
  ENCRYPTED_DATA=$(echo "$line" | openssl rsautl -decrypt -inkey "$PRIVATE_KEY")
  
  # Извлечение временной метки и зашифрованной строки
  TIMESTAMP=$(echo "$ENCRYPTED_DATA" | cut -d':' -f1)
  ENCRYPTED_LINE=$(echo "$ENCRYPTED_DATA" | cut -d':' -f2-)

  # Расшифровка строки с использованием временного ключа
  TEMP_KEY=$(cat "${OUTPUT_DIR}/$(basename "$line" .enc).key" | openssl rsautl -decrypt -inkey "$PRIVATE_KEY")
  DECRYPTED_LINE=$(echo "$ENCRYPTED_LINE" | openssl enc -d -aes-256-cbc -pass pass:"$TEMP_KEY")

  # Запись расшифрованной строки с временной меткой в выходной файл
  echo "$TIMESTAMP: $DECRYPTED_LINE" >> "$OUTPUT_FILE"
done < "$INPUT_FILE"

echo "Расшифровка завершена. Результаты сохранены в $OUTPUT_FILE."
```
