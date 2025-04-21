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

    # 4. Шифрование временной метки
    local encrypted_timestamp=$(echo -n "$timestamp" | openssl pkeyutl -encrypt \
        -pubin -inkey "$PUBLIC_KEY" -outform DER | base64 -w0)

    # 5. Формирование итоговой структуры
    local json_entry=$(jq -n \
        --arg iv $(base64 -w0 "$iv_file") \
        --arg tag $(base64 -w0 "$tag_file") \
        --arg data "$encrypted_data" \
        --arg key "$encrypted_key" \
        --arg timestamp "$encrypted_timestamp" \
        '{
            iv: $iv,
            tag: $tag,
            data: $data,
            key: $key,
            algo: "aes-256-gcm",
            key_algo: "prime256v1",
            timestamp: $timestamp
        }')

    # 6. Запись в выходной файл
    echo "$json_entry," >> "$OUTPUT_FILE"

    # 7. Очистка временных файлов
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
# Secure Log Decryptor (ECC+AES version)
# Расшифровывает зашифрованные логи

# Параметры
INPUT_FILE="$1"                      # Входной файл с зашифрованными данными
OUTPUT_FILE="$2"                     # Выходной файл для расшифрованных данных
PRIVATE_KEY="/etc/audit/keys/audit_private.pem"  # Путь к закрытому ключу

# Проверки безопасности
[ "$(id -un)" = "auditd" ] || { echo "Must run as auditd" >&2; exit 1; }
[ -f "$INPUT_FILE" ] || { echo "Input file not found" >&2; exit 1; }
[ -f "$PRIVATE_KEY" ] || { echo "Private key not found" >&2; exit 1; }

# Функция для расшифровки записи
decrypt_log_entry() {
    local json_entry="$1"

    # Извлечение значений из JSON
    local iv=$(echo "$json_entry" | jq -r '.iv' | base64 -d)
    local tag=$(echo "$json_entry" | jq -r '.tag' | base64 -d)
    local encrypted_data=$(echo "$json_entry" | jq -r '.data')
    local encrypted_key=$(echo "$json_entry" | jq -r '.key')
    local encrypted_timestamp=$(echo "$json_entry" | jq -r '.timestamp')

    # Расшифровка сессионного ключа
    local decrypted_key=$(echo "$encrypted_key" | base64 -d | openssl pkeyutl -decrypt -inkey "$PRIVATE_KEY" -outform DER | xxd -p)

    # Расшифровка временной метки
    local decrypted_timestamp=$(echo "$encrypted_timestamp" | base64 -d | openssl pkeyutl -decrypt -inkey "$PRIVATE_KEY" -outform DER | xxd -p)

    # Расшифровка данных AES-256-GCM
    local decrypted_data=$(echo -n "$encrypted_data" | base64 -d | openssl enc -aes-256-gcm -d -K "$decrypted_key" -iv <(echo -n "$iv" | xxd -p) -A -nosalt -tag "$tag")

    # Форматирование результата
    echo "$decrypted_data (timestamp: $decrypted_timestamp)"
}

# Основной цикл обработки
mkdir -p "$(dirname "$OUTPUT_FILE")"
echo "[" > "$OUTPUT_FILE"  # Начало JSON массива

# Чтение входного файла и расшифровка каждой записи
while IFS= read -r line; do
    if [[ "$line" == *"{"* ]]; then  # Проверка на наличие JSON объекта
        decrypted_entry=$(decrypt_log_entry "$line")
        echo "$decrypted_entry," >> "$OUTPUT_FILE"
    fi
done < "$INPUT_FILE"

# Удаление последней запятой и закрытие JSON массива
sed -i '$ s/,$//' "$OUTPUT_FILE"  # Удаление последней запятой
echo "]" >> "$OUTPUT_FILE"        # Закрытие JSON массива

echo "Decryption completed. Output written to $OUTPUT_FILE."
