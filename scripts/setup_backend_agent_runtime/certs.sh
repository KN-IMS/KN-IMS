cert_pubkey_matches() {
    local cert_path="$1"
    local key_path="$2"

    diff -q \
        <(openssl x509 -in "$cert_path" -pubkey -noout 2>/dev/null | openssl pkey -pubin -pubout 2>/dev/null) \
        <(openssl pkey -in "$key_path" -pubout 2>/dev/null) \
        >/dev/null 2>&1
}

full_cert_bundle_consistent() {
    [[ -n "$CA_SRC" ]] || return 1
    [[ -n "$SERVER_CERT_SRC" ]] || return 1
    [[ -n "$SERVER_KEY_SRC" ]] || return 1
    [[ -n "$AGENT_CERT_SRC" ]] || return 1
    [[ -n "$AGENT_KEY_SRC" ]] || return 1

    [[ -f "$CA_SRC" ]] || return 1
    [[ -f "$SERVER_CERT_SRC" ]] || return 1
    [[ -f "$SERVER_KEY_SRC" ]] || return 1
    [[ -f "$AGENT_CERT_SRC" ]] || return 1
    [[ -f "$AGENT_KEY_SRC" ]] || return 1

    command -v openssl >/dev/null 2>&1 || return 1

    openssl verify -CAfile "$CA_SRC" "$SERVER_CERT_SRC" >/dev/null 2>&1 || return 1
    openssl verify -CAfile "$CA_SRC" "$AGENT_CERT_SRC" >/dev/null 2>&1 || return 1
    cert_pubkey_matches "$SERVER_CERT_SRC" "$SERVER_KEY_SRC" || return 1
    cert_pubkey_matches "$AGENT_CERT_SRC" "$AGENT_KEY_SRC" || return 1

    return 0
}

resolve_cert_sources() {
    local generated_dir="${CERT_OUTPUT_DIR:-${BACKEND_CERT_DIR}/generated-legacy}"

    if [[ "$MODE" == "backend" || "$MODE" == "all" ]]; then
        if [[ -z "$CA_SRC" ]]; then
            CA_SRC="$(first_existing_file \
                "${BACKEND_CERT_DIR}/ca.crt" \
                "${generated_dir}/ca.crt" \
                "${ROOT_DIR}/ca.crt" || true)"
        fi
        if [[ -z "$SERVER_CERT_SRC" ]]; then
            SERVER_CERT_SRC="$(first_existing_file \
                "${BACKEND_CERT_DIR}/server.crt" \
                "${generated_dir}/server.crt" \
                "${ROOT_DIR}/server.crt" || true)"
        fi
        if [[ -z "$SERVER_KEY_SRC" ]]; then
            SERVER_KEY_SRC="$(first_existing_file \
                "${BACKEND_CERT_DIR}/server.key" \
                "${generated_dir}/server.key" \
                "${ROOT_DIR}/server.key" || true)"
        fi
    fi

    if [[ "$MODE" == "backend" || "$MODE" == "all" || "$VM_SYNC_ENABLED" -eq 1 ]]; then
        if [[ -z "$CA_SRC" ]]; then
            CA_SRC="$(first_existing_file \
                "${BACKEND_CERT_DIR}/ca.crt" \
                "${generated_dir}/ca.crt" \
                "${ROOT_DIR}/ca.crt" || true)"
        fi
        if [[ -z "$AGENT_CERT_SRC" ]]; then
            AGENT_CERT_SRC="$(first_existing_file \
                "${BACKEND_CERT_DIR}/agent.crt" \
                "${generated_dir}/agent.crt" \
                "${ROOT_DIR}/agent.crt" || true)"
        fi
        if [[ -z "$AGENT_KEY_SRC" ]]; then
            AGENT_KEY_SRC="$(first_existing_file \
                "${BACKEND_CERT_DIR}/agent.key" \
                "${generated_dir}/agent.key" \
                "${ROOT_DIR}/agent.key" || true)"
        fi
    fi

    if [[ "$MODE" == "agent" ]]; then
        if [[ -z "$CA_SRC" ]]; then
            CA_SRC="$(first_existing_file \
                "${ROOT_DIR}/ca.crt" \
                "${BACKEND_CERT_DIR}/ca.crt" \
                "${generated_dir}/ca.crt" || true)"
        fi
        if [[ -z "$AGENT_CERT_SRC" ]]; then
            AGENT_CERT_SRC="$(first_existing_file \
                "${ROOT_DIR}/agent.crt" \
                "${BACKEND_CERT_DIR}/agent.crt" \
                "${generated_dir}/agent.crt" || true)"
        fi
        if [[ -z "$AGENT_KEY_SRC" ]]; then
            AGENT_KEY_SRC="$(first_existing_file \
                "${ROOT_DIR}/agent.key" \
                "${BACKEND_CERT_DIR}/agent.key" \
                "${generated_dir}/agent.key" || true)"
        fi
    fi

    if [[ "$MODE" == "backend" || "$MODE" == "all" ]]; then
        if ! full_cert_bundle_consistent; then
            GENERATE_LEGACY_CERTS=1
            [[ -n "$CERT_OUTPUT_DIR" ]] || CERT_OUTPUT_DIR="${generated_dir}"
            log "backend/server/agent 인증서 묶음이 없거나 서로 맞지 않아 legacy mTLS 인증서를 자동 생성합니다."
        fi
    fi
}

generate_legacy_certs() {
    require_command openssl

    local out_dir="$CERT_OUTPUT_DIR"
    if [[ -z "$out_dir" ]]; then
        out_dir="${BACKEND_CERT_DIR}/generated-legacy"
    fi

    mkdir -p "$out_dir"

    local ca_key="${out_dir}/ca.key"
    local ca_csr="${out_dir}/ca.csr"
    local ca_crt="${out_dir}/ca.crt"
    local server_key="${out_dir}/server.key"
    local server_csr="${out_dir}/server.csr"
    local server_crt="${out_dir}/server.crt"
    local agent_key="${out_dir}/agent.key"
    local agent_csr="${out_dir}/agent.csr"
    local agent_crt="${out_dir}/agent.crt"
    local ca_ext="${out_dir}/ca_ext.cnf"
    local server_ext="${out_dir}/server_ext.cnf"
    local agent_ext="${out_dir}/agent_ext.cnf"

    log "구형 호환 인증서 생성 (RSA 2048 + SHA256)"

    cat > "$ca_ext" <<'EOF'
[v3_ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

    openssl genrsa -out "$ca_key" 2048
    openssl req -new -sha256 \
        -key "$ca_key" \
        -out "$ca_csr" \
        -subj "/CN=${CA_CN}"
    openssl x509 -req -sha256 -days 3650 \
        -in "$ca_csr" \
        -signkey "$ca_key" \
        -out "$ca_crt" \
        -extfile "$ca_ext" \
        -extensions v3_ca

    cat > "$server_ext" <<EOF
[v3_server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=@alt_names

[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
EOF
    if [[ -n "$BACKEND_HOST" ]]; then
        if [[ "$BACKEND_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            printf 'IP.2=%s\n' "$BACKEND_HOST" >> "$server_ext"
        else
            printf 'DNS.2=%s\n' "$BACKEND_HOST" >> "$server_ext"
        fi
    fi

    openssl genrsa -out "$server_key" 2048
    openssl req -new -sha256 \
        -key "$server_key" \
        -out "$server_csr" \
        -subj "/CN=${SERVER_CN}"
    openssl x509 -req -sha256 -days 3650 \
        -in "$server_csr" \
        -CA "$ca_crt" \
        -CAkey "$ca_key" \
        -CAcreateserial \
        -out "$server_crt" \
        -extfile "$server_ext" \
        -extensions v3_server

    cat > "$agent_ext" <<'EOF'
[v3_agent]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

    openssl genrsa -out "$agent_key" 2048
    openssl req -new -sha256 \
        -key "$agent_key" \
        -out "$agent_csr" \
        -subj "/CN=${AGENT_CN}"
    openssl x509 -req -sha256 -days 3650 \
        -in "$agent_csr" \
        -CA "$ca_crt" \
        -CAkey "$ca_key" \
        -CAcreateserial \
        -out "$agent_crt" \
        -extfile "$agent_ext" \
        -extensions v3_agent

    CA_SRC="$ca_crt"
    SERVER_CERT_SRC="$server_crt"
    SERVER_KEY_SRC="$server_key"
    AGENT_CERT_SRC="$agent_crt"
    AGENT_KEY_SRC="$agent_key"

    cat <<EOF

legacy mTLS 인증서 생성 완료
  dir        : ${out_dir}
  ca.crt     : ${ca_crt}
  server.crt : ${server_crt}
  server.key : ${server_key}
  agent.crt  : ${agent_crt}
  agent.key  : ${agent_key}

EOF
}
