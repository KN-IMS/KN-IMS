vm_ssh_auth_hint() {
    printf 'ssh -p %s %s@%s\n' "$VM_PORT" "$VM_USER" "$VM_HOST"
}

sync_vm_runtime() {
    local ssh_target=""
    local remote_root_q=""
    local remote_agent_q=""
    local remote_scripts_q=""
    local ssh_base_cmd=()
    local scp_base_cmd=()
    local ssh_cmd=()
    local scp_cmd=()
    local rsync_ssh=""

    [[ "$VM_SYNC_ENABLED" -eq 1 ]] || return 0
    [[ -d "$AGENT_DIR" ]] || die "VM으로 전송할 Agent 디렉토리가 없습니다: ${AGENT_DIR}"
    [[ -d "$RUNTIME_HELPER_DIR" ]] || die "VM으로 전송할 runtime helper 디렉토리가 없습니다: ${RUNTIME_HELPER_DIR}"
    [[ -n "$BACKEND_HOST" ]] || die "VM 자동 전송에는 -c/--backend-host 값이 필요합니다."
    [[ -n "$CA_SRC" ]] || die "VM으로 전송할 CA 인증서를 찾지 못했습니다."
    [[ -n "$AGENT_CERT_SRC" ]] || die "VM으로 전송할 Agent 인증서를 찾지 못했습니다."
    [[ -n "$AGENT_KEY_SRC" ]] || die "VM으로 전송할 Agent 개인키를 찾지 못했습니다."

    assert_file "$CA_SRC"
    assert_file "$AGENT_CERT_SRC"
    assert_file "$AGENT_KEY_SRC"

    require_command ssh
    require_command scp
    prepare_vm_remote_auth_prefix

    ssh_target="${VM_USER}@${VM_HOST}"
    printf -v remote_root_q '%q' "$VM_REMOTE_DIR"
    printf -v remote_agent_q '%q' "${VM_REMOTE_DIR}/Agent"
    printf -v remote_scripts_q '%q' "${VM_REMOTE_DIR}/scripts"

    ssh_base_cmd=(
        ssh
        -o StrictHostKeyChecking=accept-new
        -o PreferredAuthentications=publickey,password,keyboard-interactive
        -o ConnectTimeout=10
        -p "$VM_PORT"
    )
    scp_base_cmd=(
        scp
        -o StrictHostKeyChecking=accept-new
        -o PreferredAuthentications=publickey,password,keyboard-interactive
        -o ConnectTimeout=10
        -P "$VM_PORT"
    )

    ssh_cmd=("${VM_REMOTE_AUTH_PREFIX[@]}" "${ssh_base_cmd[@]}" "$ssh_target")
    scp_cmd=("${VM_REMOTE_AUTH_PREFIX[@]}" "${scp_base_cmd[@]}")

    log "VM 디렉토리 준비: ${ssh_target}:${VM_REMOTE_DIR}"
    "${ssh_cmd[@]}" "mkdir -p ${remote_root_q} ${remote_scripts_q}" \
        || die "VM 대상 디렉토리 생성 실패: ${ssh_target}:${VM_REMOTE_DIR} (SSH 확인: $(vm_ssh_auth_hint))"

    log "VM Agent 코드 전송"
    if command -v rsync >/dev/null 2>&1; then
        rsync_ssh="ssh -o StrictHostKeyChecking=accept-new -o PreferredAuthentications=publickey,password,keyboard-interactive -o ConnectTimeout=10 -p ${VM_PORT}"
        "${VM_REMOTE_AUTH_PREFIX[@]}" rsync -az --delete -e "$rsync_ssh" \
            "${AGENT_DIR}/" \
            "${ssh_target}:${VM_REMOTE_DIR}/Agent/" \
            || die "Agent 디렉토리 rsync 실패"
        "${VM_REMOTE_AUTH_PREFIX[@]}" rsync -az --delete -e "$rsync_ssh" \
            "${RUNTIME_HELPER_DIR}/" \
            "${ssh_target}:${VM_REMOTE_DIR}/scripts/setup_backend_agent_runtime/" \
            || die "runtime helper 디렉토리 rsync 실패"
    else
        warn "rsync가 없어 scp -r 로 전체 복사합니다."
        "${ssh_cmd[@]}" "rm -rf ${remote_agent_q} ${remote_scripts_q}/setup_backend_agent_runtime" \
            || die "기존 VM runtime 디렉토리 정리 실패"
        "${scp_cmd[@]}" -r "$AGENT_DIR" "${ssh_target}:${VM_REMOTE_DIR}/" \
            || die "Agent 디렉토리 scp 실패"
        "${scp_cmd[@]}" -r "$RUNTIME_HELPER_DIR" "${ssh_target}:${VM_REMOTE_DIR}/scripts/" \
            || die "runtime helper 디렉토리 scp 실패"
    fi

    log "VM setup 스크립트와 인증서 전송"
    "${scp_cmd[@]}" "$ROOT_DIR/setup_backend_agent_runtime.sh" "${ssh_target}:${VM_REMOTE_DIR}/setup_backend_agent_runtime.sh" \
        || die "setup_backend_agent_runtime.sh 전송 실패"
    "${scp_cmd[@]}" "$CA_SRC" "${ssh_target}:${VM_REMOTE_DIR}/ca.crt" \
        || die "CA 인증서 전송 실패"
    "${scp_cmd[@]}" "$AGENT_CERT_SRC" "${ssh_target}:${VM_REMOTE_DIR}/agent.crt" \
        || die "Agent 인증서 전송 실패"
    "${scp_cmd[@]}" "$AGENT_KEY_SRC" "${ssh_target}:${VM_REMOTE_DIR}/agent.key" \
        || die "Agent 개인키 전송 실패"

    "${ssh_cmd[@]}" "chmod +x ${remote_root_q}/setup_backend_agent_runtime.sh" \
        || die "원격 setup_backend_agent_runtime.sh 실행 권한 설정 실패"

    cat <<EOF

VM 전송 완료
  host : ${ssh_target}
  dir  : ${VM_REMOTE_DIR}

다음 단계:
  ssh -p ${VM_PORT} ${ssh_target}
  cd ${VM_REMOTE_DIR}
  sudo ./setup_backend_agent_runtime.sh -m agent -c ${BACKEND_HOST} --tcp-addr ${TCP_ADDR}

EOF
}
