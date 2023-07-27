#!/bin/sh
set -e
set -o noglob

# Inspired by https://get.k3s.io./

# Usage:
#   curl ... | ENV_VAR=... sh -
#       or
#   ENV_VAR=... ./install.sh
#

GITHUB_URL=https://github.com/venafi/notation-venafi-csp
DOWNLOADER=

# --- helper functions for logs ---
info()
{
    echo '[INFO] ' "$@"
}
warn()
{
    echo '[WARN] ' "$@" >&2
}
fatal()
{
    echo '[ERROR] ' "$@" >&2
    exit 1
}

# --- add quotes to command arguments ---
quote() {
    for arg in "$@"; do
        printf '%s\n' "$arg" | sed "s/'/'\\\\''/g;1s/^/'/;\$s/\$/'/"
    done
}

# --- add indentation and trailing slash to quoted args ---
quote_indent() {
    printf ' \\\n'
    for arg in "$@"; do
        printf '\t%s \\\n' "$(quote "$arg")"
    done
}

# --- escape most punctuation characters, except quotes, forward slash, and space ---
escape() {
    printf '%s' "$@" | sed -e 's/\([][!#$%&()*;<=>?\_`{|}]\)/\\\1/g;'
}

# --- escape double quotes ---
escape_dq() {
    printf '%s' "$@" | sed -e 's/"/\\"/g'
}

# --- define needed environment variables ---
setup_env() {

    # --- use sudo if we are not already root ---
    SUDO=sudo
    if [ $(id -u) -eq 0 ]; then
        SUDO=
    fi

    OS="$(uname)"

    if [ "${OS}" = "Darwin" ]; then
        BIN_DIR="${HOME}/Library/Application\ Support/notation/plugins/venafi-csp"
    elif [ "${OS}" = "Linux" ]; then
        if [ -z "${XDG_CONFIG_HOME}"]; then
            BIN_DIR="${HOME}/.config/notation/plugins/venafi-csp"
        else 
            BIN_DIR="${XDG_CONFIG_HOME}/notation/plugins/venafi-csp"
        fi
    else
        abort "this script is only supported on macOS and Linux."
    fi

    # --- get hash of config & exec for currently installed k3s ---
    PRE_INSTALL_HASHES=$(get_installed_hashes)
}

# --- check if skip download environment variable set ---
can_skip_download_binary() {
    if [ "${INSTALL_CSP_SKIP_DOWNLOAD}" != true ] && [ "${INSTALL_CSP_SKIP_DOWNLOAD}" != binary ]; then
        return 1
    fi
}

can_skip_download_selinux() {                                                        
    if [ "${INSTALL_CSP_SKIP_DOWNLOAD}" != true ] && [ "${INSTALL_CSP_SKIP_DOWNLOAD}" != selinux ]; then 
        return 1                                                                     
    fi                                                                               
}  

# --- verify an executable notation-venafi-csp binary is installed ---
verify_csp_is_executable() {
    if [ ! -x ${BIN_DIR}/notation-venafi-csp ]; then
        fatal "Executable notation-venafi-csp binary not found at ${BIN_DIR}/notation-venafi-csp"
    fi
}

# --- set arch and suffix, fatal if architecture not supported ---
setup_verify_arch() {
    OS="$(uname)"
    if [ -z "$ARCH" ]; then
        ARCH=$(uname -m)
    fi
    case $ARCH in
        amd64)
            ARCH=amd64
            SUFFIX=-${OS}-${ARCH}
            ;;
        x86_64)
            ARCH=amd64
            SUFFIX=-${OS}-${ARCH}
            ;;
        arm64)
            ARCH=arm64
            SUFFIX=-${OS}-${ARCH}
            ;;
        aarch64)
            ARCH=arm64
            SUFFIX=-${OS}-${ARCH}
            ;;
        *)
            fatal "Unsupported architecture $ARCH"
    esac
}

# --- verify existence of network downloader executable ---
verify_downloader() {
    # Return failure if it doesn't exist or is no executable
    [ -x "$(command -v $1)" ] || return 1

    # Set verified executable as our downloader program and return success
    DOWNLOADER=$1
    return 0
}

# --- create temporary directory and cleanup when done ---
setup_tmp() {
    TMP_DIR=$(mktemp -d -t notation-venafi-csp-install.XXXXXXXXXX)
    TMP_HASH=${TMP_DIR}/notation-venafi-csp.hash
    TMP_BIN=${TMP_DIR}/notation-venafi-csp.bin
    cleanup() {
        code=$?
        set +e
        trap - EXIT
        rm -rf ${TMP_DIR}
        exit $code
    }
    trap cleanup INT EXIT
}

# --- use desired notation-venafi-csp version if defined or find version from github releases ---
get_release_version() {

    info "Finding release for channel $GITHUB_URL"
    case $DOWNLOADER in
        curl)
            VERSION_CSP=$(curl -I $GITHUB_URL/releases/latest | awk -F '/' '/^location/ {print  substr($NF, 1, length($NF)-1)}')
            ;;
        wget)
            VERSION_CSP=$(wget --server-response $GITHUB_URL/releases/latest 2>&1 | awk -F '/' '/^Location/ {print substr($NF, 1, length($NF)-length("[following]"))}')
            ;;
        *)
            fatal "Incorrect downloader executable '$DOWNLOADER'"
            ;;
    esac
   
    info "Using ${VERSION_CSP} as release"
}

# --- download from github url ---
download() {
    [ $# -eq 2 ] || fatal 'download needs exactly 2 arguments'

    case $DOWNLOADER in
        curl)
            curl -o $1 -sfL $2
            ;;
        wget)
            wget -qO $1 $2
            ;;
        *)
            fatal "Incorrect executable '$DOWNLOADER'"
            ;;
    esac

    # Abort if download command failed
    [ $? -eq 0 ] || fatal 'Download failed'
}

# --- download hash from github url ---
download_hash() {
    OS="$(uname)"
    HASH_URL=${GITHUB_URL}/releases/download/${VERSION_CSP}/notation-venafi-csp-${OS}-${ARCH}.sha256
    info "Downloading hash ${HASH_URL}"
    download ${TMP_HASH} ${HASH_URL}
    HASH_EXPECTED=$(grep -i " notation-venafi-csp${SUFFIX}$" ${TMP_HASH})
    HASH_EXPECTED=${HASH_EXPECTED%%[[:blank:]]*}
}

# --- check hash against installed version ---
installed_hash_matches() {
    if [ -x "${BIN_DIR}/notation-venafi-csp" ]; then
        if [ "${OS}" = "Darwin" ]; then
            HASH_INSTALLED=$(shasum -a 256 "${BIN_DIR}/notation-venafi-csp")
        elif [ "${OS}" = "Linux" ]; then
            HASH_INSTALLED=$(sha256sum ${BIN_DIR}/notation-venafi-csp)
        fi
       
        HASH_INSTALLED=${HASH_INSTALLED%%[[:blank:]]*}
        if [ "${HASH_EXPECTED}" = "${HASH_INSTALLED}" ]; then
            return
        fi
    fi
    return 1
}

# --- download binary from github url ---
download_binary() { 
    OS="$(uname)"
    BIN_URL=${GITHUB_URL}/releases/download/${VERSION_CSP}/notation-venafi-csp-${OS}-${ARCH}
    info "Downloading binary ${BIN_URL}"
    download ${TMP_BIN} ${BIN_URL}
}

# --- verify downloaded binary hash ---
verify_binary() {
    info "Verifying binary download"
    if [ "${OS}" = "Darwin" ]; then
        HASH_BIN=$(shasum -a 256 ${TMP_BIN})
    elif [ "${OS}" = "Linux" ]; then
        HASH_BIN=$(sha256sum ${TMP_BIN})
    fi
    HASH_BIN=${HASH_BIN%%[[:blank:]]*}
    if [ "${HASH_EXPECTED}" != "${HASH_BIN}" ]; then
        fatal "Download sha256 does not match ${HASH_EXPECTED}, got ${HASH_BIN}"
    fi
}

# --- setup permissions and move binary to notation plugins directory ---
setup_binary() {
    chmod 755 ${TMP_BIN}
    info "Installing notation-venafi-csp to ${BIN_DIR}/notation-venafi-csp"
    #$SUDO chown root:root ${TMP_BIN}
    $SUDO mkdir -p "${BIN_DIR}"
    $SUDO mv -f ${TMP_BIN} "${BIN_DIR}/notation-venafi-csp"
}

# --- download and verify notation-venafi-csp ---
download_and_verify() {
    if can_skip_download_binary; then
       info 'Skipping notation-venafi-csp download and verify'
       verify_csp_is_executable
       return
    fi

    setup_verify_arch
    verify_downloader curl || verify_downloader wget || fatal 'Can not find curl or wget for downloading files'
    setup_tmp
    get_release_version
    download_hash

    if installed_hash_matches; then
        info 'Skipping binary downloaded, installed notation-venafi-csp matches hash'
        info "Follow the steps at ${GITHUB_URL} for configuring the Venafi CodeSign Protect plugin for notation (notary v2)"
        return
    fi

    download_binary
    verify_binary
    setup_binary
    info "Follow the steps at ${GITHUB_URL} for configuring the Venafi CodeSign Protect plugin for notation (notary v2)"
}

# --- get hashes of the current notation-venafi-csp bin
get_installed_hashes() {
    $SUDO sha256sum ${BIN_DIR}/notation-venafi-csp 2>&1 || true
}

# --- run the install process --
{
    setup_env "$@"
    download_and_verify
}