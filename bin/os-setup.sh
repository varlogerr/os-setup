#!/usr/bin/env bash

# {CONFBLOCK}
declare -A CONF=(
  #
  # USER ACTIONS
  # Change root pass
  [root_chpass]=false
  # Create a user with this login name. Leave blank to skip the
  # rest of user actions
  [user_login]=""
  # Create the user from another one, i.e. just rename an existing
  # account to `user_login`
  [user_mv_from]=""
  # Account owner full name
  [user_fullname]=""
  # Make a system user. Works only if user doesn't exist
  [user_is_system]=false
  # Is the user sudoer
  [user_is_sudoer]=true
  # Change user password
  [user_chpass]=false
  #
  # HOSTNAME ACTIONS
  # Machine hostname. Leave blank to skip any changes
  [hostname]=""
  # Loopback address to bind the hostname to
  [hostname_ip]="127.0.1.1"
  #
  # INSTALLS
  # Ansible target prereqs
  [ansible_prereq]=false
  # GP vpn
  [gp]=false
  #
  # MISC
  # Generate sample net config to $(pwd)
  [netconf]=false
  #
  # MAINTENANCE ACTIONS
  # Upgrade the system
  [upgrade]=false
  # Clean up the system installation and temporary junk
  [cleanup]=false
)
# {/CONFBLOCK}

declare -A DEF=(
  [root_chpass]=false
  [user_login]=""
  [user_mv_from]=""
  [user_fullname]=""
  [user_is_system]=false
  [user_is_sudoer]=true
  [user_chpass]=false
  [hostname]=""
  [hostname_ip]="127.0.1.1"
  [ansible_prereq]=false
  [gp]=false
  [netconf]=false
  [upgrade]=false
  [cleanup]=false
  [is_deb]=false
  [is_rhel]=false
  # alternatives:
  # * https://software.digi.com/
  # * https://confluence.esg.wsu.edu/display/KB/Installing+and+Troubleshooting+GlobalProtect+for+Linux
  # * https://software.anu.edu.au/itservices/it-security
  # * https://www.hunter.cuny.edu/it/it-services/vpn
  # * https://www.utep.edu/technologysupport/_Files/docs/NET_VPN_GlobalProtectforLinux.pdf
  [gp_url]=https://software.digi.com/PanGPLinux-6.0.0-c18.tgz
)

for c in "${!DEF[@]}"; do
  CONF[$c]="${CONF[$c]:-${DEF[$c]}}"
done

declare -A NETCONF_TPL=(
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files
  # https://www.liquidweb.com/kb/how-to-install-and-configure-nmcli/
  [rhel]='
    # * review the config and modify if required
    # * `mv ./ifcfg-{{ iface }} /etc/sysconfig/network-scripts/ifcfg-{{ iface }}`
    # * `nmcli connection down {{ iface }}; nmcli connection up {{ iface }}`
    TYPE=Ethernet
    BOOTPROTO=none
    DEVICE={{ iface }} # <- check interface
    NAME={{ iface }} # <- check interface
    IPADDR={{ ipaddr }} # <- change ip?
    PREFIX={{ prefix }} # <- check prefix
    GATEWAY={{ gateway }} # <- check gateway
    ONBOOT=yes
    DNS1={{ dns1 }} # <- use gateway for dns1 ({{ gateway }})?
    DNS2={{ dns2 }}
  '
  [ubu]='
    # * review the config and modify if required
    # * `mv ./{{ iface }}.yaml /etc/netplan/01-{{ iface }}.yaml
    # * `netplan apply`
    network:
   .  version: 2
   .  renderer: networkd # <- for DE can be changed to NetworkManager
   .  ethernets:
   .    {{ iface }}: # <- check interface
   .      dhcp4: no
   .      addresses:
   .      - {{ ipaddr }}/{{ prefix }} # <- check prefix. change ip?
   .      # gateway4: {{ gateway }} # <- deprecated since ubuntu 22.04, use `routes`
   .      routes:
   .      - to: default
   .        via: {{ gateway }} # <- check gateway
   .      nameservers:
   .        addresses:
   .        - {{ dns1 }} # <- use gateway for dns1 ({{ gateway }})?
   .        - {{ dns2 }}
  '
)

{
  print_msg() {
    local res
    res="$(printf -- '%s\n' "${@}" \
      | sed -e 's/^\s*//' -e 's/\s*$//' \
      | grep -vFx '' | sed 's/^\.//')"
    [[ -n "${res}" ]] || return 1
    printf -- '%s\n' "${res}"
    return 0
  }

  log_msg() {
    print_msg "${@}" | sed 's/^/[os-setup] /'
  }
  log_err() { log_msg "${@}" >&2; }

  log_fail_rc() {
    local rc=${1}
    shift
    local msg="${@}"

    [[ "${rc}" -lt 1 ]] && return ${rc}

    log_err "${msg[@]}"
    exit "${rc}"
  }

  _opt_change() {
    [[ -w "${0}" ]] || return
    local flag="${1}"
    local old="['\"]?${2}['\"]?"
    local new="${3}"
    (set -x; sed -i -E 's/^(\s+\['"${flag}"'\]=)'"${old}"'$/\1'"${new}"'/' "${0}")
  }

  opt_switch_off() {
    local flag="${1}"
    _opt_change "${flag}" true false
  }

  opt_empty() {
    local flag="${1}"
    local old="${2}"
    _opt_change "${flag}" "${old}" '""'
  }
}

{
  declare -A DIST_MAP=(
    [rhel]=rhel
    [centos]=rhel
    [debian]=deb
    [ubuntu]=deb
  )
  _distro_detect() {
    unset _distro_detect

    local ids
    ids="$(cat /etc/os-release \
      | grep -E '^(ID|ID_LIKE)=' | cut -d'=' -f2 \
      | sed -e 's/^"//' -e 's/"$//' | tr ' ' '\n'
    )"

    local dist
    dist="$(grep -Fx -f <(printf -- '%s\n' "${!DIST_MAP[@]}") <<< "${ids}")" || return 1
    dist="$(head -n 1 <<< "${dist}")"

    CONF+=(
      [is_${DIST_MAP[$dist]}]=true
    )
  }; _distro_detect || {
    log_fail_rc 1 "
      Unsupported distro. Supported list:
      $(printf -- '* %s\n' "${!DIST_MAP[@]}")
    "
  }
}

# validation functions
{
  check_bool() {
    local val="${1}"
    [[ "${val}" =~ ^(true|false)$ ]] && return 0
    return 1
  }

  check_unix_login() {
    # https://unix.stackexchange.com/questions/157426/what-is-the-regex-to-validate-linux-users
    local val="${1}"
    local rex='[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)'
    grep -qEx -- "${rex}" <<< "${val}"
  }

  check_ip4() {
    local val="${1}"
    [[ "$(wc -l <<< "${val}")" == 1 ]] || return 1

    local segments_nl
    segments_nl="$(tr '.' '\n' <<< "${val}")"
    [[ "$(wc -l <<< "${segments_nl}")" == 4 ]] || return 1

    local -a segments_arr
    mapfile -t segments_arr <<< "${segments_nl}"
    local seg
    for seg in "${segments_arr[@]}"; do
      [[ "${seg}" =~ ^[0-9]+$ ]] || return 1
      [[ ${seg} -lt 0 ]] && return 1
      [[ ${seg} -gt 255 ]] && return 1
    done

    return 0
  }

  check_loopback_ip4() {
    local val="${1}"

    check_ip4 "${val}" || return $?
    test "$(cut -d'.' -f1 <<< "${val}")" -eq 127
  }
}

declare -a DEPENDENCIES
declare -a ERRBAG
declare -a POST_MSG
# for debian-based system unattended installation
export DEBIAN_FRONTEND=noninteractive

# validate bools
for c in "${!DEF[@]}"; do
  [[ "${DEF[$c]}" =~ ^(true|false)$ ]] || continue
  check_bool "${CONF[$c]}" || ERRBAG+=("${c} = ${CONF[$c]}")
done

# validate logins
for c in \
  user_login \
; do
  [[ -n "${CONF[$c]}" ]] || continue
  check_unix_login "${CONF[$c]}" || ERRBAG+=("${c} = ${CONF[$c]}")
done

# validate ips
for c in \
  hostname_ip \
; do
  check_ip4 "${CONF[$c]}" || ERRBAG+=("${c} = ${CONF[$c]}")
done

[[ ${#ERRBAG[@]} -gt 0 ]] && {
  log_fail_rc 1 "
    Invalid configs:
    $(printf -- '* %s\n' "${ERRBAG[@]}")
  "
}

_validate_root() {
  unset _validate_root
  [[ $(id -u) -lt 1 ]] && return 0
  log_fail_rc 1 '
    Errors:
    * Root is required
  '
}; _validate_root

dummy() {
  :
}

install_deps() {
  [[ ${#DEPENDENCIES[@]} -gt 0 ]] || return 0

  local -a pm_cmd
  local -a deps=($(printf -- '%s\n' "${DEPENDENCIES[@]}" | sort -u))

  if ${CONF[is_deb]}; then
    pm_cmd=(apt-get -q)
    (set -x; "${pm_cmd[0]}" update >/dev/null)
  elif ${CONF[is_rhel]}; then
    pm_cmd=(dnf -q)
  fi

  (set -x; "${pm_cmd[0]}" install -y "${deps[@]}" >/dev/null) \
    && DEPENDENCIES=()
}

declare USER_MV_FUNC=dummy
{
  _user_mv() {
    local from="${CONF[user_mv_from]}"
    local login="${CONF[user_login]}"

    # change login name and home
    # rename primary group
    (
      set -x
      usermod -l "${login}" -d "/home/${login}" -m "${from}" \
      && groupmod -n "${login}" "${from}"
    ) && {
      opt_empty user_mv_from "${from}"
    }
  }

  _user_mv_init() {
    local from="${CONF[user_mv_from]}"
    local login="${CONF[user_login]}"

    [[ (-n "${login}" && -n "${from}") ]] || return

    ${CONF[is_deb]} && DEPENDENCIES+=(passwd)
    ${CONF[is_rhel]} && DEPENDENCIES+=(shadow-utils)
    USER_MV_FUNC=_user_mv
  }; _user_mv_init; unset _user_mv_init
}

declare USER_MK_FUNC=dummy
{
  _user_mk() {
    local login="${CONF[user_login]}"
    local system="${CONF[user_is_system]}"

    id -u "${login}" > /dev/null 2>&1 && return

    local -a args
    local shell=/bin/bash
    ${system} && args+=('-r')
    [[ -f /usr/bin/bash ]] && shell=/usr/bin/bash
    args+=(-s "${shell}")

    ( set -x; useradd "${args[@]}" -m "${login}") || return $?
  }

  _user_mk_init() {
    local login="${CONF[user_login]}"

    [[ -n "${login}" ]] || return

    ${CONF[is_deb]} && DEPENDENCIES+=(passwd)
    ${CONF[is_rhel]} && DEPENDENCIES+=(shadow-utils)
    USER_MK_FUNC=_user_mk
  }; _user_mk_init; unset _user_mk_init
}

declare USER_CHFN_FUNC=dummy
{
  _user_chfn() {
    local login="${CONF[user_login]}"
    local fullname="${CONF[user_fullname]}"
    local actual_fn="$(getent passwd "${login}" 2> /dev/null \
      | cut -d ':' -f 5 | cut -d ',' -f 1)"

    [[ "${fullname}" == "${actual_fn}" ]] && return

    (set -x; usermod -c "${fullname}" "${login}") || return $?
  }

  _user_chfn_init() {
    local login="${CONF[user_login]}"

    [[ (-n "${login}") ]] || return

    ${CONF[is_deb]} && DEPENDENCIES+=(passwd)
    ${CONF[is_rhel]} && DEPENDENCIES+=(shadow-utils)
    USER_CHFN_FUNC=_user_chfn
  }; _user_chfn_init; unset _user_chfn_init
}

declare USER_CHPASS_FUNC=dummy
{
  declare -a _USER_CHPASS_LOGINS

  _user_chpass() {
    local again
    local login

    for login in "${_USER_CHPASS_LOGINS[@]}"; do
      while :; do
        passwd "${login}" && {
          [[ "${login}" == "${CONF[user_login]}" ]] && opt_switch_off user_chpass
          [[ "${login}" == root ]] && opt_switch_off root_chpass
          break 1
        }

        while :; do
          read -e -p "Another try? [y/n]: " -i "y" again
          [[ "${again,,}" == y ]] && break 1
          [[ "${again,,}" == n ]] && break 2

          log_err "Invalid choice"
        done
      done
    done
  }

  _user_chpass_init() {
    [[ -n "${CONF[user_login]}" ]] && ${CONF[user_chpass]} \
      && _USER_CHPASS_LOGINS+=("${CONF[user_login]}")
    ${CONF[root_chpass]} && _USER_CHPASS_LOGINS+=(root)

    [[ ${#_USER_CHPASS_LOGINS[@]} -gt 0 ]] || return
    _USER_CHPASS_LOGINS=($(printf -- '%s\n' "${_USER_CHPASS_LOGINS[@]}" | sort -u))

    DEPENDENCIES+=(passwd)
    USER_CHPASS_FUNC=_user_chpass
  }; _user_chpass_init; unset _user_chpass_init
}

declare USER_SUDOER_FUNC=dummy
{
  _user_sudoer() {
    local login="${CONF[user_login]}"
    local is_sudoer="${CONF[user_is_sudoer]}"
    local group
    local cur_groups="$(id -Gn "${login}" 2>/dev/null)"
    ${CONF[is_deb]} && group=sudo
    ${CONF[is_rhel]} && group=wheel

    ${is_sudoer} && {
      [[ " ${cur_groups} " != *" ${group} "* ]] \
        && (set -x; usermod -aG "${group}" "${login}")
      return
    }

    if [[ " ${cur_groups} " == *" ${group} "* ]]; then
      (set -x; gpasswd -d "${login}" "${group}")
    fi
  }

  _user_sudoer_init() {
    local login="${CONF[user_login]}"
    [[ -n "${login}" ]] || return

    ${CONF[is_deb]} && DEPENDENCIES+=(passwd)
    ${CONF[is_rhel]} && DEPENDENCIES+=(shadow-utils)
    USER_SUDOER_FUNC=_user_sudoer
  }; _user_sudoer_init; unset _user_sudoer_init
}

declare HOSTNAME_FUNC=dummy
{
  _hostname() {
    local hostname="${CONF[hostname]}"
    local ip="${CONF[hostname_ip]}"

    [[ "$(hostname)" != "${hostname}" ]] && {
      (set -x; hostnamectl set-hostname "${hostname}") || return $?
    }

    local host_rex="${hostname//\./\\.}"
    local ip_rex="${ip//\./\\.}"
    local file=/etc/hosts

    # nothing to do if the hostname is the only entry for the ip
    grep -qE "^\\s*${ip_rex}\\s*\\s${host_rex}\\s*(#.*)?$" "${file}" && return

    local ip4_rex='([0-9]{1,3}\.){3}[0-9]{1,3}'

    # remove all lines where the hostname is the only entry for ip
    sed -i -E "/^\\s*${ip4_rex}\\s+${host_rex}\\s*(#.*)?$/d" /etc/hosts
    # remove hostname other ip entries
    sed -i -E "s/^(\s*${ip4_rex}[^#]*)\\s${host_rex}(\\s.*)?$/\1\3/" "${file}"
    # ensure new line at EOF (https://unix.stackexchange.com/a/31955)
    sed -i -e '$a\' "${file}"
    # add a bound entry
    (set -x; printf -- '%s %s\n' "${ip}" "${hostname}" >> "${file}")
  }

  _hostname_init() {
    local hostname="${CONF[hostname]}"
    [[ -n "${hostname}" ]] || return
    HOSTNAME_FUNC=_hostname
  }; _hostname_init; unset _hostname_init
}

declare NETCONF_FUNC=dummy
{
  _netconf() {
    local default_route
    local -A conf=(
      [dns1]=1.1.1.1
      [dns2]=8.8.8.8
    )
    local -A def=(
      [gateway]=192.168.0.1
      [iface]=eth0
      [ipaddr]=192.168.0.10
      [prefix]=24
    )
    local ip_range

    default_route="$(ip route | grep 'default' | tail -n 1)"
    conf[gateway]="$(grep -o '\svia\s.*' <<< "${default_route}" \
      | sed -E 's/^\s+//' | cut -d' ' -f2)"
    conf[iface]="$(grep -o '\sdev\s.*' <<< "${default_route}" \
      | sed -E 's/^\s+//' | cut -d' ' -f2)"
    ip_range="$(ip a show "${conf[iface]}" 2>/dev/null \
      | grep '\s*inet\s' | sed -E 's/^\s+//' | cut -d' ' -f2)"
    conf[ipaddr]="$(cut -d'/' -f1 <<< "${ip_range}/")"
    conf[prefix]="$(cut -d'/' -f2 <<< "${ip_range}/")"

    local c; for c in "${!def[@]}"; do
      conf[$c]="${conf[$c]:-${def[$c]}}"
    done

    local filename
    local content
    ${CONF[is_deb]} && {
      content="${NETCONF_TPL[ubu]}"
      filename="${conf[iface]}.yaml"
    }
    ${CONF[is_rhel]} && {
      content="${NETCONF_TPL[rhel]}"
      filename="ifcfg-${conf[iface]}"
    }

    local c; for c in "${!conf[@]}"; do
      content="$(sed "s/{{ $c }}/${conf[$c]}/g" <<< "${content}")"
    done

    (print_msg "${content}" | { set -x; tee "${filename}" >/dev/null; } )
    (set -x; chmod 0644 "${filename}")

    POST_MSG+=("$(print_msg "
      Review and apply ${filename}
    ")")
    opt_switch_off netconf
  }

  _netconf_init() {
    "${CONF[netconf]}" || return
    NETCONF_FUNC=_netconf
  }; _netconf_init; unset _netconf_init
}

declare INSTALLS_FUNC=dummy
{
  declare -a _INSTALLS_PKGS

  _installs() {
    local -a pm_cmd

    ${CONF[is_rhel]} && pm_cmd=(dnf -q)
    ${CONF[is_deb]} && {
      pm_cmd=(apt-get -q)
      (set -x; "${pm_cmd[@]}" update >/dev/null)
    }

    (set -x; "${pm_cmd[@]}" install -y "${_INSTALLS_PKGS[@]}" >/dev/null)
  }

  _installs_init() {
    "${CONF[ansible_prereq]}" && _INSTALLS_PKGS+=(openssh-server python3)

    [[ ${#_INSTALLS_PKGS[@]} -gt 0 ]] || return
    _INSTALLS_PKGS=($(printf -- '%s\n' "${_INSTALLS_PKGS[@]}" | sort -u))
    INSTALLS_FUNC=_installs
  }; _installs_init; unset _installs_init
}

GP_INSTALL_FUNC=dummy
{
  _gp_install() {
    local tmp_archive
    local tmp_dir
    local -a clean=(rm -f)
    tmp_archive="$(set -x; mktemp --suffix -gp.tgz)" || return 1
    tmp_dir="$(set -x; mktemp -d --suffix -gp)" || return 1
    clean+=("${tmp_archive}" "${tmp_dir}"/*)

    (
      set -x
      curl -s -L -o "${tmp_archive}" "${CONF[gp_url]}" \
      && tar -xf "${tmp_archive}" -C "${tmp_dir}"
    ) || { "${clean[@]}"; return 1; }

    local pkg_ext=deb
    local -a pm_cmd=(dpkg)
    local installer_ptn
    local installer
    ${CONF[is_rhel]} && { pkg_ext=rpm; pm_cmd=(rpm); }
    installer_ptn="GlobalProtect_${pkg_ext}-*.${pkg_ext}"

    installer="$(find "${tmp_dir}" -name "${installer_ptn}")"
    [[ -n "${installer}" ]] || { "${clean[@]}"; return 1; }

    (set -x; "${pm_cmd[@]}" -i "${installer}" >/dev/null) || { "${clean[@]}"; return 1; }

    POST_MSG+=("$(print_msg "
      Restart the machine, login and connect to a GP portal with:
      \`globalprotect connect -p PORTAL -u PORTAL_USER\`
    ")")
  }

  _gp_install_init() {
    ${CONF[gp]} || return
    globalprotect help >/dev/null 2>/dev/null && return
    DEPENDENCIES+=(tar curl)
    GP_INSTALL_FUNC=_gp_install
  }; _gp_install_init; unset _gp_install_init
}

declare UPGRADE_FUNC=dummy
{
  _upgrade() {
    local -a pm_cmd

    ${CONF[is_rhel]} && {
      pm_cmd=(dnf -q)
      (set -x; "${pm_cmd[@]}" upgrade -y >/dev/null)
    }
    ${CONF[is_deb]} && {
      pm_cmd=(apt-get -q)
      (set -x; "${pm_cmd[@]}" update >/dev/null)
      (set -x; "${pm_cmd[@]}" dist-upgrade -y >/dev/null)
    }
  }

  _upgrade_init() {
    "${CONF[upgrade]}" || return
    UPGRADE_FUNC=_upgrade
  }; _upgrade_init; unset _upgrade_init
}

declare CLEANUP_FUNC=dummy
{
  _cleanup() {
    local pm_cmd
    ${CONF[is_deb]} && pm_cmd=(apt-get -q)
    ${CONF[is_rhel]} && pm_cmd=(dnf -q)

    (set -x; "${pm_cmd[@]}" -y autoremove >/dev/null)
    ${CONF[is_deb]} && (
      set -x
      "${pm_cmd[@]}" -y clean >/dev/null
      "${pm_cmd[@]}" -y autoclean >/dev/null
    )
    ${CONF[is_rhel]} && (
      set -x
      "${pm_cmd[@]}" -y --enablerepo='*' clean all >/dev/null
    )

    (
      set -x
      find /tmp/ /var/tmp/ -mindepth 1 -maxdepth -exec rm -rf {} \; 2> /dev/null
      find /var/log/ -type f -exec truncate -s 0 {} \;
    )
  }

  _cleanup_init() {
    "${CONF[cleanup]}" || return
    CLEANUP_FUNC=_cleanup
  }; _cleanup_init; unset _cleanup_init
}

install_deps

# user_mk only should work if user_mv didn't fail
"${USER_MV_FUNC}" && "${USER_MK_FUNC}"
"${USER_CHFN_FUNC}"
"${USER_SUDOER_FUNC}"
"${USER_CHPASS_FUNC}"

"${HOSTNAME_FUNC}"
"${NETCONF_FUNC}"

"${INSTALLS_FUNC}"
"${GP_INSTALL_FUNC}"
"${UPGRADE_FUNC}"
"${CLEANUP_FUNC}"

[[ ${#POST_MSG[@]} -gt 0 ]] && {
  print_msg "
   .
    POST MESSAGE
    ============
  "
  printf -- '* %s\n' "${POST_MSG[@]}" \
  | sed -e 's/^[^*]/  &/'
}
