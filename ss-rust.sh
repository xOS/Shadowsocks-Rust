#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS/Debian/Ubuntu
#	Description: Shadowsocks Rust 管理脚本
#	Author: 翠花
#	WebSite: https://about.nange.cn
#=================================================

# 当前脚本版本号
sh_ver="1.5.3"

# Shadowsocks Rust 相关路径
SS_Folder="/etc/ss-rust"
SS_File="/usr/local/bin/ss-rust"
SS_Conf="/etc/ss-rust/config.json"
SS_Now_ver_File="/etc/ss-rust/ver.txt"

# BBR 配置文件
BBR_Local="/etc/sysctl.d/local.conf"

# Shadow TLS 相关路径
STLS_Folder="/etc/shadowtls"
STLS_File="/usr/local/bin/shadow-tls"
STLS_Conf="/etc/shadowtls/config.json"
STLS_Now_ver_File="/etc/shadowtls/ver.txt"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m" && Yellow_font_prefix="\033[0;33m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Yellow_font_prefix}[注意]${Font_color_suffix}"

check_root(){
	if [[ $EUID != 0 ]]; then
		echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_background_prefix}sudo su${Font_color_suffix} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。"
		exit 1
	fi
}

check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
}

sys_arch() {
    uname=$(uname -m)
    if [[ "$uname" == "i686" ]] || [[ "$uname" == "i386" ]]; then
        arch="i686"
    elif [[ "$uname" == *"armv7"* ]] || [[ "$uname" == "armv6l" ]]; then
        arch="arm"
    elif [[ "$uname" == *"armv8"* ]] || [[ "$uname" == "aarch64" ]]; then
        arch="aarch64"
    else
        arch="x86_64"
    fi    
}

#开启系统 TCP Fast Open
enable_systfo() {
	kernel=$(uname -r | awk -F . '{print $1}')
	if [ "$kernel" -ge 3 ]; then
		echo 3 >/proc/sys/net/ipv4/tcp_fastopen
		[[ ! -e $BBR_Local ]] && echo "fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_ecn=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.d/local.conf && sysctl --system >/dev/null 2>&1
	else
		echo -e "$Error系统内核版本过低，无法支持 TCP Fast Open ！"
	fi
}

check_installed_status(){
	[[ ! -e ${SS_File} ]] && echo -e "${Error} Shadowsocks Rust 没有安装，请检查！" && exit 1
}

check_status(){
	status=`systemctl status ss-rust | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1`
}

check_new_ver(){
	new_ver=$(wget -qO- https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases| jq -r '[.[] | select(.prerelease == false) | select(.draft == false) | .tag_name] | .[0]')
	[[ -z ${new_ver} ]] && echo -e "${Error} Shadowsocks Rust 最新版本获取失败！" && exit 1
	echo -e "${Info} 检测到 Shadowsocks Rust 最新版本为 [ ${new_ver} ]"
}

check_ver_comparison(){
	now_ver=$(cat ${SS_Now_ver_File})
	if [[ "${now_ver}" != "${new_ver}" ]]; then
		echo -e "${Info} 发现 Shadowsocks Rust 已有新版本 [ ${new_ver} ]，旧版本 [ ${now_ver} ]"
		read -e -p "是否更新 ？ [Y/n]：" yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ $yn == [Yy] ]]; then
			check_status
			# [[ "$status" == "running" ]] && systemctl stop ss-rust
			\cp "${SS_Conf}" "/tmp/config.json"
			# rm -rf ${SS_Folder}
			download
			mv -f "/tmp/config.json" "${SS_Conf}"
			restart
		fi
	else
		echo -e "${Info} 当前 Shadowsocks Rust 已是最新版本 [ ${new_ver} ] ！" && exit 1
	fi
}

# 官方源
stable_download() {
	echo -e "${Info} 默认开始下载官方源 Shadowsocks Rust ……"
	wget --no-check-certificate -N "https://github.com/shadowsocks/shadowsocks-rust/releases/download/${new_ver}/shadowsocks-${new_ver}.${arch}-unknown-linux-gnu.tar.xz"
	if [[ ! -e "shadowsocks-${new_ver}.${arch}-unknown-linux-gnu.tar.xz" ]]; then
		echo -e "${Error} Shadowsocks Rust 官方源下载失败！"
		return 1 && exit 1
	else
		tar -xvf "shadowsocks-${new_ver}.${arch}-unknown-linux-gnu.tar.xz"
	fi
	if [[ ! -e "ssserver" ]]; then
		echo -e "${Error} Shadowsocks Rust 解压失败！"
		echo -e "${Error} Shadowsocks Rust 安装失败 !"
		return 1 && exit 1
	else
		rm -rf "shadowsocks-${new_ver}.${arch}-unknown-linux-gnu.tar.xz"
        chmod +x ssserver
	    mv -f ssserver "${SS_File}"
	    rm sslocal ssmanager ssservice ssurl
	    echo "${new_ver}" > ${SS_Now_ver_File}

        echo -e "${Info} Shadowsocks Rust 主程序下载安装完毕！"
		return 0
	fi
}

# 备用源
backup_download() {
	echo -e "${Info} 试图请求 备份源(旧版本) Shadowsocks Rust ……"
	wget --no-check-certificate -N "https://raw.githubusercontent.com/xOS/Others/master/shadowsocks-rust/v1.14.1/shadowsocks-v1.14.1.${arch}-unknown-linux-gnu.tar.xz"
	if [[ ! -e "shadowsocks-v1.14.1.${arch}-unknown-linux-gnu.tar.xz" ]]; then
		echo -e "${Error} Shadowsocks Rust 备份源(旧版本) 下载失败！"
		return 1 && exit 1
	else
		tar -xvf "shadowsocks-v1.14.1.${arch}-unknown-linux-gnu.tar.xz"
	fi
	if [[ ! -e "ssserver" ]]; then
		echo -e "${Error} Shadowsocks Rust 备份源(旧版本) 解压失败 !"
		echo -e "${Error} Shadowsocks Rust 备份源(旧版本) 安装失败 !"
		return 1 && exit 1
	else
		rm -rf "shadowsocks-v1.14.1.${arch}-unknown-linux-gnu.tar.xz"
		chmod +x ssserver
	    mv -f ssserver "${SS_File}"
	    rm sslocal ssmanager ssservice ssurl
		echo "v1.14.1" > ${SS_Now_ver_File}
		echo -e "${Info} Shadowsocks Rust 备份源(旧版本) 主程序下载安装完毕！"
		return 0
	fi
}

download() {
	if [[ ! -e "${SS_Folder}" ]]; then
		mkdir "${SS_Folder}"
	# else
		# [[ -e "${SS_File}" ]] && rm -rf "${SS_File}"
	fi
	stable_download
	if [[ $? != 0 ]]; then
		backup_download
	fi
}

# Shadow TLS 官方源下载
stable_download_stls() {
	echo -e "${Info} 默认开始下载官方源 Shadow TLS ……"
	wget --no-check-certificate -N "https://github.com/ihciah/shadow-tls/releases/download/${stls_new_ver}/shadow-tls-${arch}-unknown-linux-musl"
	if [[ ! -e "shadow-tls-${arch}-unknown-linux-musl" ]]; then
		echo -e "${Error} Shadow TLS 官方源下载失败！"
		return 1 && exit 1
	else
		chmod +x "shadow-tls-${arch}-unknown-linux-musl"
		mv -f "shadow-tls-${arch}-unknown-linux-musl" "${STLS_File}"
		echo "${stls_new_ver}" > ${STLS_Now_ver_File}
		echo -e "${Info} Shadow TLS 主程序下载安装完毕！"
		return 0
	fi
}

download_stls() {
	if [[ ! -e "${STLS_Folder}" ]]; then
		mkdir "${STLS_Folder}"
	fi
	stable_download_stls
}

# Shadow TLS 配置相关函数
set_stls_port(){
	while true
		do
		echo -e "${Tip} Shadow TLS 端口需与防火墙端口一致！"
		echo -e "请输入 Shadow TLS 端口 [1-65535]"
		read -e -p "(默认：8443)：" stls_port
		[[ -z "${stls_port}" ]] && stls_port="8443"
		echo $((${stls_port}+0)) &>/dev/null
		if [[ $? -eq 0 ]]; then
			if [[ ${stls_port} -ge 1 ]] && [[ ${stls_port} -le 65535 ]]; then
				echo && echo "========================================"
				echo -e "Shadow TLS 端口：${Red_background_prefix} ${stls_port} ${Font_color_suffix}"
				echo "========================================" && echo
				break
			else
				echo "输入错误, 请输入正确的端口。"
			fi
		else
			echo "输入错误, 请输入正确的端口。"
		fi
		done
}

set_stls_password(){
	echo "请输入 Shadow TLS 密码 [0-9][a-z][A-Z]"
	read -e -p "(默认：随机生成)：" stls_password
	[[ -z "${stls_password}" ]] && stls_password=$(< /dev/urandom tr -dc 'a-zA-Z0-9' | head -c 16)
	echo && echo "========================================"
	echo -e "Shadow TLS 密码：${Red_background_prefix} ${stls_password} ${Font_color_suffix}"
	echo "========================================" && echo
}

set_stls_sni(){
	echo "请输入 Shadow TLS SNI 域名"
	read -e -p "(默认：cloudflare.com)：" stls_sni
	[[ -z "${stls_sni}" ]] && stls_sni="cloudflare.com"
	echo && echo "========================================"
	echo -e "Shadow TLS SNI：${Red_background_prefix} ${stls_sni} ${Font_color_suffix}"
	echo "========================================" && echo
}

set_stls_fastopen(){
	echo -e "是否开启 Shadow TLS TCP Fast Open ？
========================================
${Green_font_prefix} 1.${Font_color_suffix} 开启  ${Green_font_prefix} 2.${Font_color_suffix} 关闭
========================================"
	read -e -p "(默认：1.开启)：" stls_fastopen_choice
	[[ -z "${stls_fastopen_choice}" ]] && stls_fastopen_choice="1"
	if [[ ${stls_fastopen_choice} == "1" ]]; then
		stls_fastopen="true"
	else
		stls_fastopen="false"
	fi
	echo && echo "========================================"
	echo -e "Shadow TLS FastOpen：${Red_background_prefix} ${stls_fastopen} ${Font_color_suffix}"
	echo "========================================" && echo
}

set_stls_strict(){
	echo -e "是否开启 Shadow TLS Strict 模式 ？
========================================
${Green_font_prefix} 1.${Font_color_suffix} 开启  ${Green_font_prefix} 2.${Font_color_suffix} 关闭
========================================"
	read -e -p "(默认：1.开启)：" stls_strict_choice
	[[ -z "${stls_strict_choice}" ]] && stls_strict_choice="1"
	if [[ ${stls_strict_choice} == "1" ]]; then
		stls_strict="true"
	else
		stls_strict="false"
	fi
	echo && echo "========================================"
	echo -e "Shadow TLS Strict：${Red_background_prefix} ${stls_strict} ${Font_color_suffix}"
	echo "========================================" && echo
}

set_stls_tls_wildcard_sni(){
	echo -e "请选择 Shadow TLS Wildcard SNI 模式：
========================================
${Green_font_prefix} 1.${Font_color_suffix} authed (默认)
${Green_font_prefix} 2.${Font_color_suffix} off
${Green_font_prefix} 3.${Font_color_suffix} all
========================================"
	read -e -p "(默认：1.authed)：" stls_tls_wildcard_sni_choice
	[[ -z "${stls_tls_wildcard_sni_choice}" ]] && stls_tls_wildcard_sni_choice="1"
	case "${stls_tls_wildcard_sni_choice}" in
		1) stls_tls_wildcard_sni="authed" ;;
		2) stls_tls_wildcard_sni="off" ;;
		3) stls_tls_wildcard_sni="all" ;;
		*) stls_tls_wildcard_sni="authed" ;;
	esac
	echo && echo "========================================"
	echo -e "TLS Wildcard SNI：${Red_background_prefix} ${stls_tls_wildcard_sni} ${Font_color_suffix}"
	echo "========================================" && echo
}

set_stls_fallback(){
	echo "请输入 Shadow TLS 回退域名"
	read -e -p "(默认：cloud.tencent.com:443)：" stls_fallback
	[[ -z "${stls_fallback}" ]] && stls_fallback="cloud.tencent.com:443"
	echo && echo "========================================"
	echo -e "Shadow TLS 回退域名：${Red_background_prefix} ${stls_fallback} ${Font_color_suffix}"
	echo "========================================" && echo
}

service(){
	echo "
[Unit]
Description= Shadowsocks Rust Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service
[Service]
LimitNOFILE=32767 
Type=simple
User=root
Restart=on-failure
RestartSec=5s
DynamicUser=true
ExecStartPre=/bin/sh -c 'ulimit -n 51200'
ExecStart=${SS_File} -c ${SS_Conf}
[Install]
WantedBy=multi-user.target" > /etc/systemd/system/ss-rust.service
systemctl enable --now ss-rust
	echo -e "${Info} Shadowsocks Rust 服务配置完成！"
}

service_stls(){
	cat > /etc/systemd/system/shadowtls.service<<-EOF
[Unit]
Description=Shadow TLS Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
LimitNOFILE=32767
Type=simple
User=root
Restart=on-failure
RestartSec=5s
Environment=MONOIO_FORCE_LEGACY_DRIVER=1
ExecStartPre=/bin/sh -c 'ulimit -n 51200'
ExecStart=${STLS_File} config --config ${STLS_Conf}

[Install]
WantedBy=multi-user.target
EOF
	systemctl enable --now shadowtls
	echo -e "${Info} Shadow TLS 服务配置完成！"
}

installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		yum update
		yum install jq gzip wget curl unzip xz openssl -y
	else
		apt-get update
		apt-get install jq gzip wget curl unzip xz-utils openssl -y
	fi
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}

write_config(){
	cat > ${SS_Conf}<<-EOF
{
    "server": "::",
    "server_port": ${port},
    "password": "${password}",
    "method": "${cipher}",
    "fast_open": ${tfo},
    "mode": "tcp_and_udp",
    "user":"nobody",
    "timeout":300,
    "nameserver":"1.1.1.1"
}
EOF
}

write_stls_config(){
	# 设置默认值
	[[ -z "${stls_fastopen}" ]] && stls_fastopen="true"
	[[ -z "${stls_strict}" ]] && stls_strict="true"
	[[ -z "${stls_tls_wildcard_sni}" ]] && stls_tls_wildcard_sni="authed"
	[[ -z "${stls_fallback}" ]] && stls_fallback="cloud.tencent.com:443"
	
	# 构建 dispatch 配置
	if [[ -z "${stls_dispatch}" ]]; then
		# 没有现有配置，使用默认配置
		# SNI 域名对应的目标地址也使用相同的域名:443
		stls_dispatch_config="\"${stls_sni}\": \"${stls_sni}:443\",
        \"captive.apple.com\": \"captive.apple.com:443\""
	else
		# 有现有配置，需要智能更新 SNI
		if [[ ! -z "${stls_sni}" && -e ${STLS_Conf} ]]; then
			# 查找需要更新的 SNI（排除 captive.apple.com）
			old_sni=$(cat ${STLS_Conf}|jq -r '.server.tls_addr.dispatch | keys[] | select(. != "captive.apple.com")' 2>/dev/null | head -1)
			if [[ ! -z "${old_sni}" && "${old_sni}" != "null" && "${old_sni}" != "${stls_sni}" ]]; then
				# 需要替换旧的 SNI 为新的 SNI，同时更新键和值
				echo -e "${Info} 更新主要 SNI 从 ${old_sni} 到 ${stls_sni}"
				
				# 使用 jq 来精确替换键和值
				stls_dispatch_config=$(cat ${STLS_Conf} | jq -r --arg old_sni "${old_sni}" --arg new_sni "${stls_sni}" '
					.server.tls_addr.dispatch | 
					to_entries | 
					map(if .key == $old_sni then (.key = $new_sni | .value = ($new_sni + ":443")) else . end) | 
					map("\"\(.key)\": \"\(.value)\"") | 
					join(",\n        ")
				' 2>/dev/null)
				
				# 如果 jq 处理失败，回退到字符串替换
				if [[ -z "${stls_dispatch_config}" || "${stls_dispatch_config}" == "null" ]]; then
					echo -e "${Info} jq 处理失败，使用字符串替换"
					# 先替换键，再替换对应的值
					stls_dispatch_config=$(echo "${stls_dispatch}" | sed "s/\"${old_sni}\": \"[^\"]*\"/\"${stls_sni}\": \"${stls_sni}:443\"/g")
				fi
			else
				# 如果没有找到需要更新的 SNI，或者 SNI 已经是正确的，直接使用现有配置
				stls_dispatch_config="${stls_dispatch}"
			fi
		else
			stls_dispatch_config="${stls_dispatch}"
		fi
	fi
	
	# 调试信息（可选，用于排查问题）
	# echo -e "${Info} 调试信息："
	# echo -e "  stls_sni: ${stls_sni}"
	# echo -e "  stls_dispatch_config: ${stls_dispatch_config}"
	
	cat > ${STLS_Conf}<<-EOF
{
  "disable_nodelay": false,
  "fastopen": ${stls_fastopen},
  "v3": true,
  "strict": ${stls_strict},
  "server": {
    "listen": "0.0.0.0:${stls_port}",
    "server_addr": "127.0.0.1:${port}",
    "tls_addr": {
      "wildcard_sni": "${stls_tls_wildcard_sni}",
      "dispatch": {
        ${stls_dispatch_config}
      },
      "fallback": "${stls_fallback}"
    },
    "password": "${stls_password}",
    "wildcard_sni": "authed"
  }
}
EOF
	
	# 验证配置文件是否正确生成
	if [[ -e ${STLS_Conf} ]]; then
		# 检查配置文件是否为有效的 JSON
		if ! jq . ${STLS_Conf} >/dev/null 2>&1; then
			echo -e "${Error} Shadow TLS 配置文件格式错误！"
			return 1
		fi
		echo -e "${Info} Shadow TLS 配置文件写入成功"
		
		# 显示当前配置的 SNI
		current_sni=$(cat ${STLS_Conf}|jq -r '.server.tls_addr.dispatch | keys[0]' 2>/dev/null)
		if [[ ! -z "${current_sni}" && "${current_sni}" != "null" ]]; then
			echo -e "${Info} 当前配置的 SNI: ${Green_font_prefix}${current_sni}${Font_color_suffix}"
		fi
	else
		echo -e "${Error} Shadow TLS 配置文件写入失败！"
		return 1
	fi
}

read_config(){
	[[ ! -e ${SS_Conf} ]] && echo -e "${Error} Shadowsocks Rust 配置文件不存在！" && exit 1
	port=$(cat ${SS_Conf}|jq -r '.server_port')
	password=$(cat ${SS_Conf}|jq -r '.password')
	cipher=$(cat ${SS_Conf}|jq -r '.method')
	tfo=$(cat ${SS_Conf}|jq -r '.fast_open')
}

read_stls_config(){
	[[ ! -e ${STLS_Conf} ]] && echo -e "${Error} Shadow TLS 配置文件不存在！" && exit 1
	stls_port=$(cat ${STLS_Conf}|jq -r '.server.listen' | grep -oE '[0-9]+$')
	stls_password=$(cat ${STLS_Conf}|jq -r '.server.password')
	stls_sni=$(cat ${STLS_Conf}|jq -r '.server.tls_addr.dispatch | keys[0]')
	stls_fastopen=$(cat ${STLS_Conf}|jq -r '.fastopen')
	stls_strict=$(cat ${STLS_Conf}|jq -r '.strict')
	stls_tls_wildcard_sni=$(cat ${STLS_Conf}|jq -r '.server.tls_addr.wildcard_sni')
	stls_fallback=$(cat ${STLS_Conf}|jq -r '.server.tls_addr.fallback')
	# 读取完整的 dispatch 配置
	stls_dispatch=$(cat ${STLS_Conf}|jq -r '.server.tls_addr.dispatch | to_entries | map("\"\(.key)\": \"\(.value)\"") | join(",\n        ")')
}

set_port(){
	while true
		do
		echo -e "${Tip} 本步骤不涉及系统防火墙端口操作，请手动放行相应端口！"
		echo -e "请输入 Shadowsocks Rust 端口 [1-65535]"
		read -e -p "(默认：2525)：" port
		[[ -z "${port}" ]] && port="2525"
		echo $((${port}+0)) &>/dev/null
		if [[ $? -eq 0 ]]; then
			if [[ ${port} -ge 1 ]] && [[ ${port} -le 65535 ]]; then
				echo && echo "========================================"
				echo -e "端口：${Red_background_prefix} ${port} ${Font_color_suffix}"
				echo "========================================" && echo
				break
			else
				echo "输入错误, 请输入正确的端口。"
			fi
		else
			echo "输入错误, 请输入正确的端口。"
		fi
		done
}

set_tfo(){
	echo -e "是否开启 TCP Fast Open ？
========================================
${Green_font_prefix} 1.${Font_color_suffix} 开启  ${Green_font_prefix} 2.${Font_color_suffix} 关闭
========================================"
	read -e -p "(默认：1.开启)：" tfo
	[[ -z "${tfo}" ]] && tfo="1"
	if [[ ${tfo} == "1" ]]; then
		tfo=true
		enable_systfo
	else
		tfo=false
	fi
	echo && echo "=================================="
	echo -e "TCP Fast Open 开启状态：${Red_background_prefix} ${tfo} ${Font_color_suffix}"
	echo "==================================" && echo
}

set_password(){
	echo "请输入 Shadowsocks Rust 密码 [0-9][a-z][A-Z]"
	read -e -p "(默认：随机生成)：" password
	# 当用户未输入密码时，执行默认生成逻辑
	if [[ -z "${password}" ]]; then
		# 判断是否为2022系列加密
		if [[ ${cipher} == "2022-blake3-aes-256-gcm" || ${cipher} == "2022-blake3-chacha20-poly1305" ]]; then
			# 2022系列必须使用指定长度的Base64密钥
			echo -e "${Tip} 为 ${cipher} 生成 32 字节 Base64 密钥..."
			password=$(openssl rand -base64 32)
		elif [[ ${cipher} == "2022-blake3-aes-128-gcm" ]]; then
			# 2022系列必须使用指定长度的Base64密钥
			echo -e "${Tip} 为 ${cipher} 生成 16 字节 Base64 密钥..."
			password=$(openssl rand -base64 16)
		else
			# 其他加密方式，生成一个普通的16位字母和数字的随机密码
			echo -e "${Tip} 为 ${cipher} 生成 16 位随机密码 (非Base64)..."
			password=$(< /dev/urandom tr -dc 'a-zA-Z0-9' | head -c 16)
		fi
	fi
	echo && echo "========================================"
	echo -e "密码：${Red_font_prefix} ${password} ${Font_color_suffix}"
	echo "========================================" && echo
}

set_cipher(){
	echo -e "请选择 Shadowsocks Rust 加密方式
========================================	
 ${Green_font_prefix} 1.${Font_color_suffix} aes-128-gcm ${Green_font_prefix}(默认)${Font_color_suffix}
 ${Green_font_prefix} 2.${Font_color_suffix} aes-256-gcm ${Green_font_prefix}(推荐)${Font_color_suffix}
 ${Green_font_prefix} 3.${Font_color_suffix} chacha20-ietf-poly1305 ${Green_font_prefix}${Font_color_suffix}
 ${Green_font_prefix} 4.${Font_color_suffix} plain ${Red_font_prefix}(不推荐)${Font_color_suffix}
 ${Green_font_prefix} 5.${Font_color_suffix} none ${Red_font_prefix}(不推荐)${Font_color_suffix}
 ${Green_font_prefix} 6.${Font_color_suffix} table
 ${Green_font_prefix} 7.${Font_color_suffix} aes-128-cfb
 ${Green_font_prefix} 8.${Font_color_suffix} aes-256-cfb
 ${Green_font_prefix} 9.${Font_color_suffix} aes-256-ctr 
 ${Green_font_prefix}10.${Font_color_suffix} camellia-256-cfb
 ${Green_font_prefix}11.${Font_color_suffix} rc4-md5
 ${Green_font_prefix}12.${Font_color_suffix} chacha20-ietf
========================================
 ${Tip} AEAD 2022 加密（须v1.15.0及以上版本且密码须经过Base64加密）
========================================	
 ${Green_font_prefix}13.${Font_color_suffix} 2022-blake3-aes-128-gcm ${Green_font_prefix}(推荐)${Font_color_suffix}
 ${Green_font_prefix}14.${Font_color_suffix} 2022-blake3-aes-256-gcm ${Green_font_prefix}(推荐)${Font_color_suffix}
 ${Green_font_prefix}15.${Font_color_suffix} 2022-blake3-chacha20-poly1305
 ========================================
 ${Tip} 如需其它加密方式请手动修改配置文件 !" && echo
	read -e -p "(默认: 1. aes-128-gcm)：" cipher
	[[ -z "${cipher}" ]] && cipher="1"
	if [[ ${cipher} == "1" ]]; then
		cipher="aes-128-gcm"
	elif [[ ${cipher} == "2" ]]; then
		cipher="aes-256-gcm"
	elif [[ ${cipher} == "3" ]]; then
		cipher="chacha20-ietf-poly1305"
	elif [[ ${cipher} == "4" ]]; then
		cipher="plain"
	elif [[ ${cipher} == "5" ]]; then
		cipher="none"
	elif [[ ${cipher} == "6" ]]; then
		cipher="table"
	elif [[ ${cipher} == "7" ]]; then
		cipher="aes-128-cfb"
	elif [[ ${cipher} == "8" ]]; then
		cipher="aes-256-cfb"
	elif [[ ${cipher} == "9" ]]; then
		cipher="aes-256-ctr"
	elif [[ ${cipher} == "10" ]]; then
		cipher="camellia-256-cfb"
	elif [[ ${cipher} == "11" ]]; then
		cipher="arc4-md5"
	elif [[ ${cipher} == "12" ]]; then
		cipher="chacha20-ietf"
	elif [[ ${cipher} == "13" ]]; then
		cipher="2022-blake3-aes-128-gcm"
	elif [[ ${cipher} == "14" ]]; then
		cipher="2022-blake3-aes-256-gcm"
	elif [[ ${cipher} == "15" ]]; then
		cipher="2022-blake3-chacha20-poly1305"		
	else
		cipher="aes-128-gcm"
	fi
	echo && echo "========================================"
	echo -e "加密：${Red_background_prefix} ${cipher} ${Font_color_suffix}"
	echo "========================================" && echo
}

set_config(){
	check_installed_status
	echo && echo -e "你要做什么？
========================================
 ${Green_font_prefix}1.${Font_color_suffix}  修改 端口配置
 ${Green_font_prefix}2.${Font_color_suffix}  修改 加密配置
 ${Green_font_prefix}3.${Font_color_suffix}  修改 密码配置
 ${Green_font_prefix}4.${Font_color_suffix}  修改 TFO 配置
========================================
 ${Green_font_prefix}5.${Font_color_suffix}  修改 全部配置" && echo
	read -e -p "(默认：取消)：" modify
	[[ -z "${modify}" ]] && echo "已取消..." && exit 1
	if [[ "${modify}" == "1" ]]; then
		read_config
		set_port
		cipher=${cipher}
		password=${password}
		tfo=${tfo}
		write_config
		restart
	elif [[ "${modify}" == "2" ]]; then
		read_config
		set_cipher
		port=${port}
		password=${password}
		tfo=${tfo}
		write_config
		restart
	elif [[ "${modify}" == "3" ]]; then
		read_config
		cipher=${cipher}
		set_password
		port=${port}
		tfo=${tfo}
		write_config
		restart
	elif [[ "${modify}" == "4" ]]; then
		read_config
		set_tfo
		cipher=${cipher}
		port=${port}
		password=${password}
		write_config
		restart
	elif [[ "${modify}" == "5" ]]; then
		read_config
		set_port
		set_cipher
		set_password
		set_tfo
		write_config
		restart
	else
		echo -e "${Error} 请输入正确的数字(1-5)" && exit 1
	fi
}

install(){
	[[ -e ${SS_File} ]] && echo -e "${Error} 检测到 Shadowsocks Rust 已安装！" && exit 1
	echo -e "${Info} 开始设置 配置..."
	set_port
	set_cipher
	set_password
	set_tfo
	echo -e "${Info} 开始安装/配置 依赖..."
	installation_dependency
	echo -e "${Info} 开始下载/安装..."
	check_new_ver
	download
	echo -e "${Info} 开始安装系统服务脚本..."
	service
	echo -e "${Info} 开始写入 配置文件..."
	write_config
	echo -e "${Info} 所有步骤 安装完毕，开始启动..."
	start
	echo -e "${Info} Shadowsocks Rust 安装完成！"
	
	# 询问是否继续安装 Shadow TLS
	echo && echo -e "${Tip} 是否继续安装 Shadow TLS 流量伪装？"
	read -e -p "(默认: N 不安装) [y/N]: " install_stls_choice
	[[ -z "${install_stls_choice}" ]] && install_stls_choice="n"
	
	if [[ ${install_stls_choice} == [Yy] ]]; then
		echo -e "${Info} 开始安装 Shadow TLS..."
		install_stls_after_ss
	else
		echo -e "${Info} 跳过 Shadow TLS 安装，显示 Shadowsocks Rust 配置..."
		view_ss_only
	fi
}

install_stls(){
	[[ -e ${STLS_File} ]] && echo -e "${Error} 检测到 Shadow TLS 已安装！" && exit 1
	
	# 检查 Shadowsocks Rust 是否已安装
	if [[ ! -e ${SS_File} ]]; then
		echo -e "${Error} 检测到 Shadowsocks Rust 尚未安装！"
		echo -e "${Info} Shadow TLS 需要配合 Shadowsocks Rust 使用。"
		echo -e "${Info} 建议先安装 Shadowsocks Rust，再安装 Shadow TLS。"
		echo && read -e -p "是否现在安装 Shadowsocks Rust？[Y/n]：" install_ss_choice
		[[ -z "${install_ss_choice}" ]] && install_ss_choice="Y"
		if [[ ${install_ss_choice} == [Yy] ]]; then
			echo -e "${Info} 开始安装 Shadowsocks Rust..."
			install
			echo -e "${Info} Shadowsocks Rust 安装完成，现在开始安装 Shadow TLS..."
		else
			echo -e "${Info} 已取消安装，返回上级菜单..."
			shadowtls_menu
			return
		fi
	fi
	
	echo -e "${Info} 开始设置 Shadow TLS 配置..."
	read_config # 读取现有 SS 配置
	
	# 使用交互式配置，每项都有默认值
	echo -e "${Info} 请配置 Shadow TLS 参数（可直接回车使用默认值）："
	
	set_stls_port
	set_stls_password
	set_stls_sni
	set_stls_fastopen
	set_stls_strict
	set_stls_tls_wildcard_sni
	set_stls_fallback
	manage_stls_dispatch
	
	echo -e "${Info} 开始下载/安装 Shadow TLS..."
	check_stls_new_ver
	download_stls
	echo -e "${Info} 开始安装 Shadow TLS 服务脚本..."
	service_stls
	echo -e "${Info} 开始写入 Shadow TLS 配置文件..."
	write_stls_config
	echo -e "${Info} Shadow TLS 安装完毕，开始启动..."
	start_stls
	echo -e "${Info} Shadow TLS 安装完成！显示完整配置信息..."
	view_combined_config_with_return
}

install_stls_after_ss(){
	echo -e "${Info} 开始设置 Shadow TLS 配置..."
	read_config # 读取现有 SS 配置
	
	# 使用交互式配置，每项都有默认值
	echo -e "${Info} 请配置 Shadow TLS 参数（可直接回车使用默认值）："
	
	set_stls_port
	set_stls_password
	set_stls_sni
	set_stls_fastopen
	set_stls_strict
	set_stls_tls_wildcard_sni
	set_stls_fallback
	manage_stls_dispatch
	
	echo -e "${Info} 开始下载/安装 Shadow TLS..."
	check_stls_new_ver
	download_stls
	echo -e "${Info} 开始安装 Shadow TLS 服务脚本..."
	service_stls
	echo -e "${Info} 开始写入 Shadow TLS 配置文件..."
	write_stls_config
	echo -e "${Info} Shadow TLS 安装完毕，开始启动..."
	start_stls
	echo -e "${Info} Shadow TLS 安装完成！显示完整配置信息..."
	view_combined_config_with_return
}

view(){
	check_installed_status
	read_config
	getipv4
	getipv6
	link_qr
	clear && echo
	echo -e "Shadowsocks Rust 配置："
	echo -e "————————————————————————————————————————"
	[[ "${ipv4}" != "IPv4_Error" ]] && echo -e " 地址：${Green_font_prefix}${ipv4}${Font_color_suffix}"
	[[ "${ipv6}" != "IPv6_Error" ]] && echo -e " 地址：${Green_font_prefix}${ipv6}${Font_color_suffix}"
	echo -e " 端口：${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " 密码：${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " 加密：${Green_font_prefix}${cipher}${Font_color_suffix}"
	echo -e " TFO ：${Green_font_prefix}${tfo}${Font_color_suffix}"
	echo -e "————————————————————————————————————————"
	[[ ! -z "${link_ipv4}" ]] && echo -e "${link_ipv4}"
	[[ ! -z "${link_ipv6}" ]] && echo -e "${link_ipv6}"
	echo -e "—————————————————————————"
	echo -e "${Info} Surge 配置："
	if [[ "${ipv4}" != "IPv4_Error" ]]; then
	echo -e "$(uname -n) = ss, ${ipv4},${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true, ecn=true"
	else
	echo -e "$(uname -n) = ss, ${ipv6},${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true, ecn=true"
	fi
	echo -e "—————————————————————————"
	echo && echo -n " 按回车键返回主菜单..." && read
	start_menu
}

view_ss_only(){
	check_installed_status
	read_config
	getipv4
	getipv6
	link_qr
	clear && echo
	echo -e "Shadowsocks Rust 配置："
	echo -e "————————————————————————————————————————"
	[[ "${ipv4}" != "IPv4_Error" ]] && echo -e " 地址：${Green_font_prefix}${ipv4}${Font_color_suffix}"
	[[ "${ipv6}" != "IPv6_Error" ]] && echo -e " 地址：${Green_font_prefix}${ipv6}${Font_color_suffix}"
	echo -e " 端口：${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " 密码：${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " 加密：${Green_font_prefix}${cipher}${Font_color_suffix}"
	echo -e " TFO ：${Green_font_prefix}${tfo}${Font_color_suffix}"
	echo -e "————————————————————————————————————————"
	[[ ! -z "${link_ipv4}" ]] && echo -e "${link_ipv4}"
	[[ ! -z "${link_ipv6}" ]] && echo -e "${link_ipv6}"
	echo -e "—————————————————————————"
	echo -e "${Info} Surge 配置："
	if [[ "${ipv4}" != "IPv4_Error" ]]; then
	echo -e "$(uname -n) = ss, ${ipv4},${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true, ecn=true"
	else
	echo -e "$(uname -n) = ss, ${ipv6},${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true, ecn=true"
	fi
	echo -e "—————————————————————————"
	echo && echo -n " 按回车键返回主菜单..." && read
	start_menu
}

view_combined_config(){
	local menu_source="$1"  # 接收调用来源参数
	check_installed_status
	read_config
	getipv4
	getipv6
	link_qr
	clear && echo
	
	echo -e "完整配置信息："
	echo -e "========================================"
	
	# 显示 Shadow TLS + SS 配置
	if [[ -e ${STLS_File} ]]; then
		read_stls_config
		echo -e "${Info} Shadow TLS + Shadowsocks Rust 配置："
		echo -e "————————————————————————————————————————"
		[[ "${ipv4}" != "IPv4_Error" ]] && echo -e " 服务器：${Green_font_prefix}${ipv4}${Font_color_suffix}"
		[[ "${ipv6}" != "IPv6_Error" ]] && echo -e " 服务器：${Green_font_prefix}${ipv6}${Font_color_suffix}"
		echo -e " Shadow TLS 端口：${Green_font_prefix}${stls_port}${Font_color_suffix}"
		echo -e " Shadow TLS 密码：${Green_font_prefix}${stls_password}${Font_color_suffix}"
		echo -e " Shadow TLS SNI：${Green_font_prefix}${stls_sni}${Font_color_suffix}"
		echo -e " SS 本地端口：${Green_font_prefix}${port}${Font_color_suffix}"
		echo -e " SS 密码：${Green_font_prefix}${password}${Font_color_suffix}"
		echo -e " SS 加密：${Green_font_prefix}${cipher}${Font_color_suffix}"
		echo -e "————————————————————————————————————————"
		echo -e "${Info} Shadow TLS + SS Surge 配置："
		if [[ "${ipv4}" != "IPv4_Error" ]]; then
			echo -e "$(uname -n) = ss, ${ipv4}, ${stls_port}, encrypt-method=${cipher}, password=${password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, tfo=${tfo}, udp-relay=true, ecn=true, udp-port=${port}"
		else
			echo -e "$(uname -n) = ss, ${ipv6}, ${stls_port}, encrypt-method=${cipher}, password=${password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, tfo=${tfo}, udp-relay=true, ecn=true, udp-port=${port}"
		fi
		echo && echo -e "========================================"
	fi
	
	# 显示纯 SS 配置
	echo -e "${Info} 原始 Shadowsocks Rust 配置："
	echo -e "————————————————————————————————————————"
	[[ "${ipv4}" != "IPv4_Error" ]] && echo -e " 地址：${Green_font_prefix}${ipv4}${Font_color_suffix}"
	[[ "${ipv6}" != "IPv6_Error" ]] && echo -e " 地址：${Green_font_prefix}${ipv6}${Font_color_suffix}"
	echo -e " 端口：${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " 密码：${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " 加密：${Green_font_prefix}${cipher}${Font_color_suffix}"
	echo -e "————————————————————————————————————————"
	[[ ! -z "${link_ipv4}" ]] && echo -e "${link_ipv4}"
	[[ ! -z "${link_ipv6}" ]] && echo -e "${link_ipv6}"
	echo -e "—————————————————————————"
	echo -e "${Info} 原始 SS Surge 配置："
	if [[ "${ipv4}" != "IPv4_Error" ]]; then
		echo -e "$(uname -n) = ss, ${ipv4}, ${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true, ecn=true"
	fi
	echo -e "========================================"
	
	# 根据调用来源返回到相应菜单
	if [[ "$menu_source" == "shadowtls" ]]; then
		echo && echo -n " 按回车键返回 Shadow TLS 菜单..." && read
		shadowtls_menu
	else
		echo && echo -n " 按回车键返回主菜单..." && read
		start_menu
	fi
}

view_combined_config_with_return(){
	check_installed_status
	read_config
	getipv4
	getipv6
	link_qr
	clear && echo
	
	echo -e "完整配置信息："
	echo -e "========================================"
	
	# 显示 Shadow TLS + SS 配置
	if [[ -e ${STLS_File} ]]; then
		read_stls_config
		echo -e "${Info} Shadow TLS + Shadowsocks Rust 配置："
		echo -e "————————————————————————————————————————"
		[[ "${ipv4}" != "IPv4_Error" ]] && echo -e " 服务器：${Green_font_prefix}${ipv4}${Font_color_suffix}"
		[[ "${ipv6}" != "IPv6_Error" ]] && echo -e " 服务器：${Green_font_prefix}${ipv6}${Font_color_suffix}"
		echo -e " Shadow TLS 端口：${Green_font_prefix}${stls_port}${Font_color_suffix}"
		echo -e " Shadow TLS 密码：${Green_font_prefix}${stls_password}${Font_color_suffix}"
		echo -e " Shadow TLS SNI：${Green_font_prefix}${stls_sni}${Font_color_suffix}"
		echo -e " SS 本地端口：${Green_font_prefix}${port}${Font_color_suffix}"
		echo -e " SS 密码：${Green_font_prefix}${password}${Font_color_suffix}"
		echo -e " SS 加密：${Green_font_prefix}${cipher}${Font_color_suffix}"
		echo -e "————————————————————————————————————————"
		echo -e "${Info} Shadow TLS + SS Surge 配置："
		if [[ "${ipv4}" != "IPv4_Error" ]]; then
			echo -e "$(uname -n) = ss, ${ipv4}, ${stls_port}, encrypt-method=${cipher}, password=${password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, tfo=${tfo}, ecn=true, udp-relay=true, udp-port=${port}"
		else
			echo -e "$(uname -n) = ss, ${ipv6}, ${stls_port}, encrypt-method=${cipher}, password=${password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${stls_sni}, shadow-tls-version=3, tfo=${tfo}, ecn=true, udp-relay=true, udp-port=${port}"
		fi
		echo && echo -e "========================================"
	fi
	
	# 显示纯 SS 配置
	echo -e "${Info} 原始 Shadowsocks Rust 配置："
	echo -e "————————————————————————————————————————"
	[[ "${ipv4}" != "IPv4_Error" ]] && echo -e " 地址：${Green_font_prefix}${ipv4}${Font_color_suffix}"
	[[ "${ipv6}" != "IPv6_Error" ]] && echo -e " 地址：${Green_font_prefix}${ipv6}${Font_color_suffix}"
	echo -e " 端口：${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " 密码：${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " 加密：${Green_font_prefix}${cipher}${Font_color_suffix}"
	echo -e "————————————————————————————————————————"
	[[ ! -z "${link_ipv4}" ]] && echo -e "${link_ipv4}"
	[[ ! -z "${link_ipv6}" ]] && echo -e "${link_ipv6}"
	echo -e "—————————————————————————"
	echo -e "${Info} SS Surge 配置："
	if [[ "${ipv4}" != "IPv4_Error" ]]; then
		echo -e "$(uname -n) = ss, ${ipv4}, ${port}, encrypt-method=${cipher}, password=${password}, tfo=${tfo}, udp-relay=true, ecn=true"
	fi
	echo -e "========================================"
	echo && echo -n " 按回车键继续..." && read
}

# 综合 Shadow TLS 配置函数
set_stls_config(){
	check_stls_installed_status
	read_config
	read_stls_config
	
	echo && echo -e "你要修改哪项 Shadow TLS 配置？
========================================
 ${Green_font_prefix}1.${Font_color_suffix}  修改 端口配置
 ${Green_font_prefix}2.${Font_color_suffix}  修改 密码配置
 ${Green_font_prefix}3.${Font_color_suffix}  修改 Shadow TLS SNI 域名
 ${Green_font_prefix}4.${Font_color_suffix}  修改 FastOpen 配置
 ${Green_font_prefix}5.${Font_color_suffix}  修改 Strict 模式配置
 ${Green_font_prefix}6.${Font_color_suffix}  修改 TLS Wildcard SNI 配置
 ${Green_font_prefix}7.${Font_color_suffix}  修改 回退域名配置
 ${Green_font_prefix}8.${Font_color_suffix}  管理 Dispatch 分发配置
========================================
 ${Green_font_prefix}9.${Font_color_suffix}  修改 全部配置" && echo
	read -e -p "(默认：取消)：" modify
	[[ -z "${modify}" ]] && echo "已取消..." && return
	
	case "${modify}" in
		1)
			set_stls_port
			write_stls_config
			restart_stls
			;;
		2)
			set_stls_password
			write_stls_config
			restart_stls
			;;
		3)
			set_stls_sni
			write_stls_config
			restart_stls
			;;
		4)
			set_stls_fastopen
			write_stls_config
			restart_stls
			;;
		5)
			set_stls_strict
			write_stls_config
			restart_stls
			;;
		6)
			set_stls_tls_wildcard_sni
			write_stls_config
			restart_stls
			;;
		7)
			set_stls_fallback
			write_stls_config
			restart_stls
			;;
		8)
			manage_stls_dispatch
			if [[ ! -z "${stls_dispatch}" ]]; then
				write_stls_config
				restart_stls
			fi
			;;
		9)
			set_stls_port
			set_stls_password
			set_stls_sni
			set_stls_fastopen
			set_stls_strict
			set_stls_tls_wildcard_sni
			set_stls_fallback
			manage_stls_dispatch
			write_stls_config
			restart_stls
			;;
		*)
			echo -e "${Error} 请输入正确的数字(1-9)"
			set_stls_config
			;;
	esac
}

# Dispatch 管理的简化版本
manage_stls_dispatch(){
	echo -e "${Info} 当前 dispatch 配置："
	if [[ -e ${STLS_Conf} ]]; then
		echo -e "${Green_font_prefix}$(cat ${STLS_Conf}|jq -r '.server.tls_addr.dispatch | to_entries | map("  \(.key) -> \(.value)") | join("\n")')${Font_color_suffix}"
	else
		echo -e "  ${stls_sni} -> 1.1.1.1:443"
		echo -e "  captive.apple.com -> captive.apple.com:443"
	fi
	
	echo && echo -e "是否需要修改 dispatch 配置？
========================================
${Green_font_prefix} 1.${Font_color_suffix} 使用默认配置（推荐）
${Green_font_prefix} 2.${Font_color_suffix} 自定义配置所有条目
========================================"
	read -e -p "(默认：1.使用默认)：" dispatch_choice
	[[ -z "${dispatch_choice}" ]] && dispatch_choice="1"
	
	if [[ "${dispatch_choice}" == "1" ]]; then
		# 使用默认配置，确保使用当前设置的 SNI
		echo -e "${Info} 使用默认 dispatch 配置，SNI: ${stls_sni}"
		# 不设置 stls_dispatch，让 write_stls_config 使用默认逻辑
		stls_dispatch=""
	elif [[ "${dispatch_choice}" == "2" ]]; then
		echo -e "${Info} 重新配置 dispatch 条目"
		echo "请输入 dispatch 配置 (每行格式: 域名:目标地址，回车结束)："
		echo "示例: cloudflare.com:1.1.1.1:443"
		
		local dispatch_entries=""
		local line_count=0
		while true; do
			read -e -p "条目 $((line_count+1)) (直接回车结束)：" dispatch_entry
			if [[ -z "${dispatch_entry}" ]]; then
				break
			fi
			
			if [[ "${dispatch_entry}" =~ ^([^:]+):(.+)$ ]]; then
				local sni="${BASH_REMATCH[1]}"
				local target="${BASH_REMATCH[2]}"
				
				if [[ ${line_count} -gt 0 ]]; then
					dispatch_entries="${dispatch_entries},
        "
				fi
				dispatch_entries="${dispatch_entries}\"${sni}\": \"${target}\""
				line_count=$((line_count+1))
			else
				echo -e "${Error} 格式错误，请使用格式: 域名:目标地址"
			fi
		done
		
		if [[ ${line_count} -gt 0 ]]; then
			stls_dispatch="${dispatch_entries}"
			echo -e "${Info} 已配置 ${line_count} 个 dispatch 条目"
		else
			echo -e "${Info} 没有输入条目，使用默认 dispatch 配置"
			# 不设置 stls_dispatch，让 write_stls_config 使用默认逻辑
			stls_dispatch=""
		fi
	fi
}

# 增强版 Dispatch 管理（支持单条增删改）
manage_stls_dispatch_advanced(){
	echo -e "${Info} 当前 dispatch 配置："
	if [[ -e ${STLS_Conf} ]]; then
		echo -e "${Green_font_prefix}$(cat ${STLS_Conf}|jq -r '.server.tls_addr.dispatch | to_entries | map("  \(.key) -> \(.value)") | join("\n")')${Font_color_suffix}"
	else
		echo -e "  ${stls_sni} -> 1.1.1.1:443"
		echo -e "  captive.apple.com -> captive.apple.com:443"
	fi
	
	echo && echo -e "请选择 dispatch 管理操作：
========================================
${Green_font_prefix} 1.${Font_color_suffix} 保持当前配置
${Green_font_prefix} 2.${Font_color_suffix} 添加新条目
${Green_font_prefix} 3.${Font_color_suffix} 删除指定条目
${Green_font_prefix} 4.${Font_color_suffix} 修改指定条目
${Green_font_prefix} 5.${Font_color_suffix} 重新配置所有条目
========================================"
	read -e -p "(默认：1.保持当前)：" dispatch_choice
	[[ -z "${dispatch_choice}" ]] && dispatch_choice="1"
	
	case "${dispatch_choice}" in
		1)
			echo -e "${Info} 保持当前配置"
			;;
		2)
			add_dispatch_entry
			;;
		3)
			delete_dispatch_entry
			;;
		4)
			modify_dispatch_entry
			;;
		5)
			reconfigure_all_dispatch
			;;
		*)
			echo -e "${Error} 输入错误，保持当前配置"
			;;
	esac
}

# 添加 dispatch 条目
add_dispatch_entry(){
	echo -e "${Info} 添加新的 dispatch 条目"
	read -e -p "请输入域名 (如: example.com)：" new_sni
	if [[ -z "${new_sni}" ]]; then
		echo -e "${Error} 域名不能为空"
		return
	fi
	
	read -e -p "请输入目标地址 (如: 1.1.1.1:443)：" new_target
	if [[ -z "${new_target}" ]]; then
		echo -e "${Error} 目标地址不能为空"
		return
	fi
	
	# 获取当前 dispatch 配置
	if [[ -e ${STLS_Conf} ]]; then
		current_dispatch=$(cat ${STLS_Conf}|jq -r '.server.tls_addr.dispatch | to_entries | map("\"\(.key)\": \"\(.value)\"") | join(",\n        ")')
		stls_dispatch="${current_dispatch},
        \"${new_sni}\": \"${new_target}\""
	else
		stls_dispatch="\"${stls_sni}\": \"1.1.1.1:443\",
        \"captive.apple.com\": \"captive.apple.com:443\",
        \"${new_sni}\": \"${new_target}\""
	fi
	
	echo -e "${Info} 已添加条目: ${new_sni} -> ${new_target}"
}

# 删除 dispatch 条目
delete_dispatch_entry(){
	if [[ ! -e ${STLS_Conf} ]]; then
		echo -e "${Error} 配置文件不存在"
		return
	fi
	
	echo -e "${Info} 当前 dispatch 条目："
	# 显示带编号的列表
	local domains=($(cat ${STLS_Conf}|jq -r '.server.tls_addr.dispatch | keys[]'))
	local targets=($(cat ${STLS_Conf}|jq -r '.server.tls_addr.dispatch | to_entries | map(.value) | .[]'))
	
	if [[ ${#domains[@]} -eq 0 ]]; then
		echo -e "${Error} 没有可删除的条目"
		return
	fi
	
	for i in "${!domains[@]}"; do
		echo -e " ${Green_font_prefix}$((i+1)).${Font_color_suffix} ${domains[i]} -> ${targets[i]}"
	done
	
	read -e -p "请输入要删除的条目编号 (1-${#domains[@]})：" del_num
	if [[ -z "${del_num}" ]] || [[ ${del_num} -lt 1 ]] || [[ ${del_num} -gt ${#domains[@]} ]]; then
		echo -e "${Error} 输入的编号无效"
		return
	fi
	
	# 重新构建 dispatch 配置，排除删除的条目
	local del_domain="${domains[$((del_num-1))]}"
	local new_entries=""
	local count=0
	
	for i in "${!domains[@]}"; do
		if [[ "${domains[i]}" != "${del_domain}" ]]; then
			if [[ ${count} -gt 0 ]]; then
				new_entries="${new_entries},
        "
			fi
			new_entries="${new_entries}\"${domains[i]}\": \"${targets[i]}\""
			count=$((count+1))
		fi
	done
	
	if [[ ${count} -eq 0 ]]; then
		# 如果删除后没有条目，使用默认配置
		stls_dispatch="\"${stls_sni}\": \"1.1.1.1:443\",
        \"captive.apple.com\": \"captive.apple.com:443\""
	else
		stls_dispatch="${new_entries}"
	fi
	
	echo -e "${Info} 已删除条目: ${del_domain}"
}

# 修改 dispatch 条目
modify_dispatch_entry(){
	if [[ ! -e ${STLS_Conf} ]]; then
		echo -e "${Error} 配置文件不存在"
		return
	fi
	
	echo -e "${Info} 当前 dispatch 条目："
	# 显示带编号的列表
	local domains=($(cat ${STLS_Conf}|jq -r '.server.tls_addr.dispatch | keys[]'))
	local targets=($(cat ${STLS_Conf}|jq -r '.server.tls_addr.dispatch | to_entries | map(.value) | .[]'))
	
	if [[ ${#domains[@]} -eq 0 ]]; then
		echo -e "${Error} 没有可修改的条目"
		return
	fi
	
	for i in "${!domains[@]}"; do
		echo -e " ${Green_font_prefix}$((i+1)).${Font_color_suffix} ${domains[i]} -> ${targets[i]}"
	done
	
	read -e -p "请输入要修改的条目编号 (1-${#domains[@]})：" mod_num
	if [[ -z "${mod_num}" ]] || [[ ${mod_num} -lt 1 ]] || [[ ${mod_num} -gt ${#domains[@]} ]]; then
		echo -e "${Error} 输入的编号无效"
		return
	fi
	
	local mod_domain="${domains[$((mod_num-1))]}"
	local mod_target="${targets[$((mod_num-1))]}"
	
	echo -e "${Info} 当前条目: ${mod_domain} -> ${mod_target}"
	read -e -p "请输入新的域名 (直接回车保持不变)：" new_domain
	read -e -p "请输入新的目标地址 (直接回车保持不变)：" new_target
	
	[[ -z "${new_domain}" ]] && new_domain="${mod_domain}"
	[[ -z "${new_target}" ]] && new_target="${mod_target}"
	
	# 重新构建 dispatch 配置
	local new_entries=""
	for i in "${!domains[@]}"; do
		if [[ ${i} -gt 0 ]]; then
			new_entries="${new_entries},
        "
		fi
		
		if [[ ${i} -eq $((mod_num-1)) ]]; then
			new_entries="${new_entries}\"${new_domain}\": \"${new_target}\""
		else
			new_entries="${new_entries}\"${domains[i]}\": \"${targets[i]}\""
		fi
	done
	
	stls_dispatch="${new_entries}"
	echo -e "${Info} 已修改条目: ${mod_domain} -> ${mod_target} => ${new_domain} -> ${new_target}"
}

# 重新配置所有 dispatch 条目
reconfigure_all_dispatch(){
	echo -e "${Info} 重新配置所有 dispatch 条目"
	echo "请输入 dispatch 配置 (每行格式: 域名:目标地址，回车结束)："
	echo "示例: cloudflare.com:1.1.1.1:443"
	
	local dispatch_entries=""
	local line_count=0
	while true; do
		read -e -p "条目 $((line_count+1)) (直接回车结束)：" dispatch_entry
		if [[ -z "${dispatch_entry}" ]]; then
			break
		fi
		
		if [[ "${dispatch_entry}" =~ ^([^:]+):(.+)$ ]]; then
			local sni="${BASH_REMATCH[1]}"
			local target="${BASH_REMATCH[2]}"
			
			if [[ ${line_count} -gt 0 ]]; then
				dispatch_entries="${dispatch_entries},
        "
			fi
			dispatch_entries="${dispatch_entries}\"${sni}\": \"${target}\""
			line_count=$((line_count+1))
		else
			echo -e "${Error} 格式错误，请使用格式: 域名:目标地址"
		fi
	done
	
	if [[ ${line_count} -gt 0 ]]; then
		stls_dispatch="${dispatch_entries}"
		echo -e "${Info} 已配置 ${line_count} 个 dispatch 条目"
	else
		echo -e "${Info} 使用默认 dispatch 配置"
		stls_dispatch="\"${stls_sni}\": \"1.1.1.1:443\",
        \"captive.apple.com\": \"captive.apple.com:443\""
	fi
}

start(){
    check_installed_status
    check_status
    if [[ "$status" == "running" ]]; then
        echo -e "${Info} Shadowsocks Rust 已在运行！"
    else
        systemctl start ss-rust
        check_status
        if [[ "$status" == "running" ]]; then
            echo -e "${Info} Shadowsocks Rust 启动成功！"
        else
            echo -e "${Error} Shadowsocks Rust 启动失败！"
            exit 1
        fi
    fi
    sleep 3s
}

start_stls(){
	check_stls_installed_status
	check_stls_status
	if [[ "$stls_status" == "running" ]]; then
		echo -e "${Info} Shadow TLS 已在运行！"
	else
		systemctl start shadowtls
		check_stls_status
		if [[ "$stls_status" == "running" ]]; then
			echo -e "${Info} Shadow TLS 启动成功！"
		else
			echo -e "${Error} Shadow TLS 启动失败！"
			exit 1
		fi
	fi
	sleep 3s
}

stop(){
	check_installed_status
	check_status
	[[ !"$status" == "running" ]] && echo -e "${Error} Shadowsocks Rust 没有运行，请检查！" && exit 1
	systemctl stop ss-rust
    sleep 3s
    start_menu
}

stop_stls(){
	check_stls_installed_status
	check_stls_status
	[[ !"$stls_status" == "running" ]] && echo -e "${Error} Shadow TLS 没有运行，请检查！" && exit 1
	systemctl stop shadowtls
	sleep 3s
}

restart(){
	check_installed_status
	systemctl restart ss-rust
	echo -e "${Info} Shadowsocks Rust 重启完毕 ！"
	sleep 3s
    start_menu
}

restart_stls(){
	check_stls_installed_status
	systemctl restart shadowtls
	echo -e "${Info} Shadow TLS 重启完毕 ！"
	sleep 3s
}

update(){
	check_installed_status
	check_new_ver
	check_ver_comparison
	echo -e "${Info} Shadowsocks Rust 更新完毕！"
    sleep 3s
    start_menu
}

update_stls(){
	check_stls_installed_status
	check_stls_new_ver
	check_stls_ver_comparison
	echo -e "${Info} Shadow TLS 更新完毕！"
	sleep 3s
}

# 脚本更新函数
update_sh(){
	echo -e "当前版本为 [ ${sh_ver} ]，开始检测最新版本..."
	sh_new_ver=$(wget --no-check-certificate -qO- "https://raw.githubusercontent.com/xOS/Shadowsocks-Rust/master/ss-rust.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} 检测最新版本失败 !" && start_menu
	if [[ ${sh_new_ver} != ${sh_ver} ]]; then
		echo -e "发现新版本[ ${sh_new_ver} ]，是否更新？[Y/n]"
		read -p "(默认：y)：" yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ ${yn} == [Yy] ]]; then
			wget -O ss-rust.sh --no-check-certificate https://raw.githubusercontent.com/xOS/Shadowsocks-Rust/master/ss-rust.sh && chmod +x ss-rust.sh
			echo -e "脚本已更新为最新版本[ ${sh_new_ver} ]！"
			echo -e "3s后执行新脚本"
			sleep 3s
			bash ss-rust.sh
		else
			echo && echo "	已取消..." && echo
			sleep 3s
			start_menu
		fi
	else
		echo -e "当前已是最新版本[ ${sh_new_ver} ] ！"
		sleep 3s
		start_menu
	fi
	sleep 3s
	bash ss-rust.sh
}

uninstall(){
	check_installed_status
	echo "确定要卸载 Shadowsocks Rust ? (y/N)"
	echo
	read -e -p "(默认：n)：" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_status
		[[ "$status" == "running" ]] && systemctl stop ss-rust
        systemctl disable ss-rust
		rm -rf "${SS_Folder}"
		rm -rf "${SS_File}"
		echo && echo "Shadowsocks Rust 卸载完成！" && echo
	else
		echo && echo "卸载已取消..." && echo
	fi
    sleep 3s
    start_menu
}

uninstall_stls(){
	check_stls_installed_status
	echo "确定要卸载 Shadow TLS ? (y/N)"
	echo
	read -e -p "(默认：n)：" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_stls_status
		[[ "$stls_status" == "running" ]] && systemctl stop shadowtls
		systemctl disable shadowtls
		rm -rf "${STLS_Folder}"
		rm -rf "${STLS_File}"
		rm -f "/etc/systemd/system/shadowtls.service"
		systemctl daemon-reload
		echo && echo "Shadow TLS 卸载完成！" && echo
	else
		echo && echo "卸载已取消..." && echo
	fi
	sleep 3s
}

getipv4(){
	ipv4=$(wget -qO- -4 -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ipv4}" ]]; then
		ipv4=$(wget -qO- -4 -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ipv4}" ]]; then
			ipv4=$(wget -qO- -4 -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ipv4}" ]]; then
				ipv4="IPv4_Error"
			fi
		fi
	fi
}

getipv6(){
	ipv6=$(wget -qO- -6 -t1 -T2 ifconfig.co)
	if [[ -z "${ipv6}" ]]; then
		ipv6="IPv6_Error"
	fi
}

urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}

link_qr(){
	if [[ "${ipv4}" != "IPv4_Error" ]]; then
		SSbase64=$(urlsafe_base64 "${cipher}:${password}@${ipv4}:${port}")
		SSurl="ss://${SSbase64}"
		SSQRcode="https://cli.im/api/qrcode/code?text=${SSurl}"
		link_ipv4=" 链接  [IPv4]：${Red_font_prefix}${SSurl}${Font_color_suffix} \n 二维码[IPv4]：${Red_font_prefix}${SSQRcode}${Font_color_suffix}"
	fi
	if [[ "${ipv6}" != "IPv6_Error" ]]; then
		SSbase64=$(urlsafe_base64 "${cipher}:${password}@${ipv6}:${port}")
		SSurl="ss://${SSbase64}"
		SSQRcode="https://cli.im/api/qrcode/code?text=${SSurl}"
		link_ipv6=" 链接  [IPv6]：${Red_font_prefix}${SSurl}${Font_color_suffix} \n 二维码[IPv6]：${Red_font_prefix}${SSQRcode}${Font_color_suffix}"
	fi
}

before_start_menu(){
	echo && echo -n " 任意键继续..." && read
	start_menu
}

before_shadowtls_menu(){
	echo && echo -n " 任意键继续..." && read
	shadowtls_menu
}

# Shadow TLS 状态和版本检查函数
check_stls_installed_status(){
	[[ ! -e ${STLS_File} ]] && echo -e "${Error} Shadow TLS 没有安装，请检查！" && exit 1
}

check_stls_status(){
	stls_status=`systemctl status shadowtls | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1`
}

check_stls_new_ver(){
	stls_new_ver=$(wget -qO- https://api.github.com/repos/ihciah/shadow-tls/releases| jq -r '[.[] | select(.prerelease == false) | select(.draft == false) | .tag_name] | .[0]')
	[[ -z ${stls_new_ver} ]] && echo -e "${Error} Shadow TLS 最新版本获取失败！" && exit 1
	echo -e "${Info} 检测到 Shadow TLS 最新版本为 [ ${stls_new_ver} ]"
}

check_stls_ver_comparison(){
	stls_now_ver=$(cat ${STLS_Now_ver_File})
	if [[ "${stls_now_ver}" != "${stls_new_ver}" ]]; then
		echo -e "${Info} 发现 Shadow TLS 已有新版本 [ ${stls_new_ver} ]，旧版本 [ ${stls_now_ver} ]"
		read -e -p "是否更新 ？ [Y/n]：" yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ $yn == [Yy] ]]; then
			check_stls_status
			\cp "${STLS_Conf}" "/tmp/stls_config.json"
			download_stls
			mv -f "/tmp/stls_config.json" "${STLS_Conf}"
			restart_stls
		fi
	else
		echo -e "${Info} 当前 Shadow TLS 已是最新版本 [ ${stls_new_ver} ] ！" && exit 1
	fi
}

# Shadow TLS 专用菜单
shadowtls_menu(){
	check_root
	check_sys
	sys_arch
	
	# 检查 Shadow TLS 安装状态
	if [[ -e ${STLS_File} ]]; then
		check_stls_status
		if [[ "$stls_status" == "running" ]]; then
			stls_status_show="${Green_font_prefix}已安装${Font_color_suffix} 且 ${Green_font_prefix}运行中${Font_color_suffix}"
		else
			stls_status_show="${Green_font_prefix}已安装${Font_color_suffix} 但 ${Yellow_font_prefix}未运行${Font_color_suffix}"
		fi
	else
		stls_status_show="${Red_font_prefix}未安装${Font_color_suffix}"
	fi
	
	clear
	echo -e "Shadow TLS 管理菜单 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  
==================状态==================
 Shadow TLS        : [${stls_status_show}]
========================================
 ${Green_font_prefix}0.${Font_color_suffix}  更新脚本
==================菜单==================
 ${Green_font_prefix}1.${Font_color_suffix}  安装 Shadow TLS
 ${Green_font_prefix}2.${Font_color_suffix}  更新 Shadow TLS
 ${Green_font_prefix}3.${Font_color_suffix}  卸载 Shadow TLS
————————————————————————————————————————
 ${Green_font_prefix}4.${Font_color_suffix}  启动 Shadow TLS
 ${Green_font_prefix}5.${Font_color_suffix}  停止 Shadow TLS
 ${Green_font_prefix}6.${Font_color_suffix}  重启 Shadow TLS
————————————————————————————————————————
 ${Green_font_prefix}7.${Font_color_suffix}  修改 Shadow TLS 配置
 ${Green_font_prefix}8.${Font_color_suffix}  查看 Shadow TLS 配置
 ${Green_font_prefix}9.${Font_color_suffix}  查看 Shadow TLS 状态
————————————————————————————————————————
 ${Green_font_prefix}10.${Font_color_suffix} 查看完整配置信息
 ${Green_font_prefix}11.${Font_color_suffix} 返回主菜单
————————————————————————————————————————
 ${Green_font_prefix}00.${Font_color_suffix} 退出脚本
========================================" && echo

	read -e -p " 请输入数字 [0-11]：" stls_num
	case "$stls_num" in
		1)
			install_stls
			shadowtls_menu
			;;
		2)
			update_stls
			shadowtls_menu
			;;
		3)
			uninstall_stls
			shadowtls_menu
			;;
		4)
			start_stls
			shadowtls_menu
			;;
		5)
			stop_stls
			shadowtls_menu
			;;
		6)
			restart_stls
			shadowtls_menu
			;;
		7)
			set_stls_config
			shadowtls_menu
			;;
		8)
			view_stls_only
			;;
		9)
			view_stls_status
			;;
		10)
			view_combined_config shadowtls
			;;
		11)
			start_menu
			;;
		0)
			update_sh
			;;
		00)
			exit 1
			;;
		*)
			echo -e "${Error} 请输入正确数字 [0-11] (退出输入00)"
			sleep 5s
			shadowtls_menu
			;;
	esac
}

# 查看 Shadowsocks Rust 状态函数
view_ss_status(){
	check_installed_status
	
	echo -e "${Info} 正在获取 Shadowsocks Rust 状态信息..."
	echo
	echo "=================================="
	echo -e " Shadowsocks Rust 服务状态"
	echo "=================================="
	
	systemctl status ss-rust
	
	echo "=================================="
	echo
	read -e -p "按回车键返回主菜单..." 
	start_menu
}

# 查看 Shadow TLS 状态函数  
view_stls_status(){
	check_stls_installed_status
	
	echo -e "${Info} 正在获取 Shadow TLS 状态信息..."
	echo
	echo "=================================="
	echo -e " Shadow TLS 服务状态"
	echo "=================================="
	
	systemctl status shadowtls
	
	echo "=================================="
	echo
	read -e -p "按回车键返回 Shadow TLS 菜单..." 
	shadowtls_menu
}

# 查看 Shadow TLS 配置函数
view_stls_only(){
	check_stls_installed_status
	echo -e "${Info} 正在获取 Shadow TLS 配置信息..."
	echo
	echo "=================================="
	echo -e " Shadow TLS 配置信息"  
	echo "=================================="
	
	if [[ -f "$STLS_Conf" ]]; then
		cat "$STLS_Conf"
	else
		echo -e "${Error} Shadow TLS 配置文件不存在！"
	fi
	
	echo "=================================="
	echo
	read -e -p "按回车键返回 Shadow TLS 菜单..." 
	shadowtls_menu
}

# 主菜单函数
start_menu(){
	echo -e "${Info} 正在启动 Shadowsocks Rust 管理脚本..."
	check_root
	echo -e "${Info} 权限检查完成，正在检测系统..."
	check_sys
	echo -e "${Info} 系统检测完成，正在检测架构..."
	sys_arch
	echo -e "${Info} 架构检测完成，正在检查服务状态..."
	
	# 检查安装状态
	if [[ -e ${SS_File} ]]; then
		check_status
		if [[ "$status" == "running" ]]; then
			ss_status_show="${Green_font_prefix}已安装${Font_color_suffix} 且 ${Green_font_prefix}运行中${Font_color_suffix}"
		else
			ss_status_show="${Green_font_prefix}已安装${Font_color_suffix} 但 ${Yellow_font_prefix}未运行${Font_color_suffix}"
		fi
	else
		ss_status_show="${Red_font_prefix}未安装${Font_color_suffix}"
	fi
	
	# 检查 Shadow TLS 安装状态
	if [[ -e ${STLS_File} ]]; then
		check_stls_status
		if [[ "$stls_status" == "running" ]]; then
			stls_status_show="${Green_font_prefix}已安装${Font_color_suffix} 且 ${Green_font_prefix}运行中${Font_color_suffix}"
		else
			stls_status_show="${Green_font_prefix}已安装${Font_color_suffix} 但 ${Yellow_font_prefix}未运行${Font_color_suffix}"
		fi
	else
		stls_status_show="${Red_font_prefix}未安装${Font_color_suffix}"
	fi
	
	clear
	echo -e "Shadowsocks Rust 管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  
==================状态==================
 Shadowsocks Rust  : [${ss_status_show}]
 Shadow TLS        : [${stls_status_show}]
========================================
 ${Green_font_prefix}0.${Font_color_suffix}  更新脚本
==================菜单==================
 ${Green_font_prefix}1.${Font_color_suffix}  安装 Shadowsocks Rust
 ${Green_font_prefix}2.${Font_color_suffix}  更新 Shadowsocks Rust
 ${Green_font_prefix}3.${Font_color_suffix}  卸载 Shadowsocks Rust
————————————————————————————————————————
 ${Green_font_prefix}4.${Font_color_suffix}  启动 Shadowsocks Rust
 ${Green_font_prefix}5.${Font_color_suffix}  停止 Shadowsocks Rust
 ${Green_font_prefix}6.${Font_color_suffix}  重启 Shadowsocks Rust
————————————————————————————————————————
 ${Green_font_prefix}7.${Font_color_suffix}  配置 Shadowsocks Rust 相关
 ${Green_font_prefix}8.${Font_color_suffix}  查看 Shadowsocks Rust 配置
 ${Green_font_prefix}9.${Font_color_suffix}  查看 Shadowsocks Rust 状态
========================================
 ${Green_font_prefix}10.${Font_color_suffix} 配置 Shadow TLS 相关
 ${Green_font_prefix}11.${Font_color_suffix} 查看完整配置信息
————————————————————————————————————————
 ${Green_font_prefix}00.${Font_color_suffix} 退出脚本
========================================" && echo
	read -e -p " 请输入数字 [0-11]：" num
	case "$num" in
		1)
			install
			;;
		2)
			update
			start_menu
			;;
		3)
			uninstall
			start_menu
			;;
		4)
			start
			start_menu
			;;
		5)
			stop
			start_menu
			;;
		6)
			restart
			start_menu
			;;
		7)
			set_config
			;;
		8)
			view
			;;
		9)
			view_ss_status
			;;
		10)
			shadowtls_menu
			;;
		11)
			view_combined_config
			;;
		0)
			update_sh
			;;
		00)
			exit 1
			;;
		*)
			echo -e "${Error} 请输入正确数字 [0-11] (退出输入00)"
			sleep 5s
			start_menu
			;;
	esac
}

# 脚本执行入口
start_menu
