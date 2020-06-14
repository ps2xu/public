#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
stty erase ^H

#版本
sh_ver="7.4.6"
github="https://raw.githubusercontent.com/AmuyangA/public/master"

#颜色信息
green_font(){
	echo -e "\033[32m\033[01m$1\033[0m\033[37m\033[01m$2\033[0m"
}
red_font(){
	echo -e "\033[31m\033[01m$1\033[0m"
}
white_font(){
	echo -e "\033[37m\033[01m$1\033[0m"
}
yello_font(){
	echo -e "\033[33m\033[01m$1\033[0m"
}
Info=`green_font [信息]` && Error=`red_font [错误]` && Tip=`yello_font [注意]`

#check root
[ $(id -u) != '0' ] && { echo -e "${Error}您必须以root用户运行此脚本"; exit 1; }

#系统检测
check_sys(){
	#检查系统
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
	#检查版本
	if [[ -s /etc/redhat-release ]]; then
		version=`grep -oE  "[0-9.]+" /etc/redhat-release | cut -d . -f 1`
	else
		version=`grep -oE  "[0-9.]+" /etc/issue | cut -d . -f 1`
	fi
	#检查系统安装命令
	if [[ ${release} == "centos" ]]; then
		PM='yum'
	else
		PM='apt'
	fi
	bit=`uname -m`
	myinfo="我们爱中国"
}

#获取IP
get_ip(){
	IP=$(curl -s ipinfo.io/ip)
	[ -z ${IP} ] && IP=$(curl -s http://api.ipify.org)
	[ -z ${IP} ] && IP=$(curl -s ipv4.icanhazip.com)
	[ -z ${IP} ] && IP=$(curl -s ipv6.icanhazip.com)
	[ ! -z ${IP} ] && echo ${IP} || echo
}
get_char(){
	SAVEDSTTY=`stty -g`
	stty -echo
	stty cbreak
	dd if=/dev/tty bs=1 count=1 2> /dev/null
	stty -raw
	stty echo
	stty $SAVEDSTTY
}

#防火墙配置
firewall_restart(){
	if [[ ${release} == 'centos' ]]; then
		if [[ ${version} -ge '7' ]]; then
			firewall-cmd --reload
		else
			service iptables save
			if [ -e /root/test/ipv6 ]; then
				service ip6tables save
			fi
		fi
	else
		iptables-save > /etc/iptables.up.rules
		if [ -e /root/test/ipv6 ]; then
			ip6tables-save > /etc/ip6tables.up.rules
		fi
	fi
	echo -e "${Info}防火墙设置完成！"
}
add_firewall(){
	if [[ ${release} == 'centos' &&  ${version} -ge '7' ]]; then
		if [[ -z $(firewall-cmd --zone=public --list-ports |grep -w ${port}/tcp) ]]; then
			firewall-cmd --zone=public --add-port=${port}/tcp --add-port=${port}/udp --permanent >/dev/null 2>&1
		fi
	else
		if [[ -z $(iptables -nvL INPUT |grep :|awk -F ':' '{print $2}' |grep -w ${port}) ]]; then
			iptables -I INPUT -p tcp --dport ${port} -j ACCEPT
			iptables -I INPUT -p udp --dport ${port} -j ACCEPT
			iptables -I OUTPUT -p tcp --sport ${port} -j ACCEPT
			iptables -I OUTPUT -p udp --sport ${port} -j ACCEPT
			if [ -e /root/test/ipv6 ]; then
				ip6tables -I INPUT -p tcp --dport ${port} -j ACCEPT
				ip6tables -I INPUT -p udp --dport ${port} -j ACCEPT
				ip6tables -I OUTPUT -p tcp --sport ${port} -j ACCEPT
				ip6tables -I OUTPUT -p udp --sport ${port} -j ACCEPT
			fi
		fi
	fi
}
add_firewall_base(){
	ssh_port=$(cat /etc/ssh/sshd_config |grep 'Port ' |awk -F ' ' '{print $2}')
	if [[ ${release} == 'centos' &&  ${version} -ge '7' ]]; then
		if [[ -z $(firewall-cmd --zone=public --list-ports |grep -w ${ssh_port}/tcp) ]]; then
			firewall-cmd --zone=public --add-port=${ssh_port}/tcp --add-port=${ssh_port}/udp --permanent >/dev/null 2>&1
		fi
	else
		iptables_base(){
			$1 -A INPUT -p icmp --icmp-type any -j ACCEPT
			$1 -A INPUT -s localhost -d localhost -j ACCEPT
			$1 -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
			$1 -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
			$1 -P INPUT DROP
			$1 -I INPUT -p tcp --dport ${ssh_port} -j ACCEPT
			$1 -I INPUT -p udp --dport ${ssh_port} -j ACCEPT
		}
		iptables_base iptables
		if [ -e /root/test/ipv6 ]; then
			iptables_base ip6tables
		fi
	fi
}
delete_firewall(){
	if [[ ${release} == 'centos' &&  ${version} -ge '7' ]]; then
		if [[ -n $(firewall-cmd --zone=public --list-ports |grep -w ${port}/tcp) ]]; then
			firewall-cmd --zone=public --remove-port=${port}/tcp --remove-port=${port}/udp --permanent >/dev/null 2>&1
		fi
	else
		if [[ -n $(iptables -nvL INPUT |grep :|awk -F ':' '{print $2}' |grep -w ${port}) ]]; then
			clean_iptables(){
				TYPE=$1
				LINE_ARRAY=($(iptables -nvL $TYPE --line-number|grep :|grep -w ${port}|awk -F ':' '{print $2"  " $1}'|awk '{print $2" "$1}'|awk -F ' ' '{print $1}'))
				length=${#LINE_ARRAY[@]}
				for(( i = 0; i < ${length}; i++ ))
				do
					LINE_ARRAY[$i]=$[${LINE_ARRAY[$i]}-$i]
					iptables -D $TYPE ${LINE_ARRAY[$i]}
				done
			}
			clean_iptables INPUT
			clean_iptables OUTPUT
			if [ -e /root/test/ipv6 ]; then
				clean_ip6tables(){
					TYPE=$1
					LINE_ARRAY=($(ip6tables -nvL $TYPE --line-number|grep :|grep -w ${port}|awk '{printf "%s %s\n",$1,$NF}'|awk -F ' ' '{print $1}'))
					length=${#LINE_ARRAY[@]}
					for(( i = 0; i < ${length}; i++ ))
					do
						LINE_ARRAY[$i]=$[${LINE_ARRAY[$i]}-$i]
						ip6tables -D $TYPE ${LINE_ARRAY[$i]}
					done
				}
				clean_ip6tables INPUT
				clean_ip6tables OUTPUT
			fi
		fi
	fi
}

#赞赏作者
donation_developer(){
	clear
	yello_font "\n您的支持是作者更新和完善脚本的动力！"
	yello_font '请访问以下网址扫码捐赠：'
	green_font "\n[支付宝] \c" && white_font "${github}/donation/alipay.jpg"
	green_font "[微信]   \c" && white_font "${github}/donation/wechat.png"
	green_font "[银联]   \c" && white_font "${github}/donation/unionpay.png"
	green_font "[QQ]     \c" && white_font "${github}/donation/qq.png"
	echo -e "\n${Info}按任意键返回主页..."
	char=`get_char`
}

#检查VPN运行状态
check_vpn_status(){
	command=$1 && TYPE=$2 && message=$3
	if [[ `${command}|grep Active` =~ 'running' ]]; then
		green_font "${TYPE}${message}成功..."
		sleep 2s
	else
		red_font "${TYPE}${message}失败！q 键退出..."
		${command}
	fi
}

#安装V2ray
manage_v2ray(){
	check_pip(){
		if [[ ! `pip -V|awk -F '(' '{print $2}'` =~ 'python 3' ]]; then
			pip_array=($(whereis pip|awk -F 'pip: ' '{print $2}'))
			for node in ${pip_array[@]};
			do
				if [[ ! $node =~ [0-9] ]]; then
					rm -f $node
				fi
				if [[ $node =~ '3.' ]]; then
					pip_path=$node
				fi
			done
			if [[ -n $pip_path ]]; then
				ln -s $pip_path /usr/local/bin/pip
				ln -s $pip_path /usr/bin/pip
				pip install --upgrade pip
			else
				unset CMD
				py_array=(python3.1 python3.2 python3.3 python3.4 python3.5 python3.6 python3.7 python3.8 python3.9)
				for node in ${py_array[@]};
				do
					if type $node >/dev/null 2>&1; then
						CMD=$node
					fi
				done
				if [[ -n $CMD ]]; then
					wget -O get-pip.py https://bootstrap.pypa.io/get-pip.py
					$CMD get-pip.py
					rm -f get-pip.py
				else
					zlib_ver='1.2.11'
					wget "http://www.zlib.net/zlib-${zlib_ver}.tar.gz"
					tar -xvzf zlib-${zlib_ver}.tar.gz
					cd zlib-${zlib_ver}
					./configure
					make && make install && cd /root
					rm -rf zlib*
					py_ver='3.7.7'
					wget "https://www.python.org/ftp/python/${py_ver}/Python-${py_ver}.tgz"
					tar xvf Python-${py_ver}.tgz
					cd Python-${py_ver}
					./configure --prefix=/usr/local
					make && make install && cd /root
					rm -rf Python*
				fi
				check_pip
			fi
		fi
	}
	v2ray_info(){
		sed -i 's#ps": ".*"#ps": "'${myinfo}'"#g' $(cat /root/test/v2raypath)
		clear
		if [[ $1 == '1' ]]; then
			i=$[${i}+1]
			start=$(v2ray info |grep -Fxn ${i}. |awk -F: '{print $1}')
			if [[ $i == "${num}" ]]; then
				end=$(v2ray info |grep -wn Tip: |awk -F: '{print $1}')
			else
				end=$(v2ray info |grep -Fxn $[${i}+1]. |awk -F: '{print $1}')
			fi
			v2ray info|sed -n "${start},$[${end}-1]p"
		else
			v2ray info
		fi
	}
	change_uuid(){
		clear
		num=$(jq ".inbounds | length" /etc/v2ray/config.json)
		echo -e "\n${Info}当前用户总数：$(red_font $num)\n"
		unset i
		until [[ "${i}" -ge "1" && "${i}" -le "${num}" ]]
		do
			read -p "请输入要修改的用户序号[1-${num}]：" i
		done
		i=$[${i}-1]
		uuid1=$(jq -r ".inbounds[${i}].settings.clients[0].id" /etc/v2ray/config.json)
		uuid2=$(cat /proc/sys/kernel/random/uuid)
		sed -i "s#${uuid1}#${uuid2}#g" /etc/v2ray/config.json
		clear
		v2ray restart
		v2ray_info '1'
		white_font '      ————胖波比————'
		yello_font '——————————————————————————'
		green_font ' 1.' '  继续更改UUID'
		yello_font '——————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 2.' '  返回V2Ray用户管理页'
		green_font ' 3.' '  退出脚本'
		yello_font "——————————————————————————\n"
		read -p "请输入数字[0-3](默认:3)：" num
		[ -z $num ] && num=3
		case $num in
			0)
			start_menu_main
			;;
			1)
			change_uuid
			;;
			2)
			manage_v2ray_user
			;;
			3)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-3]"
			sleep 2s
			manage_v2ray_user
			;;
		esac
	}
	change_ws(){
		TYPE=$1
		num=$(jq ".inbounds | length" /etc/v2ray/config.json)
		for(( i = 0; i < ${num}; i++ ))
		do
			protocol=$(jq -r ".inbounds[${i}].streamSettings.network" /etc/v2ray/config.json)
			if [[ ${protocol} != "ws" ]]; then
				cat /etc/v2ray/config.json | jq "del(.inbounds[${i}].streamSettings.${protocol}Settings[])" | jq '.inbounds['${i}'].streamSettings.network="ws"' > /root/test/temp.json
				temppath="/$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 8)/"
				cat /root/test/temp.json | jq '.inbounds['${i}'].streamSettings.wsSettings.path="'${temppath}'"' | jq '.inbounds['${i}'].streamSettings.wsSettings.headers.Host="www.bilibili.com"' > /etc/v2ray/config.json
			fi
		done
		v2ray restart
		v2ray_info $TYPE
		if [[ $TYPE != '1' ]]; then
			echo -e "\n${Info}按任意键返回V2Ray用户管理页..."
			char=`get_char`
			manage_v2ray_user
		fi
	}
	add_user_v2ray(){
		add_v2ray_single(){
			clear
			i=$(jq ".inbounds | length" /etc/v2ray/config.json)
			echo -e "\n${Info}当前用户总数：$(red_font ${i})\n"
			v2ray add
			firewall_restart
			change_ws '1'
			white_font '     ————胖波比————'
			yello_font '——————————————————————————'
			green_font ' 1.' '  继续添加用户'
			yello_font '——————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 2.' '  返回V2Ray用户管理页'
			green_font ' 3.' '  退出脚本'
			yello_font "——————————————————————————\n"
			read -p "请输入数字[0-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				add_v2ray_single
				;;
				2)
				manage_v2ray_user
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-3]"
				sleep 2s
				manage_v2ray_user
				;;
			esac
		}
		add_v2ray_multi(){
			clear
			echo -e "\n${Info}当前用户总数：$(red_font $(jq ".inbounds | length" /etc/v2ray/config.json))\n"
			read -p "请输入要添加的用户个数(默认:1)：" num
			[ -z $num ] && num=1
			for(( i = 0; i < ${num}; i++ ))
			do
				echo | v2ray add
			done
			firewall_restart
			change_ws '2'
		}
		add_v2ray_menu(){
			clear
			white_font "\n    ————胖波比————\n"
			yello_font '——————————————————————————'
			green_font ' 1.' '  逐个添加'
			green_font ' 2.' '  批量添加'
			yello_font '——————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  返回V2Ray用户管理页'
			green_font ' 4.' '  退出脚本'
			yello_font "——————————————————————————\n"
			read -p "请输入数字[0-4](默认:2)：" num
			[ -z "${num}" ] && num=2
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				add_v2ray_single
				;;
				2)
				add_v2ray_multi
				;;
				3)
				manage_v2ray_user
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-4]"
				sleep 2s
				add_v2ray_menu
				;;
			esac
		}
		add_v2ray_menu
	}
	manage_v2ray_user(){
		clear
		white_font "\n   V2Ray用户管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font '	  -- 胖波比 --'
		white_font "手动修改配置文件：vi /etc/v2ray/config.json\n"
		yello_font '——————————————————————————'
		green_font ' 1.' '  更改UUID'
		green_font ' 2.' '  查看用户链接'
		green_font ' 3.' '  流量统计'
		yello_font '——————————————————————————'
		green_font ' 4.' '  添加用户'
		green_font ' 5.' '  删除用户'
		green_font ' 6.' '  更改端口'
		yello_font '——————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 7.' '  返回上页'
		green_font ' 8.' '  退出脚本'
		yello_font "——————————————————————————\n"
		read -p "请输入数字[0-8](默认:1)：" num
		[ -z $num ] && num=1
		clear
		case $num in
			0)
			start_menu_main
			;;
			1)
			change_uuid
			;;
			2)
			v2ray_info '2'
			echo -e "${Info}按任意键继续..."
			char=`get_char`
			;;
			3)
			v2ray iptables
			;;
			4)
			add_user_v2ray
			;;
			5)
			v2ray del
			;;
			6)
			v2ray port
			;;
			7)
			start_menu_v2ray
			;;
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
			sleep 2s
			manage_v2ray_user
			;;
		esac
		manage_v2ray_user
	}
	install_v2ray(){
		check_pip
		bash <(curl -sL $v2ray_url) --zh
		find /usr/local/lib/python*/*-packages/v2ray_util -name group.py > /root/test/v2raypath
		change_ws
	}
	install_v2ray_repair(){
		check_pip
		bash <(curl -sL $v2ray_url) -k
		echo -e "${Info}已保留配置更新，任意键继续..."
		char=`get_char`
	}
	start_menu_v2ray(){
		v2ray_url='https://multi.netlify.com/v2ray.sh'
		clear
		white_font "\n V2Ray一键安装脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	-- 胖波比 --\n"
		yello_font '——————————————————————————'
		green_font ' 1.' '  管理V2Ray用户'
		yello_font '——————————————————————————'
		green_font ' 2.' '  安装V2Ray'
		green_font ' 3.' '  修复V2Ray'
		green_font ' 4.' '  卸载V2Ray'
		yello_font '——————————————————————————'
		green_font ' 5.' '  重启V2Ray'
		green_font ' 6.' '  关闭V2Ray'
		green_font ' 7.' '  启动V2Ray'
		green_font ' 8.' '  查看V2Ray状态'
		yello_font '——————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 9.' '  退出脚本'
		yello_font "——————————————————————————\n"
		read -p "请输入数字[1-10](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			manage_v2ray_user
			;;
			2)
			install_v2ray
			;;
			3)
			install_v2ray_repair
			;;
			4)
			bash <(curl -sL $v2ray_url) --remove
			echo -e "${Info}已卸载，任意键继续..."
			char=`get_char`
			;;
			5)
			v2ray restart && sleep 2s
			;;
			6)
			v2ray stop && sleep 2s
			;;
			7)
			v2ray start && sleep 2s
			;;
			8)
			check_vpn_status 'service v2ray status' 'V2Ray' '运行'
			;;
			9)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-9]"
			sleep 2s
			start_menu_v2ray
			;;
		esac
		start_menu_v2ray
	}
	start_menu_v2ray
}

#安装Trojan
manage_trojan(){
	install_trojan(){
		#选择未占用端口
		if [ ! -e /root/test/trojan ]; then
			port=443
			until [[ -z $(lsof -i:${port}) ]]
			do
				port=$[${port}+1]
			done
			add_firewall
			firewall_restart
			mkdir -p /root/certificate
			echo $port > /root/test/trojan
		fi
		#下载trojan包
		cd /usr/local
		VERSION=1.14.1
		DOWNLOADURL="https://github.com/trojan-gfw/trojan/releases/download/v${VERSION}/trojan-${VERSION}-linux-amd64.tar.xz"
		wget --no-check-certificate "${DOWNLOADURL}"
		tar xf "trojan-$VERSION-linux-amd64.tar.xz"
		rm -f "trojan-$VERSION-linux-amd64.tar.xz"
		cd trojan
		chmod -R 755 /usr/local/trojan
		mv config.json /etc/trojan.json
		#编辑配置文件
		sed -i 's#local_port": 443#local_port": '${port}'#g' /etc/trojan.json
		password=$(cat /proc/sys/kernel/random/uuid)
		sed -i "s#password1#${password}#g" /etc/trojan.json
		password=$(cat /proc/sys/kernel/random/uuid)
		sed -i "s#password2#${password}#g" /etc/trojan.json
		sed -i 's#open": false#open": true#g' /etc/trojan.json
		cp examples/client.json-example /root/certificate/config.json
		sed -i 's#remote_port": 443#remote_port": '${port}'#g' /root/certificate/config.json
		sed -i 's#open": false#open": true#g' /root/certificate/config.json
		#上传证书
		clear && echo && read -p "请输入已成功解析到本机的域名：" ydomain
		echo -e "${Tip}请将证书重命名为 fullchain.cer 并放在文件夹 /root/certificate 中"
		echo -e "${Tip}请将私钥重命名为 private.key 并放在文件夹 /root/certificate 中"
		echo -e "${Info}完成上述操作后任意键继续..."
		char=`get_char`
		cd /usr/local/trojan
		sed -i "s#/path/to/certificate.crt#/root/certificate/fullchain.cer#g" /etc/trojan.json
		sed -i "s#/path/to/private.key#/root/certificate/private.key#g" /etc/trojan.json
		sed -i "s#example.com#${ydomain}#g" /root/certificate/config.json
		sed -i 's#cert": "#cert": "fullchain.cer#g' /root/certificate/config.json
		sed -i "s#sni\": \"#sni\": \"${ydomain}#g" /root/certificate/config.json
		echo ${ydomain} >> /root/test/trojan
		base64 -d <<< W1VuaXRdDQpBZnRlcj1uZXR3b3JrLnRhcmdldCANCg0KW1NlcnZpY2VdDQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC90cm9qYW4vdHJvamFuIC1jIC9ldGMvdHJvamFuLmpzb24NClJlc3RhcnQ9YWx3YXlzDQoNCltJbnN0YWxsXQ0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQ=  > /etc/systemd/system/trojan.service
		systemctl daemon-reload
		systemctl enable trojan
		systemctl start trojan
		view_password '2'
		echo -e "${Tip}安装完成,如需设置伪装,请手动删除配置文件中监听的 ${port} 端口,否则会报错!!!"
		echo -e "${Tip}证书以及用户配置文件所在文件夹：/root/certificate"
		echo -e "${Info}任意键返回Trojan用户管理页..."
		char=`get_char`
		manage_user_trojan
	}
	uninstall_trojan(){
		systemctl stop trojan
		rm -rf /usr/local/trojan 
		rm -f /root/test/trojan /etc/trojan.json /etc/systemd/system/trojan.service
		systemctl daemon-reload
	}
	add_user_trojan(){
		clear
		add_trojan_single(){
			clear
			num=$(jq '.password | length' /etc/trojan.json)
			password=$(cat /proc/sys/kernel/random/uuid)
			cat /etc/trojan.json | jq '.password['${num}']="'${password}'"' > /root/test/temp.json
			cp /root/test/temp.json /etc/trojan.json
			systemctl restart trojan
			view_password '2'
			white_font "       ————胖波比————\n"
			yello_font '————————————————————————————'
			green_font ' 1.' '  继续添加用户'
			yello_font '————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 2.' '  返回Trojan用户管理页'
			green_font ' 3.' '  退出脚本'
			yello_font "————————————————————————————\n"
			read -p "请输入数字[0-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				add_trojan_single
				;;
				2)
				manage_user_trojan
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-3]"
				sleep 2s
				add_user_trojan
				;;
			esac
		}
		add_trojan_multi(){
			clear
			read -p "请输入要添加的用户个数(默认:1)：" num
			[ -z "${num}" ] && num=1
			base=$(jq '.password | length' /etc/trojan.json)
			for(( i = 0; i < ${num}; i++ ))
			do
				password=$(cat /proc/sys/kernel/random/uuid)
				j=$[ $base + $i ]
				cat /etc/trojan.json | jq '.password['${j}']="'${password}'"' > /root/test/temp.json
				cp /root/test/temp.json /etc/trojan.json
			done
			systemctl restart trojan
			view_password '1'
		}
		white_font "\n     ————胖波比————\n"
		yello_font '————————————————————————————'
		green_font ' 1.' '  逐个添加'
		green_font ' 2.' '  批量添加'
		yello_font '————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 3.' '  返回Trojan用户管理页'
		green_font ' 4.' '  退出脚本'
		yello_font "————————————————————————————\n"
		read -p "请输入数字[0-4](默认:2)：" num
		[ -z "${num}" ] && num=2
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			add_trojan_single
			;;
			2)
			add_trojan_multi
			;;
			3)
			manage_user_trojan
			;;
			4)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-4]"
			sleep 2s
			add_user_trojan
			;;
		esac
	}
	delete_user_trojan(){
		delete_trojan_single(){
			clear
			num=$(jq '.password | length' /etc/trojan.json)
			echo -e "\n${Info}当前用户总数：$(red_font $num)\n"
			unset i
			until [[ "${i}" -ge "1" && "${i}" -le "${num}" ]]
			do
				read -p "请输入要删除的用户序号[1-${num}]：" i
			done
			i=$[${i}-1]
			cat /etc/trojan.json | jq 'del(.password['${i}'])' > /root/test/temp.json
			cp /root/test/temp.json /etc/trojan.json
			systemctl restart trojan
			view_password '2'
			white_font "       ————胖波比————\n"
			yello_font '————————————————————————————'
			green_font ' 1.' '  继续删除用户'
			yello_font '————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 2.' '  返回Trojan用户管理页'
			green_font ' 3.' '  退出脚本'
			yello_font "————————————————————————————\n"
			read -p "请输入数字[0-3](默认:2)：" num
			[ -z "${num}" ] && num=2
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				delete_trojan_single
				;;
				2)
				manage_user_trojan
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-3]"
				sleep 2s
				manage_user_trojan
				;;
			esac
		}
		delete_trojan_multi(){
			clear
			cat /etc/trojan.json | jq 'del(.password[])' > /root/test/temp.json
			cp /root/test/temp.json /etc/trojan.json
			echo -e "${Info}所有用户已删除！"
			echo -e "${Tip}Trojan至少要有一个用户，任意键添加用户..."
			char=`get_char`
			add_user_trojan
		}
		delete_trojan_menu(){
			clear
			white_font "\n       ————胖波比————\n"
			yello_font '————————————————————————————'
			green_font ' 1.' '  逐个删除'
			green_font ' 2.' '  全部删除'
			yello_font '————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  返回Trojan用户管理页'
			green_font ' 4.' '  退出脚本'
			yello_font "————————————————————————————\n"
			read -p "请输入数字[0-4](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				delete_trojan_single
				;;
				2)
				delete_trojan_multi
				;;
				3)
				manage_user_trojan
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-4]"
				sleep 2s
				delete_trojan_menu
				;;
			esac
		}
		delete_trojan_menu
	}
	change_pw_trojan(){
		change_trojan_single(){
			clear
			num=$(jq '.password | length' /etc/trojan.json)
			echo -e "\n${Info}当前用户总数：$(red_font $num)\n"
			unset i
			until [[ "${i}" -ge "1" && "${i}" -le "${num}" ]]
			do
				read -p "请输入要改密的用户序号 [1-${num}]:" i
			done
			i=$[${i}-1]
			password1=$(cat /etc/trojan.json | jq '.password['${i}']' | sed 's#"##g')
			password=$(cat /proc/sys/kernel/random/uuid)
			sed -i "s#${password1}#${password}#g" /etc/trojan.json
			systemctl restart trojan
			view_password '2'
			white_font "       ————胖波比————\n"
			yello_font '————————————————————————————'
			green_font ' 1.' '  继续更改密码'
			yello_font '————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 2.' '  返回Trojan用户管理页'
			green_font ' 3.' '  退出脚本'
			yello_font "————————————————————————————\n"
			read -p "请输入数字[0-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				change_trojan_single
				;;
				2)
				manage_user_trojan
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-3]"
				sleep 2s
				change_trojan_menu
				;;
			esac
		}
		change_trojan_multi(){
			clear
			num=$(jq '.password | length' /etc/trojan.json)
			for(( i = 0; i < ${num}; i++ ))
			do
				password=$(cat /proc/sys/kernel/random/uuid)
				cat /etc/trojan.json | jq '.password['${i}']="'${password}'"' > /root/test/temp.json
				cp /root/test/temp.json /etc/trojan.json
			done
			view_password '1'
		}
		change_trojan_menu(){
			clear
			white_font "\n      ————胖波比————\n"
			yello_font '————————————————————————————'
			green_font ' 1.' '  逐个修改'
			green_font ' 2.' '  全部修改'
			yello_font '————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  返回Trojan用户管理页'
			green_font ' 4.' '  退出脚本'
			yello_font "————————————————————————————\n"
			read -p "请输入数字[0-4](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				change_trojan_single
				;;
				2)
				change_trojan_multi
				;;
				3)
				manage_user_trojan
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-4]"
				sleep 2s
				change_trojan_menu
				;;
			esac
		}
		change_trojan_menu
	}
	view_password(){
		clear
		ipinfo=$(cat /root/test/trojan|sed -n '2p')
		port=$(cat /root/test/trojan|sed -n '1p')
		pw_trojan=$(jq '.password' /etc/trojan.json)
		length=$(jq '.password | length' /etc/trojan.json)
		tr_info="$(curl -s https://ipapi.co/country/)-%E6%88%91%E4%BB%AC%E7%88%B1%E4%B8%AD%E5%9B%BD"
		cat /root/certificate/config.json | jq 'del(.password[])' > /root/test/temp.json
		cp /root/test/temp.json /root/certificate/config.json
		for i in `seq 0 $[length-1]`
		do
			password=$(echo $pw_trojan | jq ".[$i]" | sed 's/"//g')
			#更新用户配置文件
			cat /root/certificate/config.json | jq '.password['${i}']="'${password}'"' > /root/test/temp.json
			cp /root/test/temp.json /root/certificate/config.json
			Trojanurl="trojan://${password}@${ipinfo}:${port}?allowInsecure=1&tfo=1#${tr_info}"
			echo -e "密码：$(red_font $password)"
			echo -e "Trojan链接：$(green_font $Trojanurl)\n"
		done
		echo -e "${Info}IP或域名：$(red_font ${ipinfo})"
		echo -e "${Info}端口：$(red_font ${port})"
		echo -e "${Info}当前用户总数：$(red_font ${length})\n"
		if [[ $1 == "1" ]]; then
			echo -e "${Info}任意键返回Trojan用户管理页..."
			char=`get_char`
			manage_user_trojan
		fi
	}
	manage_user_trojan(){
		clear
		white_font "\n   Trojan用户管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font '	    -- 胖波比 --'
		white_font "手动修改配置文件：vi /etc/trojan.json\n"
		yello_font '———————Trojan用户管理———————'
		green_font ' 1.' '  更改密码'
		green_font ' 2.' '  查看用户链接'
		yello_font '————————————————————————————'
		green_font ' 3.' '  添加用户'
		green_font ' 4.' '  删除用户'
		yello_font '————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 5.' '  退出脚本'
		yello_font "————————————————————————————\n"
		read -p "请输入数字[0-5](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			change_pw_trojan
			;;
			2)
			view_password '1'
			;;
			3)
			add_user_trojan
			;;
			4)
			delete_user_trojan
			;;
			5)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-5]"
			sleep 2s
			manage_user_trojan
			;;
		esac
	}
	start_menu_trojan(){
		clear
		white_font "\n Trojan一键安装脚本 \c" && red_font "[v${sh_ver}]"
		white_font "        -- 胖波比 --\n"
		yello_font '————————————————————————————'
		green_font ' 1.' '  管理Trojan用户'
		yello_font '————————————————————————————'
		green_font ' 2.' '  安装Trojan'
		green_font ' 3.' '  卸载Trojan'
		yello_font '————————————————————————————'
		green_font ' 4.' '  重启Trojan'
		green_font ' 5.' '  关闭Trojan'
		green_font ' 6.' '  启动Trojan'
		green_font ' 7.' '  查看Trojan状态'
		yello_font '————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 8.' '  退出脚本'
		yello_font "————————————————————————————\n"
		read -p "请输入数字[0-8](默认:1)：" num
		[ -z $num ] && num=1
		case $num in
			0)
			start_menu_main
			;;
			1)
			manage_user_trojan
			;;
			2)
			install_trojan
			;;
			3)
			uninstall_trojan
			;;
			4)
			systemctl restart trojan
			check_vpn_status 'systemctl status trojan' 'Trojan' '重启'
			;;
			5)
			systemctl stop trojan
			;;
			6)
			systemctl start trojan
			check_vpn_status 'systemctl status trojan' 'Trojan' '启动'
			;;
			7)
			check_vpn_status 'systemctl status trojan' 'Trojan' '运行'
			;;
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
			sleep 2s
			start_menu_trojan
			;;
		esac
		start_menu_trojan
	}
	start_menu_trojan
}

#安装SSR
install_ssr(){
	libsodium_file="libsodium-1.0.17"
	libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.17/libsodium-1.0.17.tar.gz"
	shadowsocks_r_file="shadowsocksr-3.2.2"
	shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"

	#Current folder
	cur_dir=`pwd`
	red='\033[0;31m' && green='\033[0;32m' && plain='\033[0m'
	# Reference URL:
	# https://github.com/shadowsocksr-rm/shadowsocks-rss/blob/master/ssr.md
	# https://github.com/shadowsocksrr/shadowsocksr/commit/a3cf0254508992b7126ab1151df0c2f10bf82680
	
	# Disable selinux
	disable_selinux(){
		if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
			sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
			setenforce 0
		fi
	}
	#Check system
	check_sys_ssr(){
		local checkType=$1
		local value=$2

		local release=''
		local systemPackage=''

		if [[ -f /etc/redhat-release ]]; then
			release="centos"
			systemPackage="yum"
		elif grep -Eqi "debian|raspbian" /etc/issue; then
			release="debian"
			systemPackage="apt"
		elif grep -Eqi "ubuntu" /etc/issue; then
			release="ubuntu"
			systemPackage="apt"
		elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
			release="centos"
			systemPackage="yum"
		elif grep -Eqi "debian|raspbian" /proc/version; then
			release="debian"
			systemPackage="apt"
		elif grep -Eqi "ubuntu" /proc/version; then
			release="ubuntu"
			systemPackage="apt"
		elif grep -Eqi "centos|red hat|redhat" /proc/version; then
			release="centos"
			systemPackage="yum"
		fi

		if [[ "${checkType}" == "sysRelease" ]]; then
			if [ "${value}" == "${release}" ]; then
				return 0
			else
				return 1
			fi
		elif [[ "${checkType}" == "packageManager" ]]; then
			if [ "${value}" == "${systemPackage}" ]; then
				return 0
			else
				return 1
			fi
		fi
	}
	# Get version
	getversion(){
		if [[ -s /etc/redhat-release ]]; then
			grep -oE  "[0-9.]+" /etc/redhat-release
		else
			grep -oE  "[0-9.]+" /etc/issue
		fi
	}
	# CentOS version
	centosversion(){
		if check_sys_ssr sysRelease centos; then
			local code=$1
			local version="$(getversion)"
			local main_ver=${version%%.*}
			if [ "$main_ver" == "$code" ]; then
				return 0
			else
				return 1
			fi
		else
			return 1
		fi
	}

	#选择加密
	set_method(){
		# Stream Ciphers
		ciphers=(
			none
			aes-256-cfb
			aes-192-cfb
			aes-128-cfb
			aes-256-cfb8
			aes-192-cfb8
			aes-128-cfb8
			aes-256-ctr
			aes-192-ctr
			aes-128-ctr
			chacha20-ietf
			chacha20
			salsa20
			xchacha20
			xsalsa20
			rc4-md5
		)
		while true
		do
		echo -e "${Info}请选择ShadowsocksR加密方式:"
		for ((i=1;i<=${#ciphers[@]};i++ )); do
			hint="${ciphers[$i-1]}"
			echo -e "${green}${i}${plain}) ${hint}"
		done
		read -p "Which cipher you'd select(默认: ${ciphers[1]}):" pick
		[ -z "$pick" ] && pick=2
		expr ${pick} + 1 &>/dev/null
		if [ $? -ne 0 ]; then
			echo -e "[${red}Error${plain}] Please enter a number"
			continue
		fi
		if [[ "$pick" -lt 1 || "$pick" -gt ${#ciphers[@]} ]]; then
			echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#ciphers[@]}"
			continue
		fi
		method=${ciphers[$pick-1]}
		echo
		echo "---------------------------"
		echo "cipher = ${method}"
		echo "---------------------------"
		echo
		break
		done
	}
	#选择协议
	set_protocol(){
		# Protocol
		protocols=(
			origin
			verify_deflate
			auth_sha1_v4
			auth_sha1_v4_compatible
			auth_aes128_md5
			auth_aes128_sha1
			auth_chain_a
			auth_chain_b
			auth_chain_c
			auth_chain_d
			auth_chain_e
			auth_chain_f
		)
		while true
		do
		echo -e "${Info}请选择ShadowsocksR协议:"
		for ((i=1;i<=${#protocols[@]};i++ )); do
			hint="${protocols[$i-1]}"
			echo -e "${green}${i}${plain}) ${hint}"
		done
		read -p "Which protocol you'd select(默认: ${protocols[3]}):" protocol
		[ -z "$protocol" ] && protocol=4
		expr ${protocol} + 1 &>/dev/null
		if [ $? -ne 0 ]; then
			echo -e "[${red}Error${plain}] Input error, please input a number"
			continue
		fi
		if [[ "$protocol" -lt 1 || "$protocol" -gt ${#protocols[@]} ]]; then
			echo -e "[${red}Error${plain}] Input error, please input a number between 1 and ${#protocols[@]}"
			continue
		fi
		protocol=${protocols[$protocol-1]}
		echo
		echo "---------------------------"
		echo "protocol = ${protocol}"
		echo "---------------------------"
		echo
		break
		done
	}
	#选择混淆
	set_obfs(){
		# obfs
		obfs=(
			plain
			http_simple
			http_simple_compatible
			http_post
			http_post_compatible
			tls1.2_ticket_auth
			tls1.2_ticket_auth_compatible
			tls1.2_ticket_fastauth
			tls1.2_ticket_fastauth_compatible
		)
		while true
		do
		echo -e "${Info}请选择ShadowsocksR混淆方式:"
		for ((i=1;i<=${#obfs[@]};i++ )); do
			hint="${obfs[$i-1]}"
			echo -e "${green}${i}${plain}) ${hint}"
		done
		read -p "Which obfs you'd select(默认: ${obfs[2]}):" r_obfs
		[ -z "$r_obfs" ] && r_obfs=3
		expr ${r_obfs} + 1 &>/dev/null
		if [ $? -ne 0 ]; then
			echo -e "[${red}Error${plain}] Input error, please input a number"
			continue
		fi
		if [[ "$r_obfs" -lt 1 || "$r_obfs" -gt ${#obfs[@]} ]]; then
			echo -e "[${red}Error${plain}] Input error, please input a number between 1 and ${#obfs[@]}"
			continue
		fi
		obfs=${obfs[$r_obfs-1]}
		echo
		echo "---------------------------"
		echo "obfs = ${obfs}"
		echo "---------------------------"
		echo
		break
		done
	}
	
	# Pre-installation settings
	pre_install(){
		if check_sys_ssr packageManager yum || check_sys_ssr packageManager apt; then
			# Not support CentOS 5
			if centosversion 5; then
				echo -e "$[{red}Error${plain}] Not supported CentOS 5, please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
				exit 1
			fi
		else
			echo -e "[${red}Error${plain}] Your OS is not supported. please change OS to CentOS/Debian/Ubuntu and try again."
			exit 1
		fi
		# Set ShadowsocksR config password
		echo -e "${Info}请设置ShadowsocksR密码:"
		read -p "(默认密码: pangbobi):" password
		[ -z "${password}" ] && password="pangbobi"
		echo
		echo "---------------------------"
		echo "password = ${password}"
		echo "---------------------------"
		echo
		# Set ShadowsocksR config port
		while true
		do
			dport=$(shuf -i 1000-9999 -n1)
			echo -e "${Info}请设置ShadowsocksR端口[1000-9999]："
			read -p "(默认随机端口:${dport})：" port
			[ -z "${port}" ] && port=${dport}
			expr ${port} + 1 &>/dev/null
			if [ $? -eq 0 ]; then
				if [ ${port} -ge 1000 ] && [ ${port} -le 9999 ] && [ -z $(lsof -i:${port}) ]; then
					echo
					echo "---------------------------"
					echo "port = ${port}"
					echo "---------------------------"
					echo
					break
				fi
			fi
			echo -e "[${red}Error${plain}] Please enter a correct number [1000-9999]"
		done

		# Set shadowsocksR config stream ciphers
		set_method

		# Set shadowsocksR config protocol
		set_protocol
		
		# Set shadowsocksR config obfs
		set_obfs

		echo
		echo "Press any key to start...or Press Ctrl+C to cancel"
		char=`get_char`
		cd ${cur_dir}
	}
	# Download files
	download_files(){
		# Download libsodium file
		if ! wget --no-check-certificate -O ${libsodium_file}.tar.gz ${libsodium_url}; then
			echo -e "[${red}Error${plain}] Failed to download ${libsodium_file}.tar.gz!"
			exit 1
		fi
		# Download ShadowsocksR file
		if ! wget --no-check-certificate -O ${shadowsocks_r_file}.tar.gz ${shadowsocks_r_url}; then
			echo -e "[${red}Error${plain}] Failed to download ShadowsocksR file!"
			exit 1
		fi
		# Download ShadowsocksR init script
		if check_sys_ssr packageManager yum; then
			if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR -O /etc/init.d/shadowsocks; then
				echo -e "[${red}Error${plain}] Failed to download ShadowsocksR chkconfig file!"
				exit 1
			fi
		elif check_sys_ssr packageManager apt; then
			if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR-debian -O /etc/init.d/shadowsocks; then
				echo -e "[${red}Error${plain}] Failed to download ShadowsocksR chkconfig file!"
				exit 1
			fi
		fi
	}
	# Config ShadowsocksR
	config_shadowsocks(){
		cat > /etc/shadowsocks.json<<-EOF
{
    "server":"0.0.0.0",
    "server_ipv6":"[::]",
    "local_address":"127.0.0.1",
    "local_port":1080,
    "port_password":{
                "${port}":"${password}"
        },
    "timeout":300,
    "method":"${method}",
    "protocol":"${protocol}",
    "protocol_param":"3",
    "obfs":"${obfs}",
    "obfs_param":"",
    "redirect":"*:*#127.0.0.1:80",
    "dns_ipv6":false,
    "fast_open":true,
    "workers":1
}
EOF
	}
	# Install cleanup
	install_cleanup(){
		cd ${cur_dir}
		rm -rf ${shadowsocks_r_file} ${libsodium_file}
		rm -f ${shadowsocks_r_file}.tar.gz ${libsodium_file}.tar.gz
	}
	# Install ShadowsocksR
	install(){
		# Install libsodium
		if [ ! -f /usr/lib/libsodium.a ]; then
			cd ${cur_dir}
			tar zxf ${libsodium_file}.tar.gz
			cd ${libsodium_file}
			./configure --prefix=/usr && make && make install
			if [ $? -ne 0 ]; then
				echo -e "[${red}Error${plain}] libsodium install failed!"
				install_cleanup
				exit 1
			fi
		fi

		ldconfig
		# Install ShadowsocksR
		cd ${cur_dir}
		tar zxf ${shadowsocks_r_file}.tar.gz
		mv ${shadowsocks_r_file}/shadowsocks /usr/local/
		if [ -f /usr/local/shadowsocks/server.py ]; then
			chmod +x /etc/init.d/shadowsocks
			if check_sys_ssr packageManager yum; then
				chkconfig --add shadowsocks
				chkconfig shadowsocks on
			elif check_sys_ssr packageManager apt; then
				update-rc.d -f shadowsocks defaults
			fi
			/etc/init.d/shadowsocks start
			install_cleanup
			get_info
			set_ssrurl
			echo -e "Congratulations, ShadowsocksR server install completed!"
			echo -e "Your Server IP        : \033[41;37m $(get_ip) \033[0m"
			echo -e "Your Server Port      : \033[41;37m ${port} \033[0m"
			echo -e "Your Password         : \033[41;37m ${password} \033[0m"
			echo -e "Your Protocol         : \033[41;37m ${protocol} \033[0m"
			echo -e "Your obfs             : \033[41;37m ${obfs} \033[0m"
			echo -e "Your Encryption Method: \033[41;37m ${method} \033[0m"
			white_font "\n	Enjoy it!\n	请记录你的SSR信息!\n"
			yello_font '——————————胖波比—————————'
			green_font ' 1.' '  进入SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 2.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-2](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				manage_ssr
				;;
				2)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-2]"
				sleep 2s
				start_menu_main
				;;
			esac
		else
			echo -e "${Error}ShadowsocksR install failed, please Email to Teddysun <i@teddysun.com> and contact"
			install_cleanup
			exit 1
		fi
	}
	# Uninstall ShadowsocksR
	uninstall_shadowsocksr(){
		printf "Are you sure uninstall ShadowsocksR? (y/n)"
		printf "\n"
		read -p "(Default: n):" answer
		[ -z ${answer} ] && answer="n"
		if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
			/etc/init.d/shadowsocks status > /dev/null 2>&1
			if [ $? -eq 0 ]; then
				/etc/init.d/shadowsocks stop
			fi
			if check_sys_ssr packageManager yum; then
				chkconfig --del shadowsocks
			elif check_sys_ssr packageManager apt; then
				update-rc.d -f shadowsocks remove
			fi
			rm -f /etc/shadowsocks.json
			rm -f /etc/init.d/shadowsocks
			rm -f /var/log/shadowsocks.log
			rm -rf /usr/local/shadowsocks
			echo "ShadowsocksR uninstall success!"
		else
			echo
			echo "uninstall cancelled, nothing to do..."
			echo
		fi
	}
	# Install ShadowsocksR
	install_shadowsocksr(){
		disable_selinux
		pre_install
		download_files
		config_shadowsocks
		add_firewall
		firewall_restart
		install
	}

	#字符转换
	urlsafe_base64(){
		date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
		echo -e "${date}"
	}
	#获取配置信息
	get_info(){
		#获取协议
		protocol=$(jq -r '.protocol' /etc/shadowsocks.json)
		#获取加密方式
		method=$(jq -r '.method' /etc/shadowsocks.json)
		#获取混淆
		obfs=$(jq -r '.obfs' /etc/shadowsocks.json)
		#预处理
		SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
		SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
		Remarksbase64=$(urlsafe_base64 "${myinfo}")
		Groupbase64=$(urlsafe_base64 "我们爱中国")
	}
	#生成SSR链接
	set_ssrurl(){
		SSRPWDbase64=$(urlsafe_base64 "${password}")
		SSRbase64=$(urlsafe_base64 "$(get_ip):${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?remarks=${Remarksbase64}&group=${Groupbase64}")
		SSRurl="ssr://${SSRbase64}"
		service shadowsocks restart
		clear
		#输出链接
		echo -e "\n${Info}端口：$(red_font $port)   密码：$(red_font $password)"
		echo -e "${Info}SSR链接：$(red_font $SSRurl)\n"
	}
	#查看所有链接
	view_ssrurl(){
		clear
		jq '.port_password' /etc/shadowsocks.json | sed '1d' | sed '$d' | sed 's#"##g' | sed 's# ##g' | sed 's#,##g' > /root/test/ppj
		cat /root/test/ppj | while read line; do
			port=`echo $line|awk -F ':' '{print $1}'`
			password=`echo $line|awk -F ':' '{print $2}'`
			echo -e "端口：$(red_font $port)   密码：$(red_font $password)"
			SSRPWDbase64=$(urlsafe_base64 "${password}")
			SSRbase64=$(urlsafe_base64 "$(get_ip):${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?remarks=${Remarksbase64}&group=${Groupbase64}")
			SSRurl="ssr://${SSRbase64}"
			echo -e "SSR链接 ：$(red_font $SSRurl)\n"
		done
		echo -e "服务器IP    ：$(red_font $(get_ip))"
		echo -e "加密方式    ：$(red_font $method)"
		echo -e "协议        ：$(red_font $protocol)"
		echo -e "混淆        ：$(red_font $obfs)"
		echo -e "当前用户总数：$(red_font $(jq '.port_password | length' /etc/shadowsocks.json))\n"
		if [[ $1 == "1" ]]; then
			service shadowsocks restart
			echo -e "${Info}SSR已重启！"
		fi
		echo -e "${Info}按任意键回到SSR用户管理页..."
		char=`get_char`
		manage_ssr
	}

	#更改密码
	change_pw(){
		change_pw_single(){
			clear
			jq '.port_password' /etc/shadowsocks.json
			echo -e "${Info}以上是配置文件的内容\n"
			#判断端口是否已有,清空port内存
			unset port
			until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '1' && ${port} -ge '1000' && ${port} -le '9999' && ${port} -ne '1080' ]]
			do
				read -p "请输入要改密的端口号：" port
			done
			password1=$(jq -r '.port_password."'${port}'"' /etc/shadowsocks.json)
			password=$(openssl rand -base64 6)
			et=$(sed -n -e "/${port}/=" /etc/shadowsocks.json)
			sed -i "${et}s#${password1}#${password}#g" /etc/shadowsocks.json
			#调用生成链接的函数
			set_ssrurl
			white_font "\n	 ————胖波比————\n"
			yello_font '—————————————————————————'
			green_font ' 1.' '  继续更改密码'
			green_font ' 2.' '  返回SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-3](默认:2)：" num
			[ -z "${num}" ] && num=2
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				change_pw_single
				;;
				2)
				manage_ssr
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-3]"
				sleep 2s
				change_pw_menu
				;;
			esac
		}
		change_pw_multi(){
			clear
			jq '.port_password' /etc/shadowsocks.json | sed '1d' | sed '$d' | sed 's#"##g' | sed 's# ##g' | sed 's#,##g' > /root/test/ppj
			cat /root/test/ppj | while read line; do
				port=`echo $line|awk -F ':' '{print $1}'`
				password1=`echo $line|awk -F ':' '{print $2}'`
				password=$(openssl rand -base64 6)
				et=$(sed -n -e "/${port}/=" /etc/shadowsocks.json)
				sed -i "${et}s#${password1}#${password}#g" /etc/shadowsocks.json
				echo -e "端口：$(red_font $port)   密码：$(red_font $password)"
				SSRPWDbase64=$(urlsafe_base64 "${password}")
				SSRbase64=$(urlsafe_base64 "$(get_ip):${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?remarks=${Remarksbase64}&group=${Groupbase64}")
				SSRurl="ssr://${SSRbase64}"
				echo -e "SSR链接 : $(red_font $SSRurl)\n"
			done
			echo -e "服务器IP    ：$(red_font $(get_ip))"
			echo -e "加密方式    ：$(red_font $method)"
			echo -e "协议        ：$(red_font $protocol)"
			echo -e "混淆        ：$(red_font $obfs)"
			echo -e "当前用户总数：$(red_font $(jq '.port_password | length' /etc/shadowsocks.json))\n"
			service shadowsocks restart
			echo -e "${Info}SSR已重启！"
			echo -e "${Info}按任意键回到SSR用户管理页..."
			char=`get_char`
			manage_ssr
		}
		change_pw_menu(){
			clear
			white_font "\n    ————胖波比————\n"
			yello_font '—————————————————————————'
			green_font ' 1.' '  逐个修改'
			green_font ' 2.' '  全部修改'
			green_font ' 3.' '  返回SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 4.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-4](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				change_pw_single
				;;
				2)
				change_pw_multi
				;;
				3)
				manage_ssr
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-4]"
				sleep 2s
				change_pw_menu
				;;
			esac
		}
		change_pw_menu
	}
	#添加用户
	add_user(){
		#逐个添加
		add_user_single(){
			port=$(shuf -i 1000-9999 -n1)
			until [[ -z $(lsof -i:${port}) && ${port} -ne '1080' ]]
			do
				port=$(shuf -i 1000-9999 -n1)
			done
			add_firewall
			firewall_restart
			password=$(openssl rand -base64 6)
			cat /etc/shadowsocks.json | jq '.port_password."'${port}'"="'${password}'"' > /root/test/temp.json
			cp /root/test/temp.json /etc/shadowsocks.json
			set_ssrurl
			white_font "     ————胖波比————\n"
			yello_font '—————————————————————————'
			green_font ' 1.' '  继续添加用户'
			green_font ' 2.' '  返回SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				add_user_single
				;;
				2)
				manage_ssr
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-3]"
				sleep 2s
				manage_ssr
				;;
			esac
		}
		#批量添加
		add_user_multi(){
			clear
			echo -e "\n${Info}当前用户总数：$(red_font $(jq '.port_password | length' /etc/shadowsocks.json))\n"
			read -p "请输入要添加的用户个数(默认:1)：" num
			[ -z "${num}" ] && num=1
			unset port
			for(( i = 0; i < ${num}; i++ ))
			do
				port=$(shuf -i 1000-9999 -n1)
				until [[ -z $(lsof -i:${port}) && ${port} -ne '1080' ]]
				do
					port=$(shuf -i 1000-9999 -n1)
				done
				add_firewall
				password=$(openssl rand -base64 6)
				cat /etc/shadowsocks.json | jq '.port_password."'${port}'"="'${password}'"' > /root/test/temp.json
				cp /root/test/temp.json /etc/shadowsocks.json
				SSRPWDbase64=$(urlsafe_base64 "${password}")
				SSRbase64=$(urlsafe_base64 "$(get_ip):${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?remarks=${Remarksbase64}&group=${Groupbase64}")
				SSRurl="ssr://${SSRbase64}"
				echo -e "${Info}端口：$(red_font $port)   密码：$(red_font $password)"
				echo -e "${Info}SSR链接：$(red_font $SSRurl)\n"
			done
			firewall_restart
			service shadowsocks restart
			echo -e "${Info}SSR已重启！"
			echo -e "${Info}当前用户总数：$(red_font $(jq '.port_password | length' /etc/shadowsocks.json))\n"
			echo -e "${Info}按任意键返回SSR用户管理页..."
			char=`get_char`
			manage_ssr
		}
		#添加用户菜单
		add_user_menu(){
			clear
			white_font "\n     ————胖波比————\n"
			yello_font '—————————————————————————'
			green_font ' 1.' '  逐个添加'
			green_font ' 2.' '  批量添加'
			green_font ' 3.' '  返回SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 4.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-4](默认:2)：" num
			[ -z "${num}" ] && num=2
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				add_user_single
				;;
				2)
				add_user_multi
				;;
				3)
				manage_ssr
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-4]"
				sleep 2s
				add_user_menu
				;;
			esac
		}
		add_user_menu
	}
	delete_user(){
		delete_user_single(){
			clear
			jq '.port_password' /etc/shadowsocks.json
			echo -e "${Info}以上是配置文件的内容\n"
			unset port
			until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '1' && ${port} -ge '1000' && ${port} -le '9999' && ${port} -ne '1080' ]]
			do
				read -p "请输入要删除的端口：" port
			done
			cat /etc/shadowsocks.json | jq 'del(.port_password."'${port}'")' > /root/test/temp.json
			cp /root/test/temp.json /etc/shadowsocks.json
			echo -e "${Info}用户已删除..."
			delete_firewall
			firewall_restart
			service shadowsocks restart
			echo -e "${Info}SSR已重启！"
			sleep 2s
			clear
			white_font "\n    ————胖波比————\n"
			yello_font '—————————————————————————'
			green_font ' 1.' '  继续删除用户'
			green_font ' 2.' '  返回SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				delete_user_single
				;;
				2)
				manage_ssr
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-3]"
				sleep 2s
				manage_ssr
				;;
			esac
		}
		delete_user_multi(){
			clear
			jq '.port_password' /etc/shadowsocks.json |sed '1d' |sed '$d' |sed 's#"##g' |sed 's# ##g' |sed 's#,##g' > /root/test/ppj
			cat /root/test/ppj | while read line; do
				port=`echo $line|awk -F ':' '{print $1}'`
				delete_firewall
			done
			firewall_restart
			cat /etc/shadowsocks.json | jq "del(.port_password[])" > /root/test/temp.json
			cp /root/test/temp.json /etc/shadowsocks.json
			echo -e "${Info}所有用户已删除！"
			echo -e "${Info}SSR至少要有一个用户，任意键添加用户..."
			char=`get_char`
			add_user
		}
		delete_user_menu(){
			clear
			white_font "\n    ————胖波比————\n"
			yello_font '—————————————————————————'
			green_font ' 1.' '  逐个删除'
			green_font ' 2.' '  全部删除'
			green_font ' 3.' '  返回SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 4.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-4](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				delete_user_single
				;;
				2)
				delete_user_multi
				;;
				3)
				manage_ssr
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-4]"
				sleep 2s
				delete_user_menu
				;;
			esac
		}
		delete_user_menu
	}
	#更改端口
	change_port(){
		clear
		jq '.port_password' /etc/shadowsocks.json | sed '1d' | sed '$d' | sed 's#"##g' | sed 's# ##g' | sed 's#,##g' > /root/test/ppj
		jq '.port_password' /etc/shadowsocks.json
		echo -e "${Info}以上是配置文件的内容\n"
		unset port
		until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '1' && ${port} -ge '1000' && ${port} -le '9999' && ${port} -ne '1080' ]]
		do
			read -p "请输入要修改的端口号：" port
		done
		password=$(cat /root/test/ppj | grep "${port}:" | awk -F ':' '{print $2}')
		delete_firewall
		port1=${port}
		port=$(shuf -i 1000-9999 -n1)
		until [[ -z $(lsof -i:${port}) && ${port} -ne '1080' ]]
		do
			port=$(shuf -i 1000-9999 -n1)
		done
		add_firewall
		firewall_restart
		sed -i "s/${port1}/${port}/g"  /etc/shadowsocks.json
		set_ssrurl
		white_font "     ————胖波比————\n"
		yello_font '—————————————————————————'
		green_font ' 1.' '  继续更改端口'
		green_font ' 2.' '  返回SSR用户管理页'
		yello_font '—————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 3.' '  退出脚本'
		yello_font "—————————————————————————\n"
		read -p "请输入数字[0-3](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			change_port
			;;
			2)
			manage_ssr
			;;
			3)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-3]"
			sleep 2s
			manage_ssr
			;;
		esac
	}
	#更改加密
	change_method(){
		method1=$(jq -r '.method' /etc/shadowsocks.json)
		set_method
		sed -i "s/${method1}/${method}/g"  /etc/shadowsocks.json
		view_ssrurl '1'
	}
	#更改协议
	change_protocol(){
		protocol1=$(jq -r '.protocol' /etc/shadowsocks.json)
		set_protocol
		sed -i "s/${protocol1}/${protocol}/g"  /etc/shadowsocks.json
		SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
		view_ssrurl '1'
	}
	#更改混淆
	change_obfs(){
		obfs1=$(jq -r '.obfs' /etc/shadowsocks.json)
		set_obfs
		sed -i "s/${obfs1}/${obfs}/g"  /etc/shadowsocks.json
		SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
		view_ssrurl '1'
	}
	
	#管理SSR配置
	manage_ssr(){
		clear
		get_info
		white_font "\n   SSR用户管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font '	  -- 胖波比 --'
		white_font "手动修改配置文件：vi /etc/shadowsocks.json\n"
		yello_font '———————SSR用户管理———————'
		green_font ' 1.' '  更改密码'
		green_font ' 2.' '  查看用户链接'
		yello_font '—————————————————————————'
		green_font ' 3.' '  添加用户'
		green_font ' 4.' '  删除用户'
		yello_font '—————————————————————————'
		green_font ' 5.' '  更改端口'
		green_font ' 6.' '  更改加密'
		green_font ' 7.' '  更改协议'
		green_font ' 8.' '  更改混淆'
		yello_font '—————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 9.' '  退出脚本'
		yello_font "—————————————————————————\n"
		read -p "请输入数字[0-9](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			change_pw
			;;
			2)
			view_ssrurl '2'
			;;
			3)
			add_user
			;;
			4)
			delete_user
			;;
			5)
			change_port
			;;
			6)
			change_method
			;;
			7)
			change_protocol
			;;
			8)
			change_obfs
			;;
			9)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-9]"
			sleep 2s
			manage_ssr
			;;
		esac
	}
	
	# Initialization step
	start_menu_ssr(){
		clear
		white_font "\n SSR一键安装脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	 -- 胖波比 --\n"
		yello_font '—————————SSR安装—————————'
		green_font ' 1.' '  管理SSR用户'
		yello_font '—————————————————————————'
		green_font ' 2.' '  安装SSR'
		green_font ' 3.' '  卸载SSR'
		yello_font '—————————————————————————'
		green_font ' 4.' '  重启SSR'
		green_font ' 5.' '  关闭SSR'
		green_font ' 6.' '  启动SSR'
		green_font ' 7.' '  查看SSR状态'
		yello_font '—————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 8.' '  退出脚本'
		yello_font "—————————————————————————\n"
		read -p "请输入数字[0-8](默认:1)：" num
		[ -z $num ] && num=1
		case $num in
			0)
			start_menu_main
			;;
			1)
			manage_ssr
			;;
			2)
			install_shadowsocksr
			;;
			3)
			uninstall_shadowsocksr
			;;
			4)
			service shadowsocks restart
			check_vpn_status 'service shadowsocks status' 'SSR' '重启'
			;;
			5)
			service shadowsocks stop
			;;
			6)
			service shadowsocks start
			check_vpn_status 'service shadowsocks status' 'SSR' '启动'
			;;
			7)
			check_vpn_status 'service shadowsocks status' 'SSR' '运行'
			;;
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
			sleep 2s
			start_menu_ssr
			;;
		esac
	}
	start_menu_ssr
}

#卸载全部加速
remove_all(){
	rm -rf bbrmod
	sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
	sed -i '/fs.file-max/d' /etc/sysctl.conf
	sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
	sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
	sed -i '/net.core.rmem_default/d' /etc/sysctl.conf
	sed -i '/net.core.wmem_default/d' /etc/sysctl.conf
	sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
	sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_tw_recycle/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_keepalive_time/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
	sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
	sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
	sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
	sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
	if [[ -e /appex/bin/lotServer.sh ]]; then
		bash <(wget --no-check-certificate -qO- ${bbrgithub}/Install.sh) uninstall
	fi
}
#启用BBRplus
startbbrplus(){
	if [[ `lsmod|grep bbr|awk '{print $1}'` != 'tcp_bbrplus' ]]; then
		remove_all
		echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control=bbrplus" >> /etc/sysctl.conf
		sysctl -p
	fi
	clear && echo
	white_font '已安装\c' && green_font 'BBRPLUS\c' && white_font '内核！BBRPLUS启动\c'
	if [[ `lsmod|grep bbr|awk '{print $1}'` == 'tcp_bbrplus' ]]; then
		green_font '成功！\n'
		echo 'bbrplus' > /root/test/de
	else
		red_font '失败！\n'
		echo 'false' > /root/test/de
	fi
	sleep 2s
	exec ./xbdz.sh
}

check_port(){
	unset port
	until [[ ${port} -ge "1" && ${port} -le "65535" ]]
	do
		clear
		echo && read -p "${webinfo}" port
		[ -z "${port}" ] && port=80
		if [[ -n "$(lsof -i:${port})" ]]; then
			echo -e "${Error}端口${port}已被占用！请输入新的端口!!!"
			sleep 2s && check_port
		fi
	done
}
set_fakeweb(){
	clear
	webinfo='请输入网站访问端口(未占用端口)(默认:80)：'
	check_port
	install_docker
	i=0
	until [[ $i -ge '1' && ! -d "${fakeweb}" ]]
	do
		i=$[$i+1] && fakeweb="/opt/fakeweb${i}"
	done
	mkdir -p ${fakeweb} && cd ${fakeweb}
	wget https://raw.githubusercontent.com/AmuyangA/public/master/panel/nginx/dingyue.zip
	wget https://raw.githubusercontent.com/AmuyangA/public/master/panel/nginx/docker-compose.yml
	unzip dingyue.zip
	sed -i "s#weburl#http://$(get_ip):${port}#g" ${fakeweb}/html/dingyue.html
	sed -i "s#de_port#${port}#g" docker-compose.yml
	echo -e "${Info}首次启动会拉取镜像，国内速度比较慢，请耐心等待完成..."
	docker-compose up -d
}

#生成字符二维码
manage_qrcode(){
	clear
	echo && read -p "请输入生成二维码的链接：" num
	qrencode -o - -t ANSI "${num}"
	white_font "\n   -- 胖波比 --\n"
	yello_font '—————二维码生成——————'
	green_font ' 1.' '  继续生成'
	yello_font '—————————————————————'
	green_font ' 0.' '  回到主页'
	green_font ' 2.' '  退出脚本'
	yello_font "—————————————————————\n"
	read -p "请输入数字[0-2](默认:0)：" num
	[ -z $num ] && num=0
	case $num in
		0)
		start_menu_main
		;;
		1)
		manage_qrcode
		;;
		2)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}请输入正确数字 [0-2]"
		sleep 2s
		manage_qrcode
		;;
	esac
}

#安装宝塔面板
manage_btpanel(){
	set_btpanel(){
		clear
		bt
		echo -e "${Info}按任意键继续..."
		char=`get_char`
	}
	install_btpanel(){
		wget -qO install_panel.sh "${github}/panel/btpanel/install_panel.sh" && chmod +x install_panel.sh && ./install_panel.sh
		start_menu_main
	}
	start_menu_btpanel(){
		clear
		white_font "\n BT-PANEL一键安装脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	-- 胖波比 --\n"
		yello_font '———————BT-PANEL管理—————————'
		green_font ' 1.' '  管理BT-PANEL'
		yello_font '————————————————————————————'
		green_font ' 2.' '  安装BT-PANEL'
		green_font ' 3.' '  卸载BT-PANEL'
		green_font ' 4.' '  解除拉黑,解锁文件'
		yello_font '————————————————————————————'
		green_font ' 5.' '  重启BT-PANEL'
		green_font ' 6.' '  关闭BT-PANEL'
		green_font ' 7.' '  启动BT-PANEL'
		green_font ' 8.' '  查看BT-PANEL状态'
		yello_font '————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 9.' '  退出脚本'
		yello_font "————————————————————————————\n"
		read -p "请输入数字[0-9](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			set_btpanel
			;;
			2)
			install_btpanel
			;;
			3)
			wget -O bt_uninstall.sh https://raw.githubusercontent.com/AmuyangA/public/master/panel/btpanel/bt_uninstall.sh && chmod +x bt_uninstall.sh && ./bt_uninstall.sh
			;;
			4)
			wget -O waf.sh https://raw.githubusercontent.com/AmuyangA/public/master/panel/btpanel/waf.sh && chmod +x waf.sh && ./waf.sh
			;;
			5)
			bt restart
			check_vpn_status 'bt status' '宝塔面板' '重启'
			;;
			6)
			bt stop
			;;
			7)
			bt start
			check_vpn_status 'bt status' '宝塔面板' '启动'
			;;
			8)
			check_vpn_status 'bt status' '宝塔面板' '运行'
			;;
			9)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-9]"
			sleep 2s
			start_menu_btpanel
			;;
		esac
		start_menu_btpanel
	}
	start_menu_btpanel
}

#设置SSH端口
set_ssh(){
	clear
	ssh_port=$(cat /etc/ssh/sshd_config |grep 'Port ' |awk -F ' ' '{print $2}')
	while :; do echo
		read -p "请输入要修改为的SSH端口(默认:$ssh_port)：" SSH_PORT
		[ -z "$SSH_PORT" ] && SSH_PORT=$ssh_port
		if [ $SSH_PORT -eq 22 >/dev/null 2>&1 -o $SSH_PORT -gt 1024 >/dev/null 2>&1 -a $SSH_PORT -lt 65535 >/dev/null 2>&1 ];then
			break
		else
			echo "${Error}input error! Input range: 22,1025~65534${CEND}"
		fi
	done
	if [[ ${SSH_PORT} != "${ssh_port}" ]]; then
		#开放安全权限
		if type sestatus >/dev/null 2>&1 && [ $(getenforce) != "Disabled" ]; then
			if type semanage >/dev/null 2>&1 && [ ${release} == "centos" ]; then
				pack_semanage=$(yum provides semanage|grep ' : '|head -1|awk -F ' :' '{print $1}')
				yum -y install ${pack_semanage}
			fi
			semanage port -a -t ssh_port_t -p tcp ${SSH_PORT}
		fi
		#修改SSH端口
		sed -i "s/.*Port ${ssh_port}/Port ${SSH_PORT}/g" /etc/ssh/sshd_config
		#开放端口
		port=$SSH_PORT
		add_firewall
		port=$ssh_port
		delete_firewall
		firewall_restart
		#重启SSH
		if [[ ${release} == "centos" ]]; then
			service sshd restart
		else
			service ssh restart
		fi
		#关闭安全权限
		if type semanage >/dev/null 2>&1 && [ ${ssh_port} != '22' ]; then
			semanage port -d -t ssh_port_t -p tcp ${ssh_port}
		fi
		echo -e "${Info}SSH防火墙已重启！"
	fi
	echo -e "${Info}已将SSH端口修改为：$(red_font $SSH_PORT)"
	echo -e "\n${Info}按任意键返回主页..."
	char=`get_char`
}

#设置Root密码
set_root(){
	clear
	white_font "\n     ————胖波比————\n"
	yello_font '——————————————————————————'
	green_font ' 1.' '  使用高强度随机密码'
	green_font ' 2.' '  输入自定义密码'
	yello_font '——————————————————————————'
	green_font ' 0.' '  回到主页'
	green_font ' 3.' '  退出脚本'
	yello_font "——————————————————————————\n"
	read -p "请输入数字[0-3](默认:1)：" num
	[ -z $num ] && num=1
	case $num in
		0)
		start_menu_main
		;;
		1)
		pw=$(tr -dc 'A-Za-z0-9!@#$%^&*()[]{}+=_,' </dev/urandom | head -c 17)
		;;
		2)
		read -p "请设置密码(默认:pangbobi)：" pw
		[ -z $pw ] && pw="pangbobi"
		;;
		3)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}请输入正确数字 [0-3]"
		sleep 2s
		set_root
		;;
	esac
	echo root:${pw} | chpasswd
	# 启用root密码登陆
	sed -i '1,/PermitRootLogin/{s/.*PermitRootLogin.*/PermitRootLogin yes/}' /etc/ssh/sshd_config
	sed -i '1,/PasswordAuthentication/{s/.*PasswordAuthentication.*/PasswordAuthentication yes/}' /etc/ssh/sshd_config
	# 重启ssh服务
	if [[ ${release} == "centos" ]]; then
		service sshd restart
	else
		service ssh restart
	fi
	echo -e "\n${Info}您的密码是：$(red_font $pw)，下次登录将使用新密码!!!"
	echo -e "${Tip}请务必记录您的密码！然后任意键返回主页"
	char=`get_char`
}

#设置防火墙
set_firewall(){
	add_firewall_single(){
		until [[ "${port}" -ge "1" && "${port}" -le "65535" ]]
		do
			echo && read -p "请输入端口号[1-65535]：" port
		done
		add_firewall
		firewall_restart
	}
	delete_firewall_single(){
		until [[ "${port}" -ge "1" && "${port}" -le "65535" ]]
		do
			echo && read -p "请输入端口号[1-65535]：" port
		done
		delete_firewall
		firewall_restart
	}
	delete_firewall_free(){
		if [[ ${release} == "centos" &&  ${version} -ge "7" ]]; then
			port_array=($(firewall-cmd --zone=public --list-ports|sed 's# #\n#g'|grep tcp|sed 's#/tcp##g'))
			length=${#port_array[@]}
			for(( i = 0; i < ${length}; i++ ))
			do
				[[ -z $(lsof -i:${port_array[$i]}) ]] &&  firewall-cmd --zone=public --remove-port=${port_array[$i]}/tcp --remove-port=${port_array[$i]}/udp --permanent >/dev/null 2>&1
			done
		else
			clean_iptables_free(){
				TYPE=$1
				LINE_ARRAY=($(iptables -nvL $TYPE --line-number|grep :|awk -F ':' '{print $2"  " $1}'|awk '{print $2" "$1}'|awk -F ' ' '{print $1}'))
				port_array=($(iptables -nvL $TYPE --line-number|grep :|awk -F ':' '{print $2"  " $1}'|awk '{print $2" "$1}'|awk -F ' ' '{print $2}'))
				length=${#LINE_ARRAY[@]} && t=0
				for(( i = 0; i < ${length}; i++ ))
				do
					if [[ -z $(lsof -i:${port_array[$i]}) ]]; then
						LINE_ARRAY[$i]=$[${LINE_ARRAY[$i]}-$t]
						iptables -D $TYPE ${LINE_ARRAY[$i]}
						t=$[${t}+1]
					fi
				done
			}
			clean_iptables_free INPUT
			clean_iptables_free OUTPUT
			if [ -e /root/test/ipv6 ]; then
				clean_ip6tables_free(){
					TYPE=$1
					LINE_ARRAY=($(ip6tables -nvL $TYPE --line-number|grep :|awk '{printf "%s %s\n",$1,$NF}'|awk -F ' ' '{print $1}'))
					port_array=($(ip6tables -nvL $TYPE --line-number|grep :|awk '{printf "%s %s\n",$1,$NF}'|awk -F ':' '{print $2}'))
					length=${#LINE_ARRAY[@]} && t=0
					for(( i = 0; i < ${length}; i++ ))
					do
						if [[ -z $(lsof -i:${port_array[$i]}) ]]; then
							LINE_ARRAY[$i]=$[${LINE_ARRAY[$i]}-$t]
							ip6tables -D $TYPE ${LINE_ARRAY[$i]}
							t=$[${t}+1]
						fi
					done
				}
				clean_ip6tables_free INPUT
				clean_ip6tables_free OUTPUT
			fi
		fi
		firewall_restart
	}
	add_firewall_all(){
		if [[ ${release} == 'centos' &&  ${version} -ge '7' ]]; then
			firewall-cmd --zone=public --add-port=1-65535/tcp --add-port=1-65535/udp --permanent >/dev/null 2>&1
		else
			iptables -I INPUT -p tcp --dport 1:65535 -j ACCEPT
			iptables -I INPUT -p udp --dport 1:65535 -j ACCEPT
			if [ -e /root/test/ipv6 ]; then
				ip6tables -I INPUT -p tcp --dport 1:65535 -j ACCEPT
				ip6tables -I INPUT -p udp --dport 1:65535 -j ACCEPT
			fi
		fi
		firewall_restart
	}
	delete_firewall_all(){
		echo -e "${Info}开始设置防火墙..."
		if [[ ${release} == "centos" && ${version} -ge "7" ]]; then
			firewall-cmd --zone=public --remove-port=1-65535/tcp --remove-port=1-65535/udp --permanent >/dev/null 2>&1
		else
			iptables -P INPUT ACCEPT
			iptables -F
			iptables -X
			if [ -e /root/test/ipv6 ]; then
				ip6tables -P INPUT ACCEPT
				ip6tables -F
				ip6tables -X
			fi
		fi
		add_firewall_base
		firewall_restart
	}
	clear
	unset port
	white_font "\n Firewall一键管理脚本 \c" && red_font "[v${sh_ver}]"
	white_font "	-- 胖波比 --\n"
	yello_font '————————Firewall管理————————'
	green_font ' 1.' '  开放防火墙端口'
	green_font ' 2.' '  关闭防火墙端口'
	green_font ' 3.' '  关闭空闲端口'
	green_font ' 4.' '  开放所有防火墙'
	green_font ' 5.' '  关闭所有防火墙'
	yello_font '————————————————————————————'
	green_font ' 0.' '  回到主页'
	green_font ' 6.' '  退出脚本'
	yello_font "————————————————————————————\n"
	read -p "请输入数字[0-6](默认:1)：" num
	[ -z "${num}" ] && num=1
	clear
	case "$num" in
		0)
		start_menu_main
		;;
		1)
		add_firewall_single
		;;
		2)
		delete_firewall_single
		;;
		3)
		delete_firewall_free
		;;
		4)
		add_firewall_all
		;;
		5)
		delete_firewall_all
		;;
		6)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}请输入正确数字 [0-6]"
		sleep 2s
		set_firewall
		;;
	esac
	set_firewall
}

#系统性能测试
test_sys(){
	clear
	bash <(curl -Lso- https://git.io/superspeed)
	echo -e "${Info}测试已结束，任意键返回主页..."
	char=`get_char`
}

#重装VPS系统
reinstall_sys(){
	sysgithub="https://raw.githubusercontent.com/chiakge/installNET/master/InstallNET.sh"
	#安装环境
	first_job(){
		if [[ ${release} == "centos" ]]; then
			yum install -y xz openssl gawk file
		elif [[ ${release} == "debian" || ${release} == "ubuntu" ]]; then
			apt-get update
			apt-get install -y xz-utils openssl gawk file	
		fi
	}
	# 安装系统
	InstallOS(){
		clear
		TYPE=$1
		echo -e "\n${Info}重装系统需要时间,请耐心等待..."
		echo -e "${Tip}重装完成后,请用root身份从22端口连接服务器！\n"
		white_font '     ————胖波比————'
		yello_font '—————————————————————————'
		green_font ' 0.' '  返回主页'
		green_font ' 1.' '  使用高强度随机密码'
		green_font ' 2.' '  输入自定义密码'
		yello_font "—————————————————————————\n"
		read -p "请输入数字[0-2](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			pw=$(tr -dc 'A-Za-z0-9!@#$%^&*()[]{}+=_,' </dev/urandom | head -c 17)
			;;
			2)
			read -p "请设置密码(默认:pangbobi)：" pw
			[ -z $pw ] && pw="pangbobi"
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-2]"
			sleep 2s
			reinstall_sys
			;;
		esac
		echo -e "\n${Info}您的密码是：$(red_font $pw)"
		echo -e "${Tip}请务必记录您的密码！然后任意键继续..."
		char=`get_char`
		if [[ ${model} == "自动" ]]; then
			model="a"
		else 
			model="m"
		fi
		if [[ ${country} == "国外" ]]; then
			country=""
		else 
			if [[ ${os} == "c" ]]; then
				country="--mirror https://mirrors.tuna.tsinghua.edu.cn/centos/"
			elif [[ ${os} == "u" ]]; then
				country="--mirror https://mirrors.tuna.tsinghua.edu.cn/ubuntu/"
			elif [[ ${os} == "d" ]]; then
				country="--mirror https://mirrors.tuna.tsinghua.edu.cn/debian/"
			fi
		fi
		wget --no-check-certificate $sysgithub && chmod +x InstallNET.sh
		bash InstallNET.sh -${os} ${TYPE} -v ${vbit} -${model} -p ${pw} ${country}
	}
	# 安装系统
	installadvanced(){
		read -p "请设置参数：" advanced
		wget --no-check-certificate $sysgithub && chmod +x InstallNET.sh
		bash InstallNET.sh $advanced
	}

	# 切换位数
	switchbit(){
		if [[ ${vbit} == "64" ]]; then
			vbit="32"
		else
			vbit="64"
		fi
	}
	# 切换模式
	switchmodel(){
		if [[ ${model} == "自动" ]]; then
			model="手动"
		else
			model="自动"
		fi
	}
	# 切换国家
	switchcountry(){
		if [[ ${country} == "国外" ]]; then
			country="国内"
		else
			country="国外"
		fi
	}

	#安装CentOS
	installCentos(){
		clear
		os="c"
		white_font "\n 一键网络重装管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "		  -- 胖波比 --\n"
		yello_font '————————————选择版本————————————'
		green_font ' 1.' '  安装 CentOS6.8系统'
		green_font ' 2.' '  安装 CentOS6.9系统'
		yello_font '————————————切换模式————————————'
		green_font ' 3.' '  切换安装位数'
		green_font ' 4.' '  切换安装模式'
		green_font ' 5.' '  切换镜像源'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 6.' '  返回上页'
		green_font ' 7.' '  退出脚本'
		yello_font "————————————————————————————————\n"
		echo -e "当前模式: 安装$(red_font $vbit)位系统,$(red_font $model)模式,$(red_font $country)镜像源.\n"
		read -p "请输入数字[0-7](默认:6)：" num
		[ -z "${num}" ] && num=6
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			InstallOS "6.8"
			;;
			2)
			InstallOS "6.9"
			;;
			3)
			switchbit
			installCentos
			;;
			4)
			switchmodel
			installCentos
			;;
			5)
			switchcountry
			installCentos
			;;
			6)
			start_menu_resys
			;;
			7)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-7]"
			sleep 2s
			installCentos
			;;
		esac
	}
	#安装Debian
	installDebian(){
		clear
		os="d"
		white_font "\n 一键网络重装管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "		  -- 胖波比 --\n"
		yello_font '————————————选择版本————————————'
		green_font ' 1.' '  安装 Debian7系统'
		green_font ' 2.' '  安装 Debian8系统'
		green_font ' 3.' '  安装 Debian9系统'
		yello_font '————————————切换模式————————————'
		green_font ' 4.' '  切换安装位数'
		green_font ' 5.' '  切换安装模式'
		green_font ' 6.' '  切换镜像源'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 7.' '  返回上页'
		green_font ' 8.' '  退出脚本'
		yello_font "————————————————————————————————\n"
		echo -e "当前模式: 安装$(red_font $vbit)位系统,$(red_font $model)模式,$(red_font $country)镜像源.\n"
		read -p "请输入数字[0-8](默认:3)：" num
		[ -z "${num}" ] && num=3
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			InstallOS "7"
			;;
			2)
			InstallOS "8"
			;;
			3)
			InstallOS "9"
			;;
			4)
			switchbit
			installDebian
			;;
			5)
			switchmodel
			installDebian
			;;
			6)
			switchcountry
			installDebian
			;;
			7)
			start_menu_resys
			;;
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
			sleep 2s
			installCentos
			;;
		esac
	}
	#安装Ubuntu
	installUbuntu(){
		clear
		os="u"
		white_font "\n 一键网络重装管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "		  -- 胖波比 --\n"
		yello_font '————————————选择版本————————————'
		green_font ' 1.' '  安装 Ubuntu14系统'
		green_font ' 2.' '  安装 Ubuntu16系统'
		green_font ' 3.' '  安装 Ubuntu18系统'
		yello_font '————————————切换模式————————————'
		green_font ' 4.' '  切换安装位数'
		green_font ' 5.' '  切换安装模式'
		green_font ' 6.' '  切换镜像源'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 7.' '  返回上页'
		green_font ' 8.' '  退出脚本'
		yello_font "————————————————————————————————\n"
		echo -e "当前模式: 安装$(red_font $vbit)位系统,$(red_font $model)模式,$(red_font $country)镜像源.\n"
		read -p "请输入数字[0-8](默认:3)：" num
		[ -z "${num}" ] && num=3
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			InstallOS "trusty"
			;;
			2)
			InstallOS "xenial"
			;;
			3)
			InstallOS "cosmic"
			;;
			4)
			switchbit
			installUbuntu
			;;
			5)
			switchmodel
			installUbuntu
			;;
			6)
			switchcountry
			installUbuntu
			;;
			7)
			start_menu_resys
			;;
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
			sleep 2s
			installCentos
			;;
		esac
	}

	#开始菜单
	start_menu_resys(){
		clear
		white_font "\n 一键网络重装管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "		  -- 胖波比 --\n"
		yello_font '————————————重装系统————————————'
		green_font ' 1.' '  安装 CentOS系统'
		green_font ' 2.' '  安装 Debian系统'
		green_font ' 3.' '  安装 Ubuntu系统'
		green_font ' 4.' '  高级模式(自定义参数)'
		yello_font '————————————切换模式————————————'
		green_font ' 5.' '  切换安装位数'
		green_font ' 6.' '  切换安装模式'
		green_font ' 7.' '  切换镜像源'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 8.' '  退出脚本'
		yello_font "————————————————————————————————\n"
		echo -e "当前模式: 安装$(red_font $vbit)位系统,$(red_font $model)模式,$(red_font $country)镜像源.\n"
		read -p "请输入数字[0-8](默认:2)：" num
		[ -z "${num}" ] && num=2
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			installCentos
			;;
			2)
			installDebian
			;;
			3)
			installUbuntu
			;;
			4)
			installadvanced
			;;
			5)
			switchbit
			start_menu_resys
			;;
			6)
			switchmodel
			start_menu_resys
			;;
			7)
			switchcountry
			start_menu_resys
			;;
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
			sleep 2s
			start_menu_resys
			;;
		esac
	}
	first_job
	model="自动"
	vbit="64"
	country="国外"
	start_menu_resys
}

#更新脚本
update_sv(){
	clear
	newgithub="${github}/panel/nginx/xbdz.sh"
	echo -e "\n${Info}当前版本为 [ ${sh_ver} ]，开始检测最新版本..."
	sh_new_ver=$(curl -sH "${newgithub}"|grep 'sh_ver="'|head -1|awk -F "=" '{print $NF}'|sed 's/\"//g')
	[[ -z $sh_new_ver ]] && echo -e "${Error}检测最新版本失败！"
	if [[ ${sh_new_ver} != ${sh_ver} ]]; then
		echo -e "${Info}发现新版本 [ ${sh_new_ver} ]"
		echo -e "${Info}正在更新..."
		wget -qO xbdz.sh $newgithub
		chmod +x xbdz.sh
		sed -i "s#我们爱中国#${myinfo}#g" xbdz.sh
		exec ./xbdz.sh
	else
		echo -e "${Info}当前已是最新版本[ ${sh_new_ver} ] !"
	fi
	sleep 2s
}

#开始菜单
start_menu_main(){
	clear
	white_font "\n      小白特别定制版 \c" && red_font "[v${sh_ver}]"
	white_font '	  -- 胖波比 --'
	white_font '	执行脚本：./xbdz.sh'
	white_font "   终止正在进行的操作：Ctrl+C\n"
	yello_font ' 0.  赞赏作者'
	yello_font '—————————————VPN搭建——————————————'
	green_font ' 1.' '  V2Ray安装管理'
	green_font ' 2.' '  Trojan安装管理'
	green_font ' 3.' '  SSR安装管理'
	yello_font '—————————————节点相关—————————————'
	green_font ' 4.' '  生成链接二维码'
	yello_font '—————————————控制面板—————————————'
	green_font ' 5.' '  宝塔面板安装管理'
	yello_font '—————————————系统设置—————————————'
	green_font ' 6.' '  设置SSH端口'
	green_font ' 7.' '  设置root密码'
	green_font ' 8.' '  设置防火墙'
	green_font ' 9.' '  系统性能测试'
	green_font ' 10.' ' 重装VPS系统'
	yello_font '—————————————脚本设置—————————————'
	green_font ' 11.' ' 更新脚本'
	green_font ' 12.' ' 退出脚本'
	yello_font "——————————————————————————————————\n"
	read -p "请输入数字[0-12](默认:1)：" num
	[ -z $num ] && num=1
	case $num in
		0)
		donation_developer
		;;
		1)
		manage_v2ray
		;;
		2)
		manage_trojan
		;;
		3)
		install_ssr
		;;
		4)
		manage_qrcode
		;;
		5)
		manage_btpanel
		;;
		6)
		set_ssh
		;;
		7)
		set_root
		;;
		8)
		set_firewall
		;;
		9)
		test_sys
		;;
		10)
		reinstall_sys
		;;
		11)
		update_sv
		;;
		12)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}请输入正确数字 [0-12]"
		sleep 2s
		start_menu_main
		;;
	esac
	start_menu_main
}

check_sys
if [[ ! -e /root/test/de ]]; then
	[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error}本脚本不支持当前系统！" && exit 1

	#判断是否支持IPV6
	mkdir -p /root/test
	[ ! -z $(wget -qO- -t1 -T2 ipv6.icanhazip.com) ] && echo $(wget -qO- -t1 -T2 ipv6.icanhazip.com) > /root/test/ipv6
	if [[ ${release} == 'centos' ]]; then
		if [[ ${version} -ge '7' ]]; then
			systemctl start firewalld
			systemctl enable firewalld
		else
			service iptables save
			chkconfig --level 2345 iptables on
			if [ -e /root/test/ipv6 ]; then
				service ip6tables save
				chkconfig --level 2345 ip6tables on
			fi
		fi
	else
		mkdir -p /etc/network/if-pre-up.d
		iptables-save > /etc/iptables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules' > /etc/network/if-pre-up.d/iptables
		if [ -e /root/test/ipv6 ]; then
			ip6tables-save > /etc/ip6tables.up.rules
			echo -e '/sbin/ip6tables-restore < /etc/ip6tables.up.rules' >> /etc/network/if-pre-up.d/iptables
		fi
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
	echo 'export LANG="en_US.UTF-8"' >> /root/.bash_profile

	add_firewall_base
	#是阿里云则卸载云盾
	org=$(wget -qO- -t1 -T2 https://ipapi.co/org)
	if [[ ${org} =~ 'Alibaba' ]]; then
		wget http://update.aegis.aliyun.com/download/uninstall.sh && chmod +x uninstall.sh && ./uninstall.sh
		wget http://update.aegis.aliyun.com/download/quartz_uninstall.sh && chmod +x quartz_uninstall.sh && ./quartz_uninstall.sh
		pkill aliyun-service
		rm -fr /etc/init.d/agentwatch /usr/sbin/aliyun-service /usr/local/aegis*
		rm -f uninstall.sh quartz_uninstall.sh
		iptables -I INPUT -s 140.205.201.0/28 -j DROP
		iptables -I INPUT -s 140.205.201.16/29 -j DROP
		iptables -I INPUT -s 140.205.201.32/28 -j DROP
		iptables -I INPUT -s 140.205.225.192/29 -j DROP
		iptables -I INPUT -s 140.205.225.200/30 -j DROP
		iptables -I INPUT -s 140.205.225.184/29 -j DROP
		iptables -I INPUT -s 140.205.225.183/32 -j DROP
		iptables -I INPUT -s 140.205.225.206/32 -j DROP
		iptables -I INPUT -s 140.205.225.205/32 -j DROP
		iptables -I INPUT -s 140.205.225.195/32 -j DROP
		iptables -I INPUT -s 140.205.225.204/32 -j DROP
	fi
	firewall_restart

	#安装依赖
	clear && echo -e "\n${Info}首次运行此脚本会安装依赖环境,按任意键继续..."
	char=`get_char`
	${PM} update
	${PM} -y install jq qrencode openssl git bash curl wget zip unzip gcc automake autoconf make libtool ca-certificates vim
	if [[ ${release} == 'centos' ]]; then
		yum -y install libnss3.so epel-release python36 openssl-devel
		if [[ ${version} == '8' ]]; then
			yum -y install python-pip
		else
			yum -y install python3-pip
		fi
	else
		apt-get --fix-broken install
		apt-get -y install libnss3 python python-pip python-setuptools libssl-dev
	fi

	#开启脚本自启
	if [[ `grep -c "./xbdz.sh" .bash_profile` -eq '0' ]]; then
		echo "./xbdz.sh" >> /root/.bash_profile
	fi

	#添加地区信息
	country=$(curl -s https://ipapi.co/country/)
	sed -i "s#${myinfo}#${country}-${myinfo}#g" xbdz.sh

	#脚本放在/root文件夹
	if [[ `pwd` != '/root' ]]; then
		cp xbdz.sh /root/xbdz.sh
		chmod +x /root/xbdz.sh
	fi

	#开启bbrplus
	kernel_version='4.14.129-bbrplus'
	bbrgithub='https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master'
	if [[ `uname -r` != "${kernel_version}" ]]; then
		if [[ ${bit} =~ "64" ]]; then
			bit="x64"
		else
			bit="x32"
		fi
		if [[ ${release} == 'debian' && ${version} -ge '8' ]] || [[ ${release} == 'centos' && ${version} == '7' ]] || [[ ${release} == 'ubuntu' && ${version} -ge '14' ]]; then
			if [[ ${release} == 'centos' ]]; then
				wget -N --no-check-certificate ${bbrgithub}/bbrplus/${release}/${version}/kernel-headers-${kernel_version}.rpm
				wget -N --no-check-certificate ${bbrgithub}/bbrplus/${release}/${version}/kernel-${kernel_version}.rpm
				yum install -y kernel-headers-${kernel_version}.rpm
				yum install -y kernel-${kernel_version}.rpm
				rm -f kernel-headers-${kernel_version}.rpm
				rm -f kernel-${kernel_version}.rpm
			else
				mkdir bbrplus && cd bbrplus
				wget -N --no-check-certificate ${bbrgithub}/bbrplus/debian-ubuntu/${bit}/linux-headers-${kernel_version}.deb
				wget -N --no-check-certificate ${bbrgithub}/bbrplus/debian-ubuntu/${bit}/linux-image-${kernel_version}.deb
				dpkg -i linux-headers-${kernel_version}.deb
				dpkg -i linux-image-${kernel_version}.deb
				cd .. && rm -rf bbrplus
			fi
			#删除多余内核
			if [[ ${release} == 'centos' ]]; then
				rpm_total=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | wc -l`
				if [ ${rpm_total} > '1' ]; then
					echo -e "${Info}检测到 ${rpm_total} 个其余内核，开始卸载..."
					for((integer = 1; integer <= ${rpm_total}; integer++)); do
						rpm_del=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer}`
						echo -e "${Info}开始卸载 ${rpm_del} 内核..."
						rpm --nodeps -e ${rpm_del}
						echo -e "${Info}卸载 ${rpm_del} 内核卸载完成，继续..."
					done
					echo -e "${Info}内核卸载完毕，继续..."
				else
					echo -e "${Info}检测到 内核 数量不正确，请检查 !" && exit 1
				fi
			else
				deb_total=`dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l`
				if [ ${deb_total} > '1' ]; then
					echo -e "${Info}检测到 ${deb_total} 个其余内核，开始卸载..."
					for((integer = 1; integer <= ${deb_total}; integer++)); do
						deb_del=`dpkg -l|grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer}`
						echo -e "${Info}开始卸载 ${deb_del} 内核..."
						apt-get purge -y ${deb_del}
						echo -e "${Info}卸载 ${deb_del} 内核卸载完成，继续..."
					done
					echo -e "${Info}内核卸载完毕，继续..."
				else
					echo -e "${Info}检测到 内核 数量不正确，请检查 !" && exit 1
				fi
			fi
			#更新引导
			if [[ ${release} == 'centos' ]]; then
				if [ ! -f '/boot/grub2/grub.cfg' ]; then
					echo -e "${Error}找不到 /boot/grub2/grub.cfg ，请检查..."
					exit 1
				fi
				grub2-set-default 0
			else
				/usr/sbin/update-grub
			fi
			echo 'false' > /root/test/de
			reboot
		else
			echo -e "${Error}BBRplus内核不支持${release} ${version} ${bit} !" && exit 1
			echo 'bbrplus' > /root/test/de
		fi
	else
		startbbrplus
	fi
elif [[ $(cat /root/test/de) == 'false' ]]; then
	startbbrplus
else
	start_menu_main
fi
