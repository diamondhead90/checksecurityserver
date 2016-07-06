#!/bin/bash
echo "----------------------------------------------- CHECK  OS -----------------------------------------------"
if [ -f /etc/redhat-release ]; then
		os_version="CentOS"
		os=`cat /etc/redhat-release`
		echo "OS VERSION: "$os
elif [ -f /etc/lsb-release ]; then
		os_version="Ubuntu"
		os=`cat /etc/os-release | grep "PRETTY_NAME" | sed 's/PRETTY_NAME=//g' | sed 's/["]//g' | awk '{print $1" " $2}'`
		echo "OS VERSION: "$os
else 
		echo "Dont know OS"
fi
echo "----------------------------------------------- CHECK SSH -----------------------------------------------"
ssh_pam=`cat /etc/ssh/sshd_config |grep "^UsePAM" |awk {'print $2'}`
ssh_response=`cat /etc/ssh/sshd_config |grep "^ChallengeResponseAuthentication" |awk {'print $2'}`
ssh_port=`cat /etc/ssh/sshd_config |grep "^Port" |awk {'print $2'}`
ssh_include=`cat /etc/ssh/sshd_config |grep "@include"`
if [ -z "$ssh_port" ]; then
        ssh_port_use=22
else
        ssh_port_use=$ssh_port
fi
echo "[+] SEVER USE PORT SSH: " $ssh_port_use

if [[ (( "$ssh_pam" == "yes" ) || ( "$ssh_pam" == "Yes" )) && (("$ssh_response" == "yes") || ("$ssh_response" == "Yes"))  ]]; then
        check_otp_google=$(cat /etc/pam.d/* |grep "pam_google_authenticator.so" |wc -l)
        check_otpw=$(cat /etc/pam.d/* |grep "pam_otpw.so" |wc -l)
        check_linotp=$(cat /etc/pam.d/* |grep "pam_linotp.so" |wc -l)
        check_openotp=$(cat /etc/pam.d/* |grep "pam_openotp.so" |wc -l)
        if [ $check_otp_google -ge 1 ]; then
                echo "[+] SERVER CONFIGURE: GOOGLE OTP"
        elif [ $check_otpw -ge 1 ]; then
                echo "[+] SERVER CONFIGURE: OTPW"
        elif [ $check_linotp -ge 1 ]; then
                echo "[+] SERVER CONFIGURE: LinOTP"
        elif [ $check_openotp -ge 1 ]; then
                echo "[+] SERVER CONFIGURE: OpenOTP"
        else
                echo "[+] DONT FIND OTP USE IN SERVER. CHECK MANUAL CONFIGURE OTP"
        fi
else
        echo "[+] DONT FIND OTP USE IN SERVER. CHECK MANUAL CONFIGURE OTP"
fi
limit_ip_ssh=$(iptables -n -L INPUT |grep "dpt:$ssh_port_use" |awk {'print $4'})
if [ -z $limit_ip_ssh ]; then
        echo  "[+] SERVER DONT CONFIGURE IPTABLES FOR SSH"
else
        echo "[+] SERVER CONFIGURE SSH SOURCE PORT LIMIT WITH IP:" $limit_ip_ssh
fi

echo "--------------------------------------------- CHECK IPTABLE ---------------------------------------------"
echo "[+] CHECK RULE IPTABLES CHAIN INPUT SERVER"
port_input=`iptables -n -L INPUT |grep "ACCEPT" |awk {'print $7}'|uniq |grep  -v "ESTABLISHED" |grep '[^[:blank:]]'`
if [ -z $port_output ]; then 
		echo "    [-] NO RULE IN CHAIN OUTPUT"
else
		for port in $port_input
				do
						list_ip=`iptables -n -L INPUT |grep "$port" |awk {'print $4'} |uniq`
						if [[ $port == type* ]]; then
								echo "    [-] SOURCE IP:" $list_ip " PORT: ICMP"
						else
								echo "    [-] SOURCE IP:" $list_ip " PORT: " $port
						fi
				done
fi
echo "[+] CHECK RULE IPTABLES CHAIN OUTPUT SERVER"
port_output=`iptables -n -L OUTPUT |grep "ACCEPT" |awk {'print $7}'|uniq |grep  -v "ESTABLISHED" |grep '[^[:blank:]]'`
if [ -z $port_output ]; then 
		echo "    [-] NO RULE IN CHAIN OUTPUT"
else
		for port in $port_output
        		do
                		list_ip=`iptables -n -L OUTPUT |grep "$port" |awk {'print $5'} |uniq`
						if [[ $port == type* ]]; then
								echo "    [-] DESTINATION IP:" $list_ip " PORT: ICMP"
						else
                				echo "    [-] DESTINATION IP:" $list_ip " PORT:"  $port
						fi
        		done
fi
echo "[+] CHECK RULE IPTABLES CHAIN FORWARD SERVER"
rule_forward=`iptables -n -L FORWARD |grep -v "Chain" |grep "ACCEPT" |awk '{ if (-length($7) == 0 ) print "    [-] SOURCE IP: ", $4 ,"  DEST IP: ", $ 5 ,"  PORT: ALL";else if ( match("type", $7) ) print "    [-] SOURCE IP: ", $4 ,"  DEST IP: ", $ 5 ,"  PORT: ICMP"; else print "    [-] SOURCE IP: ", $4 ,"  DEST IP: ", $ 5 ,"  PORT: ", $7, $8;}' |uniq`
if [ -z $rule_forward ]; then
		echo "    [-] NO RULE IN CHAIN FORWARD"
else
		for rule in "$rule_forward"
				do
						echo "$rule"
				done
fi

echo "--------------------------------------------- CHECK MALWARE ---------------------------------------------"
check_cron=`crontab -l 2>/dev/null`
if [ $? == 0 ]; then
	cron=1
else
	cron=0
fi
function check_schedule_crontab {
	for user in `cat /etc/passwd | cut -d":" -f1`;
        do
                a=`crontab -l -u $user |grep -v "^#" |grep $1 |wc -l`
        done
}
check_maldet=`maldet  2>/dev/null`
if [ $? == 0 ]; then
		ldm=1
		echo "[+] MALDET ALREADY INSTALLED"
else
		ldm=0
fi
check_clamav=`clamdscan -V  2>/dev/null`
if [ $? == 0 ]; then
		clamav=1
		echo "[+] CLAMAV ALREADY INSTALLED"
else
		clamav=0
fi
if [[ ($ldm -eq 1) && ( $clamav -eq 1 ) && ( $cron -eq 1 ) ]]; then
		check_scan_clamav_lmd=`check_schedule_crontab 'maldet -a'`
		if [ $check_scan_clamav_lmd -ge 1 ]; then
				echo "[+] CLAMAV_LDM ALREADY SCHEDULED SCAN"
		else
				echo "[+] DONT FIND CONFIGURE CLAMAV_LDM SCHEDULED SCAN ON CRONTAB. CHECK MANUAL"
		fi
		check_update_clamav_lmd=`check_schedule_crontab 'maldet -u'`
		if [ $check_update_clamav_lmd -ge 1 ]; then
				echo "[+] CLAMAV_LDM ALREADY SCHEDULED UPDATE"
		else
				echo "[+] DONT FIND CONFIGURE CLAMAV_LDM SCHEDULED UPDATE ON CRONTAB. CHECK MANUAL"
		fi
elif [[ ($ldm -ne 1) && ( $clamav -eq 1) && ( $cron -eq 1 ) ]]; then
		check_scan_clamav=`check_schedule_crontab 'clamavscan'`
		if [ $check_scan_clamav -ge 1 ]; then
				echo "[+] CLAMAV ALREADY SCHEDULED SCAN"
		else
				echo "[+] DONT FIND CONFIGURE CLAMAV SCHEDULED SCAN ON CRONTAB. CHECK MANUAL"
		fi
		check_update_clamav=`check_schedule_crontab 'freshclam'`
		if [ $check_update_clamav -ge 1 ]; then
				echo "[+] CLAMAV ALREADY SCHEDULED UPDATE"
		else
				echo "[+] DONT FIND CONFIGURE CLAMAV SCHEDULED UPDATE ON CRONTAB. CHECK MANUAL"
		fi
fi
check_avg=`avgscan -v  2>/dev/null`
if [ $? == 0 ]; then
		avg=1
		echo "[+] AVG ALREADY INSTALLED"
else
		avg=0
fi
if [[ ($avg -eq 1) && ( $cron -eq 1 ) ]]; then
		check_scan_avg=check_schedule_crontab 'avgscan'
		if [ $check_scan_avg -ge 1 ]; then
				echo "[+] AVG ANTIVIRUT ALREADY SCHEDULED SCAN"
		else
				echo "[+] DONT FIND CONFIGURE AVG ANTIVIRUT SCHEDULED SCAN ON CRONTAB. CHECK MANUAL"
		fi
		check_update_avg=`check_schedule_crontab 'avgupdate'`
		if [ $check_update_avg -ge 1 ]; then
				echo "[+] AVG ALREADY SCHEDULED UPDATE"
		else
				echo "[+] DONT FIND CONFIGURE AVG SCHEDULED UPDATE ON CRONTAB. CHECK MANUAL"
		fi
fi

check_chkrootkit=`chkrootkit -V 2>/dev/null`
if [ $? == 1 ]; then
		chkrootkit=1
		echo "[+] CHKROOTKIT ALREADY INSTALLED"
else
		chkrootkit=0
fi
if [[ ($chkrootkit -eq 1) && ( $cron -eq 1 ) ]]; then
		check_scan_chkrootkit=`check_schedule_crontab 'chkrootkit'`
		if [ $check_scan_chkrootkit -ge 1 ]; then
				echo "[+] CHKROOTKIT ALREADY SCHEDULED SCAN"
		else
				echo "[+] DONT FIND CONFIGURE CHKROOTKIT SCHEDULED SCAN ON CRONTAB. CHECK MANUAL"
		fi
fi

check_rkhunter=`rkhunter --versioncheck 2>/dev/null`
if [ $? == 0 ]; then
		rkhunter=1
		echo "[+] RKHUNTER ALREADY INSTALLED"
else
		rkhunter=0
fi
if [[ ($rkhunter -eq 1) && ( $cron -eq 1 ) ]]; then
		check_scan_rkhunter=`check_schedule_crontab 'rkhunter'`
		if [ $check_scan_rkhunter -ge 1 ]; then
				echo "[+] RKHUNTER ALREADY SCHEDULED SCAN"
		else
				echo "[+] DONT FIND CONFIGURE RKHUNTER SCHEDULED SCAN ON CRONTAB. CHECK MANUAL"
		fi
fi
if [ $cron -eq 0 ]; then
		echo "[+] CRONTAB NO CONFIGURE TO ANOTHER USER. PLEASE CONFIRM INFORMATION CHECK SCHEDULED UPDATE AND SCAN MALWARE!"
fi

echo "--------------------------------------------- CHECK  POLICY ---------------------------------------------"
# PARAMETER
PASS=`echo -e "[ PASS ]"`
FAIL=`echo -e "[ FAIL ]"`
NOT_CHECKED=`echo -e "[ NOT CHECKED ]"`
function not_check {
	echo $NOT_CHECKED
}

# Parameter return 0 or OFF is PASS
function alert0 {
 	if [[ ( $1 -le 0 ) || ( "$1" == "off" ) ]];then
		echo $PASS
	else 
		echo $FAIL
	fi
}
# Parameter return 1 or ON is PASS
function alert1 {
 	if [[ ( $1 -ge 1 ) || ( "$1" == "on" ) ]];then
		echo $PASS
	else 
		echo $FAIL
	fi
}
# Two Parameter return 0 is PASS
function alert00 {
 	if [[ ( $1 -eq 0 ) && ( $2 -eq 0 ) ]];then
		echo $PASS
	else 
		echo $FAIL
	fi
}
# Two Parameter return 1 is PASS
function alert11 {
 	if [[ ( $1 -ge 1 ) && ( $2 -ge 1 ) ]];then
		echo $PASS
	else 
		echo $FAIL
	fi
}

function check_partition {
	count1=`cat /etc/fstab |grep "[[:space:]]$1[[:space:]]" |wc -l`
	alert1 $count1
}

function check_option_partition {
	count1=`cat /etc/fstab | grep $2 |grep $1 | wc -l`
	count2=`mount | grep $2 |grep $1 | wc -l`
	alert11 $count1 $count2
}

function check_module_kernel {
	count1=`cat /etc/modprobe.d/*.conf |grep -w $1 |wc -l`
	count2=`lsmod |grep $1 |wc -l`
	if [[ $count1 -eq 1 && $count2 -eq 0 ]]; then
		echo $PASS
	else
		echo $FAIL
	fi
}
function check_directory_exit {
	check_directory_exit=`cat $1 2>/dev/null`
	}
function check_package_install {
	check_package=`dpkg -s $1 2>/dev/null | grep "^Status: install ok installed" | wc -l`
	alert1 $check_package
}

function check_package_not_install {
	check_package=`dpkg -s $1 2>/dev/null | grep "^Status: install ok installed" | wc -l`
	alert0 $check_package
}

function check_inet_service {
	kq1=`grep $1 /etc/inetd.conf 2>/dev/null |wc -l`
	if [[ $kq1 == 0 ]]
	then
	        echo $PASS
	else
	        echo $FAIL
	fi
}

function check_service_not_enable {
	kq1=`initctl show-config $1 2>/dev/null | grep "start" | wc -l`
	if [[ $kq1 == 0 ]]
	then
	        echo $PASS
	else
	        echo $FAIL
	fi
}

function check_service_enable {
	kq1=`initctl show-config $1 2>/dev/null | grep "start" | wc -l`
	if [[ $kq1 == 0 ]]
	then
	        echo $PASS
	else
	        echo $FAIL
	fi
}
function check_rpm_install {
	check_rpm=`rpm -q $1`
	check_OK=`echo $?`
	alert0 $check_OK
	}
function check_rpm_not_install {
	check_rpm=`rpm -q $1`
	check_NOT_OK=`echo $?`
	alert1 $check_NOT_OK
	}
function check_chkconfig_on {
	level=`runlevel |awk '{print $2}'`
	check_chk1=`chkconfig --list $1 2>/dev/null`
	if [ $? -eq 0 ]; then
		check_chk2=`chkconfig --list $1 | cut -d $level -f 2 |awk '{print $1}' | cut -d ':' -f 2`
		alert1 $check_chk2
	else
	echo $FAIL
	fi
}
function check_chkconfig_off {
	level=`runlevel |awk '{print $2}'`
	check_chk1=`chkconfig --list $1 2>/dev/null`
	if [ $? -eq 0 ]; then
	check_chk2=`chkconfig --list $1 | cut -d $level -f 2 |awk '{print $1}' | cut -d ':' -f 2`
	alert0 $check_chk2
	else
	echo $PASS
	fi
}
function check_chkconfg_xinetd_off {
	check_chk=`chkconfig --list $1 | awk '{print $2}' 2>/dev/null`
	alert0 $check_chk
}
if [ $os_version == "Ubuntu" ]; then
		echo      "---------------------------------------------------------------------------------------------------------"
		echo -n   "1. Patching and Software Updates:                                                        "
		not_check
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "2. Filesystem Configuration                                                              "
		echo -n   "    2.1. Create Separate Partition for /tmp                                              "
		check_partition /tmp
		echo -n   "    2.2. Set nodev option for /tmp Partition:                                            "
		check_option_partition /tmp nodev
		echo -n   "    2.3. Set nosuid option for /tmp Partition:                                           "
		check_option_partition /tmp nosuid
		echo -n   "    2.4. Set noexec option for /tmp Partition:                                           "
		check_option_partition /tmp noexec
		echo -n   "    2.5. Create Separate Partition for /var:                                             "
		check_partition /var
		echo -n   "    2.6. Bind Mount the /var/tmp directory to /tmp:                                      "
		count_bind=`grep -e "^/tmp[[:space:]]" /etc/fstab | grep /var/tmp |grep bind |wc -l`
		alert1 $count_bind
		echo -n   "    2.7. Create Separate Partition for /var/log:                                         "
		check_partition /var/log
		echo -n   "    2.8. Create Separate Partition for /var/log/audit:                                   "
		check_partition /var/log/audit
		echo -n   "    2.9. Create Separate Partition for /home:                                            "
		check_partition /home
		echo -n   "    2.10. Add nodev Option to /home:                                                     "
		check_option_partition /home nodev
		echo -n   "    2.11. Add nodev Option to Removable Media Partitions:                                "
		not_check
		echo -n   "    2.12. Add noexec Option to Removable Media Partitions:                               "
		not_check
		echo -n   "    2.13. Add nosuid Option to Removable Media Partitions:                               "
		not_check
		echo -n   "    2.14. Add nodev Option to /dev/shm Partition:                                        "
		check_option_partition /dev/shm nodev
		echo -n   "    2.15. Add nosuid Option to /dev/shm Partition:                                       "
		check_option_partition /dev/shm nosuid
		echo -n   "    2.16. Add noexec Option to /dev/shm Partition:                                       "
		check_option_partition /dev/shm noexec
		echo -n   "    2.17. Set Sticky Bit on All World-Writable Directories:                              "
		check_sticky_bit=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null |wc -l`
		alert0 $check_sticky_bit
		echo -n   "    2.18. Disable Mounting of cramfs Filesystems:                                        "
		check_module_kernel cramfs
		echo -n   "    2.19. Disable Mounting of freevxfs Filesystems:                                      "
		check_module_kernel freevxfs
		echo -n   "    2.20. Disable Mounting of jffs2 Filesystems:                                         "
		check_module_kernel jffs2
		echo -n   "    2.21. Disable Mounting of hfs Filesystems:                                           "
		check_module_kernel hfs
		echo -n   "    2.22. Disable Mounting of hfsplus Filesystems:                                       "
		check_module_kernel hfsplus
		echo -n   "    2.23. Disable Mounting of squashfs Filesystems:                                      "
		check_module_kernel squashfs
		echo -n   "    2.24. Disable Mounting of udf Filesystems:                                           "
		check_module_kernel udf
		echo -n   "    2.25. Disable Automounting:                                                          "
		not_check
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "3. Secure Boot Settings:                                                                 "
		echo -n   "    3.1 Set User/Group Owner on bootloader config:                                       "
		status_owner=`stat -L -c "%u %g" /boot/grub/grub.cfg`
		if [ "$status_owner" == "0 0" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "    3.2 Set Permissions on bootloader config:                                            "
		permission_grub=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /boot/grub/grub.cfg | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$permission_grub" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "    3.3. Set Boot Loader Password:                                                       "
		password_bootloader1=`cat /boot/grub/grub.cfg |grep "^set superusers" |wc -l`
		password_bootloader2=`cat /boot/grub/grub.cfg |grep "password_pbkdf2" |wc -l`
		alert11 $password_bootloader1 $password_bootloader2
		echo -n   "    3.4. Require Authentication for Single-User Mode:                                    "
		not_check
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "4. Additional Process Hardening:                                                         "
		echo -n   "    4.1. Restrict Core Dumps:                                                            "
		check_core_dump1=`cat /etc/security/limits.conf |grep 'hard' | grep 'core' | grep '*' | grep '0' |wc -l`
		check_core_dump2=`sysctl fs.suid_dumpable |awk '{print $3}'`
		if [[ ("$check_core_dump1" -eq "1") && ("$check_core_dump2" -eq "0") ]]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "    4.2. Enable XD/NX Support on 32-bit x86 Systems:                                     "
		result=`dmesg | grep " NX (Execute Disable) protection: active" | wc -l`
		alert0 $result
		echo -n   "    4.3. Enable Randomized Virtual Memory Region Placement:                              "
		check_random_vm=`sysctl kernel.randomize_va_space |awk '{print $3}'`
		if [ $check_random_vm -eq 2 ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "    4.4. Disable Prelink:                                                                "
		not_check
		echo -n   "    4.5. Activate AppArmor:                                                              "
		not_check
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "5. OS Services:                                                                          "
		echo      "    5.1. Ensure Legacy Services are Not Enabled:                                         "
		echo -n   "        5.1.1. Ensure nis is not installed:                                              "
		check_package_not_install nis
		echo -n   "        5.1.2. Ensure rsh server is not installed:                                       "
		check_package_not_install rsh-server
		echo -n   "        5.1.3. Ensure rsh client is not installed:                                       "
		kq1=$(check_package_not_install rsh-client)
		kq2=$(check_package_not_install rsh-redone-client)
		if [[ ( $kq1 == "$PASS" ) && ( $kq2 == "$PASS" )  ]]
		then
				echo $PASS
		else
				echo $FAIL
		fi
		echo -n   "        5.1.4. Ensure talk server is not enabled:                                        "
		kq1=`grep ^talk /etc/inetd.conf 2>/dev/null |wc -l`
		kq2=`grep ^ntalk /etc/inetd.conf 2>/dev/null |wc -l`
		if [[ ( $kq1 == 0 ) && ( $kq2 == 0 )  ]]
		then
				echo $PASS
		else
				echo $FAIL
		fi
		echo -n   "        5.1.5. Ensure talk client is not installed:                                      "
		check_package_not_install talk
		echo -n   "        5.1.6. Ensure telnet server is not enabled:                                      "
		check_inet_service telnet
		echo -n   "        5.1.7. Ensure tftp-server is not enabled:                                        "
		check_inet_service tftp
		echo -n   "        5.1.8. Ensure xinetd is not enabled:                                             "
		check_service_not_enable xinetd
		echo -n   "    5.2. Ensure chargen is not enabled:                                                  "
		check_inet_service chargen
		echo -n   "    5.3. Ensure daytime is not enabled:                                                  "
		check_inet_service daytime
		echo -n   "    5.4. Ensure echo is not enabled:                                                     "
		check_inet_service echo
		echo -n   "    5.5. Ensure discard is not enabled:                                                  "
		check_inet_service discard
		echo -n   "    5.6. Ensure time is not enabled:                                                     "
		check_inet_service time
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "6. Special Purpose Services:                                                             "
		echo -n   "    6.1. Ensure the X Window system is not installed:                                    "
		check_package_not_install xserver-xorg-core
		echo -n   "    6.2. Ensure Avahi Server is not enabled:                                             "
		check_service_not_enable avahi-daemon
		echo -n   "    6.3. Ensure print server is not enabled:                                             "
		check_service_not_enable cups
		echo -n   "    6.4. Ensure DHCP Server is not enabled:                                              "
		kq1=$(check_service_not_enable isc-dhcp-server)
		kq2=$(check_service_not_enable isc-dhcp-server6)
		if [[ ( $kq1 == "$PASS" ) && ( $kq2 == "$PASS" )  ]]
		then
				echo $PASS
		else
				echo $FAIL
		fi
		echo -n   "    6.5. Configure Network Time Protocol (NTP):                                          "
		r0=$(check_package_not_install ntp)
		r1=$(grep '^[^#]' /etc/ntp.conf | grep "restrict -4 default kod nomodify notrap nopeer noquery" 2>/dev/null | wc -l)
		r2=$(grep '^[^#]' /etc/ntp.conf | grep "restrict -6 default kod nomodify notrap nopeer noquery" 2>/dev/null | wc -l)
		r3=$(grep '^[^#]' /etc/ntp.conf | grep "server .*" 2>/dev/null | wc -l)
		if [[ ( $r0 == "$FAIL" ) && ( $r1 == 1 ) && ( $r2 == 1 ) && ( $r3 -ge 1 ) ]]
		then
				echo $PASS
		else
				echo $FAIL
		fi
		echo -n   "    6.6. Ensure LDAP is not enabled:                                                     "
		check_package_not_install slapd
		echo -n   "    6.7. Ensure NFS and RPC are not enabled:                                             "
		check_directory_exit /etc/init/rpcbind-boot.conf
		if [ $? -eq 0 ]; then
			kq1=$(grep '^[^#]' /etc/init/rpcbind-boot.conf | grep "virtual-filesystems" 2>/dev/null | wc -l)
		else
			kq1=1
		fi
		check_directory_exit /etc/rc*.d/S*nfs-kernel-server
		if [ $? -eq 0 ]; then
		kq2=$(ls /etc/rc*.d/S*nfs-kernel-server | wc -l)
		else
			   kq2=0
		fi
		if [[ ( $kq1 == 1 ) && ( $kq2 == 0 ) ]]
		then
				echo $PASS
		else
				echo $FAIL
		fi
		echo -n   "    6.8. Ensure DNS Server is not enabled:                                               "
		kq1=$(ls /etc/rc*.d/S*bind9 2>/dev/null | wc -l)
		if [[ ( $kq1 == 0 ) ]]
		then
				echo $PASS
		else
				echo $FAIL
		fi
		echo -n   "    6.9. Ensure FTP Server is not enabled:                                               "
		check_service_not_enable vsftpd
		echo -n   "    6.10. Ensure HTTP Server is not enabled:                                             "
		kq1=$(ls /etc/rc*.d/S*apache2 2>/dev/null | wc -l)
		if [[ ( $kq1 == 0 ) ]]
		then
				echo $PASS
		else
				echo $FAIL
		fi
		echo -n   "    6.11. Ensure IMAP and POP server is not enabled:                                     "
		check_service_not_enable dovecot
		echo -n   "    6.12. Ensure Samba is not enabled:                                                   "
		check_service_not_enable smbd
		echo -n   "    6.13. Ensure HTTP Proxy Server is not enabled:                                       "
		check_service_not_enable squid3
		echo -n   "    6.14. Ensure SNMP Server is not enabled:                                             "
		kq1=$(ls /etc/rc*.d/S*snmpd 2>/dev/null | wc -l)
		if [[ ( $kq1 == 0 ) ]]
		then
				echo $PASS
		else
				echo $FAIL
		fi
		echo -n   "    6.15. Configure Mail Transfer Agent for Local-Only Mode:                             "
		kq1=$(grep ^[^#] /etc/postfix/main.cf 2>/dev/null | grep "inet_interfaces"  | grep "localhost" 2>/dev/null | wc -l)
		if [[ ( $kq1 == 1 ) ]]
		then
				echo $PASS
		else
				echo $FAIL
		fi
		echo -n   "    6.16. Ensure rsync service is not enabled:                                           "
		kq1=$(grep "RSYNC_ENABLE=false" /etc/default/rsync | wc -l)
		if [[ ( $kq1 == 1 ) ]]
		then
				echo $PASS
		else
				echo $FAIL
		fi
		echo -n   "    6.17. Ensure Biosdevname is not enabled:                                             "
		check_package_not_install biosdevname
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "7. Network Configuration and Firewalls:                                                  "
		echo      "    7.1. Modify Network Parameters (Host Only):                                          "
		echo -n   "        7.1.1. Disable IP Forwarding:                                                    "
		check_ip_forwarding=`sysctl net.ipv4.ip_forward | awk {'print $3'}`
		alert0 $check_ip_forwarding
		echo -n   "        7.1.2. Disable Send Packet Redirects:                                            "
		check_send_redirects1=`sysctl net.ipv4.conf.all.send_redirects | awk {'print $3'}`
		check_send_redirects2=`sysctl net.ipv4.conf.default.send_redirects | awk {'print $3'}`
		alert00 $check_send_redirects1 $check_send_redirects2
		echo      "    7.2. Ensure Avahi Server is not enabled:                                             "
		echo -n   "        7.2.1. Disable Source Routed Packet Acceptance:                                  "
		check_source_route1=`sysctl net.ipv4.conf.all.accept_source_route | awk {'print $3'}`
		check_source_route2=`sysctl net.ipv4.conf.default.accept_source_route | awk {'print $3'}`
		alert00 $check_source_route1 $check_source_route2
		echo -n   "        7.2.2. Disable ICMP Redirect Acceptance:                                         "
		check_icmp_redirect1=`sysctl net.ipv4.conf.all.accept_redirects | awk {'print $3'}`
		check_icmp_redirect2=`sysctl net.ipv4.conf.default.accept_redirects | awk {'print $3'}`
		alert00 $check_icmp_redirect1 $check_icmp_redirect2
		echo -n   "        7.2.3. Disable Secure ICMP Redirect Acceptance:                                  "
		check_secure_icmp_redirect1=`sysctl net.ipv4.conf.all.secure_redirects | awk {'print $3'}` 
		check_secure_icmp_redirect2=`sysctl net.ipv4.conf.default.secure_redirects | awk {'print $3'}`
		alert00 $check_secure_icmp_redirect1 $check_secure_icmp_redirect2
		echo -n   "        7.2.4. Log Suspicious Packets:                                                   "
		check_log_martians1=`sysctl net.ipv4.conf.all.log_martians | awk {'print $3'}`
		check_log_martians2=`sysctl net.ipv4.conf.default.log_martians | awk {'print $3'}`
		alert11 $check_log_martians1 $check_log_martians2
		echo -n   "        7.2.5. Enable Ignore Broadcast Requests:                                         "
		check_ignore_broadcasts=`sysctl net.ipv4.icmp_echo_ignore_broadcasts | awk {'print $3'}`
		alert1 $check_ignore_broadcasts
		echo -n   "        7.2.6. Enable Bad Error Message Protection:                                      "
		check_icmp_ignore_bogus=`sysctl net.ipv4.icmp_ignore_bogus_error_responses | awk {'print $3'}`
		alert1 $check_icmp_ignore_bogus
		echo -n   "        7.2.7. Enable RFC-recommended Source Route Validation:                           "
		check_rp_filter1=`sysctl net.ipv4.conf.all.rp_filter | awk {'print $3'}`
		check_rp_filter2=`sysctl net.ipv4.conf.default.rp_filter | awk {'print $3'}` 
		alert11 $check_rp_filter1 $check_rp_filter2
		echo -n   "        7.2.8. Enable TCP SYN Cookies:                                                   "
		check_tcp_sync=`sysctl net.ipv4.tcp_syncookies | awk {'print $3'}`
		alert1 $check_tcp_sync
		echo      "    7.3. Configure IPv6                                                                  "
		echo -n   "        7.3.1. Disable IPv6 Router Advertisements:                                       "
		check_disable_route_ipv6_1=`/sbin/sysctl net.ipv6.conf.all.accept_ra | awk {'print $3'}`
		check_disable_route_ipv6_2=`/sbin/sysctl net.ipv6.conf.default.accept_ra | awk {'print $3'}`
		alert00 $check_disable_route_ipv6_1 $check_disable_route_ipv6_2
		echo -n   "        7.3.2. Disable IPv6 Redirect Acceptance:                                         "
		check_disalbe_ipv6_redirect1=`/sbin/sysctl net.ipv6.conf.all.accept_redirects | awk {'print $3'}`
		check_disalbe_ipv6_redirect2=`/sbin/sysctl net.ipv6.conf.default.accept_redirects | awk {'print $3'}`
		alert00 $check_disalbe_ipv6_redirect1 $check_disalbe_ipv6_redirect2
		echo -n   "        7.3.3. Disable IPv6:                                                             "
		check1=`/sbin/sysctl net.ipv6.conf.all.disable_ipv6 | awk {'print $3'}`
		check2=`/sbin/sysctl net.ipv6.conf.default.disable_ipv6 | awk {'print $3'}`
		check3=`/sbin/sysctl net.ipv6.conf.lo.disable_ipv6 | awk {'print $3'}`
		if [[ ( $check1 == 1 ) && ( $check2 == 1 ) && ( $check3 == 1 ) ]]
		then
				echo $PASS
		else
				echo $FAIL
		fi
		echo      "    7.4. Install TCP Wrappers:                                                           "
		echo -n   "        7.4.1. Install TCP Wrappers:                                                     "
		check_package_install tcpd
		echo -n   "        7.4.2. Create /etc/hosts.allow:                                                  "
		check_exit_hosts_allow=`ls /etc/hosts.allow |wc -l`
		alert1 $check_exit_hosts_allow
		echo -n   "        7.4.3. Verify Permissions on /etc/hosts.allow:                                   "
		check_permission_allow=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/hosts.allow | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_allow" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        7.4.4. Create /etc/hosts.deny:                                                   "
		check_exit_hosts_deny=`ls /etc/hosts.deny |wc -l`
		alert1 $check_exit_hosts_deny 
		echo -n   "        7.4.5. Verify Permissions on /etc/hosts.deny:                                    "
		check_permission_deny=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/hosts.deny | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_deny" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo      "    7.5. Uncommon Network Protocols:                                                     "
		echo -n   "        7.5.1. Disable DCCP:                                                             "
		check_module_kernel dccp
		echo -n   "        7.5.2. Disable SCTP:                                                             "
		check_module_kernel sctp
		echo -n   "        7.5.3. Disable RDS:                                                              "
		check_module_kernel rds
		echo -n   "        7.5.4. Disable TIPC:                                                             "
		check_module_kernel tipc
		echo -n   "    7.6. Deactivate Wireless Interfaces:                                                 "
		not_check
		echo -n   "    7.7. Ensure Firewall is active:                                                      "
		kq1=`ufw status | grep "Status: active" 2>/dev/null | wc -l`
		kq2=`iptables -L | grep "DROP" 2>/dev/null | wc -l`
		if [[ ( $kq1 == 1 ) || ( $kq2 -ge 1 ) ]]
		then
				echo $PASS
		else
				echo $FAIL
		fi
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "8. Logging and Auditing:                                                                 "
		echo      "    8.1. Configure System Accounting (auditd):                                           "
		notify_auditd=`check_package_install auditd`
		if [ "$notify_auditd" == "$PASS" ]; then
			echo      "        8.1.1. Configure Data Retention:                                                 "
			echo -n   "            8.1.1.1. Configure Audit Log Storage Size:                                   "
			check_auto_log_size=`cat /etc/audit/auditd.conf |grep max_log_file 2>/dev/null |wc -l`
			alert1 $check_auto_log_size
			echo      "            8.1.1.2. Disable System on Audit Log Full:                                   "
			echo -n   "                8.1.1.2.1. Ensure 'space_left_action' is set to 'email':                 "
			check_space_left=`cat /etc/audit/auditd.conf |grep '^space_left_action' 2>/dev/null |awk ' {print $3}'`
			if [ "$check_space_left" == "email" ]; then
				echo $PASS
			else
				echo $FAIL
			fi
			echo -n   "                8.1.1.2.2. Ensure 'action_mail_acct' is set to 'root':                   "
			check_action_mail=`cat /etc/audit/auditd.conf |grep '^action_mail_acct' 2>/dev/null |awk ' {print $3}'`
			if [ "$check_action_mail" == "root" ]; then
				echo $PASS
			else
				echo $FAIL
			fi
			echo -n   "                8.1.1.2.3. Ensure 'admin_space_left_action' is set to 'halt':            "
			check_action_space=`cat /etc/audit/auditd.conf |grep '^admin_space_left_action' 2>/dev/null |awk ' {print $3}'`
			if [ "$check_action_space" == "halt" ]; then
				echo $PASS
			else
				echo $FAIL
			fi
			echo -n   "            8.1.1.3. Keep All Auditing Information:                                      "
			check_keep_log=`cat /etc/audit/auditd.conf |grep '^max_log_file_action' 2>/dev/null |awk ' {print $3}'`
			if [ "$check_keep_log" == "keep_logs" ]; then
				echo $PASS
			else
				echo $FAIL
			fi
			echo -n   "        8.1.2. Install and Enable auditd Service:                                        "
			check_service_not_enable auditd
			echo -n   "        8.1.3. Enable Auditing for Processes That Start Prior to auditd:                 "
			check=`grep "linux" /boot/grub/grub.cfg 2>/dev/null | grep "audit=1" |wc -l`
			alert1 $check
			echo      "        8.1.4. Record Events That Modify Date and Time Information:                      "
			echo -n   "            8.1.4.1. Ensure adjtimex is audited:                                         "
			check_adjtimex=`cat /etc/audit/audit.rules |grep adjtimex 2>/dev/null |wc -l`
			alert1 $check_adjtimex
			echo -n   "            8.1.4.2. Ensure clock_settime is audited:                                    "
			check_clock_settime=`cat /etc/audit/audit.rules |grep clock_settime 2>/dev/null |wc -l`
			alert1 $check_clock_settime
			echo -n   "            8.1.4.3. Ensure time-change is audited:                                      "
			check_time_change=`cat /etc/audit/audit.rules |grep time-change 2>/dev/null |wc -l`
			alert1 $check_time_change
			echo      "        8.1.5. Record Events That Modify User/Group Information:                         "
			echo -n   "            8.1.5.1. Ensure /etc/group is audited:                                       "
			check_audit_group=`cat /etc/audit/audit.rules |grep '/etc/group' 2>/dev/null |wc -l`
			alert1 $check_audit_group
			echo -n   "            8.1.5.2. Ensure /etc/passwd is audited:                                      "
			check_audit_passwd=`cat /etc/audit/audit.rules |grep '/etc/passwd' 2>/dev/null |wc -l`
			alert1 $check_audit_passwd
			echo -n   "            8.1.5.3. Ensure /etc/gshadow is audited:                                     "
			check_audit_gshadow=`cat /etc/audit/audit.rules |grep '/etc/gshadow' 2>/dev/null |wc -l`
			alert1 $check_audit_gshadow
			echo -n   "            8.1.5.4. Ensure /etc/shadow is audited:                                      "
			check_audit_shadow=`cat /etc/audit/audit.rules |grep '/etc/shadow' 2>/dev/null |wc -l`
			alert1 $check_audit_shadow
			echo -n   "            8.1.5.5. Ensure /etc/security/opasswd is audited:                            "
			check_audit_security=`cat /etc/audit/audit.rules |grep '/etc/security/opasswd' 2>/dev/null |wc -l`
			alert1 $check_audit_security
			echo      "        8.1.6. Record Events That Modify the System's Network Environment:               "
			echo -n   "            8.1.6.1. Ensure sethostname is audited:                                      "
			check_audit_sethostname=`cat /etc/audit/audit.rules |grep sethostname 2>/dev/null |wc -l`
			alert1 $check_audit_sethostname
			echo -n   "            8.1.6.2. Ensure /etc/issue is audited:                                       " 
			check_audit_issue=`cat /etc/audit/audit.rules |grep /etc/issue 2>/dev/null |wc -l`
			alert1 $check_audit_issue
			echo -n   "            8.1.6.3. Ensure /etc/issue.net is audited:                                   " 
			check_audit_issue_net=`cat /etc/audit/audit.rules |grep "/etc/issue.net" 2>/dev/null |wc -l`
			alert1 $check_audit_issue_net
			echo -n   "            8.1.6.4. Ensure /etc/hosts is audited:                                       "
			check_audit_host=`cat /etc/audit/audit.rules |grep "/etc/hosts" 2>/dev/null |wc -l`
			alert1 $check_audit_host
			echo -n   "            8.1.6.5. Ensure /etc/sysconfig/network is audited:                           "
			check_audit_sysconfig=`cat /etc/audit/audit.rules |grep "/etc/sysconfig/network" 2>/dev/null |wc -l`
			alert1 $check_audit_sysconfig
			echo -n   "        8.1.7. Record Events That Modify the System's Mandatory Access Controls:         "
			check_audit_selinux=`cat /etc/audit/audit.rules |grep "/etc/selinux/" |grep "MAC-policy" 2>/dev/null |wc -l`
			alert1 $check_audit_selinux
			echo      "        8.1.8. Collect Login and Logout Events:                                          "
			echo -n   "            8.1.8.1. Ensure /var/log/faillog is audited:                                 "
			check_audit_faillog=`cat /etc/audit/audit.rules |grep "/var/log/faillog" 2>/dev/null |wc -l`
			alert1 $check_audit_faillog
			echo -n   "            8.1.8.2. Ensure /var/log/lastlog is audited:                                 " 
			check_audit_lastlog=`cat /etc/audit/audit.rules |grep "/var/log/lastlog" 2>/dev/null |wc -l`
			alert1 $check_audit_lastlog
			echo -n   "            8.1.8.3. Ensure /var/log/tallylog is audited:                                " 
			check_audit_tallylog=`cat /etc/audit/audit.rules |grep "/var/log/tallylog" 2>/dev/null |wc -l`
			alert1 $check_audit_tallylog
			echo      "        8.1.9. Collect Session Initiation Information                                    "
			echo -n   "            8.1.9.1. Ensure /var/run/utmp is audited:                                    "
			check_audit_utmp=`cat /etc/audit/audit.rules |grep "/var/run/utmp" 2>/dev/null |wc -l`
			alert1 $check_audit_utmp
			echo -n   "            8.1.9.2. Ensure /var/log/wtmp is audited:                                    "
			check_audit_wtmp=`cat /etc/audit/audit.rules |grep "/var/log/wtmp" 2>/dev/null |wc -l`
			alert1 $check_audit_wtmp
			echo -n   "            8.1.9.3. Ensure /var/log/btmp is audited:                                    " 
			check_audit_btmp=`cat /etc/audit/audit.rules |grep "/var/log/btmp" 2>/dev/null |wc -l`
			alert1 $check_audit_btmp
			echo      "        8.1.10. Collect Discretionary Access Control Permission Modification Events:     "
			echo -n   "            8.1.10.1. Ensure chown is audited:                                           "
			check_audit_chown=`cat /etc/audit/audit.rules |grep chown 2>/dev/null |wc -l`
			alert1 $check_audit_chown
			echo -n   "            8.1.10.2. Ensure chmod is audited:                                           "
			check_audit_chmod=`cat /etc/audit/audit.rules |grep chmod 2>/dev/null |wc -l`
			alert1 $check_audit_chmod
			echo -n   "            8.1.10.3. Ensure setxattr is audited:                                        "
			check_audit_setxattr=`cat /etc/audit/audit.rules |grep setxattr 2>/dev/null |wc -l`
			alert1 $check_audit_setxattr
			echo -n   "        8.1.11. Collect Unsuccessful Unauthorized Access Attempts to Files:              "
			check_audit_creat=`cat /etc/audit/audit.rules |grep creat 2>/dev/null |grep access |wc -l`
			alert1 $check_audit_creat
			echo -n   "        8.1.12. Collect Use of Privileged Commands:                                      "
			check_prvileged_commands=`IFS=$'\n';for i in $(df --local -P|awk {'if (NR!=1) print $6'}|xargs -I '{}' find '{}' -xdev -type f \( -perm -2000 -o -perm -4000 \)); do egrep -q "^ *\-a +(always,exit|exit,always) +\-F +path=$i +\-F +perm=x +\-F +auid>=500 +\-F +auid!=4294967295 +-k +privileged$" /etc/audit/audit.rules;if [ $? -ne 0 ]; then echo $i use is not properly audited;fi;done |wc -l`
			alert0 $check_prvileged_commands
			echo -n   "        8.1.13. Collect Successful File System Mounts:                                   "
			check_audit_mount=`cat /etc/audit/audit.rules |grep mounts 2>/dev/null |grep mount |wc -l`
			alert1 $check_audit_mount
			echo -n   "        8.1.14. Collect File Deletion Events by User:                                    "
			check_audit_del=`cat /etc/audit/audit.rules |grep delete 2>/dev/null |wc -l`
			alert1 $check_audit_del
			echo -n   "        8.1.15. Collect Changes to System Administration Scope:                          "
			check_audit_sudoers=`cat /etc/audit/audit.rules |grep "/etc/sudoers" 2>/dev/null |wc -l`
			alert1 $check_audit_sudoers
			echo -n   "        8.1.16. Collect System Administrator Actions sudolog:                            "
			check_audit_sudolog=`cat /etc/audit/audit.rules |grep "/var/log/sudo.log" 2>/dev/null |wc -l`
			alert1 $check_audit_sudolog
			echo      "        8.1.17. Collect Kernel Module Loading and Unloading:                             "
			echo -n   "            8.1.17.1. Ensure /sbin/insmod is audited:                                    " 
			check_audit_insmod=`cat /etc/audit/audit.rules |grep "/sbin/insmod" |grep modules 2>/dev/null|wc -l`
			alert1 $check_audit_insmod
			echo -n   "            8.1.17.2. Ensure /sbin/rmmod is audited:                                     " 
			check_audit_rmmod=`cat /etc/audit/audit.rules |grep "/sbin/rmmod" 2>/dev/null|wc -l`
			alert1 $check_audit_rmmod
			echo -n   "            8.1.17.3. Ensure /sbin/modprobe is audited:                                  " 
			check_audit_modprobe=`cat /etc/audit/audit.rules |grep "/sbin/modprobe" 2>/dev/null|wc -l`
			alert1 $check_audit_modprobe
			echo -n   "            8.1.17.4. Ensure init_module is audited:                                     " 
			check_audit_init_module=`cat /etc/audit/audit.rules |grep "init_module" 2>/dev/null|wc -l`
			alert1 $check_audit_init_module
			echo -n   "        8.1.18. Make the Audit Configuration Immutable:                                  "
			check_audit_immutable=`cat /etc/audit/audit.rules |grep '^-e\ 2' 2>/dev/null|wc -l`
			alert1 $check_audit_immutable
		else
			echo      "        8.1.1. Configure Data Retention                                                  "
			echo      "            8.1.1.1. Configure Audit Log Storage Size:                                   $FAIL"
			echo      "            8.1.1.2. Disable System on Audit Log Full:                                   $FAIL"
			echo      "            8.1.1.3. Keep All Auditing Information:                                      $FAIL"
			echo      "        8.1.2. Install and Enable auditd Service:                                        $FAIL"
			echo      "        8.1.3. Enable Auditing for Processes That Start Prior to auditd:                 $FAIL"
			echo      "        8.1.4. Record Events That Modify Date and Time Information:                      $FAIL"
			echo      "        8.1.5. Record Events That Modify User/Group Information:                         $FAIL"
			echo      "        8.1.6. Record Events That Modify the System's Network Environment:               $FAIL"
			echo      "        8.1.7. Record Events That Modify the System's Mandatory Access Controls:         $FAIL"
			echo      "        8.1.8. Collect Login and Logout Events:                                          $FAIL"
			echo      "        8.1.9. Collect Session Initiation Information:                                   $FAIL"
			echo      "        8.1.10. Collect Discretionary Access Control Permission Modification Events:     $FAIL"
			echo      "        8.1.11. Collect Unsuccessful Unauthorized Access Attempts to Files:              $FAIL"
			echo      "        8.1.12. Collect Use of Privileged Commands:                                      $FAIL"
			echo      "        8.1.13. Collect Successful File System Mounts:                                   $FAIL"
			echo      "        8.1.14. Collect File Deletion Events by User:                                    $FAIL"
			echo      "        8.1.15. Collect Changes to System Administration Scope:                          $FAIL"
			echo      "        8.1.16. Collect System Administrator Actions sudolog:                            $FAIL"
			echo      "        8.1.17. Collect Kernel Module Loading and Unloading:                             $FAIL"
			echo      "        8.1.18. Make the Audit Configuration Immutable:                                  $FAIL"
		fi
		echo      "    8.2. Configure rsyslog:                                                               "
		echo -n   "        8.2.1. Install the rsyslog package:                                              "
		check_package_install rsyslog
		if [ "$notify_rsyslog" == "$PASS" ]; then
			echo -n   "        8.2.2. Ensure the rsyslog Service is activated:                                  "
			check_active_rsyslog=`ls /etc/rc*.d/S*auditd 2>/dev/null |wc -l`
			alert1 $check_active_rsyslog
			echo -n   "        8.2.3. Configure /etc/rsyslog.conf:                                              "
			check_exit_configure_rsyslog=`ls /etc/rsyslog.conf |wc -l`
			alert1 $check_exit_configure_rsyslog
			echo    "        8.2.4. Create and Set Permissions on rsyslog Log Files:                          "
			echo -n   "            8.2.4.1. Ensure all rsyslog log files are owned by root:                     "
			check_owner_rsyslog1=`find $(awk '/^ *[^#$]/ { print $2 }' /etc/rsyslog.conf | egrep -o "/.*") ! -user root |wc -l`
			alert0 $check_owner_rsyslog1
			echo -n   "            8.2.4.2. Ensure all rsyslog log files are not accessible to other:           "
			check_owner_rsyslog2=`find $(awk '/^ *[^#$]/ { print $2 }' /etc/rsyslog.conf | egrep -o "/.*") -perm /o+rwx |wc -l`
			alert0 $check_owner_rsyslog2
			echo -n   "            8.2.4.3. Ensure all rsyslog log files are not writable by group:             "
			check_owner_rsyslog3=`find $(awk '/^ *[^#$]/ { print $2 }' /etc/rsyslog.conf | egrep -o "/.*") -perm /g+wx |wc -l`
			alert0 $check_owner_rsyslog3
			echo -n   "     8.2.5. Configure rsyslog to Send Logs to a Remote Log Host:                      "
			check_remote_log=`cat /etc/rsyslog.conf |grep "^[^#;]" |grep -v "\*\.\*" |grep '@@' | wc -l`
			alert1 $check_remote_log
		else
			echo      "        8.2.2. Ensure the rsyslog Service is activated:                                  $FAIL"
			echo      "        8.2.3. Configure /etc/rsyslog.conf:                                              $FAIL"
			echo      "        8.2.4. Create and Set Permissions on rsyslog Log Files:                          $FAIL"
			echo      "        8.2.5. Configure rsyslog to Send Logs to a Remote Log Host:                      $FAIL"
		fi
		echo -n   "        8.2.6. Accept Remote rsyslog Messages Only on Designated Log Hosts               "
		not_check
		echo      "    8.3. Advanced Intrusion Detection Environment:                                       "
		echo -n   "        8.3.1. Install AIDE                                                              "
		check_package_install aide
		echo -n   "        8.3.2. Implement Periodic Execution of File Integrity:                           "
		check_crontab_aide=`crontab -l |grep aide |wc -l`
		alert1 $check_crontab_aide
		echo -n   "    8.4. Configure logrotate                                                             "
		not_check
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "9. System Access, Authentication and Authorization                                       "
		echo      "    9.1. Configure cron                                                                  "
		echo -n   "        9.1.1. Enable cron Daemon                                                        "
		check_service_enable cron
		echo -n   "        9.1.2. Set User/Group Owner and Permission on /etc/crontab                       "
		check_directory_exit /etc/crontab
		if [ $? -eq 0 ]; then
			check_permssion_crontab=`stat -L -c "%a %u %g" /etc/crontab | egrep "600 0 0" |wc -l`
			alert1 $check_permssion_crontab
		else
			echo $FAIL
		fi
		echo -n   "        9.1.3. Set User/Group Owner and Permission on /etc/cron.hourly                   "
		if [ -d /etc/cron.hourly ]; then
			check_permssion_crontab_hourly=`stat -L -c "%a %u %g" /etc/cron.hourly | egrep "600 0 0" |wc -l`
			alert1 $check_permssion_crontab_hourly
		else
			echo $FAIL
		fi
		echo -n   "        9.1.4. Set User/Group Owner and Permission on /etc/cron.daily                    "
		if [ -d /etc/cron.daily ]; then
			check_permssion_crontab_daily=`stat -L -c "%a %u %g" /etc/cron.daily | egrep "600 0 0" |wc -l`
			alert1 $check_permssion_crontab_daily
		else
			echo $FAIL
		fi
		echo -n   "        9.1.5. Set User/Group Owner and Permission on /etc/cron.weekly                   "
		if [ -d /etc/cron.weekly ]; then
			check_permssion_crontab_weekly=`stat -L -c "%a %u %g" /etc/cron.weekly | egrep "600 0 0" |wc -l`
			alert1 $check_permssion_crontab_weekly
		else
			echo $FAIL
		fi
		echo -n   "        9.1.6. Set User/Group Owner and Permission on /etc/cron.monthly                  "
		if [ -d /etc/cron.monthly ]; then
			check_permssion_crontab_monthly=`stat -L -c "%a %u %g" /etc/cron.monthly | egrep "600 0 0" |wc -l`
			alert1 $check_permssion_crontab_monthly
		else
			echo $FAIL
		fi
		echo -n   "        9.1.7. Set User/Group Owner and Permission on /etc/cron.d                        "
		if [ -d /etc/cron.d ]; then
			check_permssion_crond=`stat -L -c "%a %u %g" /etc/cron.d | egrep "700 0 0" |wc -l`
			alert1 $check_permssion_crond
		else
			echo $FAIL
		fi
		echo      "        9.1.8. Restrict at/cron to Authorized Users                                      "
		echo -n   "            9.1.8.1. Ensure /etc/at.deny does not exist:                                 " 
		check_directory_exit /etc/at.deny
		if [ $? -eq 1 ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "            9.1.8.2. Ensure /etc/at.allow is owned and accesible by root only:           " 
		if [ -f /etc/at.allow ]; then
			check_restrict_at2=`stat -L -c "%a %u %g" /etc/at.allow | egrep "600 0 0" |wc -l`
			alert1 $check_restrict_at2
		else
			echo $FAIL
		fi
		echo -n   "            9.1.8.3. Ensure /etc/cron.deny does not exist:                               " 
		check_directory_exit /etc/cron.deny
		if [ $? -eq 1 ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "            9.1.8.4. Ensure /etc/cron.allow is owned and accesible by root only:         " 
		if [ -f /etc/cron.allow ]; then
			check_restrict_cron2=`stat -L -c "%a %u %g" /etc/cron.allow | egrep "600 0 0" |wc -l`
			alert1 $check_restrict_cron2
		else
			echo $FAIL
		fi
		echo      "    9.2. Configure PAM:                                                                  "
		echo -n   "        9.2.1. Set Password Creation Requirement Parameters Using pam_cracklib:          "
		check_pam=`grep '^[^#]' /etc/pam.d/common-password | grep "password required pam_cracklib.so" | grep "retry" | grep "minlen" | grep "dcredit" | grep "ucredit" | grep "ocredit" | grep "lcredit" |wc -l`
		alert1 $check_pam
		echo -n   "        9.2.2. Set Lockout for Failed Password Attempts:                                 "
		check_lock_fail_pass_attemp=`cat /etc/pam.d/login |grep 'auth'|grep 'required' |grep 'pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900' |wc -l`
		alert1 $check_lock_fail_pass_attemp
		echo -n   "        9.2.3. Limit Password Reuse:                                                     "
		check_limit_word=`cat /etc/pam.d/common-password |grep password |grep sufficient |grep pam_unix.so |grep 'remember=5' |wc -l`
		alert1 $check_limit_word
		echo      "    9.3. Configure SSH:                                                                  "
		echo -n   "        9.3.1. Set SSH Protocol to 2:                                                    "
		check_protocol=`cat /etc/ssh/sshd_config |grep "^[^#;]"| grep 'Protocol 2' |wc -l`
		alert1 $check_protocol
		echo -n   "        9.3.2. Set LogLevel to INFO:                                                     "
		check_loglevel=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'LogLevel INFO'|wc -l`
		alert1 $check_loglevel
		echo -n   "        9.3.3. Set Permissions on /etc/ssh/sshd_config:                                  "
		check_directory_exit /etc/ssh/sshd_config
		if [ $? -eq 0 ]; then
			check_permssion_ssh=`stat -L -c "%a %u %g" /etc/ssh/sshd_config`
			if [[ "$check_permssion_ssh" == "600 0 0" ]]; then
				echo $PASS
			else
				echo $FAIL
			fi
		else
			echo $FAIL
		fi
		echo -n   "        9.3.4. Disable SSH X11 Forwarding:                                               "
		check_x11=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'X11Forwarding no' |wc -l`
		alert1 $check_x11
		echo -n   "        9.3.5. Set SSH MaxAuthTries to 4 or Less:                                        "
		check_ssh_max_authtri1=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'MaxAuthTries' |wc -l`
		if [ $check_ssh_max_authtri1 -eq 1 ]; then
			check_ssh_max_authtri2=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'MaxAuthTries' |awk '{print $2}'`
			if [ $check_ssh_max_authtri2 -le 4 ]; then
				echo $PASS
			else
				echo $FAIL
			fi
		else
			echo $FAIL
		fi
		echo -n   "        9.3.6. Set SSH IgnoreRhosts to Yes:                                              "
		check_ssh_authtri=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'IgnoreRhosts yes' |wc -l`
		alert1 $check_ssh_authtri
		echo -n   "        9.3.7. Set SSH HostbasedAuthentication to No:                                    "
		check_ssh_host_auth=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'HostbasedAuthentication no' |wc -l`
		alert1 $check_ssh_host_auth
		echo -n   "        9.3.8. Disable SSH Root Login:                                                   "
		check_ssh_root_login=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'PermitRootLogin no' |wc -l`
		alert1 $check_ssh_root_login
		echo -n   "        9.3.9. Set SSH PermitEmptyPasswords to No:                                       "
		check_ssh_empty_pass=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'PermitEmptyPasswords no' |wc -l`
		alert1 $check_ssh_empty_pass
		echo -n   "        9.3.10. Do Not Allow Users to Set Environment Options:                           "
		check_ssh_set_env=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'PermitUserEnvironment no' |wc -l`
		alert1 $check_ssh_set_env
		echo -n   "        6.2.11. Use Only Approved Cipher in Counter Mode:                                "
		check_ssh_set_env=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep '^Ciphers' |wc -l`
		alert1 $check_ssh_set_env
		echo -n   "        9.3.12. Set Idle Timeout Interval for User Login                                 "
		check_ssh_time_out1=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'ClientAliveInterval' |awk '{print $2}'`
		check_ssh_time_out2=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'ClientAliveCountMax' |awk '{print $2}'`
		if [[ $check_ssh_time_out1 -eq 300 && $check_ssh_time_out2 -eq 0 ]]; then 
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        9.3.13. Limit Access via SSH:                                                    "
		check_ssh_allow_user=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep "AllowUsers\|AllowGroups\|DenyUsers\|DenyGroups" |wc -l`
		alert1 $check_ssh_allow_user
		echo -n   "        9.3.14. Set SSH Banner:                                                          " 
		check_ssh_allow_user=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep "Banner /etc/issue.net" |wc -l`
		alert1 $check_ssh_allow_user
		echo -n   "    9.4. Restrict root Login to System Console:                                          "
		not_check
		echo -n   "    9.5. Restrict Access to the su Command                                               "
		restrict_su=`grep '^[^#]' /etc/pam.d/su | grep "auth required pam_wheel.so use_uid"`
		alert1 $restrict_su
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "10. User Accounts and Environment:                                                       "
		echo      "    10.1. Set Shadow Password Suite Parameter (/etc/login.defs):                         "
		echo -n   "        10.1.1. Set Password Expiration Days:                                            "
		check_exprire_pass=`cat /etc/login.defs |grep "^[^#;]" |grep 'PASS_MAX_DAYS' | awk '{print $2}'`
		if [[ "$check_exprire_pass" -le "90" ]]; then
			echo $PASS
		else 
			echo $FAIL
		fi
		echo -n   "        10.1.2. Set Password Change Minimum Number of Days:                              "
		check_exprire_change_pass=`cat /etc/login.defs |grep "^[^#;]" |grep 'PASS_MIN_DAYS' | awk '{print $2}'`
		if [[ "$check_exprire_change_pass" -ge "10" ]]; then
			echo $PASS
		else 
			echo $FAIL
		fi
		echo -n   "        10.1.3. Set Password Expiring Warning Days:                                      "
		check_exprire_warning_pass=`cat /etc/login.defs |grep "^[^#;]" |grep 'PASS_WARN_AGE' | awk '{print $2}'`
		if [[ "$check_exprire_warning_pass" -ge "10" ]]; then
				echo $PASS
		else
				echo $FAIL
		fi
		echo -n   "    10.2. Disable System Accounts:                                                       "
		check_system_account=`egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $10!="/sbin/nologin") {print}' |wc -l`
		alert0 $check_system_account
		echo -n   "    10.3. Set Default Group for root Account:                                            "
		check_default_root=`grep "^root:" /etc/passwd | cut -f4 -d:`
		alert0 $check_default_root
		echo -n   "    10.4. Set Default umask for Users:                                                   "
		check_umask=`grep '^[^#]' /etc/login.defs | grep "UMASK 077" | wc -l`
		alert1 $check_umask
		echo -n   "    10.5. Lock Inactive User Accounts:                                                   "
		check_user_day_inactive=`useradd -D | awk -F= '$1 == "INACTIVE" {print $2}'`
		if [ $check_user_day_inactive -le 35 ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "11. Warning Banners:                                                                     "
		echo      "    11.1. Set Warning Banner for Standard Login Services:                                "
		echo -n   "        11.1.1. Ensure /etc/motd permisions do not allow group/other write access:       "
		check_permission_motd=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/motd | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_motd" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        11.1.2. Ensure /etc/issue permisions do not allow group/other write access:      "
		check_permission_issue=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/issue | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_issue" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        11.1.3 Ensure /etc/issue.net permisions do not allow group/other write access:   "
		check_permission_issue_net=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/issue.net | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_issue_net" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        11.1.4. Ensure /etc/issue is not empty:                                          "
		check_issue_not_empty=`cat /etc/issue | wc -l`
		alert1 $check_issue_not_empty
		echo -n   "        11.1.5. Ensure /etc/issue.net is not empty:                                      "
		check_issue_net_not_empty=`cat /etc/issue.net | wc -l`
		alert1 $check_issue_net_not_empty
		echo      "    11.2. Remove OS Information from Login Warning Banners:                              "
		echo -n   "        11.2.1. Ensure there is no OS info in /etc/motd:                                 "
		check_OS_info1=$(cat /etc/motd |egrep '\\r | \\s | \\v | \\m' |wc -l)
		alert0 $check_OS_info1
		echo -n   "        11.2.2. Ensure there is no OS info in /etc/issue:                                "
		check_OS_info2=$(cat /etc/issue |egrep '\\r | \\s | \\v | \\m' |wc -l)
		alert0 $check_OS_info2
		echo -n   "        11.2.3. Ensure there is no OS info in /etc/issue.net:                            "
		check_OS_info3=$(cat /etc/issue.net |egrep '\\r | \\s | \\v | \\m' | wc -l)
		alert0 $check_OS_info3
		echo -n   "    11.3. Set Graphical Warning Banner:                                                  "
		not_check
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "    12.1. Verify System File Permissions:                                                "
		echo -n   "    12.1. Verify Permissions on /etc/passwd:                                             "
		check_permission_passwd=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/passwd | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_passwd" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "    12.2. Verify Permissions on /etc/shadow:                                             "
		check_permission_shadow=`ui=($(echo 7777 -n | fold -w1));sys=($(stat -L --format="%a" /etc/shadow | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_shadow" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "    12.3. Verify Permissions on /etc/group:                                              "
		check_permission_group=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/group | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_group" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "    12.4. Verify User/Group Ownership on /etc/passwd:                                    "
		check_owership_passwd=`stat -L -c "%u %g" /etc/passwd`
		if [ "$check_owership_passwd" == "0 0" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "    12.5. Verify User/Group Ownership on /etc/shadow:                                    "
		check_owership_shadow=`stat -L -c "%u %g" /etc/shadow`
		if [ "$check_owership_shadow" == "0 0" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "    12.6. Verify User/Group Ownership on /etc/group:                                     "
		check_owership_group=`stat -L -c "%u %g" /etc/group`
		if [ "$check_owership_group" == "0 0" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "    12.7. Find World Writable Files:                                                     "
		not_check
		echo -n   "    12.8. Find Un-owned Files and Directories:                                           "
		check_file_unowned=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls |wc -l`
		alert0 $check_file_unowned
		echo -n   "    12.9. Find Un-grouped Files and Directories:                                         "
		check_file_ungrouped=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls |wc -l`
		alert0 $check_file_ungrouped
		echo -n   "    12.10. Find SUID System Executables:                                                 "
		check_suid=`for sgid in $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print); do package=$(dpkg -S $sgid); if [ $? -eq 1 ]; then echo "SUID binary $sgid is not owned by an Debian package - investigate."; else echo $package|cut -d':' -f1|xargs dpkg -s | grep $sgid | egrep -q "^..5"; if [ $? -eq 0 ]; then echo "The MD5 hash of SUID binary $sgid does not match the expected value - investigate."; fi; fi; done 2>/dev/null |wc -l`
		alert0 $check_suid
		echo -n   "    12.11. Find SGID System Executables:                                                 "
		check_sgid=$(for sgid in $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print); do package=$(dpkg -S $sgid); if [ $? -eq 1 ]; then echo "SGID binary $sgid is not owned by an Debian package - investigate."; else echo $package|cut -d':' -f1|xargs dpkg -s | grep $sgid | egrep -q "^..5"; if [ $? -eq 0 ]; then echo "The MD5 hash of SGID binary $sgid does not match the expected value - investigate."; fi; fi; done 2>/dev/null |wc -l)
		alert0 $check_sgid
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "13. Review User and Group Settings:                                                      "                                       
		echo -n   "    13.1. Ensure Password Fields are Not Empty                                           "
		check_wordfields_notemty=`cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'|wc -l`
		alert0 $check_wordfields_notemty
		echo -n   "    13.2. Verify No Legacy "+" Entries Exist in /etc/passwd File:                          "
		check_legacy_sum1=`cat /etc/passwd |cut -c 1 |grep '+' |wc -l`
		alert0 $check_legacy_sum1
		echo -n   "    13.3. Verify No Legacy "+" Entries Exist in /etc/shadow File:                          "
		check_legacy_sum2=`cat /etc/shadow |cut -c 1 |grep '+' |wc -l`
		alert0 $check_legacy_sum2
		echo -n   "    13.4. Verify No Legacy "+" Entries Exist in /etc/group File:                           "
		check_legacy_sum3=`cat /etc/group |cut -c 1 |grep '+' |wc -l`
		alert0 $check_legacy_sum3
		echo -n   "    13.5. Verify No UID 0 Accounts Exist Other Than root:                                "
		check_uid_root=`/bin/cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' | grep -v '^root$' |wc -l`
		alert0 $check_uid_root
		echo      "    13.6. Ensure root PATH Integrity                                                     "
		echo -n   "            13.6.1. Ensure root PATH Integrity:                                          "
		check_PATH1=`echo $PATH |grep "(^|:):" |wc -l`
		alert0 $check_PATH1
		echo -n   "            13.6.2. Ensure no trailing colon in root:                                    "
		check_PATH2=`echo $PATH |grep ":$" |wc -l`
		alert0 $check_PATH2
		echo -n   "            13.6.3. Ensure root PATH Integrity:                                          "
		check_PATH3=`echo $PATH |grep "(^|:|/)\.+($|:|/)" |wc -l`
		alert0 $check_PATH3
		echo -n   "    13.7. Check Permissions on User Home Directories:                                    "
		check_permission_home=$(for i in $(awk -F: '($7 != "/sbin/nologin") {print $6}' /etc/passwd | sort -u); do echo $i $(stat -L --format=%a $i) | grep -v ' .[0145][0145]$';done >$directory/check.txt >/dev/null 2>&1;)
		check_tmp_home1=`cat $directory/check.txt |wc -l`
		alert0 $check_tmp_home1
		rm -rf $directory/check.txt
		echo -n   "    13.8. Check User Dot File Permissions:                                               "
		check_user_dot_file=`find $(cat /etc/passwd | egrep -v "root|sync|halt|shutdown" | awk -F: '($7 != "/sbin/login" && $7) {print $6}' | sort | uniq | grep -v "^/$") -name ".*" -perm /go+w >$directory/check.txt >/dev/null 2>&1;`
		check_tmp_home2=`cat $directory/check.txt |wc -l`
		alert0 $check_tmp_home2
		rm -rf $directory/check.txt
		echo -n   "    13.9. Check Permissions on User .netrc Files:                                        "
		check_user_netrc=`find $(cat /etc/passwd | egrep -v "root|sync|halt|shutdown" | awk -F: '($7 != "/sbin/login" && $7) {print $6}' | sort | uniq | grep -v "^/$") -name ".netrc" -perm /go+w >$directory/check.txt >/dev/null 2>&1;`
		check_tmp_home1=`cat $directory/check.txt |wc -l`
		alert0 $check_tmp_home1
		rm -rf $directory/check.txt
		echo -n   "    13.10. Check for Presence of User .rhosts Files:                                     "
		check_user_rhosts=`cut -f6 -d: /etc/passwd | sort -u | while read DIR; do ls $DIR/.rhosts 2>/dev/null; done |wc -l`
		alert0 $check_user_rhosts
		echo -n   "    13.11. Check Groups in /etc/passwd:                                                  "
		check_group=$(for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do grep -q -P "^.*?:x:$i:" /etc/group; if [ $? -ne 0 ]; then echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"; fi;done)
		alert0 $check_group
		echo -n   "    13.12. Check That Users Are Assigned Valid Home Directories:                         "
		check_user_assigned_home_user=`cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then echo "The home directory ($dir) of user $user does not exist."; fi; done |wc -l`
		alert0 $check_user_assigned_home_user
		echo -n   "    13.13. Check User Home Directory Ownership:                                          "
		check_user_assigned_home_owner=`cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then owner=$(stat -L -c "%U" "$dir"); if [ "$owner" != "$user" ]; then echo "The home directory ($dir) of user $user is owned by $owner."; fi; fi; done |wc -l`
		alert0 $check_user_assigned_home_owner
		echo -n   "    13.14. Check for Duplicate UIDs:                                                     "
		check_duplicate_uid=`egrep -v "^\+" /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | awk '{ if ($1 != 1) {print 1}}'`
		alert0 $check_duplicate_uid
		echo -n   "    13.15. Check for Duplicate GIDs:                                                     "
		check_duplicate_gid=`egrep -v "^\+" /etc/group | cut -f3 -d":" | sort -n | uniq -c | awk '{ if ($1 != 1) {print 1}}'`
		alert0 $check_duplicate_gid
		echo -n   "    13.16. Check for Duplicate User Names:                                               "
		check_duplicate_user_name=`egrep -v "^\+" /etc/passwd | cut -f1 -d":" | sort | uniq -c | awk '{ if ($1 != 1) {print 1}}'`
		alert0 $check_duplicate_user_name
		echo -n   "    13.17. Check for Duplicate Group Names:                                              "
		check_duplicate_user_name=`egrep -v "^\+" /etc/group | cut -f1 -d":" | sort -n | uniq -c | awk '{ if ($1 != 1) {print 1}}'`
		alert0 $check_duplicate_user_name
		echo -n   "    13.18. Check for Presence of User .netrc Files:                                      "
		check_duplicate_user_netrc=`egrep -v "^\+" /etc/passwd | cut -f6 -d: | sort -u | while read DIR; do ls $DIR/.netrc 2>/dev/null; done |wc -l`
		alert0 $check_duplicate_user_name
		echo -n   "    13.19. Check for Presence of User .forward Files:                                    "
		check_duplicate_user_netrc=`egrep -v "^\+" /etc/passwd | cut -f6 -d: | sort -u | while read DIR; do ls $DIR/.forward 2>/dev/null;done |wc -l`
		alert0 $check_duplicate_user_netrc
		echo -n   "    13.20. Ensure shadow group is empty:                                                 "
		shadow_id=`grep ^shadow /etc/group |cut -d':' -f3`
		check_shadow=$(awk -F: '($4 == "$shadow_id") { print }' /etc/passwd |wc -l)
		alert0 $check_shadow

elif [ $os_version == "CentOS" ]; then
		echo      "1. Install Updates, Patches and Additional Security Software:                            "
		echo      "    1.1. Filesystem Configuration:                                                       "
		echo -n   "        1.1.1. Create Separate Partition for /tmp:                                       "
		check_partition /tmp
		echo -n   "        1.1.2. Set nodev option for /tmp Partition:                                      "
		check_option_partition /tmp nodev
		echo -n   "        1.1.3. Set nosuid option for /tmp Partition:                                     "
		check_option_partition /tmp nosuid
		echo -n   "        1.1.4. Set noexec option for /tmp Partition:                                     "
		check_option_partition /tmp noexec
		echo -n   "        1.1.5. Create Separate Partition for /var:                                       "
		check_partition /var
		echo -n   "        1.1.6. Bind Mount the /var/tmp directory to /tmp:                                "
		check_option_partition var/tmp /tmp
		echo -n   "        1.1.7. Create Separate Partition for /var/log:                                   "
		check_partition /var/log
		echo -n   "        1.1.8. Create Separate Partition for /var/log/audit:                             "
		check_partition /var/log/audit
		echo -n   "        1.1.9. Create Separate Partition for /home:                                      "
		check_partition /home
		echo -n   "        1.1.10. Add nodev Option to /home:                                               "
		check_option_partition /home nodev
		echo -n   "        1.1.11. Add nodev Option to Removable Media Partitions:                          "
		not_check
		echo -n   "        1.1.12. Add noexec Option to Removable Media Partitions:                         "
		not_check
		echo -n   "        1.1.13. Add nosuid Option to Removable Media Partitions:                         "
		not_check
		echo -n   "        1.1.14. Add nodev Option to /dev/shm Partition:                                  "
		check_option_partition /dev/shm nodev
		echo -n   "        1.1.15. Add nosuid Option to /dev/shm Partition:                                 "
		check_option_partition /dev/shm nosuid
		echo -n   "        1.1.16. Add noexec Option to /dev/shm Partition:                                 "
		count_bind=`grep -e "^/tmp[[:space:]]" /etc/fstab | grep /var/tmp |grep bind |wc -l`
		alert1 $count_bind
		echo -n   "        1.1.17. Set Sticky Bit on All World-Writable Directories:                        "
		check_sticky_bit=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null |wc -l`
		alert0 $check_sticky_bit
		echo -n   "        1.1.18. Disable Mounting of cramfs Filesystems:                                  "
		check_module_kernel cramfs
		echo -n   "        1.1.19. Disable Mounting of freevxfs Filesystems:                                "
		check_module_kernel freevxfs
		echo -n   "        1.1.20. Disable Mounting of jffs2 Filesystems:                                   "
		check_module_kernel jffs2
		echo -n   "        1.1.21. Disable Mounting of hfs Filesystems:                                     "
		check_module_kernel hfs
		echo -n   "        1.1.22. Disable Mounting of hfsplus Filesystems:                                 "
		check_module_kernel hfsplus
		echo -n   "        1.1.23. Disable Mounting of squashfs Filesystems:                                "
		check_module_kernel squashfs
		echo -n   "        1.1.24. Disable Mounting of udf Filesystems:                                     "
		check_module_kernel udf
		#####Check configuration update software#####
		echo "------------------------------------------------------------------------------------------------------"
		echo      "    1.2. Configure Software Updates:                                                     "
		echo -n   "        1.2.1. Configure Connection to the CentOS RPM Repositories:                      "
		not_check
		echo -n   "        1.2.2. Verify CentOS GPG Key is Installed:                                       "
		check_rpm_install gpg-pubkey
		echo -n   "        1.2.3. Verify that gpgcheck is Globally Activated:                               "
		check_gpgcheck=`cat /etc/yum.conf |grep 'gpgcheck=1' |wc -l`
		alert1 $check_gpgcheck
		echo -n   "        1.2.4. Disable the rhnsd Daemon:                                                 "
		not_check
		echo -n   "        1.2.5. Obtain Software Package Updates with yum:                                 "
		not_check
		echo -n   "        1.2.6. Verify Package Integrity Using RPM:                                       "
		not_check
		######AIDE#####
		echo      "    1.3. Advanced Intrusion Detection Environment (AIDE):                                "
		echo -n   "        1.3.1. Install AIDE:                                                             "
		check_rpm_install aide
		echo -n   "        1.3.2. Implement Periodic Execution of File Integrity:                           "
		check_crontab_aide=`crontab -l |grep aide |wc -l`
		alert1 $check_crontab_aide
		#####SELinux######
		echo      "    1.4. Configure SELinux:                                                              "
		echo -n   "        1.4.1. Ensure SELinux is not disabled in /boot/grub2/grub.cfg                    "
		check_directory_exit /etc/grub.conf
		if [ $? -eq 0 ]; then
			selinux=`cat /etc/grub.conf |grep selinux |grep enforcing |wc -l`
			alert0 $selinux
		fi
		echo -n   "        1.4.2. Set the SELinux State:                                                    "
		status_selinux1=`cat /etc/selinux/config |grep 'SELINUX=enforcing' | wc -l`
		status_selinux2=`sestatus |grep 'SELinux status' | awk '{print $3}'`
		status_selinux3=`sestatus |grep 'Current mode' | awk '{print $3}'`
		if [[ $status_selinux1 -eq 1 && "$status_selinux2" == "enabled" && "$status_selinux3" == "enforcing" ]]; then 
			echo $PASS
		else
			echo $FAIL
		fi
		#echo -n   "- Ensure SELINUX=enforcing set in config:                                               "
		#alert1 $status_selinux1
		#echo -n   "- Ensure SELinux status is enabled:                                                     "
		#if [ "$status_selinux2" == "enabled" ]; then
		#	echo $PASS
		#else
		#	echo $FAIL
		#fi
		#echo -n   "- Ensure SELinux Current Mode is enforcing:                                             "
		#if [ "$status_selinux3" == "enforcing" ]; then
		#	echo $PASS
		#else
		#	echo $FAIL
		#fi
		echo -n   "        1.4.3. Set the SELinux Policy:                                                   "
		status_selinux4=`cat /etc/selinux/config |grep -E "SELINUXTYPE=(targeted|strict|mls)" | wc -l`
		status_selinux5=`sestatus |grep 'Policy from config file:' | awk '{print $5}'`
		if [[ $status_selinux4 -eq 1 && "$status_selinux5" == "targeted" ]] || [[ $status_selinux4 -eq 1 && "$status_selinux5" == "strict" ]] || [[ $status_selinux4 -eq 1 && "$status_selinux5" == "mls" ]]; then 
			echo $PASS
		else
			echo $FAIL
		fi
		#echo -n   "- Ensure SELINUXTYPE is targeted, strict, or mls:                                       "
		#alert1 $status_selinux4
		#echo -n   "- Ensure policy from config file is targeted strict or mls:                             "
		#if [[ "$status_selinux5" == "targeted" || "$status_selinux5" == "strict" || "$status_selinux5" == "mls" ]]; then
		#	echo $PASS
		#else
		#	echo $FAIL
		#fi
		echo -n   "        1.4.4. Remove SETroubleshoot:                                                    "
		check_rpm_not_install setroubleshoot
		echo -n   "        1.4.5. Remove MCS Translation Service (mcstrans):                                "
		check_rpm_not_install mcstrans
		echo -n   "        1.4.6. Check for Unconfined Daemons:                                             "
		count_unconfined_daemons=`ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' |wc -l`
		alert0 $count_unconfined_daemons
		#####Secure Boot Settings#####
		echo      "    1.5. Secure Boot Settings:                                                           "
		echo -n   "        1.5.1. Set User/Group Owner on /boot/grub2/grub.cfg:                             "
		status_owner=`stat -L -c "%u %g" /etc/grub.conf`
		if [ "$status_owner" == "0 0" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        1.5.2. Set Permissions on /boot/grub2/grub.cfg:                                  "
		permission_grub=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/grub.conf | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$permission_grub" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        1.5.3. Set Boot Loader password:                                                 "
		password_bootloader=`cat /etc/grub.conf |grep password |grep md5 |wc -l`
		alert1 $password_bootloader
		echo -n   "        1.5.4. Require Authentication for Single-User Mode:                              "
		check_single_user_mode1=`cat /etc/sysconfig/init |grep 'SINGLE=/sbin/sulogin' |wc -l`
		check_single_user_mode2=`cat /etc/sysconfig/init |grep 'PROMPT=no' |wc -l`
		alert11 $check_single_user_mode1 $check_single_user_mode2
		#echo -n "- Ensure init uses sulogin for single user mode:                                          "
		#alert1 $check_single_user_mode1
		#echo -n "- Ensure init uses PROMPT=no for single user mode:                                        "
		#alert1 $check_single_user_mode2
		echo -n   "        1.5.5. Disable Interactive Boot:                                                 "
		check_prompt=`cat /etc/sysconfig/init |grep PROMPT |cut -d '=' -f 2`
		if [ "$check_prompt" == "no" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		#####ProcessHanding#####
		echo      "    1.6. Additional Process Hardening:                                                   "
		echo -n   "        1.6.1. Restrict Core Dumps:                                                      "
		check_core_dump1=`cat /etc/security/limits.conf |grep "^[^#]" |grep hard |grep core |awk '{print $4}'`
		check_core_dump2=`sysctl fs.suid_dumpable |awk '{print $3}'`
		check_core_dump3=`cat /etc/security/limits.conf |grep "^[^#]" |grep hard |grep core |awk '{print $4}' |wc -l`
		if [[ $check_core_dump1 -eq 0 && $check_core_dump2 -eq 0 && $check_core_dump3 -eq 1 ]]
		then
			echo $PASS
		else
			echo $FAIL
		fi
		#echo -n "- Ensure '* hard core 0' set in /etc/security/limits.conf: "
		#if [[ $check_core_dump1 -eq 0 && $check_core_dump3 -eq 1 ]]
		#then
		#	echo $PASS
		#else
		#	echo $FAIL
		#fi
		#echo -n " fs.suid_dumpable is set to 0: "
		#alert0 $check_core_dump2
		echo -n "          1.6.2 Configure ExecShield:                                                      "
		check_execshield=`sysctl kernel.exec-shield	| awk '{print $3}'`
		alert1 $check_execshield
		echo -n   "        1.6.3 Enable Randomized Virtual Memory Region Placement:                         "
		check_random_vm=`sysctl kernel.randomize_va_space |awk '{print $3}'`
		if [ $check_random_vm -eq 2 ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		################################OS SERVICES###################################
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "2. OS Services:                                                                          "
		echo      "    2.1. Remove Legacy Services:                                                         "
		echo -n   "        2.1.1. Remove telnet-server:                                                     "
		check_rpm_not_install telnet-server
		echo -n   "        2.1.2. Remove telnet Clients:                                                    "
		check_rpm_not_install telnet 
		echo -n   "        2.1.3. Remove rsh-server:                                                        "
		check_rpm_not_install rsh-server
		echo -n   "        2.1.4. Remove rsh:                                                               "
		check_rpm_not_install rsh
		echo -n   "        2.1.5. Remove NIS Client:                                                        "
		check_rpm_not_install ypbind
		echo -n   "        2.1.6. Remove NIS Server:                                                        "
		check_rpm_not_install ypserv
		echo -n   "        2.1.7. Remove tftp:                                                              "
		check_rpm_not_install tftp
		echo -n   "        2.1.8. Remove tftp-server:                                                       "
		check_rpm_not_install tftp-server
		echo -n   "        2.1.9. Remove talk:                                                              "
		check_rpm_not_install talk
		echo -n   "        2.1.10. Remove talk-server:                                                      "
		check_rpm_not_install talk-server
		echo -n   "        2.1.11. Remove xinetd:                                                           "
		notify_xinetd=`check_rpm_not_install xinetd`
		echo $notify_xinetd
		if [ "$notify_xinetd" == "$FAIL" ]; then
			echo -n   "        2.1.12. Disable chargen-dgram:                                                   "
			check_chkconfg_xinetd_off chargen-dgram
			echo -n   "        2.1.13. Disable chargen-stream:                                                  "
			check_chkconfg_xinetd_off chargen-stream
			echo -n   "        2.1.14. Disable daytime-dgram:                                                   "
			check_chkconfg_xinetd_off daytime-dgram
			echo -n   "        2.1.15. Disable daytime-stream:                                                  "
			check_chkconfg_xinetd_off daytime-stream
			echo -n   "        2.1.16. Disable echo-dgram:                                                      "
			check_chkconfg_xinetd_off echo-dgram
			echo -n   "        2.1.17. Disable echo-stream:                                                     "
			check_chkconfg_xinetd_off echo-stream
			echo -n   "        2.1.18. Disable tcpmux-server:                                                   "
			check_chkconfg_xinetd_off tcpmux-server
		else
			echo     "        2.1.12. Disable chargen-dgram:                                                   $PASS"
			echo     "        2.1.13. Disable chargen-stream:                                                  $PASS"
			echo     "        2.1.14. Disable daytime-dgram:                                                   $PASS"
			echo     "        2.1.15. Disable daytime-stream:                                                  $PASS"
			echo     "        2.1.16. Disable echo-dgram:                                                      $PASS"
			echo     "        2.1.17. Disable echo-stream:                                                     $PASS"
			echo     "        2.1.18. Disable tcpmux-server:                                                   $PASS"
		fi
		#########################Special Purpose Services#############################
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "3. Special Purpose Services:                                                             "
		echo -n   "    3.1. Set Daemon umask:                                                               "
		check_umask=`cat /etc/sysconfig/init |grep umask`
		if [ "$check_umask" == "umask 027" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "    3.2. Remove the X Window System:                                                     "
		check_rpm_not_install xorg-x11-server-common
		echo -n   "    3.3. Disable Avahi Server:                                                           "
		check_chkconfig_off avahi-daemon
		echo -n   "    3.4. Disable Print Server - CUPS:                                                    "
		check_chkconfig_off cups
		echo -n   "    3.5. Remove DHCP Server:                                                             "
		check_rpm_not_install dhcp
		echo -n   "    3.6. Configure Network Time Protocol (NTP):                                          "
		check_directory_exit /etc/ntp.conf
		if [ $? -eq 0 ]; then
			restrict1=`cat /etc/ntp.conf |grep "restrict default kod nomodify notrap nopeer noquery" |wc -l`
			restrict2=`cat /etc/ntp.conf |grep "restrict -6 default kod nomodify notrap nopeer noquery" |wc -l`
			ntp_server=`cat /etc/ntp.conf |grep "^[^#;]"|grep server |wc -l`
			ntp_user=`cat /etc/sysconfig/ntpd |grep OPTIONS |grep /var/run/ntpd.pid |wc -l`
			if [[ restrict1 -ge 1 && restrict2 -ge 1 && ntp_server -ge 1 && ntp_user -ge 1 ]]; then
				echo $PASS
			else
				echo $FAIL
			fi
		#	echo -n "- Ensure 'restrict default kod nomodify notrap nopeer noquery' set in /etc/ntp.conf: " 
		#	alert1 $restrict1
		#	echo -n "- Ensure 'restrict -6 default kod nomodify notrap nopeer noquery' set in /etc/ntp.conf: "
		#	alert1 $restrict2
		#	echo -n "- Ensure at least one NTP server specified in /etc/ntp.conf: "
		#	alert1 $ntp_server
		#	echo -n "- Ensure NTP runs as an unpriviledged user: "
		#	alert1 $ntp_user
		else
			echo $FAIL
		#	echo "- Ensure 'restrict default kod nomodify notrap nopeer noquery' set in /etc/ntp.conf: $FAIL" 
		#	echo "- Ensure 'restrict -6 default kod nomodify notrap nopeer noquery' set in /etc/ntp.conf: $FAIL"
		#	echo "- Ensure at least one NTP server specified in /etc/ntp.conf: $FAIL"
		#	echo "- Ensure NTP runs as an unpriviledged user: $FAIL"
		fi
		echo      "    3.7. Remove LDAP:                                                                    "
		echo -n   "        3.7.1. Remove LDAP-servers:                                                      "
		check_rpm_not_install openldap-servers
		echo -n   "        3.7.2. Remove LDAP-clients:                                                      "
		check_rpm_not_install openldap-clients
		echo      "    3.8. Disable NFS and RPC:                                                            "
		echo -n   "        3.8.1. Disable nfsclock:                                                         "
		check_chkconfig_off nfslock
		echo -n   "        3.8.2. Disable rpcgssd:                                                          "
		check_chkconfig_off rpcgssd
		echo -n   "        3.8.3. Disable rpcbind:                                                          "
		check_chkconfig_off rpcbind
		echo -n   "        3.8.4. Disable rpcidmapd:                                                        "
		check_chkconfig_off rpcidmapd
		echo -n   "        3.8.5. Disable rpcsvcgssd:                                                       "
		check_chkconfig_off rpcsvcgssd
		echo -n   "    3.9. Remove DNS Server:                                                              "
		check_rpm_not_install bind
		echo -n   "    3.10. Remove FTP Server:                                                             "
		check_rpm_not_install vsftpd
		echo -n   "    3.11. Remove HTTP Server:                                                            "
		check_rpm_not_install httpd
		echo -n   "    3.12. Remove Dovecot (IMAP and POP3 services):                                       "
		check_rpm_not_install dovecot
		echo -n   "    3.13. Remove Samba:                                                                  "
		check_rpm_not_install samba
		echo -n   "    3.14. Remove HTTP Proxy Server:                                                      "
		check_rpm_not_install squid
		echo -n   "    3.15. Remove SNMP Server:                                                            "
		check_rpm_not_install snmp
		echo -n   "    3.16. Configure Mail Transfer Agent for Local-Only Mode:                             "
		check_MTA=`netstat -an | grep LIST | egrep ":25\s" | egrep -v '127.0.0.1:25|::1:25' |wc -l`
		alert0 $check_MTA
		#########################Network Configuration and Firewalls#############################
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "4. Network Configuration and Firewalls:                                                  "
		echo      "    4.1. Modify Network Parameter (Host Only):                                           "
		echo -n   "        4.1.1. Disable IP Forwarding:                                                    "
		check_ip_forwarding=`sysctl net.ipv4.ip_forward | awk {'print $3'}`
		alert0 $check_ip_forwarding
		echo -n   "        4.1.2. Disable Send Packet Redirects:                                            "
		check_send_redirects1=`sysctl net.ipv4.conf.all.send_redirects | awk {'print $3'}`
		check_send_redirects2=`sysctl net.ipv4.conf.default.send_redirects | awk {'print $3'}`
		alert00 $check_send_redirects1 $check_send_redirects2
		echo      "    4.2. Modify Network Parameter (Host and Router):                                     "
		echo -n   "        4.2.1. Disable Source Routed Packet Acceptance:                                  "
		check_source_route1=`sysctl net.ipv4.conf.all.accept_source_route | awk {'print $3'}`
		check_source_route2=`sysctl net.ipv4.conf.default.accept_source_route | awk {'print $3'}`
		alert00 $check_source_route1 $check_source_route2
		echo -n   "        4.2.2. Disable ICMP Redirect Acceptance:                                         "
		check_icmp_redirect1=`sysctl net.ipv4.conf.all.accept_redirects | awk {'print $3'}`
		check_icmp_redirect2=`sysctl net.ipv4.conf.default.accept_redirects | awk {'print $3'}`
		alert00 $check_icmp_redirect1 $check_icmp_redirect2
		echo -n   "        4.2.3. Disable Secure ICMP Redirect Acceptance:                                  "
		check_secure_icmp_redirect1=`sysctl net.ipv4.conf.all.secure_redirects | awk {'print $3'}` 
		check_secure_icmp_redirect2=`sysctl net.ipv4.conf.default.secure_redirects | awk {'print $3'}`
		alert00 $check_secure_icmp_redirect1 $check_secure_icmp_redirect2
		echo -n   "        4.2.4. Log Suspicious Packets:                                                   "
		check_log_martians1=`sysctl net.ipv4.conf.all.log_martians | awk {'print $3'}`
		check_log_martians2=`sysctl net.ipv4.conf.default.log_martians | awk {'print $3'}`
		alert11 $check_log_martians1 $check_log_martians2
		echo -n   "        4.2.5. Enable Ignore Broadcast Requests:                                         "
		check_ignore_broadcasts=`sysctl net.ipv4.icmp_echo_ignore_broadcasts | awk {'print $3'}`
		alert1 $check_ignore_broadcasts
		echo -n   "        4.2.6. Enable Bad Error Message Protection:                                      "
		check_icmp_ignore_bogus=`sysctl net.ipv4.icmp_ignore_bogus_error_responses | awk {'print $3'}`
		alert1 $check_icmp_ignore_bogus
		echo -n   "        4.2.7. Enable RFC-recommended Source Route Validation:                           "
		check_rp_filter1=`sysctl net.ipv4.conf.all.rp_filter | awk {'print $3'}`
		check_rp_filter2=`sysctl net.ipv4.conf.default.rp_filter | awk {'print $3'}` 
		alert11 $check_rp_filter1 $check_rp_filter2
		echo -n   "        4.2.8. Enable TCP SYN Cookies:                                                   "
		check_tcp_sync=`sysctl net.ipv4.tcp_syncookies | awk {'print $3'}`
		alert1 $check_tcp_sync
		echo      "    4.3. Wireless Networking:                                                            "
		echo -n   "        4.3.1. Deactivate Wireless Interfaces:                                           "
		check_wlan=`cat /proc/net/wireless |grep wlan |wc -l`
		alert0 $check_wlan
		echo      "    4.4. IPv6:                                                                           "
		echo      "        4.4.1. Configure IPv6:                                                           "
		echo -n   "            4.4.1.1. Disable IPv6 Router:                                                "
		check_disable_route_ipv6_1=`/sbin/sysctl -A |grep net.ipv6.conf.all.accept_redirects | awk {'print $3'}`
		check_disable_route_ipv6_2=`/sbin/sysctl -A |grep net.ipv6.conf.default.accept_redirects | awk {'print $3'}`
		alert00 $check_disable_route_ipv6_1 $check_disable_route_ipv6_2
		echo -n   "            4.4.1.2. Disable IPv6 Redirect :                                             "
		check_disalbe_ipv6_redirect1=`/sbin/sysctl -A |grep net.ipv6.conf.all.accept_redirects | awk {'print $3'}`
		check_disalbe_ipv6_redirect2=`/sbin/sysctl -A |grep net.ipv6.conf.default.accept_redirects | awk {'print $3'}`
		alert00 $check_disalbe_ipv6_redirect1 $check_disalbe_ipv6_redirect2
		echo -n   "        4.4.2. Disable IPv6:                                                             "
		check_ipv6=`ifconfig |grep net6 |wc -l`
		alert0 $check_ipv6
		echo      "    4.5. Install TCP Wrappers:                                                           "
		echo -n   "        4.5.1. Install TCP Wrappers:                                                     "
		check_rpm_install tcp_wrappers
		echo -n   "        4.5.2. Create /etc/hosts.allow:                                                  "
		check_exit_hosts_allow=`ls /etc/hosts.allow |wc -l`
		alert1 $check_exit_hosts_allow
		echo -n   "        4.5.3. Verify Permissions on /etc/hosts.allow:                                   "
		check_permission_allow=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/hosts.allow | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_allow" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        4.5.4. Create /etc/hosts.deny:                                                   "
		check_exit_hosts_deny=`ls /etc/hosts.deny |wc -l`
		alert1 $check_exit_hosts_deny
		echo -n   "        4.5.5. Verify Permissions on /etc/hosts.deny:                                    "
		check_permission_deny=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/hosts.deny | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_deny" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo      "    4.6. Uncommon Network Protocols:                                                     "
		echo -n   "        4.6.1. Disable DCCP:                                                             "
		check_module_kernel dccp
		echo -n   "        4.6.2. Disable SCTP:                                                             "
		check_module_kernel sctp
		echo -n   "        4.6.3. Disable RDS:                                                              "
		check_module_kernel rds
		echo -n   "        4.6.4. Disable TIPC:                                                             "
		check_module_kernel tipc
		echo -n   "    4.7. Enable IPtables:                                                                "
		check_chkconfig_on iptables
		echo -n   "    4.8 Enable IP6tables:                                                                "
		check_chkconfig_on ip6tables
		#########################LOG AUDIT#############################
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "5. Logging and Auditing:                                                                 "
		echo      "    5.1. Configure rsyslog:                                                              "
		echo -n   "        5.1.1. Install the rsyslog package:                                              "
		notify_rsyslog=`check_rpm_install rsyslog`
		echo $notify_rsyslog
		if [ "$notify_rsyslog" == "$PASS" ]; then
			echo -n   "        5.1.2. Activate the rsyslog Service:                                             "
			check_chkconfig_on rsyslog
			echo -n   "        5.1.3. Configure /etc/rsyslog.conf:                                              "
			check_exit_configure_rsyslog=`ls /etc/rsyslog.conf |wc -l`
			alert1 $check_exit_configure_rsyslog
			echo      "        5.1.4. Create and Set Permissions on rsyslog Log Files:                          "
			echo -n   "            5.1.4.1. Ensure all rsyslog log files are owned by root:                     "
			check_owner_rsyslog1=`find $(awk '/^ *[^#$]/ { print $2 }' /etc/rsyslog.conf | egrep -o "/.*") ! -user root |wc -l`
			alert0 $check_owner_rsyslog1
			echo -n "5.1.4.2 Ensure all rsyslog log files are not accessible to other: "
			check_owner_rsyslog2=`find $(awk '/^ *[^#$]/ { print $2 }' /etc/rsyslog.conf | egrep -o "/.*") -perm /o+rwx |wc -l`
			alert0 $check_owner_rsyslog2
			echo -n   "            5.1.4.3. Ensure all rsyslog log files are not writable by group:             "
			check_owner_rsyslog3=`find $(awk '/^ *[^#$]/ { print $2 }' /etc/rsyslog.conf | egrep -o "/.*") -perm /g+wx |wc -l`
			alert0 $check_owner_rsyslog3	
			echo -n   "        5.1.5. Configure rsyslog to Send Logs to a Remote Log Host:                      "
			check_remote_log=`cat /etc/rsyslog.conf |grep "^[^#;]" |grep -v "\*\.\*" |grep '@@' | wc -l`
			alert1 $check_remote_log
		else
			echo      "        5.1.2. Activate the rsyslog Service:                                             $FAIL"
			echo      "        5.1.3. Configure /etc/rsyslog.conf:                                              $FAIL"
			echo      "        5.1.4. Create and Set Permissions on rsyslog Log Files:                          $FAIL"
			echo      "        5.1.5. Configure rsyslog to Send Logs to a Remote Log Host:                      $FAIL"
		fi
			echo      "    5.2. Configure System Accounting (auditd):                                           "
			echo      "        5.2.1. Configure Data Retention: "
			echo -n   "            5.2.1.1. Configure Audit Log Storage Size:                                   "
			check_auto_log_size=`cat /etc/audit/auditd.conf |grep max_log_file |wc -l`
			alert1 $check_auto_log_size
			echo      "            5.2.1.2. Disable System on Audit Log Full:                                   "
			echo -n   "                5.2.1.2.1. Ensure 'space_left_action' is set to 'email':                 "
			check_space_left=`cat /etc/audit/auditd.conf |grep '^space_left_action' |awk ' {print $3}'`
			if [ "$check_space_left" == "email" ]; then
				echo $PASS
			else
				echo $FAIL
			fi
			echo -n   "                5.2.1.2.2. Ensure 'action_mail_acct' is set to 'root':                   "
			check_action_mail=`cat /etc/audit/auditd.conf |grep '^action_mail_acct' |awk ' {print $3}'`
			if [ "$check_action_mail" == "root" ]; then
				echo $PASS
			else
				echo $FAIL
			fi
			echo -n   "                5.2.1.2.3. Ensure 'admin_space_left_action' is set to 'halt':            "
			check_action_space=`cat /etc/audit/auditd.conf |grep '^admin_space_left_action' |awk ' {print $3}'`
			if [ "$check_action_space" == "halt" ]; then
				echo $PASS
			else
				echo $FAIL
			fi
			echo -n   "            5.2.1.3. Keep All Auditing Information:                                      "
			check_keep_log=`cat /etc/audit/auditd.conf |grep '^max_log_file_action' |awk ' {print $3}'`
			if [ "$check_keep_log" == "keep_logs" ]; then
				echo $PASS
			else
				echo $FAIL
			fi
			echo -n   "        5.2.2. Enable auditd Service:                                                    "
			check_chkconfig_on auditd
			echo -n   "        5.2.3. Enable Auditing for Processes That Start Prior to auditd:                 "
			check_audit=`grep "^[^#]" /etc/grub.conf |grep kernel | grep "audit=1" |wc -l`
			alert1 $check_audit
			echo      "        5.2.4. Record Events That Modify Date and Time Information:                      "
			echo -n   "            5.2.4.1. Ensure adjtimex is audited:                                         "
			check_adjtimex=`cat /etc/audit/audit.rules |grep adjtimex |wc -l`
			alert1 $check_adjtimex
			echo -n   "            5.2.4.2. Ensure clock_settime is audited:                                    "
			check_clock_settime=`cat /etc/audit/audit.rules |grep clock_settime |wc -l`
			alert1 $check_clock_settime
			echo -n   "            5.2.4.3. Ensure time-change is audited:                                      "
			check_time_change=`cat /etc/audit/audit.rules |grep time-change |wc -l`
			alert1 $check_time_change
			echo      "        5.2.5. Record Events That Modify User/Group Information                          "
			echo -n   "            5.2.5.1. Ensure /etc/group is audited:                                       "
			check_audit_group=`cat /etc/audit/audit.rules |grep '/etc/group' |wc -l`
			alert1 $check_audit_group
			echo -n   "            5.2.5.2. Ensure /etc/passwd is audited:                                      "
			check_audit_passwd=`cat /etc/audit/audit.rules |grep '/etc/passwd' |wc -l`
			alert1 $check_audit_passwd
			echo -n   "            5.2.5.3. Ensure /etc/gshadow is audited:                                     "
			check_audit_gshadow=`cat /etc/audit/audit.rules |grep '/etc/gshadow' |wc -l`
			alert1 $check_audit_gshadow
			echo -n   "            5.2.5.4. Ensure /etc/shadow is audited:                                      "
			check_audit_shadow=`cat /etc/audit/audit.rules |grep '/etc/shadow' |wc -l`
			alert1 $check_audit_shadow
			echo -n   "            5.2.5.5. Ensure /etc/security/opasswd is audited:                            "
			check_audit_security=`cat /etc/audit/audit.rules |grep '/etc/security/opasswd' |wc -l`
			alert1 $check_audit_security
			echo      "        5.2.6. Record Events That Modify the System's Network Environment:               "
			echo -n   "            5.2.6.1. Ensure sethostname is audited:                                      "
			check_audit_sethostname=`cat /etc/audit/audit.rules |grep sethostname |wc -l`
			alert1 $check_audit_sethostname
			echo -n   "            5.2.6.2. Ensure /etc/issue is audited:                                       "
			check_audit_issue=`cat /etc/audit/audit.rules |grep /etc/issue |wc -l`
			alert1 $check_audit_issue
			echo -n   "            5.2.6.3. Ensure /etc/issue.net is audited:                                   " 
			check_audit_issue_net=`cat /etc/audit/audit.rules |grep "/etc/issue.net" |wc -l`
			alert1 $check_audit_issue_net
			echo -n   "            5.2.6.4. Ensure /etc/hosts is audited:                                       "
			check_audit_host=`cat /etc/audit/audit.rules |grep "/etc/hosts" |wc -l`
			alert1 $check_audit_host
			echo -n   "            5.2.6.5. Ensure /etc/sysconfig/network is audited:                           "
			check_audit_sysconfig=`cat /etc/audit/audit.rules |grep "/etc/sysconfig/network" |wc -l`
			alert1 $check_audit_sysconfig
			echo -n   "        5.2.7. Record Events That Modify the System's Mandatory Access Controls:         "
			check_audit_selinux=`cat /etc/audit/audit.rules |grep "/etc/selinux/" |wc -l`
			alert1 $check_audit_selinux
			echo      "        5.2.8. Collect Login and Logout Events:                                          "
			echo -n   "            5.2.8.1. Ensure /var/log/faillog is audited:                                 "
			check_audit_faillog=`cat /etc/audit/audit.rules |grep "/var/log/faillog" |wc -l`
			alert1 $check_audit_faillog
			echo -n   "            5.2.8.2. Ensure /var/log/lastlog is audited:                                 " 
			check_audit_lastlog=`cat /etc/audit/audit.rules |grep "/var/log/lastlog" |wc -l`
			alert1 $check_audit_lastlog
			echo -n   "            5.2.8.3. Ensure /var/log/tallylog is audited:                                "  
			check_audit_tallylog=`cat /etc/audit/audit.rules |grep "/var/log/tallylog" |wc -l`
			alert1 $check_audit_tallylog
			echo      "        5.2.9. Collect Session Initiation Information:                                   "
			echo -n   "            5.2.9.1. Ensure /var/run/utmp is audited:                                    "
			check_audit_utmp=`cat /etc/audit/audit.rules |grep "/var/run/utmp" |wc -l`
			alert1 $check_audit_utmp
			echo -n   "            5.2.9.2. Ensure /var/log/wtmp is audited:                                    "
			check_audit_wtmp=`cat /etc/audit/audit.rules |grep "/var/log/wtmp" |wc -l`
			alert1 $check_audit_wtmp
			echo -n   "            5.2.9.3. Ensure /var/log/btmp is audited:                                    " 
			check_audit_btmp=`cat /etc/audit/audit.rules |grep "/var/log/btmp" |wc -l`
			alert1 $check_audit_btmp
			echo      "        5.2.10. Collect Discretionary Access Control Permission Modification Events:     "
			echo -n   "            5.2.10.1. Ensure chown is audited:                                           "
			check_audit_chown=`cat /etc/audit/audit.rules |grep chown |wc -l`
			alert1 $check_audit_chown
			echo -n   "            5.2.10.2. Ensure chmod is audited:                                           "
			check_audit_chmod=`cat /etc/audit/audit.rules |grep chmod |wc -l`
			alert1 $check_audit_chmod
			echo -n   "            5.2.10.3. Ensure setxattr is audited:                                        "
			check_audit_setxattr=`cat /etc/audit/audit.rules |grep setxattr |wc -l`
			alert1 $check_audit_setxattr
			echo -n   "        5.2.11. Collect Unsuccessful Unauthorized Access Attempts to Files:              "
			check_audit_creat=`cat /etc/audit/audit.rules |grep creat |grep access |wc -l`
			alert1 $check_audit_creat
			echo -n   "        5.2.12. Collect Use of Privileged Commands:                                      "
			check_prvileged_commands=`IFS=$'\n';for i in $(df --local -P|awk {'if (NR!=1) print $6'}|xargs -I '{}' find '{}' -xdev -type f \( -perm -2000 -o -perm -4000 \)); do egrep -q "^ *\-a +(always,exit|exit,always) +\-F +path=$i +\-F +perm=x +\-F +auid>=500 +\-F +auid!=4294967295 +-k +privileged$" /etc/audit/audit.rules;if [ $? -ne 0 ]; then echo $i use is not properly audited;fi;done |wc -l`
			alert0 $check_prvileged_commands
			echo -n   "        5.2.13. Collect Successful File System Mounts:                                   "
			check_audit_mount=`cat /etc/audit/audit.rules |grep mounts |grep mount |wc -l`
			alert1 $check_audit_mount
			echo -n   "        5.2.14. Collect File Deletion Events by User:                                    "
			check_audit_del=`cat /etc/audit/audit.rules |grep delete |wc -l`
			alert1 $check_audit_del
			echo -n   "        5.2.15. Collect Changes to System Administration Scope (sudoers):                "
			check_audit_sudoers=`cat /etc/audit/audit.rules |grep "/etc/sudoers" |wc -l`
			alert1 $check_audit_sudoers
			echo -n   "        5.2.16. Collect System Administrator Actions (sudolog):                          "
			check_audit_sudolog=`cat /etc/audit/audit.rules |grep "/var/log/sudo.log" |wc -l`
			alert1 $check_audit_sudolog
			echo      "        5.2.17. Collect Kernel Module Loading and Unloading:                             "
			echo -n   "            5.2.17.1. Ensure /sbin/insmod is audited:                                    " 
			check_audit_insmod=`cat /etc/audit/audit.rules |grep "/sbin/insmod" |wc -l`
			alert1 $check_audit_insmod
			echo -n   "            5.2.17.2. Ensure /sbin/rmmod is audited:                                     " 
			check_audit_rmmod=`cat /etc/audit/audit.rules |grep "/sbin/rmmod" |wc -l`
			alert1 $check_audit_rmmod
			echo -n   "            5.2.17.3. Ensure /sbin/modprobe is audited:                                  " 
			check_audit_modprobe=`cat /etc/audit/audit.rules |grep "/sbin/modprobe" |wc -l`
			alert1 $check_audit_modprobe
			echo -n   "            5.2.17.4. Ensure init_module is audited:                                     " 
			check_audit_init_module=`cat /etc/audit/audit.rules |grep "init_module" |wc -l`
			alert1 $check_audit_init_module
			echo -n   "        5.2.18. Make the Audit Configuration Immutable:                                  "
			check_audit_immutable=`cat /etc/audit/audit.rules |grep '^-e\ 2' |wc -l`
			alert1 $check_audit_immutable	
			echo      "    5.3. Configure logrotate:                                                            "
			echo -n   "        5.3.1. Ensure '/var/log/messages' rotated by '/etc/logrotate.d/syslog':          "
			check_logrotate_message=`cat /etc/logrotate.d/syslog |grep '/var/log/messages' |wc -l`
			alert1 $check_logrotate_message	
			echo -n   "        5.3.2. Ensure '/var/log/secure' rotated by '/etc/logrotate.d/syslog':            "
			check_logrotate_syslog=`cat /etc/logrotate.d/syslog |grep '/var/log/secure' |wc -l`
			alert1 $check_logrotate_syslog	
			echo -n   "        5.3.3. Ensure '/var/log/maillog' rotated by '/etc/logrotate.d/syslog':           " 
			check_logrotate_maillog=`cat /etc/logrotate.d/syslog |grep '/var/log/maillog' |wc -l`
			alert1 $check_logrotate_maillog
		#########################LOG AUDIT#############################
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "6. System Access, Authentication and Authorization:                                      "
		echo      "    6.1. Configure cron and anacron:                                                     "
		echo -n   "        6.1.1. Enable anacron Daemon:                                                    "
		check_rpm_install cronie-anacron
		echo -n   "        6.1.2. Enable crond Daemon:                                                      "
		check_chkconfig_on crond
		echo -n   "        6.1.3. Set User/Group Owner and Permission on /etc/anacrontab:                   "
		check_directory_exit /etc/anacrontab
		if [ $? -eq 0 ]; then
		check_permission_anacrontab1=`stat -L -c "%u %g" /etc/anacrontab`
		check_permission_anacrontab2=`ui=($(echo 0077 -n | fold -w1));sys=($(stat -L --format="%a" /etc/anacrontab | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
			if [[ "$check_permission_anacrontab1" == "0 0" && "$check_permission_anacrontab2" == "0000" ]]; then
				echo $PASS
			else
				echo $FAIL
			fi
		else
			echo $FAIL
		fi
		echo -n   "        6.1.4. Set User/Group Owner and Permission on /etc/crontab:                      "
		check_directory_exit /etc/crontab
		if [ $? -eq 0 ]; then
			check_permssion_crontab=`stat -L -c "%a %u %g" /etc/crontab`
			if [[ "$check_permssion_crontab" == "600 0 0" ]]; then
				echo $PASS
			else
				echo $FAIL
			fi
		else
			echo $FAIL
		fi
		echo -n   "        6.1.5. Set User/Group Owner and Permission on /etc/cron.hourly:                  "
		if [ -d /etc/cron.hourly ]; then
			check_permssion_crontab_hourly=`stat -L -c "%a %u %g" /etc/cron.hourly | egrep "600 0 0" |wc -l`
			alert1 $check_permssion_crontab_hourly
		else
			echo $FAIL
		fi
		echo -n   "        6.1.6. Set User/Group Owner and Permission on /etc/cron.daily:                   "
		if [ -d /etc/cron.daily ]; then
			check_permssion_crontab_daily=`stat -L -c "%a %u %g" /etc/cron.daily | egrep "600 0 0" |wc -l`
			alert1 $check_permssion_crontab_daily
		else
			echo $FAIL
		fi
		echo -n   "        6.1.7. Set User/Group Owner and Permission on /etc/cron.weekly:                  "
		if [ -d /etc/cron.weekly ]; then
			check_permssion_crontab_weekly=`stat -L -c "%a %u %g" /etc/cron.weekly | egrep "600 0 0" |wc -l`
			alert1 $check_permssion_crontab_weekly
		else
			echo $FAIL
		fi
		echo -n   "        6.1.8. Set User/Group Owner and Permission on /etc/cron.monthly:                 "
		if [ -d /etc/cron.monthly ]; then
			check_permssion_crontab_monthly=`stat -L -c "%a %u %g" /etc/cron.monthly | egrep "600 0 0" |wc -l`
			alert1 $check_permssion_crontab_monthly
		else
			echo $FAIL
		fi
		echo -n   "        6.1.9. Set User/Group Owner and Permission on /etc/cron.d:                       "
		if [ -d /etc/cron.d ]; then
			check_permssion_crond=`stat -L -c "%a %u %g" /etc/cron.d | egrep "700 0 0" |wc -l`
			alert1 $check_permssion_crond
		else
			echo $FAIL
		fi
		echo      "        6.1.10. Restrict at Daemon                                                       "
		echo -n   "            6.1.10.1. Ensure /etc/at.deny does not exist:                                "
		check_directory_exit /etc/at.deny
		if [ $? -eq 1 ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "            6.1.10.2. Ensure /etc/at.allow is owned and accesible by root only :         " 
		if [ -f /etc/at.allow ]; then
			check_restrict_at2=`stat -L -c "%a %u %g" /etc/at.allow | egrep "600 0 0" |wc -l`
			alert1 $check_restrict_at2
		else
			echo $FAIL
		fi
		echo      "        6.1.11. Restrict at/cron to Authorized Users:                                    "
		echo -n   "            6.1.11.1.Ensure /etc/cron.deny does not exist:                               "  
		check_directory_exit /etc/at.deny
		if [ $? -eq 1 ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "            6.1.11.2. Ensure /etc/cron.allow is owned and accesible by root only         "
		if [ -f /etc/cron.allow ]; then
			check_restrict_cron2=`stat -L -c "%a %u %g" /etc/cron.allow | egrep "600 0 0" |wc -l`
			alert1 $check_restrict_cron2
		else
			echo $FAIL
		fi
		echo      "    6.2. Configure SSH:                                                                  "
		echo -n   "        6.2.1. Set SSH Protocol to 2:                                                    "
		check_protocol=`cat /etc/ssh/sshd_config |grep "^[^#;]"| grep 'Protocol 2' |wc -l`
		alert1 $check_protocol
		echo -n   "        6.2.2. Set LogLevel to INFO:                                                     "
		check_loglevel=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'LogLevel INFO'|wc -l`
		alert1 $check_loglevel
		echo -n   "        6.2.3. Set Permissions on /etc/ssh/sshd_config:                                  "
		check_directory_exit /etc/ssh/sshd_config
		if [ $? -eq 0 ]; then
			check_permssion_ssh=`stat -L -c "%a %u %g" /etc/ssh/sshd_config`
			if [[ "$check_permssion_ssh" == "600 0 0" ]]; then
				echo $PASS
			else
				echo $FAIL
			fi
		else
			echo $FAIL
		fi
		echo -n   "        6.2.4. Disable SSH X11 Forwarding:                                               "
		check_x11=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'X11Forwarding no' |wc -l`
		alert1 $check_x11
		echo -n   "        6.2.5. Set SSH MaxAuthTries to 4 or Less:                                        "
		check_ssh_max_authtri1=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'MaxAuthTries' |wc -l`
		if [ $check_ssh_max_authtri1 -eq 1 ]; then
			check_ssh_max_authtri2=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'MaxAuthTries' |awk '{print $2}'`
			if [ $check_ssh_max_authtri2 -le 4 ]; then
				echo $PASS
			else
				echo $FAIL
			fi
		else
			echo $FAIL
		fi
		echo -n   "        6.2.6. Set SSH IgnoreRhosts to Yes:                                              "
		check_ssh_authtri=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'IgnoreRhosts yes' |wc -l`
		alert1 $check_ssh_authtri
		echo -n   "        6.2.7. Set SSH HostbasedAuthentication to No:                                    "
		check_ssh_host_auth=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'HostbasedAuthentication no' |wc -l`
		alert1 $check_ssh_host_auth
		echo -n   "        6.2.8. Disable SSH Root Login:                                                   "
		check_ssh_root_login=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'PermitRootLogin no' |wc -l`
		alert1 $check_ssh_root_login
		echo -n   "        6.2.9. Set SSH PermitEmptywords to No:                                           "
		check_ssh_empty_pass=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'PermitEmptyPasswords no' |wc -l`
		alert1 $check_ssh_empty_pass
		echo -n   "        6.2.10. Do Not Allow Users to Set Environment Options:                           "
		check_ssh_set_env=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'PermitUserEnvironment no' |wc -l`
		alert1 $check_ssh_set_env
		echo -n   "        6.2.11. Use Only Approved Cipher in Counter Mode:                                "
		check_ssh_set_env=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep '^Ciphers' |wc -l`
		alert1 $check_ssh_set_env
		echo -n   "        6.2.12. Set Idle Timeout Interval for User Login:                                "
		check_ssh_time_out1=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'ClientAliveInterval' |awk '{print $2}'`
		check_ssh_time_out2=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep 'ClientAliveCountMax' |awk '{print $2}'`
		if [[ $check_ssh_time_out1 -eq 300 && $check_ssh_time_out2 -eq 0 ]]; then 
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        6.2.13. Limit Access via SSH:                                                    "
		check_ssh_allow_user=`cat /etc/ssh/sshd_config |grep "^[^#;]"|grep "AllowUsers\|AllowGroups\|DenyUsers\|DenyGroups" |wc -l`
		alert1 $check_ssh_allow_user
		echo      "    6.3. Configure PAM:                                                                  "
		echo -n   "        6.3.1. Upgrade word Hashing Algorithm to SHA-512:                                "
		check_sha_512=`authconfig --test | grep hashing |grep sha512`
		if [ "$check_sha_512" == " password hashing algorithm is sha512" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo      "        6.3.2. Set word Creation Requirement Parameter Using pam_pwquality:              "
		echo -n   "            6.3.2.1. Ensure setting 'try_first_pass' in pam_pwquality.so options:        "
		check_option_partition_try_first_pass=`egrep -v "^[[:space:]]*#" /etc/pam.d/system-auth | egrep "pam_cracklib.so" | sed -e 's/#.*//' | tr -s '\t ' '\n' | awk -F = '/^try_first_pass/ { print $1 }'`
		if [ "$check_option_partition_try_first_pass" == "try_first_pass" ]; then
			echo $PASS
		else 
			echo $FAIL
		fi
		echo -n   "            6.3.2.2. Ensure setting 'retry' in pam_pwquality.so options:                 "
		check_option_partition_retry=`egrep -v "^[[:space:]]*#" /etc/pam.d/system-auth | egrep "pam_cracklib.so" | sed -e 's/#.*//' | tr -s '\t ' '\n' | awk -F = '/^retry/ { if ($2 <= 3) print $2 }'|wc -l`
		alert1 $check_option_partition_retry
		echo -n   "            6.3.2.4. Ensure setting 'minlen' in pam_pwquality.so options:                "
		check_option_partition_minlen=`egrep -v "^[[:space:]]*#" /etc/pam.d/system-auth | egrep "pam_cracklib.so" | sed -e 's/#.*//' | tr -s '\t ' '\n' | awk -F = '/^minlen/ { if ($2 >= 14) print $2}' |wc -l`
		alert1 $check_option_partition_minlen
		echo -n   "            6.3.2.5. Ensure setting 'dcredit' in pam_pwquality.so options:               "
		check_option_partition_dcredit=`egrep -v "^[[:space:]]*#" /etc/pam.d/system-auth | egrep "pam_cracklib.so" | sed -e 's/#.*//' | tr -s '\t ' '\n' | awk -F = '/^dcredit/ { if ($2 <= -1) print $2 }'|wc -l`
		alert1 $check_option_partition_dcredit
		echo -n   "            6.3.2.6. Ensure setting 'ucredit' in pam_pwquality.so options:               "
		check_option_partition_ucredit=`egrep -v "^[[:space:]]*#" /etc/pam.d/system-auth | egrep "pam_cracklib.so" | sed -e 's/#.*//' | tr -s '\t ' '\n' | awk -F = '/^ucredit/ { if ($2 <= -1) print $2 }'|wc -l`
		alert1 $check_option_partition_ucredit
		echo -n   "            6.3.2.7. Ensure setting 'ocredit' in pam_pwquality.so options:               "
		check_option_partition_ocredit=`egrep -v "^[[:space:]]*#" /etc/pam.d/system-auth | egrep "pam_cracklib.so" | sed -e 's/#.*//' | tr -s '\t ' '\n' | awk -F = '/^ocredit/ { if ($2 <= -1) print $2 }'|wc -l`
		alert1 $check_option_partition_ocredit
		echo -n   "            6.3.2.8. Ensure setting 'lcredit' in pam_pwquality.so options:               "
		check_option_partition_lcredit=`egrep -v "^[[:space:]]*#" /etc/pam.d/system-auth | egrep "pam_cracklib.so" | sed -e 's/#.*//' | tr -s '\t ' '\n' | awk -F = '/^lcredit/ { if ($2 <= -1) print $2 }'|wc -l`
		alert1 $check_option_partition_lcredit
		echo -n   "        6.3.3. Set Lockout for Failed word Attempts:                                     "
		check_lock_fail_pass_attemp=`cat /etc/pam.d/system-auth |grep 'auth'|grep 'required' |grep 'pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900' |wc -l`
		alert1 $check_lock_fail_pass_attemp
		echo -n   "        6.3.4. Limit word Reuse:                                                         "
		check_limit_word=`cat /etc/pam.d/system-auth |grep password |grep sufficient |grep pam_unix.so |grep 'remember=5' |wc -l`
		alert1 $check_limit_word
		#echo "6.4 Restrict root Login to System Console: "
		echo -n   "    6.5. Restrict Access to the su Command:                                              "
		check_restrict_acc_su=`cat /etc/pam.d/su |grep "^\s*auth" |grep required |grep pam_wheel.so |grep use_uid |wc -l`
		alert1 $check_restrict_acc_su
		#########################User Accounts and Environment#############################
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "7. User Accounts and Environment:                                                        "
		echo      "    7.1. Set Shadow Password Suite Parameter (/etc/login.defs):                          "
		echo -n   "        7.1.1. Set Password Expiration Days:                                             "
		check_exprire_pass=`cat /etc/login.defs |grep "^[^#;]" |grep 'PASS_MAX_DAYS' | awk '{print $2}'`
		if [ $check_exprire_pass -le 90 ]; then
			echo $PASS
		else 
			echo $FAIL
		fi
		echo -n   "        7.1.2. Set Password Change Minimum Number of Days:                               "
		check_exprire_change_pass=`cat /etc/login.defs |grep "^[^#;]" |grep 'PASS_MIN_DAYS' | awk '{print $2}'`
		if [ $check_exprire_change_pass -ge 7 ]; then
			echo $PASS
		else 
			echo $FAIL
		fi
		echo -n   "        7.1.3. Set Password Expiring Warning Days:                                       "
		check_exprire_warning_pass=`cat /etc/login.defs |grep "^[^#;]" |grep 'PASS_WARN_AGE' | awk '{print $2}'`
		if [ $check_exprire_warning_pass -ge 7 ]; then
			echo $PASS
		else 
			echo $FAIL
		fi
		echo -n   "    7.2. Disable System Accounts:                                                        "
		check_system_account=`egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print}' |wc -l`
		alert0 $check_system_account
		echo -n   "    7.3. Set Default Group for root Account:                                             "
		check_default_root=`grep "^root:" /etc/passwd | cut -f4 -d:`
		alert0 $check_default_root
		echo      "    7.4. Set Default umask for Users:                                                    "
		echo -n   "        7.4.1. Ensure /etc/bashrc umask allows access by owner only:                     "
		check_umask_owner1=`cat /etc/bashrc |grep umask |grep '077' |wc -l`
		alert1 $check_umask_owner1
		echo -n   "        7.4.2. Ensure /etc/profile.d/* umask allows access by owner only:                "
		check_umask_owner2=`egrep ^[[:space:]]*umask[[:space:]]+077 /etc/profile.d/* |wc -l`
		alert1 $check_umask_owner2
		echo -n   "    7.5. Lock Inactive User Accounts:                                                    "
		check_user_day_inactive=`useradd -D | awk -F= '$1 == "INACTIVE" {print $2}'`
		if [ $check_user_day_inactive -lt 35 ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		#########################Warning Banners#############################
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "8. Warning Banners:                                                                      "
		echo      "    8.1. Set Warning Banner for Standard Login Services:                                 "
		echo -n   "        8.1.1. Ensure /etc/motd permisions do not allow group/other write access:        "
		check_permission_motd=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/motd | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_motd" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        8.1.2. Ensure /etc/issue permisions do not allow group/other write access:       "
		check_permission_issue=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/issue | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_issue" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        8.1.3 Ensure /etc/issue.net permisions do not allow group/other write access:    "
		check_permission_issue_net=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/issue.net | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_issue_net" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        8.1.4. Ensure /etc/issue is not empty:                                           "
		check_issue_not_empty=`cat /etc/issue | wc -l`
		alert1 $check_issue_not_empty
		echo -n   "        8.1.5. Ensure /etc/issue.net is not empty:                                       "
		check_issue_net_not_empty=`cat /etc/issue.net | wc -l`
		alert1 $check_issue_net_not_empty
		echo      "    8.2. Remove OS Information from Login Warning Banners:                               "
		echo -n   "        8.2.1. Ensure there is no OS info in /etc/motd:                                  "
		check_OS_info1=$(cat /etc/motd |egrep '\\r | \\s | \\v | \\m' |wc -l)
		alert0 $check_OS_info1
		echo -n   "        8.2.2. Ensure there is no OS info in /etc/issue:                                 "
		check_OS_info2=$(cat /etc/issue |egrep '\\r | \\s | \\v | \\m' |wc -l)
		alert0 $check_OS_info2
		echo -n   "        8.2.3. Ensure there is no OS info in /etc/issue.net:                             "
		check_OS_info3=$(cat /etc/issue.net |egrep '\\r | \\s | \\v | \\m' | wc -l)
		alert0 $check_OS_info3
		echo -n   "    8.3. Set GNOME Warning Banner:                                                       "
		check_GNOME=`out=$(gconftool-2 --get /apps/gdm/simple-greeter/banner_message_enable 2>&1); echo $out | grep -q -i "true"; if [ $? -eq 0 ]; then echo "Gnome banner set."; fi; echo $out | grep -q "command not found"; if [ $? -eq 0 ]; then echo "0"; fi`
		#########################System Maintenance#############################
		echo      "---------------------------------------------------------------------------------------------------------"
		echo      "9. System Maintenance:                                                                   "
		echo      "    9.1. Verify System File Permissions:                                                 "
		echo      "        9.1.1. Verify System File Permissions:                                           "
		echo -n   "        9.1.2. Verify Permissions on /etc/passwd:                                        "
		check_permission_passwd=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/passwd | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_passwd" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        9.1.3. Verify Permissions on /etc/shadow:                                        "
		check_permission_shadow=`ui=($(echo 7777 -n | fold -w1));sys=($(stat -L --format="%a" /etc/shadow | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_shadow" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        9.1.4. Verify Permissions on /etc/gshadow:                                       "
		check_permission_gshadow=`ui=($(echo 7777 -n | fold -w1));sys=($(stat -L --format="%a" /etc/gshadow | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_gshadow" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        9.1.5. Verify Permissions on /etc/group:                                         "
		check_permission_group=`ui=($(echo 0022 -n | fold -w1));sys=($(stat -L --format="%a" /etc/group | awk '{printf "%04d\n", $0;}' | fold -w1));for (( i=0; i<4; i++ )); do echo -n $(( ${ui[$i]} & ${sys[$i]})); done;`
		if [ "$check_permission_group" == "0000" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        9.1.6. Verify User/Group Ownership on /etc/passwd:                               "
		check_owership_passwd=`stat -L -c "%u %g" /etc/passwd`
		if [ "$check_owership_passwd" == "0 0" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        9.1.7. Verify User/Group Ownership on /etc/shadow:                               "
		check_owership_shadow=`stat -L -c "%u %g" /etc/shadow`
		if [ "$check_owership_shadow" == "0 0" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        9.1.8. Verify User/Group Ownership on /etc/gshadow:                              "
		check_owership_gshadow=`stat -L -c "%u %g" /etc/gshadow`
		if [ "$check_owership_gshadow" == "0 0" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        9.1.9. Verify User/Group Ownership on /etc/group:                                "
		check_owership_group=`stat -L -c "%u %g" /etc/group`
		if [ "$check_owership_group" == "0 0" ]; then
			echo $PASS
		else
			echo $FAIL
		fi
		echo -n   "        9.1.10 Find World Writable Files:                                                "
		not_check
		echo -n   "        9.1.11. Find Un-owned Files and Directories:                                     "
		check_file_unowned=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls |wc -l`
		alert0 $check_file_unowned
		echo -n   "        9.1.12. Find Un-grouped Files and Directories:                                   "
		check_file_ungrouped=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls`
		alert0 $check_file_ungrouped
		echo -n   "        9.1.13. Find SUID System Executables:                                            "
		check_suid=`for sgid in $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print); do package=$(rpm -qf $sgid); if [ $? -eq 1 ]; then echo "SUID binary $sgid is not owned by an RPM - investigate."; else rpm -V $package | grep $sgid | egrep -q "^..5"; if [ $? -eq 0 ]; then echo "The MD5 hash of SUID binary $sgid does not match the expected value - investigate."; fi; fi; done |wc -l`
		alert0 $check_suid
		echo -n   "        9.1.14. Find SGID System Executables:                                            "
		check_sgid=`for sgid in $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print); do package=$(rpm -qf $sgid); if [ $? -eq 1 ]; then echo "SGID binary $sgid is not owned by an RPM - investigate."; else rpm -V $package | grep $sgid | egrep -q "^..5"; if [ $? -eq 0 ]; then echo "The MD5 hash of SGID binary $sgid does not match the expected value - investigate."; fi; fi; done |wc -l`
		alert0 $check_sgid
		echo      "    9.2. Review User and Group Settings:                                             "
		echo -n   "        9.2.1. Ensure word Fields are Not Empty:                                         "
		check_wordfields_notemty=`cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}'|wc -l`
		alert0 $check_wordfields_notemty
		echo -n   "        9.2.2. Verify No Legacy "+" Entries Exist in /etc/passwd File:                     "
		check_legacy_sum1=`cat /etc/passwd |cut -c 1 |grep '+' |wc -l`
		alert0 $check_legacy_sum1
		echo -n   "        9.2.3. Verify No Legacy "+" Entries Exist in /etc/shadow File:                     "
		check_legacy_sum2=`cat /etc/shadow |cut -c 1 |grep '+' |wc -l`
		alert0 $check_legacy_sum2
		echo -n   "        9.2.4. Verify No Legacy "+" Entries Exist in /etc/group File:                      "
		check_legacy_sum3=`cat /etc/group |cut -c 1 |grep '+' |wc -l`
		alert0 $check_legacy_sum3
		echo -n   "        9.2.5. Verify No UID 0 Accounts Exist Other Than root:                           "
		check_uid_root=`/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }' | grep -v '^root$' |wc -l`
		alert0 $check_uid_root
		echo      "        9.2.6. Ensure root PATH Integrity:                                               "
		echo -n   "            9.2.6.1. Ensure root PATH Integrity:                                         "
		check_PATH1=`echo $PATH |grep "(^|:):" |wc -l`
		alert0 $check_PATH1
		echo -n   "            9.2.6.2. Ensure no trailing colon in root                                    "
		check_PATH2=`echo $PATH |grep ":$" |wc -l`
		alert0 $check_PATH2
		echo -n   "            9.2.6.3. Ensure root PATH Integrity:                                         "
		check_PATH3=`echo $PATH |grep "(^|:|/)\.+($|:|/)" |wc -l`
		alert0 $check_PATH3
		echo -n   "        9.2.7. Check Permissions on User Home Directories:                               "
		check_permission_home=`for i in $(awk -F: '($7 != "/sbin/nologin") {print $6}' /etc/passwd | sort -u); do echo $i $(stat -L --format=%a $i) | grep -v ' .[0145][0145]$';done >$directory/check.txt >/dev/null 2>&1;`
		check_tmp_home1=`cat $directory/check.txt |wc -l`
		alert0 $check_tmp_home1
		rm -rf $directory/check.txt
		echo -n   "        9.2.8. Check User Dot File Permissions:                                          "
		check_user_dot_file=`find $(cat /etc/passwd | egrep -v "root|sync|halt|shutdown" | awk -F: '($7 != "/sbin/login" && $7) {print $6}' | sort | uniq | grep -v "^/$") -name ".*" -perm /go+w >$directory/check.txt >/dev/null 2>&1;`
		check_tmp_home2=`cat $directory/check.txt |wc -l`
		alert0 $check_tmp_home2
		rm -rf $directory/check.txt
		echo -n   "        9.2.9. Check Permissions on User .netrc Files:                                   "
		check_user_netrc=`find $(cat /etc/passwd | egrep -v "root|sync|halt|shutdown" | awk -F: '($7 != "/sbin/login" && $7) {print $6}' | sort | uniq | grep -v "^/$") -name ".netrc" -perm /go+w >$directory/check.txt >/dev/null 2>&1;`
		check_tmp_home1=`cat $directory/check.txt |wc -l`
		alert0 $check_tmp_home1
		rm -rf $directory/check.txt
		echo -n   "        9.2.10. Check for Presence of User .rhosts Files:                                "
		check_user_rhosts=`cut -f6 -d: /etc/passwd | sort -u | while read DIR; do ls $DIR/.rhosts 2>/dev/null; done |wc -l`
		alert0 $check_user_rhosts
		echo -n   "        9.2.11. Check Groups in /etc/passwd:                                             "
		check_group=`for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do grep -q -P "^.*?:x:$i:" /etc/group; if [ $? -ne 0 ]; then echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"; fi;done `
		alert0 $check_group
		echo -n   "        9.2.12. Check That Users Are Assigned Valid Home Directories:                    "
		check_user_assigned_home_user=`cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then echo "The home directory ($dir) of user $user does not exist."; fi; done |wc -l`
		alert0 $check_user_assigned_home_user
		echo -n   "        9.2.13. Check User Home Directory Ownership:                                     "
		check_user_assigned_home_owner=`cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then owner=$(stat -L -c "%U" "$dir"); if [ "$owner" != "$user" ]; then echo "The home directory ($dir) of user $user is owned by $owner."; fi; fi; done |wc -l`
		alert0 $check_user_assigned_home_owner
		echo -n   "        9.2.14. Check for Duplicate UIDs:                                                "
		check_duplicate_uid=`egrep -v "^\+" /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | awk '{ if ($1 != 1) {print 1}}'`
		alert0 $check_duplicate_uid
		echo -n   "        9.2.15. Check for Duplicate GIDs:                                                "
		check_duplicate_gid=`egrep -v "^\+" /etc/group | cut -f3 -d":" | sort -n | uniq -c | awk '{ if ($1 != 1) {print 1}}'`
		alert0 $check_duplicate_gid
		echo -n   "        9.2.16. Check for Duplicate User Names:                                          "
		check_duplicate_user_name=`egrep -v "^\+" /etc/passwd | cut -f1 -d":" | sort | uniq -c | awk '{ if ($1 != 1) {print 1}}'`
		alert0 $check_duplicate_user_name
		echo -n   "        9.2.17. Check for Duplicate Group Names:                                         "
		check_duplicate_user_name=`egrep -v "^\+" /etc/group | cut -f1 -d":" | sort -n | uniq -c | awk '{ if ($1 != 1) {print 1}}'`
		alert0 $check_duplicate_user_name
		echo -n "9.2.18 Check for Presence of User .netrc Files: "
		check_duplicate_user_netrc=`egrep -v "^\+" /etc/passwd | cut -f6 -d: | sort -u | while read DIR; do ls $DIR/.netrc 2>/dev/null; done |wc -l`
		alert0 $check_duplicate_user_name
		echo -n   "        9.2.18. Check for Presence of User .netrc Files:                                 "
		check_duplicate_user_netrc=`egrep -v "^\+" /etc/passwd | cut -f6 -d: | sort -u | while read DIR; do ls $DIR/.forward 2>/dev/null;done |wc -l`
		alert0 $check_duplicate_user_netrc

fi