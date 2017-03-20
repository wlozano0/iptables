#/bin/sh

case "$1" in
	mgcp)
		echo "NatVoip MGCP Starting"
		killall natvoip
		while pidof natvoip
		do
			echo "1" > /dev/null 
		done
		iptables -t raw -F
		#iptables -t raw -A PREROUTING -p udp -d 200.69.135.43 --dport 2727 -j QUEUE
		iptables -t raw -A PREROUTING -p udp -d 201.251.76.185 --dport 2727 -j QUEUE
		./natvoip -ip 200.127.118.16 -d 0 &
		;;
	sip)
		echo "NatVoip SIP Starting"
		killall natvoip
		while pidof natvoip
		do
			echo "1" > /dev/null 
		done
		iptables -t raw -F
		#iptables -t raw -A PREROUTING -p udp -d 200.69.135.45 --dport 5060 -j QUEUE
		iptables -t raw -A PREROUTING -p udp -d 201.251.76.183 --dport 5060 -j QUEUE
		./natvoip -ip 200.127.118.16 -d 0 &
		;;
	voip)
		echo "NatVoip MGCP/SIP Starting"
		killall natvoip
		while pidof natvoip
		do
			echo "1" > /dev/null 
		done
		iptables -t raw -F
		#iptables -t raw -A PREROUTING -p udp -d 200.69.135.43 --dport 2727 -j QUEUE
		#iptables -t raw -A PREROUTING -p udp -d 200.69.135.45 --dport 5060 -j QUEUE
		iptables -t raw -A PREROUTING -p udp -d 201.251.76.183 --dport 5060 -j QUEUE
		iptables -t raw -A PREROUTING -p udp -d 201.251.76.185 --dport 2727 -j QUEUE
		./natvoip -ip 200.127.118.16 -d 0 &
		;;
	stop)
		echo "NatVoip Stopping"
		iptables -t raw -F
		killall natvoip
		;;
	*)		
		echo "Usage NatVoip mgcp|sip|voip|stop"
		;;
esac

exit 0
