iptables -F -t raw
iptables -t raw -A PREROUTING -p udp -s 201.251.76.164 -d 201.251.115.62 -j QUEUE

echo "1" > /proc/sys/net/ipv4/ip_forward

killall natgw
/etc/init.d/natip&
