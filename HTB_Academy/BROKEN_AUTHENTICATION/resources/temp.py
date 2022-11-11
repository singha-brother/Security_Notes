# import pandas as pd 

# data = pd.read_csv("scadpass.csv")

# pwd_name = data["Default password"].unique()
# print(list(pwd_name))

lst = ['service:ABB800xA', 'admin:admin', 'root:840sw', 'root:root', 'advantech:admin', 'admin:blank', 'root:00000000',  'Root:00000000', 'Admin:00000000', 'User:00000000', 'admin:switch', 'manager:friend', 'ArgusAdmin:masterkey', 'argus:argus', '1234:1234', 'root:dbps', 'Advanced:advanced', 'webguest:1', 'Administrator:1', 'ppps:ppps', 'admin:bintec', 'admin:1234', 'admin:password', 'admin:admin', 'admin:funkwerk', 'admin:funkwerk', 'admin:admin', 'administrator:superuser', 'admin:admin', 'user:user' , 'root:froot', 'carel:fcarel', 'guest:fguest', 'httpadmin:fhttpadmin', 'admin:fadmin','admin:abc123', 'root:deif7800', 'ilon:ilon', 'Echelon:echeloncorp', 'anonymous:anonymous', 'eignet:inp100','Administrator:deltav', 'Liebert:Liebert', 'User:User', 'Liebert:Liebert', 'admin:default', 'maint:default', 'oper:default', 'exec:default', 'Supervisor:Admin', 'User1:Password1', 'User2:Password2', 'User3:Password3','admin:avocent', 'root:linux', 'super:super', 'admin:0000', 'admin:1234', 'adm:adm', 'USHA:admin', 'admin:system', 'user:system', 'Admin:admin', 'admin:tracerlab', 'tracerlab:tracerlab', 'admin:tracerlab', 'root:#bigguy', 'ctuser:4$apps', 'root:#bigguy', 'user:public', 'admin:private', 'Guest:guest', 'SysAdmin:honey', 'def:trade', 'pvserver:pvwr', 'admin:PASS', 'admin:loytec4u', 'guest:guest', 'admin:admin', 'root:root', 'MELSEC:MELSEC', 'QNUDECPU:QNUDECPU', 'ecoV:ecopass', 'guest:user', 'admin:root', 'default:default', 'admin:pass', 'wl_test:wl_test', 'vesstore:vesstore', 'ftp_boot:ftp_boot', 'Administrator:Gateway', 'Administrator:admin', 'User 1:master', 'User 2:engineer', 'User 3:operator', 'USER:USER', 'ntpupdate:ntpupdate', 'pcfactory:pcfactory', 'loader:fwdownload', 'ntpupdate:ntpupdate', 'sysdiag:factorycast@schneider', 'test:testingpw', 'webserver:webpages', 'fdrusers:sresurdf', 'nic2212:poiuypoiuy', 'nimrohs2212:qwertyqwerty', 'nip2212:fcsdfcsd', 'noe77111_v500:RcSyyebczS', 'AUTCSE:RybQRceeSd' , 'AUT_CSE:cQdd9debez', 'target:RcQbRbzRyc','USER:USERUSER', 'USER:USER', 'ftpuser:ftpuser', 'Basisk:Basisk', 'admin:admin', 'user:user', 'siemens:siemens', 'Administrator:Password', 'winccd:winccpass', 'wincce:winccpass', 'DMUser:Data&Pass', 'Administrator:Administrator', 'admin:admin', 'operator:operator', 'guest:guest', 'root:admin', 'admin:admin', 'oper:oper', 'guest:guest','root:zP2wxY4uE', 'ADMIN:SBTAdmin!', 'admin@root:charleM!800', 'sconsole:12345', 'user:12345', 'viewer:12345', 'Installer:sma', 'naztec:naztec', 'tridium:niagara','ubnt:ubnt', 'admin:wago', 'user:user00' , 'su:ko2003wa', 'root:wago', 'admin:westermo', 'Administrator:Wonderware', 'aadbo:pwddbo', 'wwdbo:pwddbo', 'aaAdmin:pwAdmin', 'wwAdmin:wwAdmin', 'aaPower:pwPower', 'wwPower:wwPower', 'aaUser:pwUser', 'wwUser:wwUser', 'administrator:blank', 'MyTurbine:m442+SRt', 'admin:!admin', 'Administrator 1:Admin1', 'Administrator 2:Admin2', 'Administrator 5:Admin5', 'User 1:User01', 'User 90:User90','CENTUM:CENTUM']


for idx, el in enumerate(lst):
	np = el.split(':')
	usernames = np[0]
	passwords = np[1]
	# print(f"{idx} -- {usernames} === {passwords}")
	print(passwords)

