# AJP Proxy 

- [AJP or JK](https://cwiki.apache.org/confluence/display/TOMCAT/Connectors) - wire protocol
- an optimized version of the HTTP protocol to allow a standalone web server such as Apache to talk to Tomcat
- to let Apache server the static content when possible but proxy the request to Tomcat for Tomcat-related content
- open AJP proxy ports (8009 TCP)
- able to use them to access the hidden Apache Tomcat Manager behind it
- AJP-Proxy - binary protocol
- can configure our own Nginx or Apache webserver with AJP modules to interact with it and access the underlying application
- can discover administrative panels, applications, and websites that would be inaccessible
- to replicate such a vulnerable environment on a local machine 
- start an Apache Tomcat Docker exposing only the AJP-Proxy as
- create a file called `tomcat-users.xml`
```xml
<tomcat-users>
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <user username="tomcat" password="s3cret" roles="manager-gui,manager-script"/>
</tomcat-users>
```
- install docker package and start the Apache Tomcat Server by
```sh
sudo docker run -it --rm -p 8009:8009 -v `pwd`/tomcat-users.xml:/usr/local/tomcat/conf/tomcat-users.xml --name tomcat "tomcat:8.0"
```

---

# Nginx Reverse Proxy & AJP

- when we come across an open AJP proxy port (8009 TCP), we can use Nginx with the ajp_module to access the hidden Tomcat Manger by compiling the Nginx source code and adding the required module as 
	- Download the Nginx source code
	- Download the required module
	- Compile Nginx source code with the ajp_module
	- Create a configuration file pointing to the AJP port

- Download the Nginx source code 
```sh
wget https://nginx.org/download/nginx-1.21.3.tar.gz
tar -xzvf nginx-1.21.3.tar.gz
```

- Compile Nginx source code with the ajp module

```sh
git clone https://github.com/dvershinin/nginx_ajp_module.git
cd nginx-1.21.3
sudo apt install libpcre3-dev
./configure --add-module=`pwd`/../nginx_ajp_module --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules
make
sudo make install
nginx -V
```

- Comment out the entire server block and append the following lines inside the http block in /etc/nginx/conf/nginx.conf.

```json
upstream tomcats {
	server <TARGET_SERVER>:8009;
	keepalive 10;
	}
server {
	listen 80;
	location / {
		ajp_keep_conn on;
		ajp_pass tomcats;
	}
}
```

- start Nginx and check is it running

```sh
sudo nginx
curl http://127.0.0.1:80
```

---

# Apache Reverse Proxy & AJP

- Configuring the AJP-Proxy in our Apache server can be done by
	- Install the libapache2-mod-jk package
	- Enable the module
	- Create the configuration file pointing to the target AJP-Proxy port

- can change the Apache's default port on `/etc/apache2/ports.conf`

```sh
sudo apt install libapache2-mod-jk
sudo a2enmod proxy_ajp
sudo a2enmod proxy_http
export TARGET="<TARGET_IP>"
echo -n """<Proxy *>
Order allow,deny
Allow from all
</Proxy>
ProxyPass / ajp://$TARGET:8009/
ProxyPassReverse / ajp://$TARGET:8009/""" | sudo tee /etc/apache2/sites-available/ajp-proxy.conf
sudo ln -s /etc/apache2/sites-available/ajp-proxy.conf /etc/apache2/sites-enabled/ajp-proxy.conf
sudo systemctl start apache2
```

```
curl http://127.0.0.1
```

---