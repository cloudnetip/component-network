package main

import (
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

type ProxiesData struct {
	Type    string `json:"type"`
	Port    int    `json:"port"`
	Dns     string `json:"dns"`
	CertKey string `json:"certKey"`
	CertPub string `json:"certPub"`
	Clients []ProxiesClient
}

type ProxiesClient struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Proxies struct{}

func NewProxies() *Proxies {
	return &Proxies{}
}

func (p *Proxies) shell(command string, errIgnore bool, timeout time.Duration) string {
	ctx, cancel := context.WithCancel(context.Background())
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput()
	if err != nil && !errIgnore {
		log.Println("[proxies] shell err:", err, "command:", command)
	}
	return strings.TrimSpace(string(out))
}

func (p *Proxies) nginxPid(pId int) string {
	return fmt.Sprintf("/tmp/netip-proxy%d.pid", pId)
}

func (p *Proxies) fileConf(pId int) string {
	return fmt.Sprintf("/tmp/netip-proxy%d.conf", pId)
}

func (p *Proxies) fileAccounts(pId int) string {
	return fmt.Sprintf("/tmp/netip-proxy%d.accounts", pId)
}

func (p *Proxies) hashBcrypt(password string) (hash string, err error) {
	passwordBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	return string(passwordBytes), nil
}

func (p *Proxies) writeAccounts(pId int, clients []ProxiesClient) {
	var fillBytes []byte
	for _, e := range clients {
		if len(e.Username) == 0 || len(e.Password) == 0 {
			continue
		}
		hash, _ := p.hashBcrypt(e.Password)
		fillBytes = append(fillBytes, []byte(e.Username+":"+hash+"\n")...)
	}

	err := os.WriteFile(p.fileAccounts(pId), fillBytes, 0644)
	if err != nil {
		log.Println("[proxies] err accounts save conf, id:", pId)
		return
	}
}

func (p *Proxies) up(pId int) {
	go p.shell("/proxy-nginx -c "+p.fileConf(pId), false, 0)
}

func (p *Proxies) down(pId int) {
	p.shell("/proxy-nginx -c "+p.fileConf(pId)+" -s stop", true, 30*time.Second)
}

func (p *Proxies) Refresh(prs map[int]ProxiesData) {
	for pId, e := range prs {
		switch e.Type {
		case "http":
			p.refreshHttp(pId, e)
		case "https":
			p.refreshHttps(pId, e)
		}
	}
}

func (p *Proxies) Destroy(pId int) {
	p.down(pId)
}

func (p *Proxies) refreshHttp(pId int, pd ProxiesData) {
	conf := strings.Builder{}
	conf.WriteString(fmt.Sprintf(`daemon off;
pid %s;
user root;
worker_processes auto;
worker_rlimit_nofile 200000;
events {
    worker_connections 10000;
    multi_accept on;
}
http {
    access_log /dev/null;
    tcp_nopush on;
    tcp_nodelay on;
    server_tokens off;
    lua_load_resty_core off;

    server {
        listen %d reuseport;
        listen [::]:%d ipv6only=on;
        resolver %s ipv6=off;

        auth_basic "Access to internal site";
        auth_basic_user_file %s;
        rewrite_by_lua_block {
            if not ngx.var.http_proxy_authorization then
                ngx.header["Proxy-Authenticate"] = "Basic realm=\"Access to internal site\""
                ngx.exit(407)
            end
            ngx.req.set_header("Authorization", ngx.var.http_proxy_authorization)
        }

        set $resolved_ip $connect_addr;
        set $dns_server %s;
        access_by_lua_block {
            require("resty.check_ssrf").run()
        }

        # forward proxy for CONNECT request
        proxy_connect;
        proxy_connect_allow all;
        proxy_connect_connect_timeout 10s;
        proxy_connect_data_timeout 60s;

        # forward proxy for non-CONNECT request
        location / {
            proxy_pass http://$host;
            proxy_set_header Host $host;
            proxy_hide_header Authorization;
            proxy_hide_header Proxy-Authorization;
        }
    }
}`, p.nginxPid(pId), pd.Port, pd.Port, pd.Dns, p.fileAccounts(pId), pd.Dns))

	err := os.WriteFile(p.fileConf(pId), []byte(conf.String()), 0644)
	if err != nil {
		log.Println("[proxies] err save conf, id:", pId)
		return
	}

	p.writeAccounts(pId, pd.Clients)
	p.down(pId)
	p.up(pId)
}

func (p *Proxies) refreshHttps(pId int, pd ProxiesData) {
	certPath := fmt.Sprintf("/tmp/netip-proxy%d.cert", pId)

	if len(pd.CertKey) == 0 || len(pd.CertPub) == 0 {
		p.shell("openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes"+
			" -keyout "+certPath+".key -out "+certPath+".pub -subj '/CN=self-signed.proxy'"+
			" -addext 'subjectAltName=DNS:self-signed.proxy,IP:127.0.0.1'", false, 30*time.Second)
	} else {
		err := os.WriteFile(certPath+".key", []byte(pd.CertKey), 0644)
		if err != nil {
			log.Println("[proxies] err save cert key, id:", pId)
			return
		}
		err = os.WriteFile(certPath+".pub", []byte(pd.CertPub), 0644)
		if err != nil {
			log.Println("[proxies] err save cert pub, id:", pId)
			return
		}
	}

	conf := fmt.Sprintf(`daemon off;
pid %s;
user root;
worker_processes auto;
worker_rlimit_nofile 200000;
events {
    worker_connections 10000;
    multi_accept on;
}
http {
    access_log /dev/null;
    tcp_nopush on;
    tcp_nodelay on;
    server_tokens off;
    lua_load_resty_core off;

    server {
        listen %d ssl default_server;
        listen [::]:%d ssl ipv6only=on;
        ssl_reject_handshake on; # reject anon handshake
    }

    server {
        listen %d ssl reuseport;
        resolver %s ipv6=off;
        server_name ~^.+\..+$; # capture all >1-lvl domains

        ssl_stapling on;
        ssl_stapling_verify on;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
        ssl_certificate_key %s.key;
        ssl_certificate %s.pub;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        auth_basic "Access to internal site";
        auth_basic_user_file %s;
        rewrite_by_lua_block {
            if not ngx.var.http_proxy_authorization then
                ngx.header["Proxy-Authenticate"] = "Basic realm=\"Access to internal site\""
                ngx.exit(407)
            end
            ngx.req.set_header("Authorization", ngx.var.http_proxy_authorization)
        }

        set $resolved_ip $connect_addr;
        set $dns_server %s;
        access_by_lua_block {
            require("resty.check_ssrf").run()
        }

        # forward proxy for CONNECT request
        proxy_connect;
        proxy_connect_allow all; # all ports
        proxy_connect_connect_timeout 10s;
        proxy_connect_data_timeout 60s;

        # forward proxy for non-CONNECT request
        location / {
            proxy_pass http://$host;
            proxy_set_header Host $host;
            proxy_hide_header Authorization;
            proxy_hide_header Proxy-Authorization;
        }
    }
}`, p.nginxPid(pId), pd.Port, pd.Port, pd.Port, pd.Dns, certPath, certPath, p.fileAccounts(pId), pd.Dns)

	err := os.WriteFile(p.fileConf(pId), []byte(conf), 0644)
	if err != nil {
		log.Println("[proxies] err save conf, id:", pId)
		return
	}

	p.writeAccounts(pId, pd.Clients)
	p.down(pId)
	p.up(pId)
}
