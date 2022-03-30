# VAULT_SERV_CERT+NGINX_SERV_SITE+BASH_SCRIPT_MAKE_CERT (VITKIN_K_N)

### 1. Создам виртуальную машину Linux.:

- *Cконфигурируем Vagrantfile*
```bash
Vagrant.configure("2") do |config|
config.vm.box = "bento/ubuntu-20.04" 
	config.vm.network "private_network", type: "dhcp"// поднимаю на Virtual Box DHCP сервер
	config.vm.network  "forwarded_port", guest: 443, host: 8810, auto_correct: true
	config.vm.network "forwarded_port", guest: 80, host: 8080, auto_correct: true
 end
```
```
vagrant up
vagrant ssh
```

#### 2. Установите ufw и разрешите к этой машине сессии на порты 22 и 443, при этом трафик на интерфейсе localhost (lo) должен ходить свободно на все порты.
```bash
sudo apt install ufw // установили ufw
sudo ufw status verbose // проверяем установку
sudo ufw allow 443
sudo ufw allow 80
sudo ufw allow from 127.0.0.1
sudo ufw enable
```
#### 3. Установите Hashicorp vault:


```bash
sudo apt-get install jq
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
```

#### 4. Cоздайте центр сертификации и выпустите сертификат для использования его в настройке веб-сервера nginx.
- *Coздадим файл службы Vault*
```
Unit]
Description="HashiCorp Vault - A tool for managing secrets"
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target

[Service]
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=/usr/local/bin/vault server -config=/etc/vault.d/vault.hcl
ExecReload=/bin/kill --signal HUP 
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitBurst=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
- *создадим конфиг файл vault*
```bash
sudo mkdir /etc/vault.d
sudo touch /etc/vault.d/vault.hcl
sudo touch /etc/vault.d/vault.hcl

ui = true
storage "raft" {
path = "./vault/data"
}
listener "tcp" {
address = "127.0.0.1:8201"
tls_disable = 1
}
disable_mlock = true
api_addr = "http://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
```
- *создадим папку сервера vault и запустим сервер vault*
```
mkdir -p ./vault/data
systemctl enable vault
systemctl start vault
systemctl status vault

● vault.service - "HashiCorp Vault - A tool for managing secrets"
     Loaded: loaded (/etc/systemd/system/vault.service; enabled; vendor preset: enabled)
     Active: activating (auto-restart) (Result: exit-code) since Fri 2022-03-04 15:46:55 UTC; 607ms ago
       Docs: https://www.vaultproject.io/docs/
    Process: 2006 ExecStart=/usr/local/bin/vault server -config=/etc/vault/config.hcl (code=exited, status=203/EXEC)
   Main PID: 2006 (code=exited, status=203/EXEC)
```
- *Запускаем Vault cервер*
```
vault server -config=/etc/vault.d/vault.hcl

-==> Vault server configuration:
             Api Address: http://127.0.0.1:8200
                     Cgo: disabled
         Cluster Address: https://127.0.0.1:8201
              Go Version: go1.17.5
              Listener 1: tcp (addr: "127.0.0.1:8201", cluster address: "127.0.0.1:8202", max_request_duration: "1m30s", max_request_size: "33554432", tls: "disabled")
               Log Level: info
                   Mlock: supported: true, enabled: false
           Recovery Mode: false
                 Storage: raft (HA available)
                 Version: Vault v1.9.3
             Version Sha: 7dbdd57243a0d8d9d9e07cd01eb657369f8e1b8a
==> Vault server started! Log data will stream in below:
2022-03-19T18:43:03.701Z [INFO]  proxy environment: http_proxy="\"\"" https_proxy="\"\"" no_proxy="\"\""
2022-03-19T18:43:03.714Z [INFO]  core: Initializing VersionTimestamps for core
```
- *В другом терминале инциируем (сохраним ключи и токен в отдельный файл vault_operator_init.txt)*
```
VAULT_ADDR='http://127.0.0.1:8201' vault operator init > vault_operator_init.txt

Unseal Key 1: *******************************************
Unseal Key 2: *******************************************
Unseal Key 3: *******************************************
Unseal Key 4: *******************************************
Unseal Key 5: *******************************************
Initial Root Token: s.****************
Vault initialized with 5 key shares and a key threshold of 3. Please securely
distribute the key shares printed above. When the Vault is re-sealed,
restarted, or stopped, you must supply at least 3 of these keys to unseal it
before it can start servicing requests.
Vault does not store the generated master key. Without at least 3 keys to
reconstruct the master key, Vault will remain permanently sealed!
It is possible to generate new unseal keys, provided you have a quorum of
existing unseal keys shares. See "vault operator rekey" for more information.
```
- *Распечатываем наш сервер с помощью трёх ключей и токена:*
```
VAULT_ADDR='http://127.0.0.1:8201' vault operator unseal *******************************************
VAULT_ADDR='http://127.0.0.1:8201' vault operator unseal *******************************************
VAULT_ADDR='http://127.0.0.1:8201' vault operator unseal *******************************************
Unseal Key (will be hidden):
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             true
Total Shares       5
Threshold          3
Unseal Progress    1/3
Unseal Nonce       6cfe01f7-145e-108d-61f1-7bdb5c87dacc
Version            1.9.3
Storage Type       raft
HA Enabled         true
vagrant@vagrant:~$ VAULT_ADDR='http://127.0.0.1:8201' vault login s.****************
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                s.****************
token_accessor       X1u1zQHu8K8wPaqmwvfLsQ6F
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]
```
- *Сервер Vault готов к работе*

#### 4. Cоздайте центр сертификации и выпустите сертификат для использования его в настройке веб-сервера nginx (срок жизни сертификата - месяц).
- *Создадим файл политик центра сертификации*
```
nano vault_pki_pol.hcl

path "sys/mounts/" {
capabilities = [ "create", "read", "update", "delete", "list" ]
}
path "sys/mounts" {
capabilities = [ "read", "list" ]
}
path "pki" {
capabilities = [ "create", "read", "update", "delete", "list", "sudo" ]
}
```
- *Прописываем политики*
```
VAULT_ADDR='http://127.0.0.1:8201' vault policy write pki vault_pki_pol.hcl
Success! Uploaded policy: pki
```
- *Открываем центры сертификации и выпускаем сертификаты: корневой, промежуточный и рабочий(основной)*
```
export VAULT_ADDR='http://127.0.0.1:8201' VAULT_TOKEN=s.****************
vault secrets enable pki
    Success! Enabled the pki secrets engine at: pki/ //ОТКРЫТИЕ ЦЕНТРА
vault secrets tune -max-lease-ttl=87600h pki
    Success! Tuned the secrets engine at: pki/ //ВРЕМЯ ЖИЗНИ ЦЕНТРА
vault write -field=certificate pki/root/generate/internal common_name="vaultmkmycrazy.com" ttl=87600h > CA.crt
    //ПОЛУЧЕНИЕ КОРНЕВОГО СЕРТИФИКАТА
vault write pki/config/urls issuing_certificates="$VAULT_ADDR/v1/pki/ca" crl_distribution_points="$VAULT_ADDR/v1/pki/crl"
    Success! Data written to: pki/config/urls    // ПУБЛИКАЦИЯ СЕРТИФИКАТА
vault secrets enable -path=pki_int pki
    Success! Enabled the pki secrets engine at: pki_int/ ОТКРЫТИЕ ЦЕНТРА ПРОМЕЖУТОЧНОЙ СЕРТИФИКАЦИИ
vault secrets tune -max-lease-ttl=43800h pki_int
    Success! Tuned the secrets engine at: pki_int/ВРЕМЯ ЖИЗНИ
vault write -format=json pki_int/intermediate/generate/internal common_name="vaultmkmycrazy.com Intermediate Authority" | jq -r .data.csr >  pki_intermediate.csr
    // ЗАПРОС НА ПОЛУЧЕНИЕ ПРОМЕЖУТОЧНОГО СЕРТИФИКАТА.
vault write -format=json pki/root/sign-intermediate csr=@pki_intermediate.csr format=pem_bundle ttl="8000h" | jq -r '.data.certificate' > intermediate.cert.pem
    // ПОЛУЧЕНИЕ ПРОМЕЖУТОЧНОГО СЕРТИФИКАТА.
vault write pki_int/intermediate/set-signed certificate=@intermediate.cert.pem
    Success! Data written to: pki_int/intermediate/set-signed//ПУБЛИКАЦИЯ СЕРТИФИКАТА
vault write pki_int/roles/vaultmkmycrazy-com allowed_domains="vaultmkmycrazy.com" allow_subdomains=true max_ttl="8000h"
    Success! Data written to: pki_int/roles/vaultmkmycrazy-com //СОЗДАНИЕ РОЛИ
vault write -format=json pki_int/issue/vaultmkmycrazy-com common_name="www.vaultmkmycrazy.com" alt_names="www.vaultmkmycrazy.com"  ttl="740h" > vault.mkmycrazy.com.crt
    // ПОЛУЧЕНИЕ СЕРТИФИКАТА ДЛЯ САЙТА

cat vault.mkmycrazy.com.crt | jq -r .data.certificate > /vagrant/vault.mkmycrazy.com.crt.pem
cat vault.mkmycrazy.com.crt | jq -r .data.issuing_ca >> /vagrant/vault.mkmycrazy.com.crt.pem
cat vault.mkmycrazy.com.crt | jq -r .data.issuing_ca >> /vagrant/vault.mkmycrazy.com.crt.pem
    //СОХРАНЯЕМ СЕРТИФИКАТ В ПРАВИЛЬНОМ ФОРМАТЕ
```
#### 5. Установите nginx.
```
sudo apt install curl gnupg2 ca-certificates lsb-release debian-archive-keyring
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
gpg --dry-run --quiet --import --import-options import-show /usr/share/keyrings/nginx-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/debian `lsb_release -cs` nginx" \
    | sudo tee /etc/apt/sources.list.d/nginx.list
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/mainline/debian `lsb_release -cs` nginx" \
    | sudo tee /etc/apt/sources.list.d/nginx.list
echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
    | sudo tee /etc/apt/preferences.d/99nginx
sudo apt update
sudo apt install nginx
```
#### 6. Установите корневой сертификат созданного центра сертификации в доверенные в хостовой системе.
- *Созданный корневой сертификат копируется на хостовую систему и рабочий браузер(Opera) и добавляется как доверенный в систему. Сделал через общую папку для виртуалки и хоста /Vagrant/
Добвил в довереные корневой сертификат*
```
sudo cp CA.crt /vagrant/
```
![](https://github.com/VitkinKN/VAULT_SERV_CERT-NGINX_SERV_SITE-BASH_SCRIPT_MAKE_CERT/blob/master/IMG/1.JPG )

#### 7. Настройте nginx на https, используя ранее подготовленный сертификат:
- *Создаём каталог для нашего сайта и делаем простую страницу*
```HTML
 sudo mkdir -p /var/www/vaultmkmycrazy.com/html
 sudo nano /var/www/vaultmkmycrazy.com/html/index.html
 
 <!DOCTYPE html>
<html lang="ru">
        <head>
        <meta charset="UTF-8">
        <title> Netology_HomeWork from VitkinKN </title>
        </head>
        <body>
                Few weeks i did this.. AND I DO THIS!!!!!!!!!!!!
         </body>
        </html>
```
- *Создаём блок сервер сайта*
```
sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/vaultmkmycrazy.com
sudo nano /etc/nginx/sites-available/vaultmkmycrazy.com

server {
        listen 443 ssl;
        listen [::]:443 ssl;
        root /var/www/vaultmkmycrazy.com/html/;
        index index.html index.htm index.nginx-debian.html;
        server_name vaultmkmycrazy.com www.vaultmkmycrazy.com;
        ssl_certificate         "/etc/pki/nginx/www.vaultmkmycrazy.com/vault.mkmycrazy.com.crt.pem";
        ssl_certificate_key     "/etc/pki/nginx/www.vaultmkmycrazy.com/vault.mkmycrazy.com.crt.key";
        ssl_protocols           TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;
        location / {
                try_files $uri $uri/ =404;
        }
}
```
- *создаём папку для сертификатов и кладём их туда*
```
sudo mkdir -p /etc/pki/nginx/www.vaultmkmycrazy.com
sudo cp /vagrant/vault.mkmycrazy.com.crt.pem /etc/pki/nginx/www.vaultmkmycrazy.com
sudo cp /vagrant/vault.mkmycrazy.com.crt.key /etc/pki/nginx/www.vaultmkmycrazy.com
```
- *Включаем наш сайт*
```
sudo ln -s /etc/nginx/sites-available/vaultmkmycrazy.com /etc/nginx/sites-enabled
```
- *Конфигурируем сервер nginx*
```
sudo nano /etc/nginx/nginx.conf

events {
        worker_connections 768;
}
http {
        sendfile on;
        tcp_nopush on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        server_names_hash_bucket_size 64;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;

server {
        server_name             www.vaultmkmycrazy.com  vaultmkmycrazy.com;
        root /var/www/vaultmkmycrazy.com/html/;
        ssl_ciphers         HIGH:!aNULL:!MD5;
        ssl_protocols           TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
        index index.html index.htm;
}
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        iclude /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}
```
- *Прописываем IP для сайта:*
```
sudo nano /etc/hosts

192.168.54.5 www.vaultmkmycrazy.com vaultmkmycrazy.com
```
- *Запускаем сервер*
```
sudo systemctl start nginx
sudo systemctl enable nginx
```
#### 8.Откройте в браузере на хосте https адрес страницы, которую обслуживает сервер nginx
- *На Virtual Box поднял DHCP сервер с адресом 192.168.56.1.
На Windows 10  прописал в файле hosts.ics:  192.168.56.5 www.vaultmkmycrazy.com
На Виртуальной машине Linux с сервером nginx прописал в файле /etc/hosts: 192.168.56.5 www.vaultmkmycrazy.com*
![](https://github.com/VitkinKN/VAULT_SERV_CERT-NGINX_SERV_SITE-BASH_SCRIPT_MAKE_CERT/blob/master/IMG/2.JPG )
#### 9. Создайте скрипт, который будет генерировать новый сертификат в vault: генерируем новый сертификат так, чтобы не переписывать конфиг nginx; перезапускаем nginx для применения нового сертификата. 
- *Делаем файлы для ключей: .vault-unseal. файл для токена существует: .vault-token.*
```
touch .vault-unseal
sudo nano .vault-unseal // вкладываем в файл 5 наших ключей для сервера vault
```
- *Создаём bash скрипт для генерации сертификата в vault*
```
sudo touch /vagrant/myscript.sh
```
```bash
#! /usr/bin/bash

token_file=/home/vagrant/.vault-token
keys_file=/home/vagrant/.vault-unseal

export VAULT_ADDR='http://127.0.0.1:8201' VAULT_TOKEN=$(cat $token_file)

vault status 2>&1 >/dev/null
if [[ $? == 2 ]]
then
   keys=()
   while read key
   do
    keys+=($key)
   done < $keys_file
 while :
 do
 vault status 2>&1 >/dev/null
 if [[ $? == 2 ]]
 then
   for i in {1..5}
   do
     vault operator unseal ${keys[$i]} 2>1 >/dev/null
   done
  else
    break
  fi
 done
fi

sudo rm -rf /etc/pki/nginx/www.vaultmkmycrazy.com/*
vault write -format=json pki_int/issue/vaultmkmycrazy-com common_name="www.vaultmkmycrazy.com" alt_names="www.vaultmkmycrazy.com"  ttl="740h" > vault.mkmycrazy.com.crt

cat vault.mkmycrazy.com.crt | jq -r '.data.certificate' > vault.mkmycrazy.com.crt.pem
cat vault.mkmycrazy.com.crt | jq -r '.data.private_key' > vault.mkmycrazy.com.crt.key
cat vault.mkmycrazy.com.crt | jq -r '.data.ca_chain[]' >> vault.mkmycrazy.com.crt.pem

sudo mv vault.mkmycrazy.com.crt.pem /etc/pki/nginx/www.vaultmkmycrazy.com/
sudo mv vault.mkmycrazy.com.crt.key /etc/pki/nginx/www.vaultmkmycrazy.com/
sudo mv vault.mkmycrazy.com.crt /etc/pki/nginx/www.vaultmkmycrazy.com/
sudo systemctl reload nginx
```
- *Проверяем работу скрипта*
![](https://github.com/VitkinKN/VAULT_SERV_CERT-NGINX_SERV_SITE-BASH_SCRIPT_MAKE_CERT/blob/master/IMG/5.JPG )
- *После запуска скрипта время выпуска сертификата обновляется.*

#### 9. Поместите скрипт в crontab, чтобы сертификат обновлялся какого-то числа каждого месяца в удобное для вас время.
- *Делаем запуск скрипта на 1 число каждого месяца.*
```
 1  *    1 1-12 * root /vagrant/myscript.sh 
```
![](https://github.com/VitkinKN/VAULT_SERV_CERT-NGINX_SERV_SITE-BASH_SCRIPT_MAKE_CERT/blob/master/IMG/4.JPG )