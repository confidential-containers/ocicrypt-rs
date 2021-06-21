## Generate keypair for unit and integration tests

### Create PMEM private key
openssl genrsa -out private_key.pem

### Create PMEM public key from PMEM private key
openssl rsa -inform pem -outform pem -pubout -in private_key.pem -out public_key.pem

### Create self-signed root certificate
openssl req -x509 -newkey rsa:2048 -keyout certificate_key.pem -out certificate.pem -days 365 -nodes -subj '/CN=localhost'

### Create Certificate Signing Request (CSR) from existing PEM private key
openssl req -new -key private_key.pem -out private_csr.csr -subj '/CN=bar/'

### Create client certificate from root certificate and CSR
openssl x509 -req -in private_csr.csr -CA certificate.pem  -CAkey certificate_key.pem -CAcreateserial -out public_certificate.pem -days 100 -sha256

### Create passwordfile
echo -n "123456" > passwordfile
