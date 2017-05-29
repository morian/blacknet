

# Clone easyrsa from repository
> cd /tmp/
> git clone https://github.com/OpenVPN/easy-rsa.git

# Then create a new Authority
> cd /tmp/easy-rsa/easyrsa3
> ./easyrsa init-pki
# When asked provide a Common Name for your CA (eg: BlackNet CA)
> ./easyrsa build-ca nopass

# Generate and sign a certificate for main server (here called maestro)
> ./easyrsa gen-req maestro nopass
> ./easyrsa sign server maestro

# Same for client
> ./easyrsa gen-req honeypot_00 nopass
> ./easyrsa sign client honeypot_00


