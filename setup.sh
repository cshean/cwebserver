#!/bin/bash

if [ "$1" == "" ]; then
    read -p "Please enter your username: " UNAME
else
    UNAME=$1
fi

echo "Registering via CSUNIX..."
ssh $UNAME@csunix.bju.edu /home/cps320/wswars/register >stdout.txt 2>stderr.txt
read IPADDR <stdout.txt
read ERROR <stderr.txt
rm stdout.txt stderr.txt

if [ "$IPADDR" == "" ]; then
    echo
    echo "Registration failure: $ERROR"
    exit 1
fi

cat >go.sh <<EOF
#!/bin/bash

# Change this if your webserver has a different name/path
WEBSERVER="./webserver"

# Shouldn't have to change this
DOC_ROOT="./wwwroot"

# Or this
WARPROXY="./warproxy.py"

# Do not change this
TIMEOUT="10"

CMD="\$WARPROXY -t \$TIMEOUT -o csunix.bju.edu -n $IPADDR -p 8080 -- \$WEBSERVER -r \$DOC_ROOT"
echo "Running: \$CMD"
read -e -N1 -iY -p "Is this OK? [Y/n]" OK
if [ "\$OK" != "Y" ]; then
    echo "OK, bailing out..."
    exit 1
fi
\$CMD
EOF
chmod +x go.sh

echo 
echo "Registered at IP address $IPADDR"
echo
echo "[Edit and] Run go.sh to enter the Wars"

