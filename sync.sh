addresses=("192.168.1.108")

for address in "${addresses[@]}";
do
    sshpass -p "1234" scp src/* f3m@"$address":/home/f3m/BNet/src
done