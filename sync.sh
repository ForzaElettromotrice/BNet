addresses=("20.0.1.163" "20.0.1.221")

for address in "${addresses[@]}";
do
    sshpass -p "1234" scp src/* f3m@"$address":/home/f3m/BNet/src
done