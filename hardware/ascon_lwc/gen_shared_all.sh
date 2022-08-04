# calls gen_shared.py for each folder in ./KAT

folders=$(ls KAT)
folders=($folders)
for i in "${folders[@]}"
do
echo $i
j=${i:0:2}
python3 gen_shared.py --design ascon_$j.toml --folder ./KAT/$i
done
