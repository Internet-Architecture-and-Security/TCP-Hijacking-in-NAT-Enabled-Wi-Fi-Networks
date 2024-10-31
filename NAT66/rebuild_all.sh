echo "Remaking each attack phase script..."

cd ./1-infer_port
make

cd ../2-infer_seq
make

echo "Finished building attack scripts."