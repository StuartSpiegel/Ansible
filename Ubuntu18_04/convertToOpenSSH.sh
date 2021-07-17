# This script is for converting from a Putty (.ppk file) into OPEN SSH Keys
# brew install putty, brew install putty-gen
puttygen Elastic.ppk -O private-openssh -o privatekey.pem
sudo chmod go-rw privatekey.pem

