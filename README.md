sudo docker compose up --build

sudo dcker cp worm/worm.py ubuntu1:/tmp/worm.py
sudo docker exec ubuntu1 python3 /tmp/worm.py

sudo ./worm/verify_worm.sh