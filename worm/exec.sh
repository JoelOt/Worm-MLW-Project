make
sudo docker cp worm ubuntu1:/tmp/worm
sudo docker exec ubuntu1 chmod +x /tmp/worm
sudo docker exec -it ubuntu1 /tmp/worm
