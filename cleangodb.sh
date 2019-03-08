y=$(sudo docker ps | awk '{print $1}' | sed -n 2p)
sudo docker stop $y
sudo docker rm $y
sudo docker volume prune

sudo docker run -d -e POSTGRES_PASSWORD="" -p 5432:5432 postgres:9.6

echo ...

sudo docker ps

echo ... 
echo done

