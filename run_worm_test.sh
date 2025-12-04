#!/bin/bash

# Script simple para ejecutar FooWorm y ver los resultados en tiempo real
 
sudo docker exec ubuntu1 bash -c "pip3 install paramiko scp"
echo ""

echo "EJECUTANDO FooWorm.py en el entorno Docker"
echo ""
sudo docker exec -it ubuntu1 python3 /home/ubuntu/FooWorm_Docker.py

echo ""
echo "RESULTADOS DE LA EJECUCIÓN:"
echo ""

echo "Ubuntu2 (172.28.0.3):"
echo "  ¿Infectado?"
sudo docker exec ubuntu2 bash -c "ls /home/ubuntu/ | grep -i fooworm && echo 'SÍ - Worm encontrado' || echo 'NO'"

echo ""
echo "Ubuntu3 (172.28.0.4):"
echo "  ¿Infectado?"
sudo docker exec ubuntu3 bash -c "ls /home/ubuntu/ | grep -i fooworm && echo 'SÍ - Worm encontrado' || echo 'NO'"

echo ""
echo "Ubuntu4 (172.28.0.5 - Servidor de Exfiltración):"
echo "  Archivos .foo exfiltrados:"
sudo docker exec ubuntu4 bash -c "ls /home/ubuntu/*.foo 2>/dev/null | wc -l" | awk '{print "    " $1 " archivos"}'

echo ""
echo "Ubuntu    1 (Atacante):"
echo "  Archivos .foo descargados:"
sudo docker exec ubuntu1 bash -c "ls /home/ubuntu/*.foo 2>/dev/null | wc -l" | awk '{print "    " $1 " archivos"}'═════════════════════════════════════════════════════════╝"
