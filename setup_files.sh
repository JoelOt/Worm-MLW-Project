#!/bin/bash

# Script de setup completo - ejecutar UNA SOLA VEZ

# Crear archivos en ubuntu2
echo "Creando archivos en ubuntu2..."
sudo docker exec ubuntu2 bash -c "echo 'Secret data from ubuntu2 - file1' > /home/ubuntu/secret1.foo"
sudo docker exec ubuntu2 bash -c "echo 'Confidential information - file2' > /home/ubuntu/data.foo"
sudo docker exec ubuntu2 bash -c "echo 'Important document' > /home/ubuntu/docs.foo"

# Crear archivos en ubuntu3
echo "Creando archivos en ubuntu3..."
sudo docker exec ubuntu3 bash -c "echo 'Ubuntu3 secret data' > /home/ubuntu/secret2.foo"
sudo docker exec ubuntu3 bash -c "echo 'Financial records' > /home/ubuntu/finance.foo"

echo "Archivos de prueba creados"
echo "ubuntu2: $(sudo docker exec ubuntu2 ls /home/ubuntu/*.foo 2>/dev/null | wc -l) archivos .foo"
echo "ubuntu3: $(sudo docker exec ubuntu3 ls /home/ubuntu/*.foo 2>/dev/null | wc -l) archivos .foo"