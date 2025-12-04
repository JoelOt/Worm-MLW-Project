#!/bin/bash

# Script para verificar el estado de la infección en los contenedores

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  Verificación del estado de infección                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}═══ UBUNTU2 (172.28.0.3) ═══${NC}"
echo "Archivos en /home/ubuntu:"
sudo docker exec ubuntu2 ls -lah /home/ubuntu/
echo ""
echo "¿Está infectado?"
sudo docker exec ubuntu2 bash -c "ls /home/ubuntu/ | grep -i fooworm && echo 'SÍ - Worm encontrado' || echo 'NO - Worm no encontrado'"
echo ""

echo -e "${BLUE}═══ UBUNTU3 (172.28.0.4) ═══${NC}"
echo "Archivos en /home/ubuntu:"
sudo docker exec ubuntu3 ls -lah /home/ubuntu/
echo ""
echo "¿Está infectado?"
sudo docker exec ubuntu3 bash -c "ls /home/ubuntu/ | grep -i fooworm && echo 'SÍ - Worm encontrado' || echo 'NO - Worm no encontrado'"
echo ""

echo -e "${BLUE}═══ UBUNTU4 (172.28.0.5 - Servidor de Exfiltración) ═══${NC}"
echo "Archivos exfiltrados en /home/ubuntu:"
sudo docker exec ubuntu4 ls -lah /home/ubuntu/
echo ""
echo "Conteo de archivos .foo exfiltrados:"
sudo docker exec ubuntu4 bash -c "ls /home/ubuntu/*.foo 2>/dev/null | wc -l"
echo ""

echo -e "${BLUE}═══ UBUNTU1 (172.28.0.2 - Atacante) ═══${NC}"
echo "Archivos descargados:"
sudo docker exec ubuntu1 ls -lah /home/ubuntu/*.foo 2>/dev/null || echo "No hay archivos .foo descargados"
echo ""
