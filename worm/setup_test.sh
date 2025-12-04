#!/bin/bash

# Script para configurar el entorno de prueba de FooWorm en Docker
# Este script debe ejecutarse DESDE EL HOST (no desde dentro de los contenedores)

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  Configurando entorno de prueba para FooWorm.py           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Colores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 1. Crear archivos .foo de prueba en ubuntu2
echo -e "${YELLOW}[1/5]${NC} Creando archivos .foo de prueba en ubuntu2 (172.28.0.3)..."
sudo docker exec ubuntu2 bash -c "echo 'Secret data from ubuntu2 - file1' > /home/ubuntu/secret1.foo"
sudo docker exec ubuntu2 bash -c "echo 'Confidential information - file2' > /home/ubuntu/data.foo"
sudo docker exec ubuntu2 bash -c "echo 'Important document' > /home/ubuntu/docs.foo"
echo -e "${GREEN}✓${NC} Archivos creados en ubuntu2"

# 2. Crear archivos .foo de prueba en ubuntu3
echo -e "${YELLOW}[2/5]${NC} Creando archivos .foo de prueba en ubuntu3 (172.28.0.4)..."
sudo docker exec ubuntu3 bash -c "echo 'Ubuntu3 secret data' > /home/ubuntu/secret2.foo"
sudo docker exec ubuntu3 bash -c "echo 'Financial records' > /home/ubuntu/finance.foo"
echo -e "${GREEN}✓${NC} Archivos creados en ubuntu3"

# 3. Instalar Python y dependencias en ubuntu1 (el atacante)
echo -e "${YELLOW}[3/5]${NC} Instalando Python y dependencias en ubuntu1..."
sudo docker exec ubuntu1 bash -c "apt-get update -qq && apt-get install -y -qq python3 python3-pip > /dev/null 2>&1"
sudo docker exec ubuntu1 bash -c "cd /home/ubuntu && pip3 install -q -r requirements.txt"
echo -e "${GREEN}✓${NC} Dependencias instaladas en ubuntu1"

# 4. Verificar conectividad SSH entre contenedores
echo -e "${YELLOW}[4/5]${NC} Verificando conectividad SSH..."
sudo docker exec ubuntu1 apt-get install -y -qq sshpass > /dev/null 2>&1
echo -e "${GREEN}✓${NC} Herramientas de SSH instaladas"

# 5. Mostrar resumen de la configuración
echo ""
echo -e "${YELLOW}[5/5]${NC} Resumen de la configuración:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}ubuntu1${NC} (172.28.0.2) - Atacante (tiene FooWorm_Docker.py)"
echo -e "${GREEN}ubuntu2${NC} (172.28.0.3) - Víctima 1 (3 archivos .foo)"
echo -e "${GREEN}ubuntu3${NC} (172.28.0.4) - Víctima 2 (2 archivos .foo)"
echo -e "${GREEN}ubuntu4${NC} (172.28.0.5) - Servidor de exfiltración"
echo ""
echo "Credenciales para todos los contenedores:"
echo "  Usuario: ubuntu"
echo "  Password: ubuntu"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${GREEN}✓ Configuración completada${NC}"
echo ""
echo "Para ejecutar el worm, usa:"
echo -e "${YELLOW}  sudo docker exec -it ubuntu1 bash${NC}"
echo -e "${YELLOW}  python3 /home/ubuntu/FooWorm_Docker.py${NC}"
echo ""
