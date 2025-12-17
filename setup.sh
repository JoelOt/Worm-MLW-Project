#!/bin/bash

rmdir -rf ./keys
mkdir -p ./keys
ssh-keygen -f ./keys/id_rsa -N ""
