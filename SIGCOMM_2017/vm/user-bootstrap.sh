#!/bin/bash

set -x

# Bmv2
git clone https://github.com/p4lang/behavioral-model
cd behavioral-model
./install_deps.sh
./autogen.sh
./configure
make
sudo make install
cd ..

# Protobuf
git clone https://github.com/google/protobuf.git
cd protobuf
git checkout v3.0.2
sudo apt-get install -y autoconf automake libtool curl make g++ unzip
./autogen.sh
./configure
make
sudo make install
sudo ldconfig
cd ..

# P4C
git clone --recursive https://github.com/p4lang/p4c
sudo apt-get install -y g++ git automake libtool libgc-dev bison flex libfl-dev libgmp-dev libboost-dev libboost-iostreams-dev pkg-config python python-scapy python-ipaddr tcpdump cmake
cd p4c
mkdir build
cd build
cmake ..
make -j4
sudo make install
cd ..
cd ..

# Tutorials
git clone https://github.com/p4lang/tutorials
cd tutorials
git checkout sigcomm_17
cd ..
