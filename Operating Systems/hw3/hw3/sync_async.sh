#!/bin/bash

./create_process -e -m -z inf1.txt
./create_process -e -m syncinf2.txt
./create_process -m -z inf3.txt
./create_process -e -z syncinf4.txt
./create_process -e -m -z syncinf5.txt
