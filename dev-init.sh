#!/bin/sh

for dir in client common server .;
do
    cd $dir
    npm i
    cd -
done
