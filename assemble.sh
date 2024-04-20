#!/bin/sh

RED="\e[0;31m"
PURPLE='\e[0;34m'
GREEN='\e[0;32m'
NC='\e[0m' # No Color

BOLD=$(tput bold)
NORMAL=$(tput sgr0)

intro="Assemble and Run program using nasm and with gcc linker. It assembles using nasm and links using gcc to binary."
author="Author: Abdullah AL Shohag <HackerShohag@outlook.com>\n\
Github: https://github.com/HackerShohag"
usage="Usagae:\n\t${0} filename \t\tto tassemble, link and run"

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  echo -e ${intro} "\n\n" ${usage} "\n\n"${author}
  exit 0
fi

file="$1"
filename=$(basename $file .asm)

if [ $# -eq 0 ] ; then
    echo -e "${RED}${BOLD}ERROR: Please, specify a filename.${NORMAL}${NC}\n"
    echo $usage "\n\n"${author}
    exit 0
fi

if ! [ -f $file ]; then
  echo -e "${RED}${BOLD}ERROR: \"$file\" does not exist.${NORMAL}${NC}\n"
  echo $usage "\n\n"${author}
  exit 0
fi

ext="${file##*.}"

if ! [ "$ext" = "asm" ]; then
   echo -e "${RED}${BOLD}Provide a valid file (*.asm)${NORMAL}${NC}"
   exit 0
fi


echo -- Found file $file

# assemble
echo -e "${PURPLE}${BOLD}NASM:${NORMAL}${PURPLE} Assebmling $file${NORMAL}${NC}"
nasmerr=$(nasm -f elf64 $file -o $filename.o)

if ! [ $? -eq 0 ]; then
    echo $nasmerr
    exit 0
fi
echo -e "${GREEN}${BOLD}NASM:${NORMAL}${GREEN} Assebmled $file"

#link
echo -e "${PURPLE}${BOLD}GCC:${NORMAL}${PURPLE} Linking $filename.o using ld${NORMAL}${NC}"
linkerr=$(ld -o $filename $filename.o)

if ! [ $? -eq 0 ]; then
    echo $linkerr
    exit 0
fi
echo -e "${GREEN}${BOLD}GCC:${NORMAL}${GREEN} Linked $filename.o to $filename${NORMAL}${NC}"

# build message
echo -e "${GREEN}${BOLD}Assemble: Built target $filename${NORMAL}${NC}"

# clean
rm $filename.o