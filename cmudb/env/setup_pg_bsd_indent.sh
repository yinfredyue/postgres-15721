#!/bin/bash

# Run this script from the root folder of your repo.

set -e

SRC_FOLDER=$(pwd)
SRC_SUB_FOLDER='./setup_env/'
BIN_FOLDER="./setup_env/noisepage-bin"
BUILD_FOLDER="./setup_env/noisepage-build"
PG_BSD_INDENT_FOLDER="./setup_env/pg_bsd_indent"

if [ "$EUID" -ne 0 ]
  then echo "This script must be run with sudo to move to /usr/local/bin."
  exit 1
fi

echo "This script will add pg_bsd_indent to /usr/local/bin."
echo "Source folder: $SRC_FOLDER"
echo "Build folder: $SRC_FOLDER/$BUILD_FOLDER"
echo "Bin folder: $SRC_FOLDER/$BIN_FOLDER"
echo "pg_bsd_indent folder: $SRC_FOLDER/$PG_BSD_INDENT_FOLDER"
read -p 'Continue? [y/N]: ' CHOICE
case "$CHOICE" in
  y|Y) ;;
  *) exit 1;
esac

set -x

# Delete and make the sub-folder for all builds.
rm -rf $SRC_FOLDER/$SRC_SUB_FOLDER
mkdir -p $SRC_FOLDER/$SRC_SUB_FOLDER

# Build and install NoisePage to the subfolder since pg_config is required.
mkdir -p $BUILD_FOLDER
cd $BUILD_FOLDER
$SRC_FOLDER/configure --prefix=$SRC_FOLDER/$BIN_FOLDER --quiet
make install -j -s

# Build and move pg_bsd_indent.
cd $SRC_FOLDER
git clone https://git.postgresql.org/git/pg_bsd_indent.git $SRC_FOLDER/$PG_BSD_INDENT_FOLDER
cd $SRC_FOLDER/$PG_BSD_INDENT_FOLDER
make PG_CONFIG=$SRC_FOLDER/$BIN_FOLDER/bin/pg_config -j -s
sudo mv ./pg_bsd_indent /usr/local/bin/pg_bsd_indent

# Clean up.
rm -rf $SRC_FOLDER/$SRC_SUB_FOLDER
