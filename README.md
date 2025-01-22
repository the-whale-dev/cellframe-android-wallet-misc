### Build from sources:

#### Linux Prerequsites 

To successfully complete of the build, you need to have the following packages to be installed 
(packages are named as in Debian GNU/Linux 10 "buster", please found the corresponding packages for your distribution):

* libsqlite3-dev
* libmagic-dev
* libz-dev
* traceroute
* build-essential
* cmake
* dpkg-dev
* debconf-utils

Please use the command below to install dependencies listed above
```
sudo apt-get install build-essential cmake dpkg-dev libz-dev libmagic-dev libsqlite3-dev traceroute debconf-utils xsltproc
```

Generaly thats all what you need


#### Get all cellframe-tool-sign sources

You'll need to retrieve the cellframe-sdk repository from the demlabs gitlab
  ```
  git clone https://gitlab.demlabs.net/cellframe/cellframe-sdk.git --recursive
  ```

#### Build cellframe-tool-sign for different architectures using cmake framework
Get into directory with cellframe-tool-sign and execute the following commands
  ```
  mkdir build
  cd build
  cmake -DCMAKE_TOOLCHAIN_FILE=/path/to/android.toolchain.cmake \
        -DANROID_ABI=arm64-v8a
        -DANROID_PLATFORM=21 \
        -DCMAKE_BUILD_TYPE=Release \
  make -j$(nproc)
  ```
*-j$(nproc)* nrpoc parameter depends on your machine capacity - number of processor cores.

-Replace arm64-v8a to any of the following architecture types if necessary:

1) armeabi-v7a
2) x86
3) x86_64

As a result, you should create a libcellframe-tool-sign.so file that can now be used on an Android device