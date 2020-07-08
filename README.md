# ssith-mit-sanctum

Top level repository containing MIT's hardware and software used in the DARPA SSITH program and the FETT Bounty Hunt.

The softare in this repo runs primarily in our Sanctum-enhanced RISC-V processor running in an AWS F1 FPGA. Verilator may be used for debugging the hardware and security monitor.

Launch an AWS F1 instance running Ubuntu 18.04. Then install the following dependences::

    sudo apt-get update
    sudo apt-get install cmake device-tree-compiler build-essential libssl-dev libcurl4-openssl-dev libsdl-dev libelf-dev

To build all the software, clone this repo, checkout all the submodules, and run the build script::

    git clone https://github.com/mit-enclaves/ssith-mit-sanctum
    cd ssith-mit-sanctum
    git submodule update --init --recursive
    ./build.sh
    
Once the software is built, program the FPGA and boot Linux on the FPGA::

    cd ssith-mit-sanctum
    ./run.sh
    
When the processor boots, login as `root` with password `riscv`. Use `ctrl-A x` to disconnect from the host console.

There are two enclave examples currently. The first uses an enclave that encrypts or decrypts using a key and code contained in the enclave. The second is a Pluggable Authentication Module (PAM) which keeps the user/password database in the enclave.

## AES Enclave

After logging into the risc-v CPU::

    /ssith/aes-main -e input.txt foo.bin
    /ssith/aes-main -d foo.bin output.txt
    diff -u input.txt output.txt

## PAM authentication enclave

Our enclaves currently only run in batch mode, which is a bit slow, so the PAM module is available in a `testing` context. One may use `pamtester` to exercise the enclave::

    pamtester testing ubuntu authenticate

The password for `ubuntu` is `rootme`. Other passwords are for you to discover.


