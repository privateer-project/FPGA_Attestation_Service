# FPGA Attestation Service

This project contains the implementation for the secure configuration of FPGA hardware accelerators based on a custom remote attestation protocol. It includes the script for the external attestation server, as well as the scripts running in the edge server, that features an x86 based server with a PCI-Express FPGA card (Xilinx/AMD ALVEO card). Furthermore, the attestation server is responsible for forwarding the attestation results to the Security Context Broker (SCB) component, that represents a Blockchain infrastructure. An abstract architecture of the system is shown in the following Figure. 

![arch](https://github.com/privateer-project/FPGA_Attestation_Service/blob/main/img/arch.png?raw=true)

Note that a VPN connection is required in the attestation server, in order to obtain network connection with the SCB.

## Attestation Server

Run the following script to initiate the remote attestation external server, used for verification of the attestation service running on the Edge server, as well as for attesting the accelerator bitstream that will be loaded to the FPGA. Note that the user must provide the reference values for each component, as well as the bitstream decryption key.
```bash
python3 server_socket_ssl.py
```

## Edge Server with FPGA

After the attestation server is online, in order to instantiate the remote attestation service in the Edge server, user must run the following script:
```bash
python3 client_socket_ssl.py
```
In case the remote attestation procedure is successful, the kernel's bitstream is decrypted and it is loaded to the FPGA.


### Prerequisites

The provided scripts run with a AMD ALVEO U280 FPGA card with ```xilinx_u280_xdma_201920_3``` shell. Vitis/Vivado 2021.1 version was used for building the AES kernel as well as the accelerator kernel. 

Prior to running the remote attestation script, the user must build the AES encryption module that is required from the remote attestation service. Specifically, it is used for encrypting the remote attestation report, containing the accelerator kernel hash. In order to build the AES encryption module, the user follows the RTL kernel to IP flow:
```bash
```
Then, the user using Python bindings, it creates a library for interfacing with the C++ script from the attestation script that is written in python.
```bash
make build_sw
```
Note that the user has to move the ```.so``` file as well as the ```.xclbin``` generate file to the directory where the Python attestation service script is located.
