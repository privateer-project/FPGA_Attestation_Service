// --------------------------------------------------------------------------------------
// AES Encryption of FPGA
// Modified by Ilias Papalamprou

// --------------------------------------------------------------------------------------
//
// Copyright 2021 Xilinx, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "experimental/xrt_kernel.h"
#include "experimental/xrt_uuid.h"
#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <iomanip>
#include <cstdlib>
#include <openssl/aes.h>
#include <string.h>
#include <bitset>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

// Please use 'xbutil list' command to get the device id of the target alveo card if multiple
//   cards are installed in the system.
#define DEVICE_ID   0

// Function to save formatted output to a std::string variable
std::string save_output_to_string(const char* output_data, size_t words_num) {
    std::ostringstream oss;

    for (size_t i = 0; i < words_num * 16; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (static_cast<unsigned int>(output_data[i]) & 0xff);
    }

    // Convert the string stream to a std::string
    return oss.str();
}

// AES Encryption function
std::string aes_encrypt_kernel(const std::string &a, const std::string &b) {
    int opt;
    const char *optstring = "w:k:";

    int words_num = 9;
	
    std::string key = a;


    // generate key and iv byte array for openssl library
    unsigned char key_byte[32], iv_byte[16];
    for (int i = 0; i < 32; i++) {
        key_byte[i] = (unsigned char)std::stoll(key.substr(i*2,2), nullptr, 16);
    }

    std::cout << "--------- Attestation Report AES256 Encryption on FPGA ----------" << std::endl;


    // --------------------------------------------------------------------------------------
    // Generate and read plain/cipher data into host buffer
    // --------------------------------------------------------------------------------------
    char* plain_data;
    char* cipher_data;
    plain_data  = new char [9 * 16];
    cipher_data  = new char [9 * 16];

    std::string plain_data_test = b;

    size_t p_length = plain_data_test.length() / 2;
    // std::cout << "p_length : " << p_length << std::endl;

    for (int i = 0; i < p_length; i++) {
        plain_data[i] = (char)std::stoll(plain_data_test.substr(i*2,2), nullptr, 16);
    }


    // --------------------------------------------------------------------------------------
    // Device and kernel initialization
    // --------------------------------------------------------------------------------------
    std::string xclbin_file = "krnl_aes_test_hw.xclbin";
    char *env_emu;

    // Load xclbin
    std::cout << "Loading " << xclbin_file << "..." << std::endl;
    xrt::device device = xrt::device(DEVICE_ID);
    xrt::uuid xclbin_uuid = device.load_xclbin(xclbin_file);
   
    // create kernel objects
    std::cout << "Create AES kernel" << std::endl;
    xrt::kernel kernel_krnl_aes = xrt::kernel(device, xclbin_uuid, 
                                                "krnl_aes",
                                                xrt::kernel::cu_access_mode::exclusive);

    std::vector <xrt::kernel> kernel_strm_issue;
    kernel_strm_issue.push_back(xrt::kernel(device, xclbin_uuid, 
                                                "strm_issue:{strm_issue_1}", 
                                                xrt::kernel::cu_access_mode::exclusive));


    std::vector <xrt::kernel> kernel_strm_dump;
    kernel_strm_dump.push_back(xrt::kernel(device, xclbin_uuid, 
                                                "strm_dump:{strm_dump_1}", 
                                                xrt::kernel::cu_access_mode::exclusive));

    // get memory bank groups
    xrtMemoryGroup bank_grp_strm_issue = kernel_strm_issue[0].group_id(1);
    xrtMemoryGroup bank_grp_strm_dump = kernel_strm_dump[0].group_id(1);

    // create device buffer objects
    std::cout << "Create input and output device buffers" << std::endl;
    std::vector <xrt::bo> buffer_strm_issue;
    std::vector <xrt::bo> buffer_strm_dump;

    buffer_strm_issue.push_back(xrt::bo(device, 9*16, xrt::bo::flags::normal, bank_grp_strm_issue));
    buffer_strm_dump.push_back(xrt::bo(device, 9*16, xrt::bo::flags::normal, bank_grp_strm_dump));

    // create kernel runner instance
    xrt::run run_key_exp(kernel_krnl_aes);  // runner for krnl_aes
    std::vector <xrt::run> run_strm_issue;  // runner for strm_issue
    std::vector <xrt::run> run_strm_dump;   // runner for strm_dump
    
    run_strm_issue.push_back(xrt::run(kernel_strm_issue[0]));
    run_strm_dump.push_back(xrt::run(kernel_strm_dump[0]));

    // --------------------------------------------------------------------------------------
    // krnl_aes kernel: finish AES key expansion operation
    // --------------------------------------------------------------------------------------
    run_key_exp.set_arg(0, 1);      // MODE = 1 (encryption)
    run_key_exp.set_arg(1, 3);      // KEY_LEN = 3 (256-bit)
    run_key_exp.set_arg(3, std::stoll(key.substr(0, 8), nullptr, 16));    // KEY word 7
    run_key_exp.set_arg(4, std::stoll(key.substr(8, 8), nullptr, 16));    // KEY word 6
    run_key_exp.set_arg(5, std::stoll(key.substr(16, 8), nullptr, 16));   // KEY word 5
    run_key_exp.set_arg(6, std::stoll(key.substr(24, 8), nullptr, 16));   // KEY word 4
    run_key_exp.set_arg(7, std::stoll(key.substr(32, 8), nullptr, 16));   // KEY word 3
    run_key_exp.set_arg(8, std::stoll(key.substr(40, 8), nullptr, 16));   // KEY word 2
    run_key_exp.set_arg(9, std::stoll(key.substr(48, 8), nullptr, 16));   // KEY word 1
    run_key_exp.set_arg(10, std::stoll(key.substr(56, 8), nullptr, 16));   // KEY word 0
    run_key_exp.start();
    run_key_exp.wait();

// --------------------------------------------------------------------------------------
// Encryption test
// strm_issue and strm_dump kernels: transfer input data to device and get output data from device
// --------------------------------------------------------------------------------------
    struct timeval kernels_start_time, kernels_finish_time;     // kernel execution time record

    // create host buffer for output data check
    char *output_data;
    output_data = new char [9 * 16];

    // write plain_data into input device buffer of strm_issue kernels
    std::cout << "Transfer plain data into device buffer" << std::endl;

    buffer_strm_issue[0].write(plain_data);
    buffer_strm_issue[0].sync(XCL_BO_SYNC_BO_TO_DEVICE);

    run_strm_issue[0].set_arg(1, buffer_strm_issue[0]);     // memory pointer
    run_strm_issue[0].set_arg(2, 9 * 16);           // transfer byte size
    run_strm_dump[0].set_arg(1, buffer_strm_dump[0]);       // memory pointer
    run_strm_dump[0].set_arg(2, 9 * 16);            // transfer byte size

    run_strm_issue[0].start();
    run_strm_dump[0].start();

    run_strm_issue[0].wait();
    run_strm_dump[0].wait();

    // std::cout << "-- AES Engine " << std::endl;
    buffer_strm_dump[0].sync(XCL_BO_SYNC_BO_FROM_DEVICE);
    buffer_strm_dump[0].read(output_data);

    std::string formatted_output = save_output_to_string(output_data, words_num);


    std::cout << "FPGA Processing completed" << std::endl;

    return formatted_output;
}


// --------------------------------------------------------------------------------------
// Python Bindings
PYBIND11_MODULE(krnl_aes_encrypt, m) {
    m.def("aes_encrypt_kernel", &aes_encrypt_kernel, "A function which performs AES Encryption");
}
