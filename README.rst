
Zephyr Mbedtls demo
###########

Overview
********

A simple sample that can verify rsa signature

Building and Running
********************

This application can be built and executed on any board, such as esp32 csk6

Sample Output on esp32_devkitc_wroom
=============

.. code-block:: console

    *** Booting Zephyr OS build zephyr-v3.5.0-2091-g0e11bcf5a0e7 ***
    Hello World! esp32_devkitc_wroom
    Start RSA verify !
    Parse RSA public key !
    parse public key ret = 0
    Set RSA padding !
    mbedtls_rsa_set_padding ret = 0
    Calculate SHA256 !
    mbedtls_sha256 ret = 0
    Raw string: testchip3>>ab1;ab2;
    Sha256 result: 48dd7bd122f63df974ab67bcac355c679ea72a43e5ae12648869e22e5f3c8b

    Get signature bin size len : 256
    binary_data k_malloc success
    mbedtls_base64_decode success, decoded_len: 256
    decoded result: len: 256
    37 05 f8 18 71 dc ea 78 e6 fe ec 1f 82 ac 27 36 c6 e2 4b 63 d7 b1 1f 6e 9b 50 65 f4 ef be 93 57 
    11 9e 92 a2 5f ea 68 76 cf be 3b a8 a8 48 0a e5 0d e3 69 b8 53 ba bb a1 ad d4 01 84 97 e2 9b fe 
    16 6f 40 e0 7b b0 3a 3c 9d 03 65 5b c7 b3 c0 5d 84 d8 26 f7 41 80 85 cf 92 f4 e0 89 3f 7f ea c9 
    a3 6b 7f 37 68 e0 1e dc 52 6d 5e 5a 1f cb 18 aa 67 4b 91 ce ab 9f af f5 fa 5f c4 53 f9 f3 4a 45 
    4a 87 d0 19 e0 8e 87 56 ff ae d3 76 f9 e6 7c ed 73 38 85 d4 4c a5 cd 14 f9 42 6b e9 0a e9 45 69 
    69 ca 84 fc 28 d9 cf ef 98 7f 4b 21 e0 05 37 5c e6 0e eb 54 a4 97 8c c4 ae bc 22 58 00 d0 71 ab 
    73 3d 32 6b 9c c4 c2 ca 0f 60 60 9f b0 e9 3b 5c 24 fe 9f e3 48 4a 75 ba a7 2d c5 78 a6 72 73 a6 
    59 e9 0c c5 07 b4 1a 8e a1 4d ed 3f e8 11 e9 19 69 3d e0 b4 2c 6b 34 d7 22 78 e4 aa 34 cb c9 6c 
    Verify RSA_SHA256_PKCS_V15 signature !
    mbedtls_pk_verify ret = 0
    Verify Passed

