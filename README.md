# Secure Hasher Project

## Overview

The Secure Hasher Project is a cross-platform Java application designed to securely generate a strong hash of a UTF-8 encoded string, download a public key from a remote URL, and encrypt the hash using that public key. To enhance security, the hashing and encryption logic is implemented in C++ to make reverse-engineering more difficult.

## Features

- Secure hashing of UTF-8 encoded strings.
- Encryption using public keys retrieved from remote URLs.
- Hybrid Java and C++ implementation for enhanced security.
- Cross-platform support (Windows, macOS, Linux).

## Prerequisites

### Java Requirements

- Java JDK (version 8 or higher) - [Download Here](https://www.oracle.com/java/technologies/javase-jdk8-downloads.html)
- Maven - [Download Here](https://maven.apache.org/download.cgi)

### C++ Requirements

- GCC (for compiling C++ code):
  - Pre-installed on most Linux systems.
  - Available via MinGW for Windows - [Download Here](http://www.mingw.org/)
- OpenSSL library (for encryption) - [Download Here](https://www.openssl.org/source/)

## Setup Instructions

### 1. Compile Java Code to Generate Header File

```sh
javac -cp "C:\Users\Ole Kacak\.m2\repository\org\json\json\20210307\json-20210307.jar" -h ../cpp src/main/java/com/secure/SecureHasher.java
```

### 2. Compile C++ Code

```sh
g++ -shared -o SecureHasherNative.dll -I"%JAVA_HOME%\include" -I"%JAVA_HOME%\include\win32" SecureHasher.cpp -lssl -lcrypto
```

### 3. Package the Application Using Maven

```sh
mvn compile package
```

### Running the Application
```
java -Djava.library.path="target" -cp "target/hashing-1.0-SNAPSHOT.jar;target/json-20210307.jar" com.secure.SecureHasher
```

### Additional Notes
- Ensure the SecureHasherNative.dll (or libSecureHasherNative.so for Linux) file is present in the target folder before running the application.
- Make sure the OpenSSL library is installed and accessible during the compilation of the C++ code.
- Adjust file paths and extensions according to your operating system.

### Compatibility
- Windows (DLL handling).
- macOS (Requires compilation with .dylib).
- Linux (Requires compilation with .so).
