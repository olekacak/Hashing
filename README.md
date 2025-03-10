Secure Hasher Project

Project Description

This project is a Java application designed to securely generate a strong hash of a UTF-8 encoded string, download a public key from a remote URL, and encrypt the hash using that public key. To enhance security, the hashing and encryption logic is implemented in C++ to make reverse-engineering more difficult.

Requirements

Java JDK (version 8 or higher): Download Here

Maven: Download Here

GCC (for compiling C++ code): Usually pre-installed on Linux systems or available via MinGW for Windows.

OpenSSL library (for encryption): Download Here

Setup Instructions

1. Compile Java Code to Generate Header File

javac -cp "C:\Users\Ole Kacak\.m2\repository\org\json\json\20210307\json-20210307.jar" -h ../cpp src/main/java/com/secure/SecureHasher.java

2. Compile C++ Code

Navigate to /src/main/cpp and run:

g++ -shared -o SecureHasherNative.dll -I"%JAVA_HOME%\include" -I"%JAVA_HOME%\include\win32" SecureHasher.cpp -lssl -lcrypto

3. Package the Application Using Maven

mvn compile package

Running the Application

Use the following command to run the jar file:

java -Djava.library.path="target" -cp "target/hashing-1.0-SNAPSHOT.jar;target/json-20210307.jar" com.secure.SecureHasher

Notes

Ensure the SecureHasherNative.dll file is present in the target folder before running the application.

Make sure the OpenSSL library is installed and accessible during the compilation of the C++ code.

This application can run on Windows, macOS, and Linux (with modifications for .dll file handling on other systems).
