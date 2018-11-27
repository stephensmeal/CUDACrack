#include <ctime>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <cmath>
#include <locale.h>

const int PWD_LENGTH = 4;
const int HASH_LENGTH = 64;
const int NUM_BLOCKS = 64;
const int NUM_THREADS = 256;
const int KERNEL_SIZE = NUM_BLOCKS * NUM_THREADS;
const int CHARACTER_SET = 94;
const int ASCII_OFFSET = 33;
const size_t PWD_TRY_ARR_MEM_SIZE = (sizeof(char) * PWD_LENGTH) * KERNEL_SIZE;
const size_t PWD_HASH_ARR_MEM_SIZE = (sizeof(char) * HASH_LENGTH) * KERNEL_SIZE;
const size_t COMP_ARR_MEM_SIZE = (sizeof(int) * KERNEL_SIZE);

// Application variables
std::string pwdSalt = "";
std::string checkFor = "";
std::string testPwdStr = "";
std::string testHash = "";
bool passwordFound = false;
std::string resultPassword = "";
unsigned long maxPwdAttempts;
int kernelPasses = 0;

// Timing variables
double totalRunTime = 0;

/**
 *  Caculates the maximum number of attempts based on password length
 */
__host__
void calcMaxAttempts() {
    for (int i = 1; i <= PWD_LENGTH; i++) {
        maxPwdAttempts += pow(CHARACTER_SET, i);
    }
    maxPwdAttempts += KERNEL_SIZE - 1;
}

/**
 *  Take user input and parse into salt and hash
 */
__host__
void parseInputHash(std::string arg) {
    pwdSalt = arg.substr(0,12);
    checkFor = arg.substr(12,HASH_LENGTH);
    std::cout << "User Entered the Following Password Hash Information...\n";
    std::cout << "Salt: " << pwdSalt << "\n";
    std::cout << "Hash: " << checkFor << "\n";
}

/**
 *  Create hash from brute force password string
 */
__host__
std::string createHash(std::string password) {
    // Create password hash from password try and salt
    testHash = crypt((char *) password.c_str(), (char *) pwdSalt.c_str());
    return testHash.substr(12,HASH_LENGTH);
}

/**
 *  Helper function to copy the individual hash to the hash array
 */
__host__
void copyHashToArr(int arrIndx, std::string hash, char *charArr) {
    // Calculate array offset
    int offset = arrIndx * HASH_LENGTH;
    // Loop through input hash to insert into hash array
    for (int i = 0; i < HASH_LENGTH; i++) {
        charArr[offset + i] = hash[i];
    }
}

/**
 *  Helper function to pull a password out of password character array
 */
__host__
std::string getPwdTry(int arrIndx, char *pwdCharArr) {
    // Calculate array offset
    int offset = arrIndx * PWD_LENGTH;
    // temp string for password
    std::string tmpPwd = "";
    for (int i = 0; i < PWD_LENGTH; i++) {
        // Skip blank characters
        if (pwdCharArr[offset + i] != ' ') {
            tmpPwd += pwdCharArr[offset + i];
        }
    }
    return tmpPwd;
}

/**
 *  Debug Helper Function to print character array entries
 */
__host__
void printArr(int length, char *charArr) {
    // Loop through character array
    for (int i = 0; i < (KERNEL_SIZE * length); i++) {
        if ((i == 0) || (i % length) != 0) {
            if (charArr[i] != ' ') {
                std::cout << charArr[i];
            }
        } else {
            std::cout << ", ";
            if (charArr[i] != ' ') {
                std::cout << charArr[i];
            }
        }
    }
    std::cout << std::endl;
}

/**
 *  Create brute force password attemps
 */
__global__
void kernel_createPwdTry(int numPass, char *tryArr) {
        // Get current thread
        int curThread = blockIdx.x * blockDim.x + threadIdx.x;
        // Create unique guess number based on thread and number of times kernel has been run
        int guess = (numPass * KERNEL_SIZE) + curThread;

        // Set fourth letter of four letter password
        tryArr[(curThread * PWD_LENGTH) + 3] = (guess % CHARACTER_SET) + ASCII_OFFSET;
        // Reduce guess number
        guess = guess / CHARACTER_SET;
        // If necessary, set third letter of four and reduce guess number
        if (guess > 0) {
            tryArr[(curThread * PWD_LENGTH) + 2] = (guess % CHARACTER_SET) + ASCII_OFFSET;
            guess = guess / CHARACTER_SET;
        } else {
            tryArr[(curThread * PWD_LENGTH) + 2] = 32; // Space
        }
        // If necessary, set second letter of four and reduce guess number
        if (guess > 0) {
            tryArr[(curThread * PWD_LENGTH) + 1] = (guess % CHARACTER_SET) + ASCII_OFFSET;
            guess = guess / CHARACTER_SET;
        } else {
            tryArr[(curThread * PWD_LENGTH) + 1] = 32; // Space
        }
        // If necessary, set first letter of four and reduce guess number
        if (guess > 0) {
            tryArr[curThread * PWD_LENGTH] = (guess % CHARACTER_SET) + ASCII_OFFSET;
            guess = guess / CHARACTER_SET;
        } else {
            tryArr[curThread * PWD_LENGTH] = 32; // Space
        }
}

/**
 * Kernel to check brute force password hash with the one application is looking for
 */
__global__
void kernel_checkHash(char *lookingFor, char *hashArr, int *compares) {
    // Get current thread
    int curThread = blockIdx.x * blockDim.x + threadIdx.x;

    // Get array offset
    int offset = (curThread * HASH_LENGTH);

    // Flag to indicate match
    int match = 1;

    for (int i = 0; i < HASH_LENGTH; i++) {
        //printf("hashArr idx %d = %c --- lookingFor idx %d = %c Match = %d\n",
        //   i, hashArr[offset + i], i, lookingFor[i], match);
        if (hashArr[offset + i] != lookingFor[i]) {
            //printf("NO MATCH FOR HASH - %d\n", curThread);
            match = 0;
            break;
        }
    }

    compares[curThread] = match;

    //if (match == 0) {
        //printf("!!! MATCH !!!\n");
    //    compares[curThread] = 1;
    //}
}

/**
 *  Main sub routine which runs cracking loop
 */
void main_sub0() {
    // Time variables
    clock_t start;
    clock_t stop;
    double elapsedTime;

    // Declare host variables
    char *h_pwdTryArr;
    char *h_pwdHashArr;
    char *h_checkingFor;
    int *h_compareArr;

    // Declare device variables
    char *d_pwdTryArr;
    char *d_pwdHashArr;
    char *d_checkingFor;
    int *d_compareArr;

    // Allocate Host memory
    h_pwdTryArr = (char *)malloc(PWD_TRY_ARR_MEM_SIZE);
    h_pwdHashArr = (char *)malloc(PWD_HASH_ARR_MEM_SIZE);
    h_checkingFor = (char *)malloc(HASH_LENGTH * sizeof(char));
    h_compareArr = (int *)malloc(COMP_ARR_MEM_SIZE);

    // Allocate GPU memory
    cudaMalloc((void **) &d_pwdTryArr, PWD_TRY_ARR_MEM_SIZE);
    cudaMalloc((void **) &d_pwdHashArr, PWD_HASH_ARR_MEM_SIZE);
    cudaMalloc((void **) &d_checkingFor, (HASH_LENGTH * sizeof(char)));
    cudaMalloc((void **) &d_compareArr, COMP_ARR_MEM_SIZE);

    strcpy(h_checkingFor, checkFor.c_str());

    // Fill array
    //for (int i = 0; i < (KERNEL_SIZE * PWD_LENGTH); i++) {
    //    h_pwdTryArr[i] = 'Z';
    //}

    // DEBUG PRINT ORIGINAL PASSWORDS
    //std::cout << "PWDTRYARR BEFORE KERNEL EXECUTION\n";
    //printArr(PWD_LENGTH, h_pwdTryArr);

    // Copy host to device
    cudaMemcpy(d_pwdTryArr, h_pwdTryArr, PWD_TRY_ARR_MEM_SIZE, cudaMemcpyHostToDevice);

    while ((!passwordFound) && ((kernelPasses * KERNEL_SIZE) < maxPwdAttempts)) {

        printf("Running round %'d of %'d password attempts\n", (kernelPasses + 1), KERNEL_SIZE);
        //std::cout << "Running round " << (kernelPasses + 1) << " of ";
        //std::cout << KERNEL_SIZE << " password attempts\n";

        // Start clock for kernel timing
        start = clock();
        std::cout << "** Running GPU Kernel to Create Brute Force Passwords... ";

        // Run create password kernel
        kernel_createPwdTry<<<NUM_BLOCKS,NUM_THREADS>>>(kernelPasses, d_pwdTryArr);

        // Stop clock for kernel timing and output results
        stop = clock();
        elapsedTime = double(stop - start) / CLOCKS_PER_SEC;
        totalRunTime += elapsedTime;
        printf("Took %.5f seconds to run\n", elapsedTime);

        // Copy device to host
        cudaMemcpy(h_pwdTryArr, d_pwdTryArr, PWD_TRY_ARR_MEM_SIZE, cudaMemcpyDeviceToHost);

        // DEBUG PRINT CREATED PASSWORDS
        //std::cout << "PWDTRYARR AFTER KERNEL EXECUTION\n";
        //printArr(PWD_LENGTH, h_pwdTryArr);

        // Start clock for host hash creation timing
        start = clock();
        std::cout << "** Running Host Method to Create Hashes... ";

        // Iterate through passowrd try array
        for (int i = 0; i < (KERNEL_SIZE); i++) {
            // Reset string
            testPwdStr = "";
            testPwdStr = getPwdTry(i, h_pwdTryArr);
            /**
            for (int j = 0; j < PWD_LENGTH; j++) {
                char c = h_pwdTryArr[(i * PWD_LENGTH) + j];
                if (c != ' ') {
                    testPwdStr += c;
                }
            }
            **/
            // Print Debug Logic
            //std::cout << testPwdStr << " --- ";
            //std::cout << createHash(testPwdStr) << std::endl;
            copyHashToArr(i, createHash(testPwdStr), h_pwdHashArr);
            // Create hash of password and store in hash array
            // strcpy(h_pwdHashArr[i], createHash(testPwdStr).c_str());
        }

        // Stop clock for host hash creation timing and output results
        stop = clock();
        elapsedTime = double(stop - start) / CLOCKS_PER_SEC;
        totalRunTime += elapsedTime;
        printf("Took %.5f seconds to run\n", elapsedTime);

        // DEBUG PRINT CREATED HASHES
        //std::cout << "PWDHASHARR\n";
        //printArr(HASH_LENGTH, h_pwdHashArr);

        // Copy host to device
        cudaMemcpy(d_checkingFor, h_checkingFor, (HASH_LENGTH * sizeof(char)), cudaMemcpyHostToDevice);
        cudaMemcpy(d_pwdHashArr, h_pwdHashArr, PWD_HASH_ARR_MEM_SIZE, cudaMemcpyHostToDevice);
        cudaMemcpy(d_compareArr, h_compareArr, COMP_ARR_MEM_SIZE, cudaMemcpyHostToDevice);

        // DEBUG PRINT LOOKINGFOR HASH
        //std::cout << "LOOKINGFOR\n";
        //for (int i = 0; i < HASH_LENGTH; i++) {
        //    std::cout << h_checkingFor[i];
        //}
        //std::cout << std::endl;

        // Start clock for hash comparison kernel timing
        start = clock();
        std::cout << "** Running GPU Kernel to Check Password Hashes... ";

        // Run check hash kernel
        kernel_checkHash<<<NUM_BLOCKS, NUM_THREADS>>>(d_checkingFor, d_pwdHashArr, d_compareArr);

        // Stop clock for hash comparison kernel timing and output results
        stop = clock();
        elapsedTime = double(stop - start) / CLOCKS_PER_SEC;
        totalRunTime += elapsedTime;
        printf("Took %.5f seconds to run\n", elapsedTime);

        // Copy device to host
        cudaMemcpy(h_compareArr, d_compareArr, COMP_ARR_MEM_SIZE, cudaMemcpyDeviceToHost);

        // DEBUG PRINT COMPAREARR
        //std::cout << "COMPAREARR --- ";
        //for (int i = 0; i < KERNEL_SIZE; i++) {
        //    std::cout << h_compareArr[i] << ", ";
        //}
        //std::cout << std::endl;

        // Start clock for host checking for match timing
        start = clock();
        std::cout << "** Checking on Host for hash match... ";

        // Check if there is a match
        for (int i = 0; i < KERNEL_SIZE; i++) {
            if (h_compareArr[i] == 1) {
                passwordFound = true;
                resultPassword = getPwdTry(i, h_pwdTryArr);
                //std::cout << "MATCH FOUND: ";
                //std::cout << getPwdTry(i, h_pwdTryArr) << "\n";
            }
        }

        // Stop clock for host checking for match timing and output results
        stop = clock();
        elapsedTime = double(stop - start) / CLOCKS_PER_SEC;
        totalRunTime += elapsedTime;
        printf("Took %.5f seconds to run\n", elapsedTime);

        // Incrememnt kernel pass
        kernelPasses++;
    }

    free(h_pwdTryArr);
    free(h_pwdHashArr);
    free(h_checkingFor);
    free(h_compareArr);
    cudaFree(d_pwdTryArr);
    cudaFree(d_pwdHashArr);
    cudaFree(d_checkingFor);
    cudaFree(d_compareArr);
}

/**
 *  Main application
 */
int main(int argc, char *argv[]) {

    setlocale(LC_NUMERIC, "");

    // Variable for command line argument
    std::string argument = "";

    // Make sure hash has been passed to program via command line
    if (argc < 2) {
        std::cout << "!!! ERROR !!! Please enter hash as argument !!!\n";
        return EXIT_FAILURE;
    } else {
        argument = argv[1];
        if (argument.length() != 77) {
            std::cout << "!!! ERROR !!! Hash must be 77 characters long !!!\n";
            return EXIT_FAILURE;
        }
    }

    // Parse argument into salt and hash
    parseInputHash(argument);
    calcMaxAttempts();

    std::cout << "Attempting to crack password...\n";

    main_sub0();

    if (passwordFound) {
        std::cout << "Password found --- " << resultPassword << "\n";
    } else {
        std::cout << "Password not found\n";
    }

    // Display total number of attempts
    printf("%'d attempts processed\n", kernelPasses * KERNEL_SIZE);
    printf("%'.5f total processing time\n", totalRunTime);

    return EXIT_SUCCESS;
}
