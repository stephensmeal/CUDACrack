
#include <stdlib.h>
#include <iostream>
#include <cmath>

const int PWD_LENGTH = 5;
const int HASH_LENGTH = 64;
const int H_THREADS = 10;
__constant__ int THREADS = 10;
__constant__ int CHAR_SET_SIZE = 94;
__constant__ int ASCII_OFFSET = 33;
const long MAX_PWD_TRYS =
    (pow(94,5) + pow(94,4) + pow(94,3) +
     pow(94,2) + 94);

typedef struct {
    char pwdTry[PWD_LENGTH];
} PwdTryArr;

const size_t PWD_TRY_ARR_MEM_SIZE = THREADS * sizeof(PwdTryArr);

typedef struct {
    char pwdHash[HASH_LENGTH];
} PwdHashArr;

const size_t PWD_HASH_ARR_MEM_SIZE = THREADS * sizeof(PwdHashArr);

__global__
void newCreatePwd(long passNum, PwdTryArr *guessArr) {
    // Get current thread
    int curThread = blockIdx.x * blockDim.x + threadIdx.x;

    long guessLong = (passNum * THREADS) + curThread;

    guessArr[curThread].pwdTry[4] = (guessLong % CHAR_SET_SIZE) + ASCII_OFFSET;
    guessLong = guessLong / CHAR_SET_SIZE;
    if (guessLong > 0) {
        guessArr[curThread].pwdTry[3] = (guessLong % CHAR_SET_SIZE) + ASCII_OFFSET;
        guessLong = guessLong / CHAR_SET_SIZE;
    }
    if (guessLong > 0) {
        guessArr[curThread].pwdTry[2] = (guessLong % CHAR_SET_SIZE) + ASCII_OFFSET;
        guessLong = guessLong / CHAR_SET_SIZE;
    }
    if (guessLong > 0) {
        guessArr[curThread].pwdTry[1] = (guessLong % CHAR_SET_SIZE) + ASCII_OFFSET;
        guessLong = guessLong / CHAR_SET_SIZE;
    }
    if (guessLong > 0) {
        guessArr[curThread].pwdTry[0] = (guessLong % CHAR_SET_SIZE) + ASCII_OFFSET;
    }
}

/**
 * Main function
 */
int main(int argc, char *argv[]) {

    std::cout << "RUNNING...\n";

    // Declare password try arrays
    PwdTryArr *h_passwordTryArr;
    PwdTryArr *d_passwordTryArr;
	PwdTryArr *h_tryPtr;

    // Allocate Host Memory
    h_tryPtr = (PwdTryArr *)malloc(sizeof(PwdTryArr));
    h_passwordTryArr = (PwdTryArr *)malloc(PWD_TRY_ARR_MEM_SIZE);

    // Allocate GPU Memory
    cudaMalloc((void **) &d_passwordTryArr, PWD_TRY_ARR_MEM_SIZE);

    cudaMemcpy(d_passwordTryArr, h_passwordTryArr, PWD_TRY_ARR_MEM_SIZE, cudaMemcpyHostToDevice);

    newCreatePwd<<<1,10>>>(0,d_passwordTryArr);

    cudaMemcpy(h_passwordTryArr, d_passwordTryArr, PWD_TRY_ARR_MEM_SIZE, cudaMemcpyDeviceToHost);

    h_tryPtr = h_passwordTryArr;
    
	for (int j = 0; j < H_THREADS; j++, h_tryPtr++) {
        std::cout << "CREATED PASSWORD: ";
        for (int i = 0; i < PWD_LENGTH; i++) {
            if (h_tryPtr->pwdTry[i] != NULL) {
                std::cout << h_tryPtr->pwdTry[i];
            }
        }
        std::cout << std::endl;
	}

    return EXIT_SUCCESS;
}
