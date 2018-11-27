#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <stdio.h>

using namespace std;

int main(int argc, char *argv[]) {

    std::string salt = "";
    std::string password = "";

    if (argc < 3) {
        std::cout << "!!! ERROR !!! Please enter salt and password strings as arguments !!!\n";
        return EXIT_FAILURE;
    }

    salt = argv[1];
    password = argv[2];

    if (salt.length() != 8) {
        std::cout << "!!! ERROR !!! Salt must be eight characters long !!!\n";
        return EXIT_FAILURE;
    }

    salt = "$6$" + salt + "$";

    string testHash = crypt((char*) password.c_str(), (char*) salt.c_str());
    testHash = testHash.substr(0,76) + "$";

    cout << "User entered information...\n";
    cout << "Salt: " << salt << endl;
    cout << "Password: " << password << endl;
    cout << "Calculated hash...\n";
    cout << testHash << endl;

    return EXIT_SUCCESS;
}
