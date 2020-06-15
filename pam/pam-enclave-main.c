
#include "pam-enclave.h"

void sm_exit_enclave()
{
}

int main(int argc, const char **argv)
{
    struct enclave_params params;
    enclave_main(&params);
    return 0;
}
