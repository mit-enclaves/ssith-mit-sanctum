#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "randombytes.h"
extern "C" {
#include "pam-enclave.h"
}

int main(int argc, const char **argv)
{
    struct enclave_params *params = (struct enclave_params *)calloc(1, sizeof(enclave_params *));
    struct auth_db *db = (struct auth_db *)calloc(1, sizeof(auth_db *));
    randombytes((uint8_t *) db, sizeof(*db));

    struct userdata {
	uint8_t username[32];
	uint8_t password[32];
    } entries[] = {
	{"ubuntu", "fred"},
	{"root",   "rootme"},
	{"bob",    "secret password"},
	{"alice",  "better password"},
	{"carol",  "better password"},
	{"ted",  "better password"},
    };

    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
	strcpy((char *) db->entries[i].username, (char *) entries[i].username);
	uint8_t password[32];
	memset(password, 0, sizeof(password));
	strcpy((char *)password, (char *) entries[i].password);
	crypto_generichash(db->entries[i].hash, sizeof(db->entries[i].hash),
			   password, sizeof(password), NULL, 0);
    }


    int encrypt_result = encrypt_db(db, params);
    if (encrypt_result != 0) {
	fprintf(stderr, "Failed to encrypt database: %d\n", encrypt_result);
    }
    const char *params_filename = "pam-enclave-db.bin";
    int fd = open(params_filename, O_RDWR|O_CREAT, 0600);
    int bytes_written = write(fd, (char *)params, sizeof(*params));
    fprintf(stderr, "Wrote %d bytes (out of %ld) to %s\n", bytes_written, sizeof(*params), params_filename);
    close(fd);

    return 0;
}
