/* Define which PAM interfaces we provide */
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#include <security_monitor/api/api.h>

#include "pam-enclave.h"

struct arg_start_enclave { api_result_t result; uintptr_t enclave_start; uintptr_t enclave_end; };
#define MAJOR_NUM 's'
#define IOCTL_START_ENCLAVE _IOR(MAJOR_NUM, 0x1, struct run_enclave*)

int call_enclave(const char *username, const char *password) {
    int fd = 0;
    struct arg_start_enclave val;
    fd = open("/dev/security_monitor", O_RDWR);
    printf("file descriptor fd(%d)", fd);
    if (fd < 0) {
        printf("File open error: %s\n", strerror(errno));
        return PAM_IGNORE;
    }
    FILE *ptr;
    const char *enclave_bin_name = "/test/pam-enclave.bin";
    ptr = fopen(enclave_bin_name,"rb");
    struct stat statbuf;
    stat(enclave_bin_name, &statbuf);
    off_t sizefile = statbuf.st_size;
    printf("Size enclave.bin (%ld)\n", sizefile);
    char* enclave = memalign(1<<12,sizefile);
    size_t sizecopied = fread(enclave, sizefile, 1, ptr);
    printf("Size copied: %ld", sizecopied);
    fclose(ptr);

    /* Allocate memory to share with the enclave. Need to find a proper place for that */
#define begin_shared 0xF000000
#define shared_size 0x1000
    char* shared_enclave = (char *)mmap((void *)begin_shared, shared_size, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0); // 
    if (shared_enclave == MAP_FAILED) {
        perror("Shared memory not allocated in a correct place, last errno: ");
        return PAM_IGNORE;
    }
    printf("Address for the shared enclave %08lx", (long)shared_enclave);

    memset(shared_enclave, 0, shared_size);

    const char *enclave_db_filename = "/test/pam-enclave-db.bin";
    {
	int fd = open(enclave_db_filename, O_RDONLY);
	if (fd < 0) {
	    fprintf(stderr, "Failed to open auth database %s: %s\n", enclave_db_filename, strerror(errno));
	    return -1;
	}
	int offset = 0;
	int bytes_to_read = sizeof(struct enclave_params);
	while (bytes_to_read > 0) {
	    int bytes_read = read(fd, shared_enclave + offset, bytes_to_read);
	    if (bytes_read < 0) {
		fprintf(stderr, "Error reading: %s\n", strerror(errno));
		return -1;
	    }
	    bytes_to_read -= bytes_read;
	    offset += bytes_read;
	}
	close(fd);
    }
    struct enclave_params *params = (struct enclave_params *)shared_enclave;
    strncpy((char *)params->username, username, sizeof(params->username));
    strncpy((char *)params->password, password, sizeof(params->password));

    val.enclave_start = (long)enclave;
    val.enclave_end = (long)(enclave + sizefile);
    printf("Sending ioctl CMD 2\n");
    fflush(stdout);
    int ret = ioctl(fd, IOCTL_START_ENCLAVE, &val);
    printf("ioctl ret val (%d) errno (%d)\n", ret, errno);
    int response = PAM_IGNORE;
    if (ret == 0) {
        printf("Received from enclave: %s\n", shared_enclave); 
	fflush(stdout);
	if (strncmp((char *)params->response, "authenticated", sizeof(params->response)) == 0)
	    response = PAM_SUCCESS;
    } else {
	fprintf(stderr, "IOCTL error %s\n", strerror(errno));
    }

    memset((char *)params->username, 0, sizeof(params->username));
    memset((char *)params->password, 0, sizeof(params->password));

    munmap(shared_enclave, shared_size);
    close(fd);
    return response;
}

/* PAM entry point for session creation */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_IGNORE);
}

/* PAM entry point for session cleanup */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_IGNORE);
}

/* PAM entry point for accounting */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_IGNORE);
}

/* PAM entry point for authentication verification */

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL;
    char *password = NULL;
    int pgu_ret, pp_ret, ce_ret;

    pgu_ret = pam_get_user(pamh, &user, NULL);
    if (pgu_ret != PAM_SUCCESS || user == NULL) {
        return(PAM_IGNORE);
    }
    fprintf(stderr, "user %s\n", user);

    pp_ret = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &password, "Password: ");
    fprintf(stderr, "password %s %d\n", password, pp_ret);

    if (pp_ret != PAM_SUCCESS) {
        _pam_overwrite(password);
        return PAM_IGNORE;
    }

    ce_ret = call_enclave(user, password);
    _pam_overwrite(password);

    if (ce_ret == PAM_SUCCESS) {
        return PAM_SUCCESS;
    }

    return(PAM_IGNORE);
}

/*
  PAM entry point for setting user credentials (that is, to actually
  establish the authenticated user's credentials to the service provider)
*/
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_IGNORE);
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL;
    const char *authtok = NULL;
    int pgu_ret, pgi_ret;

    pgu_ret = pam_get_user(pamh, &user, NULL);
    if (pgu_ret != PAM_SUCCESS || user == NULL) {
        return(PAM_IGNORE);
    }
    fprintf(stderr, "user %s\n", user);

    pgi_ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok);
    if (pgu_ret != PAM_SUCCESS || authtok == NULL) {
        return(PAM_IGNORE);
    }
    fprintf(stderr, "authtok %s %d\n", authtok, pgi_ret);
    return(PAM_IGNORE);
}

