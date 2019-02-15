#include <linux/limits.h>
#include <errno.h>
#include <sys/stat.h>

#include "extension/fake_id0/exec.h"

#include "extension/fake_id0/helper_functions.h"

/** Handles execve system calls. Checks permissions in a meta file if it exists
 *  and returns errors matching those in execve(2).
 */
int handle_exec_enter_end(Tracee *tracee, Reg filename_sysarg, Config *config)
{
	int status, perms;
	char path[PATH_MAX];
	struct stat mode;

	status = read_sysarg_path(tracee, path, filename_sysarg, ORIGINAL);
	if(status < 0) 
		return status;
	if(status == 1) 
		return 0;

	status = stat(path, &mode);
	if (status < 0)
		return 0; /* Not fatal.  */

	/* If the setuid or setgid bits are on, change config accordingly. */
	if ((mode.st_mode & S_ISUID) != 0) {
		config->ruid = 0;
		config->euid = 0;
		config->suid = 0;
	}

	if ((mode.st_mode & S_ISGID) != 0) {
		config->rgid = 0;
		config->egid = 0;
		config->sgid = 0;
	}

	return 0;
}
