#include <errno.h>
#include <unistd.h>
#include <linux/limits.h>

#include "extension/extension.h"
#include "cli/note.h"
#include "tracee/mem.h"
#include "path/path.h"
#include "syscall/chain.h"

#include "extension/fake_id0/chdir.h"

/* Change working directory. */
int handle_chdir_sysenter_end(Tracee *tracee, RegVersion stage)
{
	char original[PATH_MAX];
	char path[PATH_MAX];
	word_t path_address;

	//the path might not be translated if coming from SIG_SYS, so we need to do it
	size = read_string(tracee, original, peek_reg(tracee, stage, SYSARG_1), PATH_MAX);
	if (size < 0) {
		return size;
	}
	if (size >= PATH_MAX) {
		return -ENAMETOOLONG;
	}
	path_address = alloc_mem(tracee, sizeof(path));
	translate_path(tracee, path, AT_FDCWD, original, true);
	write_data(tracee, path_address, path, sizeof(path));

	set_sysnum(tracee, PR_openat);
	poke_reg(tracee, SYSARG_4, 0);
	poke_reg(tracee, SYSARG_3, O_RDONLY);
	poke_reg(tracee, SYSARG_2, path_address);
	poke_reg(tracee, SYSARG_1, AT_FDCWD);

	return 0;
}

/* Change working directory. */
int handle_chdir_sysexit_end(Tracee *tracee, RegVersion stage)
{
	word_t sysnum;
	word_t result;
	int shmid;

	sysnum = get_sysnum(tracee, CURRENT);
	switch (sysnum) {
	case PR_open:
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		tracee->word_store[1] = result;
		if ((int)result < 0) {
			VERBOSE(tracee, 4, "%s: cannot open directory", __PRETTY_FUNCTION__);
			return result;
		}
		register_chained_syscall(tracee, PR_fchdir, result, 0, 0, 0, 0, 0);
		return 0;
	case PR_fchdir:
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		tracee->word_store[2] = result;
		if ((int)result != 0) {
			VERBOSE(tracee, 4, "%s: cannot change to the provided directory", __PRETTY_FUNCTION__);
		}
		register_chained_syscall(tracee, PR_close, tracee->word_store[1], 0, 0, 0, 0, 0);
		return 0;
	case PR_close:
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if ((int)result != 0) {
			VERBOSE(tracee, 4, "%s: failed to close file descriptor", __PRETTY_FUNCTION__);
		}
		return tracee->word_store[2];
	default:
		return 0;
	}

	return 0;
}
