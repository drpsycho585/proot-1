#include <linux/limits.h>
#include <string.h>
#include <unistd.h>

#include "extension/fake_id0/rename.h"
#include "extension/fake_id0/helper_functions.h"

/** Handles rename and renameat syscalls. If a meta file matching the file to
 *  to be renamed exists, renames the meta file as well. See rename(2) for
 *  returned permission errors.
 */
int handle_rename_enter_end(Tracee *tracee, Reg oldfd_sysarg, Reg oldpath_sysarg, 
	Reg newfd_sysarg, Reg newpath_sysarg, Config *config)
{
	int status;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	char oldpath[PATH_MAX];
	char newpath[PATH_MAX];
	char rel_oldpath[PATH_MAX];
	char rel_newpath[PATH_MAX];
	char meta_path[PATH_MAX];

	status = read_sysarg_path(tracee, oldpath, oldpath_sysarg, CURRENT); 
	if(status < 0)
		return status;
	if(status == 1)
		return 0;

	status = read_sysarg_path(tracee, newpath, newpath_sysarg, CURRENT); 
	if(status < 0)
		return status;
	if(status == 1)
		return 0;

	status = get_fd_path(tracee, rel_oldpath, oldfd_sysarg, CURRENT);
	if(status < 0)
		return status;

	status = get_fd_path(tracee, rel_newpath, newfd_sysarg, CURRENT);
	if(status < 0)
		return status;

	status = check_dir_perms(tracee, 'w', oldpath, rel_oldpath, config);
	if(status < 0)
		return status;

	status = check_dir_perms(tracee, 'w', newpath, rel_newpath, config);
	if(status < 0)
		return status;

	//only read the meta info, so it can delete the meta file if it exists
	//TODO: Remove once there are no more meta files out there
	read_meta_info(oldpath, &mode, &uid, &gid, config);
	
	return 0;
}
