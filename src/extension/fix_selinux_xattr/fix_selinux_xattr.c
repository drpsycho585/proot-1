/*
 * Author: Unrud
 * Date:   18/12/2018
 *
 * Description: An extension that changes the return
 * value of setxattr from EACCES to zero when trying
 * to overwrite security.selinux with an identical value.
 */

#include <sys/xattr.h>
#include "extension/extension.h"
#include "tracee/mem.h"

const unsigned int MAX_NAME_LENGTH = 17;

/**
 * Return zero instead of EACCES when trying
 * to overwrite security.selinux with an identical value.
 */
static int handle_setxattr(Tracee *tracee)
{
    Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
    switch (sysnum) {
    case PR_setxattr: 
    case PR_lsetxattr:
    case PR_fsetxattr: {
        /* get the result of the syscall */
        word_t res = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if (res != -EACCES) {
            return 0;
        }

        /* get the system call arguments */
        word_t fd_or_path_start = peek_reg(tracee, MODIFIED, SYSARG_1);
        word_t name_start = peek_reg(tracee, CURRENT, SYSARG_2);
        word_t value_start = peek_reg(tracee, CURRENT, SYSARG_3);
        word_t value_size = peek_reg(tracee, CURRENT, SYSARG_4);
        word_t flags = peek_reg(tracee, CURRENT, SYSARG_5);

        /* check if the attribute name is security.selinux */
        char name[MAX_NAME_LENGTH];
        int status = read_string(tracee, name, name_start, MAX_NAME_LENGTH);
        if (status < 0) {
            return status;
        }
        if (strncmp("security.selinux", name, MAX_NAME_LENGTH) != 0) {
            return 0;
        }

        /* check if the current value and the new value are the same */
        /* retrieve the new value */
        char value[value_size];
        status = read_data(tracee, value, value_start, value_size);
        if (status < 0) {
            return status;
        }
        /* retrieve the current value from the file system */
        char current_value[value_size];
        char path[PATH_MAX];
        if (sysnum == PR_fsetxattr) {
            status = snprintf(path, PATH_MAX, "/proc/%d/fd/%d", tracee->pid, fd_or_path_start);
            if (status < 0 || status >= PATH_MAX) {
                return -EBADF;
            }
        } else {
            status = read_string(tracee, path, fd_or_path_start, PATH_MAX);
            if (status < 0) {
                return status;
            }
        }
        if (sysnum == PR_lsetxattr) {
            status = lgetxattr(path, name, current_value, value_size);
        } else {
            status = getxattr(path, name, current_value, value_size);
        }
        /* the values can't be equal in this cases */
        if (status == -E2BIG || status == -ERANGE || status == -ENODATA) {
            return 0;
        }
        /* either the original EACCES error was caused by file permissions or
         * a new error happened (e.g. the file was deleted in the meantime) */
        if (status < 0) {
            poke_reg(tracee, SYSARG_RESULT, status);
            return 0;
        }
        /* compare the current and the new value */
        if (status != value_size || memcmp(value, current_value, value_size) != 0) {
            return 0;
        }

        /* check flags */
        if (flags&XATTR_CREATE) {
            poke_reg(tracee, SYSARG_RESULT, -EEXIST);
            return 0;
        }

        /* return zero */
        poke_reg(tracee, SYSARG_RESULT, 0);
        return 0;
    }

    default:
        return 0;
    }
}

/**
 * Handler for this @extension.  It is triggered each time an @event
 * occured.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int fix_selinux_xattr_callback(Extension *extension, ExtensionEvent event,
        intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    switch (event) {
    case INITIALIZATION: {
        /* List of syscalls handled by this extension */
        static FilteredSysnum filtered_sysnums[] = {
            { PR_setxattr,   FILTER_SYSEXIT },
            { PR_lsetxattr,  FILTER_SYSEXIT },
            { PR_fsetxattr,  FILTER_SYSEXIT },
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }

    case SYSCALL_CHAINED_EXIT:
    case SYSCALL_EXIT_END: {
        return handle_setxattr(TRACEE(extension));
    }

    default:
        return 0;
    }
}
