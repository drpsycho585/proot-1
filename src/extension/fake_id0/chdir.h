#ifndef FAKE_ID0_CHDIR_H
#define FAKE_ID0_CHDIR_H

#include "tracee/tracee.h"
#include "tracee/reg.h"

extern int handle_chdir_sysenter_end(Tracee *tracee, RegVersion stage);
extern int handle_chdir_sysexit_end(Tracee *tracee, RegVersion stage);

#endif /* FAKE_ID0_CHDIR_H */
