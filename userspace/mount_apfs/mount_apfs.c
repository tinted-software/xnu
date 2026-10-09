// SPDX-License-Identifier: GPL-2.0
/*
 * /Library/Filesystems/apfs.fs/Contents/Resources/mount_apfs
 *
 * mount(8) runs `mount_<fstype>` from the filesystem's bundle to mount or
 * update a volume of that type. The in-kernel apfs (bsd/miscfs/apfsro) is a
 * read-only root filesystem: it supports only an update of the existing
 * mount (`mount -u`, which `mount -P 1` uses to apply options such as
 * nosuid) and refuses a read-write upgrade with EROFS.
 *
 * STAND-IN for Apple's mount_apfs: no volume discovery, no snapshots, no
 * encryption. Flagged in the port report.
 *
 * Freestanding: it makes the three BSD system calls it needs directly, so it
 * does not depend on a userspace libSystem build (see mount_apfs.tbd for the
 * load command dyld requires).
 *
 * usage: mount_apfs [-o options] [-u] [-r] [-w] special node
 */

/* bsd/sys/mount.h */
#define MNT_RDONLY      0x00000001
#define MNT_NOEXEC      0x00000004
#define MNT_NOSUID      0x00000008
#define MNT_NODEV       0x00000010
#define MNT_UNION       0x00000020
#define MNT_UPDATE      0x00010000
#define MNT_DONTBROWSE  0x00100000
#define MNT_NOATIME     0x10000000

/* bsd/kern/syscalls.master */
#define SYS_exit        1
#define SYS_write       4
#define SYS_mount       167

struct apfs_args {
	char *fspec;
};

/* Darwin arm64: x16 = number, svc #0x80; carry set means x0 is an errno. */
static long
syscall4(long number, long a0, long a1, long a2, long a3)
{
	register long x0 __asm__("x0") = a0;
	register long x1 __asm__("x1") = a1;
	register long x2 __asm__("x2") = a2;
	register long x3 __asm__("x3") = a3;
	register long x16 __asm__("x16") = number;
	__asm__ volatile (
		"svc #0x80\n\t"
		"b.cc 1f\n\t"
		"neg x0, x0\n"
		"1:"
		: "+r"(x0)
		: "r"(x1), "r"(x2), "r"(x3), "r"(x16)
		: "memory", "cc");
	return x0;
}

static unsigned long
length(const char *s)
{
	unsigned long n = 0;
	while (s[n]) {
		n++;
	}
	return n;
}

static int
equal(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

static void
say(const char *s)
{
	syscall4(SYS_write, 2, (long)s, (long)length(s), 0);
}

static void
say_number(long v)
{
	char buf[24];
	int i = sizeof(buf);
	unsigned long u = v < 0 ? (unsigned long)-v : (unsigned long)v;
	buf[--i] = 0;
	do {
		buf[--i] = (char)('0' + u % 10);
		u /= 10;
	} while (u);
	if (v < 0) {
		buf[--i] = '-';
	}
	say(&buf[i]);
}

static const struct {
	const char *name;
	int flag;
} option_flags[] = {
	{ "rdonly", MNT_RDONLY },
	{ "ro", MNT_RDONLY },
	{ "nosuid", MNT_NOSUID },
	{ "nodev", MNT_NODEV },
	{ "noexec", MNT_NOEXEC },
	{ "noatime", MNT_NOATIME },
	{ "update", MNT_UPDATE },
	{ "union", MNT_UNION },
	{ "dontbrowse", MNT_DONTBROWSE },
	{ "nobrowse", MNT_DONTBROWSE },
};

/* Options with no effect on a read-only filesystem, or applied elsewhere. */
static const char *const ignored_options[] = {
	"rw", "suid", "dev", "exec", "atime", "async", "sync", "perm", "owners",
	"auto", "noauto", "nofollow", "protect", "rootfs", "force",
};

static int
apply_option(const char *opt, int *flags)
{
	for (unsigned long i = 0; i < sizeof(option_flags) / sizeof(option_flags[0]); i++) {
		if (equal(opt, option_flags[i].name)) {
			*flags |= option_flags[i].flag;
			return 0;
		}
	}
	for (unsigned long i = 0; i < sizeof(ignored_options) / sizeof(ignored_options[0]); i++) {
		if (equal(opt, ignored_options[i])) {
			return 0;
		}
	}
	return -1;
}

/* Apply a comma separated option list; the list is edited in place. */
static int
apply_options(char *list, int *flags)
{
	while (*list) {
		char *end = list;
		while (*end && *end != ',') {
			end++;
		}
		char saved = *end;
		*end = 0;
		if (*list && apply_option(list, flags) != 0) {
			say("mount_apfs: unknown option -o ");
			say(list);
			say("\n");
			return -1;
		}
		*end = saved;
		list = saved ? end + 1 : end;
	}
	return 0;
}

static int
usage(void)
{
	say("usage: mount_apfs [-o options] [-u] [-r] [-w] special node\n");
	return 1;
}

static int
run(int argc, char **argv)
{
	int flags = MNT_RDONLY;
	const char *operands[2];
	int noperands = 0;

	/* The arguments as received, to see what mount(8) asks for. */
	say("mount_apfs:");
	for (int i = 1; i < argc; i++) {
		say(" ");
		say(argv[i]);
	}
	say("\n");

	for (int i = 1; i < argc; i++) {
		char *arg = argv[i];
		if (arg[0] == '-' && arg[1] != 0) {
			if (equal(arg, "-o")) {
				if (++i >= argc || apply_options(argv[i], &flags) != 0) {
					return usage();
				}
			} else if (equal(arg, "-u")) {
				flags |= MNT_UPDATE;
			} else if (equal(arg, "-r")) {
				flags |= MNT_RDONLY;
			} else if (equal(arg, "-w")) {
				flags &= ~MNT_RDONLY;
			} else {
				return usage();
			}
		} else if (noperands < 2) {
			operands[noperands++] = arg;
		} else {
			return usage();
		}
	}
	if (noperands != 2) {
		return usage();
	}

	struct apfs_args args = { .fspec = (char *)operands[0] };
	long r = syscall4(SYS_mount, (long)"apfs", (long)operands[1], flags, (long)&args);
	if (r < 0) {
		say("mount_apfs: ");
		say(operands[0]);
		say(" on ");
		say(operands[1]);
		say(": errno ");
		say_number(-r);
		say("\n");
		return 1;
	}
	return 0;
}

int
main(int argc, char **argv)
{
	syscall4(SYS_exit, run(argc, argv), 0, 0, 0);
	__builtin_unreachable();
}
