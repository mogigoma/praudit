#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bsm/libbsm.h>

#include <err.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "attributes.h"

static void	attr_count(const char *val, void *result);
static void	attr_event(const char *val, void *result);
static void	attr_gid(const char *val, void *result);
static void	attr_msec(const char *val, void *result);
static void	attr_pid(const char *val, void *result);
static void	attr_print(const char *val, void *result);
static void	attr_retval(const char *val, void *result);
static void	attr_str(const char *val, void *result);
static void	attr_tid(const char *val, void *result);
static void	attr_time(const char *val, void *result);
static void	attr_type(const char *val, void *result);
static void	attr_uid(const char *val, void *result);

extern int	 raw;
extern int	 shortfrm;

static struct {
	char	*name_el;
	char	*name_attr;
	void	 (*func)(const char *val, void *result);
} handlers[] = {
	{"arbitrary",		"count",	attr_count},
	{"arbitrary",		"print",	attr_print},
	{"arbitrary",		"type",		attr_type},

	{"argument",		"arg-num",	NULL},
	{"argument",		"desc",		NULL},
	{"argument",		"value",	NULL},

	{"attribute",		"device",	NULL},
	{"attribute",		"fsid",		NULL},
	{"attribute",		"gid",		attr_gid},
	{"attribute",		"mode",		NULL},
	{"attribute",		"nodeid",	NULL},
	{"attribute",		"uid",		attr_uid},

	{"exit",		"errval",	NULL},
	{"exit",		"retval",	attr_retval},

	{"file",		"msec",		attr_msec},
	{"file",		"time",		attr_time},

	{"ip",			"cksum",	NULL},
	{"ip",			"dest_addr",	NULL},
	{"ip",			"id",		NULL},
	{"ip",			"len",		NULL},
	{"ip",			"offset",	NULL},
	{"ip",			"protocol",	NULL},
	{"ip",			"service_type",	NULL},
	{"ip",			"src_addr",	NULL},
	{"ip",			"time_to_live",	NULL},
	{"ip",			"version",	NULL},

	{"IPC",			"ipc-id",	NULL},
	{"IPC",			"ipc-type",	NULL},

	{"IPC_perm",		"creator-gid",	attr_gid},
	{"IPC_perm",		"creator-uid",	attr_uid},
	{"IPC_perm",		"gid",		attr_gid},
	{"IPC_perm",		"key",		NULL},
	{"IPC_perm",		"mode",		NULL},
	{"IPC_perm",		"seq",		NULL},
	{"IPC_perm",		"uid",		attr_uid},

	{"process",		"audit-uid",	NULL},
	{"process",		"gid",		attr_gid},
	{"process",		"pid",		NULL},
	{"process",		"rgid",		attr_gid},
	{"process",		"ruid",		attr_uid},
	{"process",		"sid",		NULL},
	{"process",		"tid",		NULL},
	{"process",		"uid",		attr_uid},

	{"record",		"event",	attr_event},
	{"record",		"host",		NULL},
	{"record",		"modifier",	NULL},
	{"record",		"msec",		attr_msec},
	{"record",		"time",		attr_time},
	{"record",		"version",	NULL},

	{"return",		"errval",	attr_str},
	{"return",		"retval",	attr_retval},

	{"sequence",		"seq-num",	NULL},

	{"socket",		"faddr",	NULL},
	{"socket",		"fport",	NULL},
	{"socket",		"laddr",	NULL},
	{"socket",		"lport",	NULL},
	{"socket",		"sock_dom",	NULL},
	{"socket",		"sock_type",	NULL},

	{"socket-inet",		"addr",		NULL},
	{"socket-inet",		"port",		NULL},
	{"socket-inet",		"type",		NULL},

	{"socket-inet6",	"addr",		NULL},
	{"socket-inet6",	"port",		NULL},
	{"socket-inet6",	"type",		NULL},

	{"subject",		"audit-uid",	attr_uid},
	{"subject",		"gid",		attr_gid},
	{"subject",		"pid",		attr_pid},
	{"subject",		"rgid",		attr_gid},
	{"subject",		"ruid",		attr_uid},
	{"subject",		"sid",		attr_pid},
	{"subject",		"tid",		attr_tid},
	{"subject",		"uid",		attr_uid},

	{"zone",		"name",		attr_str},

	{NULL,			NULL,		NULL}
};

/*
 * Dispatch the handling of an attribute to the appropriate handler.
 */
void
handleAttributes(const char *el, const char **attr, struct attr_pair *pairs)
{
	int i, j, k;

	/* Find handlers for element. */
	for (i = 0; handlers[i].name_el != NULL; i++) {
		if (strcmp(el, handlers[i].name_el) == 0)
			break;
	}

	if (handlers[i].name_el == NULL)
		return;

	/* Handle each attribute in turn. */
	for (; handlers[i].name_el != NULL && strcmp(el, handlers[i].name_el) == 0; i++) {
		/* Skip unimplemented handlers. */
		if (handlers[i].func == NULL)
			continue;

		/* Find attribute that matches handler. */
		for (j = 0; attr[j] != NULL; j += 2) {
			if (strcmp(handlers[i].name_attr, attr[j]) == 0)
				break;
		}

		if (attr[j] == NULL)
			continue;

		/* Find pair that matches handler. */
		for (k = 0; pairs[k].name != NULL; k++) {
			if (strcmp(handlers[i].name_attr, pairs[k].name) == 0)
				break;
		}

		if (pairs[k].name == NULL)
			continue;

		/* Call element handler. */
		handlers[i].func(attr[j + 1], pairs[k].result);
	}
}

static uint64_t
parse_int(const char *val, long long min, long long max)
{
	const char *errstr;
	uint64_t ival;

	/* Convert attribute value to number. */
	ival = strtonum(val, min, max, &errstr);
	if (errstr != NULL)
		err(1, "[strtonum] %s", errstr);

	return (ival);
}

static void
attr_count(const char *val, void *result)
{
	uint8_t *count;

	count = result;

	/* XXX-MAK: Should use symbolic constants. */
	*count = parse_int(val, 0, 255);
}

static void
attr_event(const char *val, void *result)
{
	struct au_event_ent *event;
	au_event_t *num;

	num = result;

	/* Raw numbers can be returned immediately. */
	if (raw) {
		/* XXX-MAK: Should use symbolic constants. */
		*num = parse_int(val, 0, 65535);
		return;
	}

	/* Find matching event in database. */
	setauevent();
	while ((event = getauevent()) != NULL) {
		if (shortfrm && strcmp(val, event->ae_name) == 0) {
			*num = event->ae_number;
			break;
		} else if (strcmp(val, event->ae_desc) == 0) {
			*num = event->ae_number;
			break;
		}
	}
	endauevent();

	if (event == NULL)
		errx(1, "Unknown audit event '%s'.", val);
}

static void
attr_gid(const char *val, void *result)
{
	struct group *group;
	gid_t *gid;

	gid = result;

	/* Raw numbers can be returned immediately. */
	if (raw) {
		/* XXX-MAK: Should use symbolic constants. */
		*gid = parse_int(val, 0, 65535);
		return;
	}

	group = getgrnam(val);
	if (group == NULL)
		errx(1, "Invalid group '%s'", val);
	*gid = group->gr_gid;
}

static void
attr_msec(const char *val, void *result)
{
	uint16_t *msec;

	msec = result;

	if (sscanf(val, "%hu", msec) == 1)
		return;

	if (sscanf(val, " + %hu msec", msec) == 1)
		return;

	errx(1, "Couldn't parse msec attribute.");
}

static void
attr_pid(const char *val, void *result)
{
	pid_t *pid;

	pid = result;

	/* XXX-MAK: Should use symbolic constants. */
	*pid = parse_int(val, 0, 4294967295);
}

static void
attr_print(const char *val, void *result)
{
	uint8_t *print;

	print = result;

	if (strcmp(val, "binary") == 0)
		*print = AUP_BINARY;
	else if (strcmp(val, "decimal") == 0)
		*print = AUP_DECIMAL;
	else if (strcmp(val, "hex") == 0)
		*print = AUP_HEX;
	else if (strcmp(val, "octal") == 0)
		*print = AUP_OCTAL;
	else if (strcmp(val, "string") == 0)
		*print = AUP_STRING;
	else
		errx(1, "Invalid print value.");
}

static void
attr_retval(const char *val, void *result)
{
	uint32_t *retval;

	retval = result;

	/* XXX-MAK: Should use symbolic constants. */
	*retval = parse_int(val, 0, 4294967295);
}

static void
attr_str(const char *val, void *result)
{
	char **str;

	str = result;

	*str = strdup(val);
	if (*str == NULL)
		err(1, "[strdup]");
}

static void
attr_tid(const char *val, void *result)
{
	au_tid_t *tid;
	char ip[16];

	tid = result;

	if (sscanf(val, "%u %s", &tid->port, ip) != 2)
		errx(1, "Invalid tid format '%s'", val);

	tid->machine = inet_addr(ip);
	if (tid->machine == INADDR_NONE)
		errx(1, "Invalid tid address '%s'", ip);
}

static void
attr_time(const char *val, void *result)
{
	struct tm *when;
	char *format;

	when = result;

	/* Choose the format that matches the XML. */
        if (raw)
		format = "%s";
	else
		format = "%a %b %d %T %Y";

	/* Parse attribute value. */
	if (strptime(val, format, when) == NULL)
                errx(1, "[strptime]");
}

static void
attr_type(const char *val, void *result)
{
	uint8_t *type;

	type = result;

	/* XXX-MAK: Should use symbolic constants. */
	*type = parse_int(val, 0, 255);
}

static void
attr_uid(const char *val, void *result)
{
	struct passwd *user;
	uid_t *uid;

	uid = result;

	/* Raw numbers can be returned immediately. */
	if (raw) {
		/* XXX-MAK: Should use symbolic constants. */
		*uid = parse_int(val, -1, 32767);
		return;
	}

	/* Check for default. */
	if (strcmp(val, "-1") == 0) {
		*uid = AU_DEFAUDITID;
		return;
	}

	user = getpwnam(val);
	if (user == NULL)
		errx(1, "Invalid user '%s'", val);
	*uid = user->pw_uid;
}
