#include <sys/types.h>
#include <sys/uio.h>
#include <bsm/libbsm.h>

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "attributes.h"
#include "elements.h"
#include "token_buffer.h"

static void	el_arbitrary(const char *el, const char **attr, const char *body);
static void	el_argument(const char *el, const char **attr, const char *body);
static void	el_attribute(const char *el, const char **attr, const char *body);
static void	el_exec_args(const char *el, const char **attr, const char *body);
static void	el_exec_env(const char *el, const char **attr, const char *body);
static void	el_exit(const char *el, const char **attr, const char *body);
static void	el_file(const char *el, const char **attr, const char *body);
static void	el_group(const char *el, const char **attr, const char *body);
static void	el_ip(const char *el, const char **attr, const char *body);
static void	el_ip_address(const char *el, const char **attr, const char *body);
static void	el_ip_port(const char *el, const char **attr, const char *body);
static void	el_ipc(const char *el, const char **attr, const char *body);
static void	el_ipc_perm(const char *el, const char **attr, const char *body);
static void	el_opaque(const char *el, const char **attr, const char *body);
static void	el_path(const char *el, const char **attr, const char *body);
static void	el_process(const char *el, const char **attr, const char *body);
static void	el_record(const char *el, const char **attr, const char *body);
static void	el_return(const char *el, const char **attr, const char *body);
static void	el_sequence(const char *el, const char **attr, const char *body);
static void	el_socket(const char *el, const char **attr, const char *body);
static void	el_socket_inet(const char *el, const char **attr, const char *body);
static void	el_socket_inet6(const char *el, const char **attr, const char *body);
static void	el_subject(const char *el, const char **attr, const char *body);
static void	el_text(const char *el, const char **attr, const char *body);
static void	el_zone(const char *el, const char **attr, const char *body);

static struct {
	char	*name;
	void	 (*func)(const char *el, const char **attr, const char *body);
} handlers[] = {
	{"arbitrary",		el_arbitrary},
	{"arg",			el_exec_args},
	{"argument",		el_argument},
	{"attribute",		el_attribute},
	{"env",			el_exec_env},
	{"exec_args",		el_exec_args},
	{"exec_env",		el_exec_env},
	{"exit",		el_exit},
	{"file",		el_file},
	{"gid",			el_group},
	{"group",		el_group},
	{"ip",			el_ip},
	{"ip_address",		el_ip_address},
	{"ip_port",		el_ip_port},
	{"IPC",			el_ipc},
	{"IPC_perm",		el_ipc_perm},
	{"opaque",		el_opaque},
	{"path",		el_path},
	{"process",		el_process},
	{"record",		el_record},
	{"return",		el_return},
	{"sequence",		el_sequence},
	{"socket",		el_socket},
	{"socket-inet",		el_socket_inet},
	{"socket-inet6",	el_socket_inet6},
	{"subject",		el_subject},
	{"text",		el_text},
	{"zone",		el_zone},
	{NULL,			NULL}
};

static struct token_buffer tb;

/*
 * Dispatch the handling of an element to the appropriate handler.
 */
void
handleElement(const char *el, const char **attr, const char *body)
{
	int i;

	for (i = 0; handlers[i].name != NULL; i++) {
		/* Check if tag matches handler. */
		if (strcmp(el, handlers[i].name) != 0)
			continue;

		/* Check if tag is unimplemented. */
		if (handlers[i].func == NULL)
			break;

		/* Call element handler. */
		handlers[i].func(el, attr, body);
		break;
	}
}

/*
 * [arbitrary]
 *
 * Attribute
 * ---------
 * count
 * print
 * type
 *
 * Tokens
 * ------
 * AUT_DATA
 *
 * The body of this element contains arbitrary data in the format defined by the
 * print and type attributes.
 */
/*
 * token_t *
 * au_to_data(char unit_print, char unit_type, char unit_count,
 *     const char *p);
 */
static void
el_arbitrary(const char *el, const char **attr, const char *body)
{
	static uint8_t count, print, size;
	const char *body_p, *fmt;
	token_t *tok;
	int i, type;
	char *buf;
	struct attr_pair pairs[] = {
		{"count",	&count},
		{"print",	&print},
		{"type",	&size},
		{NULL,		NULL}
	};

	if (attr != NULL) {
		/* Parse element's attributes. */
		handleAttributes("arbitrary", attr, pairs);

		return;
	}

	/* Determine the format associated with that print method. */
	switch(print) {
	case AUP_BINARY:
		fmt = " %c";
		break;

	case AUP_DECIMAL:
		fmt = " %d";
		break;

	case AUP_HEX:
		fmt = " %x";
		break;

	case AUP_OCTAL:
		fmt = " %o";
		break;

	case AUP_STRING:
		fmt = "%c";
		break;
	}

	/* Determine the type associated with that size. */
	switch (size) {
	case AUR_BYTE_SIZE:
		type = AUR_BYTE;
		break;

	case AUR_SHORT_SIZE:
		type = AUR_SHORT;
		break;

	case AUR_INT32_SIZE:
		type = AUR_INT32;
		break;

	case AUR_INT64_SIZE:
		type = AUR_INT64;
		break;
	}

	/* Allocate space for buffer. */
	buf = malloc(count * size);
	if (buf == NULL)
		err(1, "[malloc]");

	/* Parse body. */
	body_p = body;
	for (i = 0; i < count * size; i += size) {
		if (body_p == NULL || *body_p == '\0')
			break;

		if (sscanf(body_p, fmt, &buf[i]) != 1)
			errx(1, "Element 'arbitrary' has invalid body.");

		switch(print) {
		case AUP_BINARY:
			body_p += 2;
			break;

		case AUP_STRING:
			body_p += 1;
			break;

		default:
			body_p = index(++body_p, ' ');
		}
	}

	/* Make sure the numbers matched. */
	if (body_p != NULL && *body_p != '\0')
		errx(1, "Element 'arbitrary' contains too much data.");

	if (i < count * size)
		errx(1, "Element 'arbitrary' contains too little data.");

	/* Create token. */
	tok = au_to_data(print, type, count, buf);
	rec_append(&tb, tok);
}

/*
 * [argument]
 *
 * Attribute
 * ---------
 * arg-num
 * desc
 * value
 *
 * Tokens
 * ------
 * AUT_ARG32
 * AUT_ARG64
 */
/*
 * token_t *
 * au_to_arg32(char n, const char *text, u_int32_t v);
 *
 * token_t *
 * au_to_arg64(char n, const char *text, u_int64_t v);
 */
static void
el_argument(const char *el, const char **attr, const char *body)
{
	// AUDIT_MAX_ARGS
}

/*
 * [attribute]
 *
 * Attribute
 * ---------
 * device
 * fsid
 * gid
 * mode
 * nodeid
 * uid
 *
 * Tokens
 * ------
 * AUT_ATTR32
 * AUT_ATTR64
 */
/*
 * token_t *
 * au_to_attr32(struct vattr *attr);
 *
 * token_t *
 * au_to_attr64(struct vattr *attr);
 */
static void
el_attribute(const char *el, const char **attr, const char *body)
{
}

/*
 * [exec_args]
 *
 * Tokens
 * ------
 * AUT_EXEC_ARGS
 *
 * The body of this element contains arg elements.
 */
/*
 * token_t *
 * au_to_exec_args(char **argv);
 */
static void
el_exec_args(const char *el, const char **attr, const char *body)
{
	// AUDIT_MAX_ARGS
}

/*
 * [exec_env]
 *
 * Tokens
 * ------
 * AUT_EXEC_ENV
 *
 * The body of this element contains env elements.
 */
/*
 * token_t *
 * au_to_exec_env(char **envp);
 */
static void
el_exec_env(const char *el, const char **attr, const char *body)
{
	// AUDIT_MAX_ENV
}

/*
 * [exit]
 *
 * Attribute
 * ---------
 * errval
 * retval
 *
 * Tokens
 * ------
 * AUT_EXIT
 */
/*
 * token_t *
 * au_to_exit(int retval, int err);
 */
static void
el_exit(const char *el, const char **attr, const char *body)
{
	int errval, retval;
	token_t *tok;
	struct attr_pair pairs[] = {
		{"errval",	&errval},
		{"retval",	&retval},
		{NULL,		NULL}
	};

	if (attr == NULL)
		return;

	/* Parse element's attributes. */
	handleAttributes("exit", attr, pairs);

	/* Create token. */
	tok = au_to_exit(retval, errval);
	rec_append(&tb, tok);
}

/*
 * [file]
 *
 * Attribute
 * ---------
 * msec
 * time
 *
 * Tokens
 * ------
 * AUT_OTHER_FILE32
 *
 * The body of this element contains a file name.
 */
/*
 * token_t *
 * au_to_file(const char *file, struct timeval tm);
 */
static void
el_file(const char *el, const char **attr, const char *body)
{
	static struct timeval tm;
	struct tm when;
	uint16_t msec;
	token_t *tok;
	struct attr_pair pairs[] = {
		{"msec",	&msec},
		{"time",	&when},
		{NULL,		NULL}
	};

	if (attr != NULL) {
		/* Parse element's attributes. */
		handleAttributes("file", attr, pairs);
		tm.tv_sec = mktime(&when);
		tm.tv_usec = msec * 1000;

		return;
	}

	/* Create token. */
	tok = au_to_file(body, tm);
	rec_append(&tb, tok);
}

/*
 * [group]
 */
/*
 * token_t *
 * au_to_newgroups(u_int16_t n, gid_t *groups);
 */
static void
el_group(const char *el, const char **attr, const char *body)
{
}

/*
 * [ip]
 *
 * Attribute
 * ---------
 * cksum
 * dest_addr
 * id
 * len
 * offset
 * protocol
 * service_type
 * src_addr
 * time_to_live
 * version
 *
 * Tokens
 * ------
 * AUT_IP
 */
/*
 * token_t *
 * au_to_ip(struct ip *ip);
 */
static void
el_ip(const char *el, const char **attr, const char *body)
{
}

/*
 * [ip_address]
 *
 * Tokens
 * ------
 * AUT_IN_ADDR
 * AUT_IN_ADDR_EX
 *
 * The body of this element contains an IP address.
 */
/*
 * token_t *
 * au_to_in_addr(struct in_addr *internet_addr);
 *
 * token_t *
 * au_to_in_addr_ex(struct in6_addr *internet_addr);
 */
static void
el_ip_address(const char *el, const char **attr, const char *body)
{
}

/*
 * [ip_port]
 *
 * Tokens
 * ------
 * AUT_IPORT
 */
/*
 * token_t *
 * au_to_iport(u_int16_t iport);
 */
static void
el_ip_port(const char *el, const char **attr, const char *body)
{
}

/*
 * [IPC]
 *
 * Attribute
 * ---------
 * ipc-id
 * ipc-type
 *
 * Tokens
 * ------
 * AUT_IPC
 */
/*
 * token_t *
 * au_to_ipc(char type, int id);
 */
static void
el_ipc(const char *el, const char **attr, const char *body)
{
}

/*
 * [IPC_perm]
 *
 * Attribute
 * ---------
 * creator-gid
 * creator-uid
 * gid
 * key
 * mode
 * seq
 * uid
 *
 * Tokens
 * ------
 * AUT_IPC_PERM
 */
/*
 * token_t *
 * au_to_ipc_perm(struct ipc_perm *perm);
 */
static void
el_ipc_perm(const char *el, const char **attr, const char *body)
{
}

/*
 * [opaque]
 *
 * Tokens
 * ------
 * AUT_OPAQUE
 *
 * The body of this element contains hex data.
 */
/*
 * token_t *
 * au_to_opaque(const char *data, u_int16_t bytes);
 */
static void
el_opaque(const char *el, const char **attr, const char *body)
{
	token_t *tok;
	char *buf;
	int i, j;

	if (attr != NULL)
		return;

	/* Ensure body has proper hexadecimal prefix. */
	if (strncmp(body, "0x", 2) != 0)
		errx(1, "Element 'opaque' has invalid prefix.");

	/* Allocate space for buffer. */
	buf = malloc(strlen(body) + 1);
	if (buf == NULL)
		err(1, "[malloc]");

	/* Parse body. */
	for (i = 2, j = 0; body[i] != '\0'; i += 2, j++) {
		if (sscanf(&body[i], "%02hhx", &buf[j]) != 1)
			errx(1, "Element 'opaque' has invalid body.");
	}

	/* Create token. */
	tok = au_to_opaque(buf, j);
	rec_append(&tb, tok);
}

/*
 * [path]
 *
 * Tokens
 * ------
 * AUT_PATH
 *
 * The body of this element contains a path.
 */
/*
 * token_t *
 * au_to_path(const char *text);
 */
static void
el_path(const char *el, const char **attr, const char *body)
{
	token_t *tok;

	if (attr != NULL)
		return;

	/* Create token. */
	tok = au_to_path(body);
	rec_append(&tb, tok);
}

/*
 * [process]
 *
 * Attribute
 * ---------
 * audit-uid
 * gid
 * pid
 * rgid
 * ruid
 * sid
 * tid
 * uid
 *
 * Tokens
 * ------
 * AUT_PROCESS32
 * AUT_PROCESS32_EX
 * AUT_PROCESS64
 * AUT_PROCESS64_EX
 */
/*
 * token_t *
 * au_to_process32(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid,
 *     gid_t rgid, pid_t pid, au_asid_t sid, au_tid_t *tid);
 *
 * token_t *
 * au_to_process64(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid,
 *     gid_t rgid, pid_t pid, au_asid_t sid, au_tid_t *tid);
 *
 * token_t *
 * au_to_process32_ex(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid,
 *     gid_t rgid, pid_t pid, au_asid_t sid, au_tid_addr_t *tid);
 *
 * token_t *
 * au_to_process64_ex(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid,
 *     gid_t rgid, pid_t pid, au_asid_t sid, au_tid_addr_t *tid);
 */
static void
el_process(const char *el, const char **attr, const char *body)
{
}

/*
 * [record]
 *
 * Attribute
 * ---------
 * event
 * host (only in *_EX)
 * modifier
 * msec
 * time
 * version
 *
 * Tokens
 * ------
 * AUT_HEADER32
 * AUT_HEADER32_EX
 * AUT_HEADER64
 * AUT_HEADER64_EX
 * AUT_TRAILER
 */
/*
 * token_t *
 * au_to_header(int rec_size, au_event_t e_type, au_emod_t emod);
 *
 * token_t *
 * au_to_header32(int rec_size, au_event_t e_type, au_emod_t emod);
 *
 * token_t *
 * au_to_header64(int rec_size, au_event_t e_type, au_emod_t e_mod);
 *
 * token_t *
 * au_to_header_ex(int rec_size, au_event_t e_type, au_emod_t e_mod);
 *
 * token_t *
 * au_to_header32_ex(int rec_size, au_event_t e_type, au_emod_t e_mod);
 *
 * token_t *
 * au_to_trailer(int rec_size);
 */
static void
el_record(const char *el, const char **attr, const char *body)
{
	struct timeval tm;
	au_event_t event;
	struct tm when;
	u_int32_t msec;
	token_t *tok;
	struct attr_pair pairs[] = {
		{"event",	&event},
		{"msec",	&msec},
		{"time",	&when},
		{NULL,		NULL}
	};

	if (attr == NULL) {
		rec_close(&tb);
		rec_write(&tb, STDOUT_FILENO);

		return;
	}

	/* Parse element's attributes. */
	/* XXX-MAK: Timezone bug exists, need to fix. */
	handleAttributes("record", attr, pairs);
	tm.tv_sec = mktime(&when);
	tm.tv_usec = msec * 1000;

	rec_open(&tb);
	/* XXX-MAK: Need to replace second 0 w/ au_emod_t e_mod. */
	tok = au_to_header32_tm(0, event, 0, tm);
	rec_append(&tb, tok);
}

/*
 * [return]
 *
 * Attribute
 * ---------
 * errval
 * retval
 *
 * Tokens
 * ------
 * AUT_RETURN32
 * AUT_RETURN64
 */
/*
 * token_t *
 * au_to_return32(char status, u_int32_t ret);
 *
 * token_t *
 * au_to_return64(char status, u_int64_t ret);
 *
 * token_t *
 * au_to_return(char status, u_int32_t ret);
 */
static void
el_return(const char *el, const char **attr, const char *body)
{
	uint32_t retval;
	u_char errval;
	token_t *tok;
	struct attr_pair pairs[] = {
		{"retval",	&retval},
		{NULL,		NULL}
	};

	if (attr == NULL)
		return;

	/* Parse element's attributes. */
	handleAttributes("return", attr, pairs);
	errval = au_errno_to_bsm(retval);

	/* Create token. */
	tok = au_to_return32(errval, retval);
	rec_append(&tb, tok);
}

/*
 * [sequence]
 *
 * Attribute
 * ---------
 * seq-num
 *
 * Tokens
 * ------
 * AUT_SEQ
 */
/*
 * token_t *
 * au_to_seq(long audit_count);
 */
static void
el_sequence(const char *el, const char **attr, const char *body)
{
}

/*
 * [socket]
 *
 * Attribute
 * ---------
 * faddr
 * fport
 * laddr
 * lport
 * sock_dom (only *_EX)
 * sock_type
 *
 * Tokens
 * ------
 * AUT_SOCKET
 * AUT_SOCKET_EX
 */
/*
 * token_t *
 * au_to_socket_ex(u_short so_domain, u_short so_type,
 *     struct sockaddr *sa_local, struct sockaddr *sa_remote);
 */
static void
el_socket(const char *el, const char **attr, const char *body)
{
}

/*
 * [socket-inet]
 *
 * Attribute
 * ---------
 * addr
 * port
 * type
 *
 * Tokens
 * ------
 * AUT_SOCKINET32
 * AUT_SOCKUNIX
 */
/*
 * token_t *
 * au_to_sock_int(struct sockaddr_in *so);
 *
 * token_t *
 * au_to_sock_inet32(struct sockaddr_in *so);
 */
static void
el_socket_inet(const char *el, const char **attr, const char *body)
{
}

/*
 * [socket-inet6]
 *
 * Attribute
 * ---------
 * addr
 * port
 * type
 *
 * Tokens
 * ------
 * AUT_SOCKINET128
 */
/*
 * token_t *
 * au_to_sock_inet128(struct sockaddr_in6 *so);
 */
static void
el_socket_inet6(const char *el, const char **attr, const char *body)
{
}

/*
 * [subject]
 *
 * Attribute
 * ---------
 * audit-uid
 * gid
 * pid
 * rgid
 * ruid
 * sid
 * tid
 * uid
 *
 * Tokens
 * ------
 * AUT_SUBJECT32
 * AUT_SUBJECT64
 * AUT_SUBJECT32_EX
 * AUT_SUBJECT64_EX
 */
/*
 * token_t *
 * au_to_subject32(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid,
 *     gid_t rgid, pid_t pid, au_asid_t sid, au_tid_t *tid);
 *
 * token_t *
 * au_to_subject64(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid,
 *     gid_t rgid, pid_t pid, au_asid_t sid, au_tid_t *tid);
 *
 * token_t *
 * au_to_subject(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid,
 *     gid_t rgid, pid_t pid, au_asid_t sid, au_tid_t *tid);
 *
 * token_t *
 * au_to_subject32_ex(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid,
 *     gid_t rgid, pid_t pid, au_asid_t sid, au_tid_addr_t *tid);
 *
 * token_t *
 * au_to_subject64_ex(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid,
 *     gid_t rgid, pid_t pid, au_asid_t sid, au_tid_addr_t *tid);
 *
 * token_t *
 * au_to_subject_ex(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid,
 *     gid_t rgid, pid_t pid, au_asid_t sid, au_tid_addr_t *tid);
 */
static void
el_subject(const char *el, const char **attr, const char *body)
{
	gid_t egid, rgid;
	uid_t euid, ruid;
	au_asid_t sid;
	au_tid_t tid;
	au_id_t auid;
	token_t *tok;
	pid_t pid;
	struct attr_pair pairs[] = {
		{"audit-uid",	&auid},
		{"gid",		&egid},
		{"pid",		&pid},
		{"rgid",	&rgid},
		{"ruid",	&ruid},
		{"sid",		&sid},
		{"tid",		&tid},
		{"uid",		&euid},
		{NULL,		NULL}
	};

	if (attr == NULL)
		return;

	/* Parse element's attributes. */
	handleAttributes("subject", attr, pairs);

	/* Create token. */
	tok = au_to_subject32(auid, euid, egid, ruid, rgid, pid, sid, &tid);
	rec_append(&tb, tok);
}

/*
 * [text]
 *
 * Tokens
 * ------
 * AUT_TEXT
 *
 * The body of this element contains arbitrary text.
 */
/*
 * token_t *
 * au_to_text(const char *text);
 */
static void
el_text(const char *el, const char **attr, const char *body)
{
	token_t *tok;

	if (attr != NULL)
		return;

	/* Create token. */
	tok = au_to_text(body);
	rec_append(&tb, tok);
}

/*
 * [zone]
 *
 * Attribute
 * ---------
 * name
 *
 * Tokens
 * ------
 * AUT_ZONENAME
 */
/*
 * token_t *
 * au_to_zonename(const char *zonename);
 */
static void
el_zone(const char *el, const char **attr, const char *body)
{
	token_t *tok;
	char *name;
	struct attr_pair pairs[] = {
		{"name",	&name},
		{NULL,		NULL}
	};

	if (attr == NULL)
		return;

	/* Parse element's attributes. */
	handleAttributes("zone", attr, pairs);

	/* Create token. */
 	tok = au_to_zonename(name);
	rec_append(&tb, tok);

	/* Clean up. */
	free(name);
}
