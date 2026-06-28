/* Analysis-neutral typedef prelude for differential testing.
 *
 * The bundled cstubs are empty, which tree-sitter (boon-rs) tolerates but the
 * original BOON's strict, typedef-tracking C parser does not.  These typedefs
 * declare the type *names* the strict parser needs to disambiguate the grammar.
 * None of them name string buffers, so they do not affect either tool's
 * string-range analysis -- they only let both parse the identical input. */
typedef struct __sFILE FILE;
typedef unsigned long size_t;
typedef long ssize_t;
typedef long off_t;
typedef long time_t;
typedef long ptrdiff_t;
typedef int wchar_t;
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
typedef char *caddr_t;
typedef unsigned int socklen_t;
typedef unsigned short sa_family_t;
typedef int pid_t;
typedef long intptr_t;
typedef unsigned long uintptr_t;

/* Minimal socket struct defs: the strict parser needs complete struct types to
 * resolve field accesses (the empty cstubs leave them incomplete, which crashes
 * the original).  No string buffers here, so analysis verdicts are unaffected. */
struct in_addr { unsigned long s_addr; };
struct sockaddr { unsigned short sa_family; char sa_data[14]; };
struct sockaddr_in { unsigned short sin_family; unsigned short sin_port; struct in_addr sin_addr; char sin_zero[8]; };
struct hostent { char *h_name; char **h_aliases; int h_addrtype; int h_length; char **h_addr_list; };
struct netent { char *n_name; char **n_aliases; int n_addrtype; unsigned long n_net; };
struct rtentry { struct sockaddr rt_dst; struct sockaddr rt_gateway; struct sockaddr rt_genmask; short rt_flags; long rt_mss; long rt_window; char *rt_dev; };
int main(int argc, char **argv) {
 char buf[100];
 char x[10];
 snprintf(x, argc, "%s", "XXXXXXXXXXXXXXXXXX");
 strcpy(buf, argv[1]);
}
