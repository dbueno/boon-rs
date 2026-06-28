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

char *Version = "@(#) route 1.70 (01/04/94)";
char * getsock(char *bufp, struct sockaddr * sap)
{
 unsigned char *ptr;
 char *sp = bufp;
 int i, val;
 struct sockaddr_in *sin;
 sin = (struct sockaddr_in *) sap;
 sin->sin_family = AF_INET;
 sin->sin_port = 0;
 ptr = (unsigned char *) (&(sin->sin_addr.s_addr) + 1);
 for (i = 0; i < sizeof(sin->sin_addr.s_addr); i++) {
  val = 0;
  if (*sp == '\t')
   break;
  if (*sp >= 'A')
   val = (int) (*sp - 'A') + 10;
  else
   val = (int) (*sp - '0');
  val <<= 4;
  sp++;
  if (*sp >= 'A')
   val |= (int) (*sp - 'A') + 10;
  else
   val |= (int) (*sp - '0');
  *--ptr = (unsigned char) (val & 0377);
  sp++;
 }
 return (sp);
}
int resolve(char *name, struct sockaddr * sap)
{
 struct hostent *hp;
 struct netent *np;
 struct sockaddr_in *sin;
 sin = (struct sockaddr_in *) sap;
 sin->sin_family = AF_INET;
 sin->sin_port = 0;
 if (!strcmp(name, "default")) {
  sin->sin_addr.s_addr = INADDR_ANY;
  return (1);
 }
 if ((np = getnetbyname(name)) != (struct netent *) NULL) {
  sin->sin_addr.s_addr = htonl(np->n_net);
  strcpy(name, np->n_name);
  return (1);
 }
 if ((hp = gethostbyname(name)) == (struct hostent *) NULL) {
  errno = h_errno;
  return (-1);
 }
 memcpy((char *) &sin->sin_addr, (char *) hp->h_addr_list[0], hp->h_length);
 strcpy(name, hp->h_name);
 return ((ntohl(sin->sin_addr.s_addr) & 0xff) == 0);
}
int rresolve(char *name, struct sockaddr * sap, int numeric)
{
 struct sockaddr_in *sin;
 struct hostent *ent;
 struct netent *np;
 unsigned long ad, host_ad;
 sin = (struct sockaddr_in *) sap;
 if (sin->sin_family != AF_INET) {
  errno = EAFNOSUPPORT;
  return (-1);
 }
 if (sin->sin_addr.s_addr == INADDR_ANY) {
  if (numeric & 0x8000)
   strcpy(name, "default");
  else
   strcpy(name, "*");
  return (0);
 }
 ad = (unsigned long) sin->sin_addr.s_addr;
 host_ad = ntohl(ad);
 np = NULL;
 ent = NULL;
 if ((numeric & 0x7FFF) == 0) {
  if ((host_ad & 0xFF) != 0) {
   ent = gethostbyaddr((char *) &ad, 4, AF_INET);
   if (ent != NULL)
    strcpy(name, ent->h_name);
  } else {
   np = getnetbyaddr(host_ad, AF_INET);
   if (np != NULL) {
    strcpy(name, np->n_name);
   }
  }
 }
 if ((ent == NULL) && (np == NULL)) {
  sprintf(name, "%d.%d.%d.%d",
   (int) (ad & 0xFF), (int) ((ad >> 8) & 0xFF),
   (int) ((ad >> 16) & 0xFF),
   (int) ((ad >> 24) & 0xFF));
 }
 return (0);
}
void reserror(char *text)
{
 herror(text);
}
int opt_n = 0;
int opt_v = 0;
int skfd = -1;
static void usage(void)
{
 fprintf(stderr, "Usage: route [-nv]\n");
 fprintf(stderr, "       route [-v] del target\n");
 fprintf(stderr, "       route [-v] add {-net|-host} target [gw gateway]\n");
 fprintf(stderr, "                  [metric NN] [netmask mask] [mss maxsegment] [window maxwindow]\n");
 fprintf(stderr, "                  [[dev] device]\n");
 exit(-1);
}
static void rt_print(void)
{
 char buff[1024], iface[16], net_addr[64];
 char gate_addr[64], mask_addr[64], flags[16];
 struct sockaddr snet, sgate, smask;
 FILE *fp;
 int num, iflags, refcnt, use, metric;
 int mss, window;
 printf("Kernel routing table\n");
 printf(
        "Destination     Gateway         Genmask         "
        "Flags MSS    Window Use Iface\n");
 if ((fp = fopen("/proc/net/route", "r")) == NULL) {
  perror("/proc/net/route");
  return;
 }
 while (fgets(buff, 1023, fp)) {
  num = sscanf(buff, "%s %s %s %X %d %d %d %s %d %d\n",
        iface, net_addr, gate_addr,
        &iflags, &refcnt, &use, &metric, mask_addr,
        &mss,&window);
  if (num != 10)
   continue;
  (void) getsock(net_addr, &snet);
  (void) rresolve(net_addr, &snet, (opt_n | 0x8000));
  net_addr[15] = '\0';
  (void) getsock(gate_addr, &sgate);
  rresolve(gate_addr, &sgate, opt_n);
  gate_addr[15] = '\0';
  (void) getsock(mask_addr, &smask);
  rresolve(mask_addr, &smask, 1);
  gate_addr[15] = '\0';
  flags[0] = '\0';
  if (iflags & RTF_UP)
   strcat(flags, "U");
  if (iflags & RTF_GATEWAY)
   strcat(flags, "G");
  if (iflags & RTF_HOST)
   strcat(flags, "H");
  if (iflags & RTF_REINSTATE)
   strcat(flags, "R");
  if (iflags & RTF_DYNAMIC)
   strcat(flags, "D");
  if (iflags & RTF_MODIFIED)
   strcat(flags, "M");
  printf("%-15s %-15s %-15s %-5s %-6d %-3d %6d %s\n",
         net_addr, gate_addr, mask_addr, flags,
         mss, window, use, iface);
 }
 (void) fclose(fp);
}
int rt_add(char **args)
{
 struct rtentry rt;
 char target[128], gateway[128] = "NONE", netmask[128] = "default";
 int xflag, isnet;
 xflag = 0;
 if (*args == NULL)
  usage();
 if (!strcmp(*args, "-net")) {
  xflag = 1;
  args++;
 } else if (!strcmp(*args, "-host")) {
  xflag = 2;
  args++;
 }
 if (*args == NULL)
  usage();
 strcpy(target, *args++);
 memset((char *) &rt, 0, sizeof(struct rtentry));
 if ((isnet = resolve(target, &rt.rt_dst)) < 0) {
  reserror(target);
  return (-1);
 }
 switch (xflag) {
 case 1:
  isnet = 1;
  break;
 case 2:
  isnet = 0;
  break;
 default:
  break;
 }
 rt.rt_flags = (RTF_UP | RTF_HOST);
 if (isnet)
  rt.rt_flags &= ~RTF_HOST;
 while (*args) {
  if (!strcmp(*args, "metric")) {
   int metric;
   args++;
   if (!*args || !isdigit(**args))
    usage();
   metric = atoi(*args);
   if (opt_v)
    fprintf(stderr,"metric %d ignored\n",metric);
   args++;
   continue;
  }
  if (!strcmp(*args, "netmask")) {
   struct sockaddr mask;
   args++;
   if (!*args || ((rt).rt_genmask))
    usage();
   strcpy(netmask, *args);
   if ((isnet = resolve(netmask, &mask)) < 0) {
    reserror(netmask);
    return (-1);
   }
   rt.rt_genmask = (((struct sockaddr_in *)&(mask))->sin_addr.s_addr);
   args++;
   continue;
  }
  if (!strcmp(*args,"gw") || !strcmp(*args,"gateway")) {
   args++;
   if (!*args)
    usage();
   if (rt.rt_flags & RTF_GATEWAY)
    usage();
   strcpy(gateway, *args);
   if ((isnet = resolve(gateway, &rt.rt_gateway)) < 0) {
    reserror(gateway);
    return (-1);
   }
   if (isnet) {
    fprintf(stderr, "%s: cannot use a NETWORK as gateway!\n",
     gateway);
    return (-1);
   }
   rt.rt_flags |= RTF_GATEWAY;
   args++;
   continue;
  }
  if (!strcmp(*args,"mss")) {
   args++;
   rt.rt_flags |= RTF_MSS;
   rt.rt_mss = atoi(*args);
   args++;
   if(rt.rt_mss<64||rt.rt_mss>32768)
   {
    fprintf(stderr,"Invalid MSS.\n");
    return -1;
   }
   continue;
  }
  if (!strcmp(*args,"window")) {
   args++;
   rt.rt_flags |= RTF_WINDOW;
   rt.rt_window = atoi(*args);
   args++;
   if(rt.rt_window<128||rt.rt_window>32768)
   {
    fprintf(stderr,"Invalid window.\n");
    return -1;
   }
   continue;
  }
  if (!strcmp(*args,"device") || !strcmp(*args,"dev")) {
   args++;
   if (!*args)
    usage();
  } else
   if (args[1])
    usage();
  if (rt.rt_dev)
   usage();
  rt.rt_dev = *args;
  args++;
 }
 if (((rt).rt_genmask)) {
  unsigned long mask = ~ntohl(((rt).rt_genmask));
  if (rt.rt_flags & RTF_HOST) {
   fprintf(stderr, "route: netmask doesn't make sense with host route\n");
   return -1;
  }
  if (mask & (mask+1)) {
   fprintf(stderr, "route: bogus netmask %s\n", netmask);
   return -1;
  }
  mask = ((struct sockaddr_in *) &rt.rt_dst)->sin_addr.s_addr;
  if (mask & ~((rt).rt_genmask)) {
   fprintf(stderr, "route: netmask doesn't match route address\n");
   return -1;
  }
 }
 if (ioctl(skfd, SIOCADDRT, &rt) < 0) {
  fprintf(stderr, "SIOCADDRT: %s\n", strerror(errno));
  return (-1);
 }
 return (0);
}
int rt_del(char **args)
{
 char target[128];
 struct sockaddr trg;
 struct rtentry rt;
 if (!args[0] || args[1])
  usage();
 strcpy(target, *args);
 if (resolve(target, &trg) < 0) {
  reserror(target);
  return (-1);
 }
 memset((char *) &rt, 0, sizeof(struct rtentry));
 memcpy((char *) &rt.rt_dst, (char *) &trg, sizeof(struct sockaddr));
 if (ioctl(skfd, SIOCDELRT, &rt) < 0) {
  fprintf(stderr, "SIOCDELRT: %s\n", strerror(errno));
  return (-1);
 }
 return (0);
}
int main(int argc, char **argv)
{
 int i;
 char *s;
 argv++;
 while ((s = *argv) != NULL) {
  if (*s != '-')
   break;
  while (*++s != '\0')
   switch (*s) {
   case 'n':
    opt_n = 1;
    break;
   case 'v':
    opt_v = 1;
    break;
   default:
    usage();
   }
  argv++;
 }
 if (*argv == NULL) {
  rt_print();
  exit(0);
 }
 if (strcmp(*argv, "add") && strcmp(*argv, "del"))
  usage();
 if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
  perror("socket");
  exit(-1);
 }
 if (!strcmp(*argv, "add"))
  i = rt_add(++argv);
 else
  i = rt_del(++argv);
 (void) close(skfd);
 return (i);
}
