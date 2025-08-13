#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <err.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <pcap.h>
#include <zlib.h>

#define PCAP_READ_LEN   2000 // number of bytes in each packet to read 
#define PCAP_TIMEOUT    1000 // if not enough packets timeout after this ms 
#define PIPE_SIZE       4096 // a UNIX pipe is one page of memory 

/* strlcpy/strlcat hack */
#define strlcpy(dst, src, len) \
	do { \
		strncpy(dst, src, len - 1); \
		dst[len - 1] = '\0'; \
	} while (0)
#define strlcat(dst, src, len) \
	do { \
		strncat(dst, src, len - strlen(dst) - 1); \
		dst[len - 1] = '\0'; \
	} while (0)

// ---------------------============= Globals =============--------------------
static char             data_dir[MAXPATHLEN];
static time_t           goal_ts;
static pcap_dumper_t    *pdump;
static pcap_t           *pcap;
static char             flag_gzip;
static gzFile           gzfd;
static FILE             *pipefd, *pcapfd;
static char             junk[sizeof(struct pcap_file_header)];
static char             pipebuf[PIPE_SIZE];
static int              read_pipe;
static char             pcap_fname[MAXPATHLEN];

// --------------------============= Functions =============-------------------
static void
usage(char *msg)
{
    if (msg != NULL)
        fprintf(stderr, "%s\n", msg);
    fprintf(stderr, 
        "Usage: pcapture [-u] [-i interface] [-s data-dir] pcap-filter\n"
        "    -k  keep the current user;do not switch to 'nobody'\n"
        "    -u  do not gzip output files\n");
    exit(1);
}

static void
close_hour_file()
{
    char pcap_done_fname[MAXPATHLEN];
    int errnum;
    
    // Close the pdump file
    // Note that when we are outputting zipped pcap, this will close
    // the 'write_fd' descriptor, so we only need to close the 'read_fd'
    if (pdump != NULL)
        pcap_dump_close(pdump);
    if (flag_gzip > 0) 
    {
        if (gzclose(gzfd) < 0)
            errx(1, "gzclose: %s\n", gzerror(gzfd, &errnum));
    }
    else
    {
        fclose(pcapfd);
    }
    
    // close the read side of the pipe
    close(read_pipe);
    
    // the file is complete so remove '.partial'
    strlcpy(pcap_done_fname, pcap_fname, sizeof(pcap_done_fname));
    pcap_done_fname[strlen(pcap_done_fname) - 8] = '\0';
    if (rename(pcap_fname, pcap_done_fname) < 0)
        err(1, "rename %s to %s failed", pcap_fname, pcap_done_fname);
}

static void
get_current_path(time_t ts, char path[MAXPATHLEN])
{
    char        *date_path, year_path[MAXPATHLEN], month_path[MAXPATHLEN], 
                day_path[MAXPATHLEN];
    struct tm   *tm;
    struct stat sb;
    
    // define a path to year's directory 
    strlcpy(year_path, data_dir, sizeof(year_path));
    date_path = year_path + strlen(data_dir);
    tm = gmtime(&ts);
    if (strftime(date_path, MAXPATHLEN-strlen(data_dir), "%Y", tm) < 0)
        err(1, "strftime");
    
    // check to see if year directory exists and if not create it 
    if (stat(year_path, &sb) < 0)
        if (mkdir(year_path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP |
            S_IROTH | S_IXOTH) < 0)
            err(1, "mkdir");
    
    // define a path to month's directory 
    strlcpy(month_path, year_path, sizeof(month_path));
    date_path = month_path + strlen(year_path);
    tm = gmtime(&ts);
    if (strftime(date_path, MAXPATHLEN-strlen(year_path), "/%m", tm) < 0)
        err(1, "strftime");
       
    // check to see if month directory exists and if not create it 
    if (stat(month_path, &sb) < 0)
        if (mkdir(month_path, S_IRUSR | S_IWUSR | S_IXUSR | 
            S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0)
            err(1, "mkdir");
    
    // define a path to the day's directory
    strlcpy(day_path, month_path, sizeof(day_path));
    date_path = day_path + strlen(month_path);
    tm = gmtime(&ts);
    if (strftime(date_path, MAXPATHLEN-strlen(month_path), "/%d", tm) < 0)
        err(1, "strftime");
        
    // check to see if day directory exists and if not create it 
    if (stat(day_path, &sb) < 0)
        if (mkdir(day_path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | 
            S_IXGRP | S_IROTH | S_IXOTH) < 0)
            err(1, "mkdir");
            
    strlcpy(path, day_path, MAXPATHLEN);
}

static void
create_hour_file(time_t ts)
{
    // gzmode - open files to create and always append 
    char        buf[32], path[MAXPATHLEN], pcap_done_fname[MAXPATHLEN];
    int         fds[2], bytes_read, rbytes, flag_append, fcntl_flags;
    struct tm   *tm;
    struct stat sb;
    
    // close current file 
    if (pdump != NULL) 
        close_hour_file();
    
    // create current hour's file
    get_current_path(ts, path);
    tm = gmtime(&ts);
    if (strftime(buf, sizeof(buf), "%Y-%m-%d.%H", tm) < 0)
        err(1, "strftime");
    
    if (flag_gzip == 0) 
    {
        snprintf(pcap_done_fname, sizeof(pcap_done_fname),
            "%s/%s.pcap", path, buf);
        snprintf(pcap_fname, sizeof(pcap_fname), "%s/%s.pcap.partial", path,
            buf);
    }
    else
    {
        snprintf(pcap_done_fname, sizeof(pcap_done_fname),
            "%s/%s.pcap.gz", path, buf);
        snprintf(pcap_fname, sizeof(pcap_fname), "%s/%s.pcap.gz.partial",
            path, buf);
    }
    
    // move file to be partial if still exists
    if (stat(pcap_done_fname, &sb) == 0)
    {
        if (rename(pcap_done_fname, pcap_fname) < 0)
            err(1, "rename %s to %s failed", pcap_done_fname, pcap_fname);
    }
    
    // check if any existing file and set append flag if so
    if (stat(pcap_fname, &sb) == 0 && sb.st_size > 0) 
        flag_append = 1;
    else
        flag_append = 0;
    
    // open gzip file
    if (flag_gzip > 0)
    {
        if ((gzfd = gzopen(pcap_fname, "a9")) == NULL)
            err(1, "gzopen(%s): ", pcap_fname);
    }
    else
    {
        if ((pcapfd = fopen(pcap_fname, "a")) == NULL)
            err(1, "fopen(%s): ", pcap_fname);
    }
    
    // create the pipe between the file writer and us
    if (pipe(fds) != 0) 
        err(1, "pipe: ");
    read_pipe = fds[0];
    if ((pipefd = fdopen(fds[1], "w")) == NULL)
        err(1, "fdopen(pipe): ");
    
    // set read pipe to be non-blocking
    if ((fcntl_flags = fcntl(read_pipe, F_GETFL, 0)) < 0)
        fcntl_flags = 0;
    if (fcntl(read_pipe, F_SETFL, fcntl_flags | O_NONBLOCK) < 0)
        err(1, "fcntl(read_pipe): ");
    
    // open the pcap/gzip files
    if ((pdump = pcap_dump_fopen(pcap, pipefd)) == NULL)
        errx(1, "pcap_dump_open: %s\n", pcap_geterr(pcap));
    pcap_dump_flush(pdump);
    
    // if we are appending then we DO NOT write the pcap header again so skip
    if (flag_append > 0)
    {
        bytes_read = 0;
        do
        {
            if ((rbytes = read(read_pipe, junk, 
                sizeof(struct pcap_file_header) - bytes_read)) < 0)
            {
                if (errno == EAGAIN)
                    if (bytes_read < sizeof(struct pcap_file_header))
                        errx(1, "could not read full pcap file header.");
                err(1, "create_hour_file() read error");
            }
            bytes_read += rbytes;
        } while (bytes_read < sizeof(struct pcap_file_header));
    }
    
    // set new goal 
    tm = gmtime(&ts);
    tm->tm_sec = 0;
    tm->tm_min = 0;
    tm->tm_hour+= 1;
    goal_ts = timegm(tm);
}

static void
rwpipe(void)
{
    int bytes_read, written, wbytes, gzerr;
    
    // read from pcap dump descriptor and write to file
    do {
        if ((bytes_read = read(read_pipe, pipebuf, sizeof(pipebuf))) < 0)
        {
            if (errno == EAGAIN)
                break;
            err(1, "handle_pkt() read error");
        }
        if (flag_gzip > 0)
        {
            written = 0;
            do {
                if ((wbytes = gzwrite(gzfd, pipebuf + written, 
                    bytes_read - written)) < 0)
                    errx(1, "read: %s\n", gzerror(gzfd, &gzerr));
                written += wbytes;
            } while (written < wbytes);
        }
        else
        {
            if (fwrite(pipebuf, bytes_read, 1, pcapfd) != 1)
                err(1, "handle_pkt() fwrite error");
        }
    } while (bytes_read > 0);
}

static void
handle_pkt(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
    // check if we need to rotate log files 
    if (hdr->ts.tv_sec >= goal_ts)
        create_hour_file(hdr->ts.tv_sec);
    
    // write packet to libpcap and flush to output pipe
    pcap_dump((u_char *)pdump, hdr, pkt);
    pcap_dump_flush(pdump);
    rwpipe();
}

static void
close_cb(int sig)
{
    // flush and close the pcap dumper and write file
    pcap_dump_flush(pdump);
    rwpipe();
    close_hour_file();
    syslog(LOG_INFO, "exiting on signal %d", sig);
    _exit(0);
}

int
main(int argc, char *argv[])
{
    char intf[32];
    int c, i, keep_user;
    char ebuf[PCAP_ERRBUF_SIZE];
    char pcap_filter[1024];
    struct bpf_program fcode;
    struct stat sb;
    struct passwd   *passwd;
    
    // parse cmd line options 
    pdump = NULL;
    intf[0] = '\0';
    data_dir[0] = '\0';
    flag_gzip = 1;
    keep_user = 0; 
    
    while ((c = getopt(argc, argv, "kui:s:h?")) != -1)
    {
        switch (c) 
        {
            case 'k':
                keep_user = 1;
                break;
            case 'u':
                flag_gzip = 0;
                break;
            case 'i':
                strlcpy(intf, optarg, sizeof(intf));
                break;
            case 's':
                strlcpy(data_dir, optarg, sizeof(data_dir));
                if (stat(data_dir, &sb) < 0)
                    err(1, "stat");
                if (!S_ISDIR(sb.st_mode))
                    usage("data path not a directory.");
                if (data_dir[strlen(data_dir) - 1] != '/')
                    strlcat(data_dir, "/", sizeof(data_dir));
                break;
            default:
                usage(NULL);
        }
    }
    argc -= optind;
    argv += optind;
    
    if (data_dir[0] == '\0') 
        usage("path to the directory for writing data files is required.");
    
    //make sure user is root
    if (getuid() != 0)
        errx(1, "error, you must run pcapture as root");
    
    if (intf[0] != '\0')
    {
        if ((pcap = pcap_open_live(intf, PCAP_READ_LEN, 1, PCAP_TIMEOUT,
            ebuf)) == NULL)
            errx(1, "pcap_open_live: %s\n", pcap_geterr(pcap));
    }
    else 
    {
        usage("you must specify an active interface to capture from.");
    }
    
    // build pcap filter - always filter on IP packets
    pcap_filter[0] = '\0';
    if (argc == 0) 
        strlcpy(pcap_filter, "ip", sizeof(pcap_filter));
    else
    {
        for (i=0; i<argc; i++)
        {
            strlcat(pcap_filter, argv[i], sizeof(pcap_filter));
            strlcat(pcap_filter, " ", sizeof(pcap_filter));
        }
        //strlcat(pcap_filter, "and ip", sizeof(pcap_filter));
    }
    if (pcap_compile(pcap, &fcode, pcap_filter, 1, 0) < 0)
        errx(1, "pcap_compile: %s\n", pcap_geterr(pcap));
    
    if (pcap_setfilter(pcap, &fcode) < 0)
        errx(1, "pcap_setfilter: %s\n", pcap_geterr(pcap));
    
    pcap_freecode(&fcode);
   
    if (keep_user == 0)
    {
        //set permissions on the data directory for nobody
        if ((passwd = getpwnam("nobody")) == NULL)
            err(1, "getpwnam(\"nobody\")");
        if (chown(data_dir, passwd->pw_uid, passwd->pw_gid) < 0)
            err(1, "chown");
        
        //setuid ourself to be nobody
        if (setuid(passwd->pw_uid) < 0)
            err(1, "setuid");
    }

    create_hour_file(time(NULL));
    
    // register exiting signal handlers for a clean exit 
    signal(SIGTERM, close_cb);
    signal(SIGINT, close_cb);
    
    // loop through all packets
    pcap_loop(pcap, -1, handle_pkt, NULL);
    
    return 0;
}