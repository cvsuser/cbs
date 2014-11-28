
#define LOG_TAG "cbs"

#include <utils/Log.h>
#include <android/log.h>
typedef unsigned char u8;

using namespace android;

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/input.h>
#include <linux/types.h>
#include <mntent.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/wait.h>
#include <libgen.h>
#include <ctype.h>
#include <sys/klog.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <semaphore.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <malloc.h>
#include <stdbool.h>
#include <math.h>
#include <arpa/inet.h>

#include "Rt10upDriver.h"
#include "kfifo.h"

#define AV_BUF_SIZE (512*1024)
#define PSI_BUF_SIZE (512*1024)
#define MMAP_SIZE (4096*1024)
#define PER_FIFO_SIZE (188*100)
#define AV1_KFIFO_STRUCT_OFFSET (MMAP_SIZE-4096)
#define AV2_KFIFO_STRUCT_OFFSET (AV1_KFIFO_STRUCT_OFFSET+(sizeof(struct my_kfifo)+sizeof(void *)))
#define AV3_KFIFO_STRUCT_OFFSET (AV1_KFIFO_STRUCT_OFFSET+2*(sizeof(struct my_kfifo)+sizeof(void *)))
#define PSI1_KFIFO_STRUCT_OFFSET (MMAP_SIZE-4096*2)
#define PSI2_KFIFO_STRUCT_OFFSET (PSI1_KFIFO_STRUCT_OFFSET+(sizeof(struct my_kfifo)+sizeof(void *)))
#define PSI3_KFIFO_STRUCT_OFFSET (PSI1_KFIFO_STRUCT_OFFSET+2*(sizeof(struct my_kfifo)+sizeof(void *)))

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define min(a, b) (a)<(b)?(a):(b)
#define max(a, b) (a)>(b)?(a):(b)

#if 0
typedef enum {
    LOG_UNKNOWN = 0,
    LOG_DEFAULT,    /* only for SetMinPriority() */
    LOG_VERBOSE,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL,
    LOG_SILENT,     /* only for SetMinPriority(); must be last */
}LogPriority;
#endif

#define LOGTRACE(format, ...) \
    __android_log_print(5, LOG_TAG, format, ##__VA_ARGS__)

#define LOGTRACE2(level, format, ...) \
    __android_log_print(level, LOG_TAG, format, ##__VA_ARGS__)


#define  ALOGD LOGTRACE

#define DEVICENAME "rt10up"
#define ADDDEVICES "add@/devices"
#define REMOVEDEVICES "remove@/devices/"


void local_server(void *arg);
void parser_http_request(int sockid);
int reset_buffer();
void recv_from_rt10up(void *arg);
double Demod2_GetSNR(char mer_h, char mer_m, char mer_l);

struct timeval g_start,g_last;
static unsigned char *g_ringbuffer = NULL;

static   off64_t writeOffset = 0;
static   off64_t readOffset = 0;
    //mLength(0x7fffffffffffffffLL) volatile
static int g_clientSocketFd = -1;


static int g_Capacity = 1024 * 188 *30;
int port = 35536;
int first_send = 0;
FILE* dump_file = NULL;
int g_getRt10up = 0;
static int g_read_pipe = 0;
static int g_write_pipe = 0;
pthread_mutex_t mutex;

int start_hotplug(void)
{
    int fd = 0;
    struct sockaddr_nl snl;
    //setlinebuf(stdout);
    memset(&snl, 0x00, sizeof(struct sockaddr_nl));
    snl.nl_family = 16;
    snl.nl_pid = getpid();
    snl.nl_groups = 1;

    fd = socket(16, SOCK_DGRAM, 15);
    if (fd == -1)
    {
        ALOGD("<%s:%d>,[%d]%s\n",__FUNCTION__,__LINE__, errno,strerror(errno)  );
        return -1;
    }

    int ret = bind(fd, (struct sockaddr *) &snl, sizeof(struct sockaddr_nl));
    if (ret < 0) {
        ALOGD("<%s:%d>,[%d]%s\n",__FUNCTION__,__LINE__, errno,strerror(errno)  );
        close(fd);
        fd = -1;
    }
    return fd;
}

int check_hotplug(){
    int try_times = 3;
    int fd;
    for(int i = 0;i<5;i++)
    {
        if((access("/dev/rt10up", F_OK) == 0))
            break;
        sleep(1);
    }

    if ((fd = open("/dev/rt10up", O_RDWR)) < 0)
    {
        ALOGD("<%s:%d>,[%d]%s\n",__FUNCTION__,__LINE__, errno,strerror(errno)  );
        return 1;
    }else{
        ALOGD("%s %d. get /dev/rt10up.\n",__FUNCTION__,__LINE__);
        close(fd);
    }
    return 0;
}

int process_hotplug(int fd)
{
    char buf[4096] = {0};
    int len1 = strlen(ADDDEVICES);
    int len2 = strlen(REMOVEDEVICES);

    read(fd, &buf, sizeof(buf));
    ALOGD("Received: %s\n", buf);
    int ret = -1;
    if (!strncasecmp(buf, ADDDEVICES,len1) && strstr(buf, DEVICENAME)) {
        ALOGD("ADD %s\n", DEVICENAME);
        if(check_hotplug() == 0)
            ret = 1;
    } else if (!strncasecmp(buf, REMOVEDEVICES,len2) && strstr(buf, DEVICENAME)) {
        ALOGD("REMOVE %s\n", DEVICENAME);
        ret = 0;
    }

    return ret;
}
int start_http(){
    int fd;
    struct sockaddr_in servAddr,clieAddr;
    fd = socket(PF_INET,SOCK_STREAM,0);
    if(fd == -1){
        ALOGD("Server cannot open socket.,[%d]%s\n", errno,strerror(errno)  );
        return fd;
    }

    /* server socket is nonblocking */
    //fcntl(fd, F_SETFL, O_NONBLOCK);

    int reuse0=1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse0, sizeof(reuse0));

    memset(&servAddr,0,sizeof(servAddr));
    servAddr.sin_family=AF_INET;
    servAddr.sin_addr.s_addr=INADDR_ANY;
    servAddr.sin_port=htons(port);

    if(bind(fd,(struct sockaddr *)&servAddr,sizeof(servAddr))==-1){
        ALOGD(".\n");
        ALOGD("Cannot bind IP and port,[%d]%s\n", errno,strerror(errno)  );
        return -1;
    }

    if(listen(fd,5)==-1){
        ALOGD("Listen error.,[%d]%s\n", errno,strerror(errno)  );
        return -1;
    }
    else{
        ALOGD("\nServer listening at port %d...\n",port);
    }
    return fd;
}

#define LISTENFD 5
int listener_fd[LISTENFD] = {-1};

int send_msg(char *s){
    for(int i = 0;i < LISTENFD; i++){
        ALOGD("\t<%s>%d,write pipe = [%d]",__FUNCTION__,__LINE__,listener_fd[i]);
        if(listener_fd[i] > 0)
            write(listener_fd[i],s,strlen(s));
    }
    return 0;
}

void hotplug_server(void *arg){

    ALOGD("%s %d. pthread start.\n",__FUNCTION__,__LINE__);
    g_getRt10up = ! check_hotplug();
    ALOGD("%s %d,g_getRt10up = %d\n",__FUNCTION__,__LINE__,g_getRt10up);
    int hotplug_fd = start_hotplug();
    int old = g_getRt10up;
    while (1) {
        int ret = process_hotplug(hotplug_fd);
        if(ret >= 0 ){
            g_getRt10up = ret;
        }
        ALOGD("%s %d,g_getRt10up = %d\n",__FUNCTION__,__LINE__,g_getRt10up);
        if(g_getRt10up != old){
            old = g_getRt10up;
            send_msg("hotplug:g_getRt10up change!");
        }
    }
    close(hotplug_fd);
    return NULL;
}

void local_server(void *arg)
{
    ALOGD("%s %d. pthread start.\n",__FUNCTION__,__LINE__);
    int http_fd = -1;
    while((http_fd = start_http()) < 0){
        sleep(2);
    }

    //fcntl(http_fd, F_SETFL, O_NONBLOCK);
    //fcntl(hotplug_fd, F_SETFL, O_NONBLOCK);
    while(1)    {//TODO
        //ALOGD("%s %d,rdfds = %d,g_getRt10up = %d\n",__FUNCTION__,__LINE__,ret,g_getRt10up);
        int clieLen = 0;
        struct sockaddr_in clieAddr;
        int connfd = accept(http_fd,(struct sockaddr *)&clieAddr,&clieLen);
        if(connfd == -1) {
            //ALOGD("Cannot accept connection socket.");
            ALOGD("%s %d,connfd == -1\n",__FUNCTION__,__LINE__);
            usleep(2000);
            //continue;
        } else {
            ALOGD("%s %d,g_getRt10up = %d\n",__FUNCTION__,__LINE__,g_getRt10up);
            if(g_getRt10up == 1){
                int ret = 1024*1024;
                reset_buffer();
                ret = setsockopt(connfd, SOL_SOCKET, SO_SNDBUF, (void *) &ret,sizeof(ret));
                ALOGD("svr get fd %d ,g_clientSocketFd=%d,ret=%d\n", connfd,g_clientSocketFd,ret);
                parser_http_request(connfd);
                fcntl(connfd, F_SETFL, O_NONBLOCK);
                g_clientSocketFd = connfd;
                send_msg("httpserver:GET new socket!");
            }else{
                close(connfd);
            }
        }
    }
    close(http_fd);
    ALOGD("<%s>:%d\n",__FILE__,__LINE__);
    return NULL;

}

void parser_http_request(int fd)
{
    char buff[4096] = {0};
    if(read(fd,buff,4096)<=0)
    {
        ALOGD("Receive error In Server.\n");
        exit(1);
    }
    ALOGD("ReceiveInServer:=%s\n",buff);
    bzero(buff,4096);
    sprintf(buff,"HTTP/1.1 200 OK\r\nContent_type: Application/Octet-stream\r\n\n");

    if(write(fd,buff,strlen(buff)) == -1)
    {
        ALOGD("Send Error In Server.");
        return;
    }
    return;
}

void recv_from_rt10up(void *arg){

    ALOGD("%s %d. pthread start.\n",__FUNCTION__,__LINE__);
    int pipe_fd[2];
    if(pipe(pipe_fd)<0)
        ALOGD("<%s>%d,pipe err",__FUNCTION__,__LINE__);
    fcntl(pipe_fd[0], F_SETFL, O_NONBLOCK);
    fcntl(pipe_fd[1], F_SETFL, O_NONBLOCK);

    //g_read_pipe = pipe_fd[0];
    //g_write_pipe = pipe_fd[1];
    for(int i = 0;i < LISTENFD; i++){
        ALOGD("\t<%s>%d,pipe = [%d:%d:%d]",__FUNCTION__,__LINE__,listener_fd[i],pipe_fd[1],pipe_fd[0]);
        if(listener_fd[i] <= 0){
            listener_fd[i] = pipe_fd[1];
            break;
        }
    }

    char *av1_start;
    char *fifo_ptr;
    struct my_kfifo *av_fifo;

    FILE *fd_r = NULL;
#if 0
    fd_r = fopen("/var/tmp/media/test.ts", "w+");
    if(fd_r < 0)
    {
        perror("foepn fread.file error");
        ALOGD("%s %d\n",__FUNCTION__,__LINE__);
        return 0;
    }
#endif

    struct timeval f1,f2;
    gettimeofday (&f1, NULL);

    int fd;
    int ret;
    int sum = 0;
    struct timeval tv;
    fd_set  wdfds,rdfds;
    char data_g[188*100];
    static float total_time = 0.0;
while(1){
    while(g_clientSocketFd == -1 || g_getRt10up == 0){

        //FD_ZERO(&wdfds);
        FD_ZERO(&rdfds);
        FD_SET(pipe_fd[0], &rdfds);
        //FD_SET(g_write_pipe, &wdfds);
        tv.tv_sec = 3;
        tv.tv_usec = 500;
        ret = select (pipe_fd[0] + 1, &rdfds, NULL, NULL, &tv);
        if(ret < 0){
            ALOGD("[%d]ret = %d,socket=[%d],[%d]%s\n",__LINE__,ret,g_clientSocketFd,errno,strerror(errno)  );
        } else if (ret == 0){
            ALOGD("%s %d,time out\n",__FUNCTION__,__LINE__);
        } else if(FD_ISSET(pipe_fd[0], &rdfds)){
            ret = read(pipe_fd[0],data_g,512);
            ALOGD("%s %d,getmsg=%s.[%d]\n",__FUNCTION__,__LINE__,data_g,ret);
        }
    }
    if(g_getRt10up == 1){
        fd = open("/dev/rt10up",O_RDWR);
        if((av1_start = (char *)mmap(NULL,AV_BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
        {

            ALOGD("<%s:%d>,mmap failed. exit[%d]%s\n",__FUNCTION__,__LINE__, errno,strerror(errno)  );
            return NULL;
        }
        ALOGD("%s %d,av1_start=%p\n",__FUNCTION__,__LINE__,av1_start);
        if((fifo_ptr = (char *)mmap(NULL,sizeof(struct my_kfifo), PROT_READ|PROT_WRITE, MAP_SHARED, fd, AV1_KFIFO_STRUCT_OFFSET)) == MAP_FAILED)
        {
            ALOGD("<%s:%d>,mmap failed. exit[%d]%s\n",__FUNCTION__,__LINE__, errno,strerror(errno)  );
            return NULL;
        }
        ALOGD("%s %d,fifo_ptr = %p\n",__FUNCTION__,__LINE__,fifo_ptr);
        struct __kfifo *__kfifo;

        av_fifo = (struct my_kfifo *)(fifo_ptr);
        typeof((av_fifo) + 1) __tmp1 = (av_fifo);
        __kfifo = &__tmp1->kfifo;
        __kfifo->data = av1_start;
        total_time = 0;
        ALOGD("%s %d,__kfifo=%p,data = %p\n",__FUNCTION__,__LINE__,__kfifo,__kfifo->data);
    }
    while(g_clientSocketFd != -1) {
        gettimeofday (&f2, NULL);
        int ll = (f2.tv_sec-f1.tv_sec)*1000+(f2.tv_usec-f1.tv_usec)/1000;
        if(ll > 3000){
            if(sum != 0)
                total_time += ll;
            ALOGD("recv = %4d ms, size = %4d KB, total time = %f Secs\n", ll,sum/1024,total_time/1000);
            gettimeofday (&f1, NULL);
            sum = 0;
        }
        int avail = kfifo_len(av_fifo);
        ret = read(pipe_fd[0],data_g,512);
        //if(ret != -1 || avail != 0)
            //ALOGD("%s %d,av_fifo = %p,avail=%d,[check pipe %d]\n",__FUNCTION__,__LINE__,av_fifo,avail,ret);
        if(avail == 0) {
            usleep(1000);
            continue;
        } else {
            //ALOGD("get data is %d,wp=%lld,rd=%lld\n", len,writeOffset,readOffset);
            if(g_ringbuffer){
                int pos = writeOffset%g_Capacity;
                if(unlikely(pos + avail > g_Capacity)) {
                    avail = g_Capacity - pos;
                }
                kfifo_out(av_fifo, g_ringbuffer+pos, avail);
                writeOffset += avail;
                sum += avail;
            }
            if(0){
                fwrite(data_g, 188, 1, fd_r);
                fflush(fd_r);
            }
        }
    }
    if(g_getRt10up == 1){
        munmap(av1_start, AV_BUF_SIZE);
        munmap(fifo_ptr, sizeof(struct my_kfifo));
        close(fd);
    }
    ALOGD("%s %d\n",__FUNCTION__,__LINE__);
}


    close(pipe_fd[0]);
    close(pipe_fd[1]);

    //ALOGD("\033[47;32mTest OK!\033[0m\n\n");
    return NULL;
}


void send_to_client(void *arg){

    ALOGD("%s %d. pthread start.\n",__FUNCTION__,__LINE__);
    int ret;
    int total = 0;
    struct timeval f1,f2;
    gettimeofday (&f1, NULL);
    gettimeofday (&f2, NULL);

    int pipe_fd[2];
    if(pipe(pipe_fd)<0)
        ALOGD("<%s>%d,pipe err",__FUNCTION__,__LINE__);
    fcntl(pipe_fd[0], F_SETFL, O_NONBLOCK);
    fcntl(pipe_fd[1], F_SETFL, O_NONBLOCK);

    //g_read_pipe = pipe_fd[0];
    //g_write_pipe = pipe_fd[1];
    for(int i = 0;i < LISTENFD; i++){
        ALOGD("\t<%s>%d,pipe = [%d:%d:%d]",__FUNCTION__,__LINE__,listener_fd[i],pipe_fd[1],pipe_fd[0]);
        if(listener_fd[i] <= 0){
            listener_fd[i] = pipe_fd[1];
            break;
        }
    }
	
    while(1){
        fd_set  wdfds,rdfds;
        while(g_clientSocketFd == -1){
			ret = ff_network_wait_fd(pipe_fd[0], 0, NULL);//5s
			if(ret > 0){
				char buf[512] = {0};
				ret = read(pipe_fd[0],buf,512);
				ALOGD("%s %d,getmsg=%s.[%d]\n",__FUNCTION__,__LINE__,data_g,ret);
			}
        }

        FD_ZERO(&wdfds);
        FD_ZERO(&rdfds);
        FD_SET(g_clientSocketFd, &rdfds);
        FD_SET(g_clientSocketFd, &wdfds);

        ret = select (g_clientSocketFd + 1, &rdfds, &wdfds, NULL, NULL);
        if(ret < 0){
            ALOGD("ret = %d,socket=[%d],[%d]%s\n",ret,g_clientSocketFd,errno,strerror(errno)  );
            if(errno == 9) {//errno.09 is: Bad file descriptor
                close(g_clientSocketFd);
                g_clientSocketFd = -1;
            }
        } else if (ret == 0){
            ALOGD("%s %d,time out\n",__FUNCTION__,__LINE__);
        } else if(FD_ISSET(g_clientSocketFd, &rdfds)){
            char buf[512] = {0};
            ret = read(g_clientSocketFd,buf,512);
            if(ret != 0)
                ALOGD("%s %d,rdfds,buf=%s,ret = %d\n",__FUNCTION__,__LINE__,buf,ret);
        } else if(FD_ISSET(g_clientSocketFd, &wdfds)){

            off64_t cur_read_offset = readOffset;
            off64_t cur_write_offset = writeOffset;
            if(cur_write_offset - cur_read_offset > g_Capacity){
                cur_read_offset = cur_write_offset - 1024*188*10;
            }
            //pthread_mutex_unlock(&mutex);
            int ll = (f2.tv_sec-f1.tv_sec)*1000+(f2.tv_usec-f1.tv_usec)/1000;
            if(ll > 3000){
                ALOGD("send= %4d, send.%4d.socket=%d,wp=%lld,rd=%lld\n", ll,total/1024,g_clientSocketFd,cur_write_offset,cur_read_offset);
                gettimeofday (&f1, NULL);
                total = 0;
            }
            if(cur_write_offset > cur_read_offset){
                int left = cur_write_offset - cur_read_offset;
                int pos = cur_read_offset%g_Capacity;
                int len1 = g_Capacity - pos;
                if(pos + left > g_Capacity)
                    left = min(left,len1);
                //left = min(left,1316);
                //for(;left > 0;)
                {
                    ret = write(g_clientSocketFd, g_ringbuffer+pos, left);
                    //ALOGD("ret = %d,socket =%d,[%d]%s",ret,g_clientSocketFd, left,strerror(errno)  );
                    if(ret > 0){
                        gettimeofday (&f2, NULL);
                        if(first_send == 0){
                            ALOGD("first_send = %d,ret=%d\n",(f2.tv_sec)*1000+(f2.tv_usec)/1000,ret);
                            first_send = 1;
                        }
                        cur_read_offset += ret;
                        pos += ret;
                        left -= ret;
                        total += ret;
                    }else{
                        ALOGD("ret = %d,socket =%d,[%d]%s\n",ret,g_clientSocketFd, errno,strerror(errno)  );
                        if(errno == 104) {
                            close(g_clientSocketFd);
                            g_clientSocketFd = -1;
                        }
                    }
                }
                readOffset = cur_read_offset;
                //usleep(150);
            }
        }
    }
    close(pipe_fd[0]);
    close(pipe_fd[1]);
    return NULL;
}

int reset_buffer()
{
    memset(g_ringbuffer,0,g_Capacity * sizeof(char));
    char buf[1024] = {0};
    //sprintf(buf,"%d\n%d\n%d\n%d\n",vpid,eVideoType,apid,eAudioType);

    if(g_clientSocketFd!=-1)
        close(g_clientSocketFd);
    g_clientSocketFd = -1;
    writeOffset = 0;
    readOffset = 0;

    gettimeofday (&g_start, NULL);
    gettimeofday (&g_last, NULL);
    struct timeval s;gettimeofday (&s, NULL);

    return 0;
}
static int g_apid[2], g_vpid[2];

typedef struct{
int freq;
int vpid;
int apid;
}programs;
programs ht[]={
{203000,272,275},//CCTV 1
{387000,5136,5139},//"上海东方卫视"
{307000,4368,4371},//"湖南卫视"SD
{323000,4944,4947},//"江苏卫视"SD


{387000,513,660},//"CCTV高清"
{459000,6060,6061},//"CCTV6电影高清"
{459000,6570,6571},//"天津卫视高清"
{650000,4020,4021},//湖南卫视高清
{666000,521,524},//东方卫视高清
{666000,511,514},//浙江卫视高清
};

int main(int argc, char ** argv)
{

    if(0)//if(argc == 1)
    {
        int fp,fd;
        signal(SIGTTOU,SIG_IGN);
        signal(SIGTTIN,SIG_IGN);
        signal(SIGTSTP,SIG_IGN);
        signal(SIGHUP,SIG_IGN);
        if (fork() != 0)
        {
            syslog(LOG_USER|LOG_INFO,"Run to Line %d\n", __LINE__);
            exit(1);
        }
        setsid();
        {
            syslog(LOG_USER|LOG_INFO,"Run to Line %d\n", __LINE__);
        }

        if ((fp = open("/dev/tty", O_RDWR)) >= 0){
            ioctl(fp, TIOCNOTTY, NULL);
            close(fp);
        }
        if (chdir("/tmp") == -1) {
            syslog(LOG_USER|LOG_INFO, "Run to Line %d\n", __LINE__);
            exit(1);
        }
        int fdtablesize;
        for (fd=0, fdtablesize = getdtablesize(); fd < fdtablesize; fd++)
            close(fd);
        umask(0);
        signal(SIGCHLD,SIG_IGN);
    }

    //pthread_mutex_init(&mutex,NULL);

    g_ringbuffer = (unsigned char *)malloc(g_Capacity * sizeof(char));
    pthread_t pid1,pid2,pid3,pid4;
    int ret = pthread_create(&pid1,NULL,&local_server,NULL);
    ret = pthread_create(&pid2,NULL,&send_to_client,NULL);
    pthread_create(&pid3,NULL,&recv_from_rt10up,NULL);
    pthread_create(&pid4,NULL,&hotplug_server,NULL);

    char buf[256] = {0};
    //tv_change(3);
    while(0)//while(fgets(buf,250,stdin))
    {
        ALOGD("get=[%s]\n",buf);
        int type = atoi(buf);
        switch(type){
        case 3:

            break;
        default:
            ALOGD("Usage:\n");
            ALOGD("3:  play argv[1]\n");
            ALOGD("q:  Quit!\n");
            break;
        }
        if(buf[0]=='q')
            break;
        memset(buf,0x0,256);
    }

    pthread_join(pid1,NULL);//TODO
    pthread_join(pid2,NULL);//TODO
    pthread_join(pid3,NULL);//TODO
    pthread_join(pid4,NULL);//TODO
    if(g_ringbuffer)        free(g_ringbuffer);
    g_ringbuffer = NULL;
    if(g_clientSocketFd!=-1) close(g_clientSocketFd);
    g_clientSocketFd = -1;
    return 0;

}
int tv_change(int index){

    int fd,ret;
    char buf[256] = {0};
    int pid,pid2,pid3,pid4;

    NOVEL_USB_FREQ_SET_CONTROL feq;
    NOVEL_USB_PID_SET_CONTROL pidtab;
    NOVEL_USB_PID_TYPE_SET_CONTROL pidTablde;

    char tuner1_signal[16], tuner2_signal[16];
    feq.QAM_ = 2;
    feq.SymbolRate_ = 6875;
    feq.freq_ = (ULONG)ht[index].freq;

    g_vpid[0] = g_vpid[1] = pid = (ULONG)ht[index].vpid;
    g_apid[0] = g_apid[1] = pid2 = (ULONG)ht[index].apid;
    pid3 = 11;
    pid4 = 12;

    if(pid==0)
    {
        pidtab.num_ = 0;
    }
    else
    {
        pidtab.num_ = 6;
        pidtab.pids_[0] = (USHORT)pid;
        pidtab.pids_[1] = (USHORT)pid2;
        pidtab.pids_[2] = (USHORT)pid3;
        pidtab.pids_[3] = (USHORT)pid4;
        pidtab.pids_[4] = 0x12;
        pidtab.pids_[5] = 0x11;
    }

    pidTablde.pidArray.num_ = 2;
    pidTablde.pidArray.pids_[0] = (USHORT)pid;
    pidTablde.pidType[0] = 2;
    pidTablde.pidArray.pids_[1] = (USHORT)pid2;
    pidTablde.pidType[1] = 4;
    int try_times = 3;
    while((access("/dev/rt10up", F_OK) != 0) && try_times--)
    {
        sleep(1);
    }
    if(try_times == 0)
    {
        ALOGD("the cable is unusable or no cable was inserted\n");
        return -1;
    }
    ALOGD("Auto test, please wait...\n");
    if ((fd = open("/dev/rt10up", O_RDWR)) < 0)
    {
        ALOGD("the cable is unusable or no cable was inserted\n");
        return -1;
    }
    ret =ioctl(fd, RT10UP_TUNER_SET_FREQ, &feq);
    for(int i=0; i<100; i++)
    {
        ret =ioctl(fd, RT10UP_TUNER_GET_SIGNAL_STATUS, buf);
        ALOGD("RT10UP_TUNER_GET_SIGNAL_STATUS %d\n",ret);
        if(buf[0] == 1)
        {
            ALOGD("tuner 0 SNR is %f\n", Demod2_GetSNR(buf[1], buf[2], buf[3]));
            ALOGD("tuner 0 signel strength is -%ddBm\n",buf[5]);
            break;
        }
        usleep(1000);
    }
    ret = ioctl(fd, RT10UP_TUNER_SET_PID, &pidtab);
    if( ret < 0)
    {
        ALOGD("\n ---------- RT10UP_TUNER_SET_PID  error--------- \n");
    }
    ret = ioctl(fd, RT10UP_TUNER_SET_PID_AND_TYPE, &pidTablde);
    if( ret < 0)
    {
        ALOGD("\n ---------- RT10UP_TUNER_SET_PID_AND_TYPE  error--------- \n");
    }
    close(fd);
    return 0;
}
double Demod2_GetSNR(char mer_h, char mer_m, char mer_l)
{
    unsigned int MER = 0;
    double SNR = 0;

    MER = mer_h << 16 | mer_m << 8 | mer_l;

    if(MER - 1000 < 1)
    {
        MER = 1000 + 1;
    }

    SNR = 60 - 10 * log10((double)(MER - 1000));

    if(SNR < 20)
    {
        SNR = 20;
    }
    else if(SNR > 45)
    {
        SNR = 45;
    }

    return SNR;
}
