/**************************************************************************
*
*  Copyright (c) 2010 Andrew Yourtchenko, ayourtch@gmail.com.
*
*  Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation
* the rights to use, copy, modify, merge, publish, distribute, sublicense,
* and/or sell copies of the Software, and to permit persons to whom
* the Software is furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included
* in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
* THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
* OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
* ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
* OR OTHER DEALINGS IN THE SOFTWARE.
*
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <ev.h>
#include <udns.h>

/* The prefix that is used to lookup the IPv4 target address */
// #define REAL_TARGET_PREFIX "real-target."
#define REAL_TARGET_PREFIX ""

#define TARGET_HTTP_PORT 80

const int LISTEN_QUEUE=128;

int logfd;
uint32_t debug_flags = 0;

typedef void signal_func(int);

/******** Housekeeping functions *******/

signal_func *
set_signal_handler(int signo, signal_func * func) {
  struct sigaction act, oact;

  act.sa_handler = func;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;

  if(sigaction(signo, &act, &oact) < 0)
    return SIG_ERR;

  return oact.sa_handler;
}

uint64_t
get_time_msec(void) {
  struct timeval tv;

  gettimeofday(&tv, NULL);
  return (((uint64_t) 1000000) * (uint64_t) tv.tv_sec +
          (uint64_t) tv.tv_usec) / (uint64_t) 1000;
}

int
debug(uint32_t dbg_bits, const char *fmt, ...) {
  static uint64_t last_sync = 0;
  uint64_t time_now;
  va_list ap;
  int result = 0;
  struct timeval tv;
  char date_buf[64];
  if((debug_flags & dbg_bits) || (dbg_bits == 0)) {
    gettimeofday(&tv, NULL);
    asctime_r(localtime(&tv.tv_sec), date_buf);
    date_buf[strlen(date_buf) - 6] = 0;
    fprintf(stderr, "%s.%06d %08x: ", date_buf, (int) tv.tv_usec, dbg_bits);
    va_start(ap, fmt);
    result = vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    time_now = get_time_msec();
    if(time_now - last_sync > 1000) {
      fflush(stderr);
      last_sync = time_now;
    }
  }
  return result;
}



void
makedaemon(char *logname) {
  int uid = 32767;
  int gid = 32767;
  char *user = "nobody";
  struct passwd *pwd;

  logfd = open(logname, O_WRONLY | O_CREAT | O_APPEND, 0600);
  assert(logfd >= 0);

  if(getuid() == 0) {
    pwd = getpwnam(user);
    if(pwd) {
      uid = pwd->pw_uid;
      gid = pwd->pw_gid;
    }
    assert(setgroups(0, (const gid_t *) 0) >= 0);
    initgroups(user, gid);      // not critical if fails
    assert(setgid(gid) >= 0);
    assert(setegid(gid) >= 0);
    assert(setuid(uid) >= 0);
    assert(seteuid(gid) >= 0);
  }

  if(fork() != 0)
    exit(0);

  setsid();
  set_signal_handler(SIGHUP, SIG_IGN);
  set_signal_handler(SIGPIPE, SIG_IGN);

  if(fork() != 0)
    exit(0);

  chdir("/tmp");
  chroot("/tmp");
  umask(077);

  close(0);
  close(1);
  close(2);
  dup2(logfd, 1);
  dup2(logfd, 2);
  debug(0, "Daemonized. PID = %d", getpid());
}

/******* Socket stuff *****/

int 
set_nonblocking(int s) {
  int flags = fcntl(s, F_GETFL);
  if (flags >= 0) {
    return fcntl(s, F_SETFL, flags | O_NONBLOCK);
  } else {
    return flags;
  }
}


int 
new_listener_socket(char *hostname, char *service) {
  int reuse_on = 1;
  int s = -1;
  struct addrinfo hints, *res = NULL, *ressave = NULL;
  int error = 0;
  struct sockaddr_in6 sa;
  
  debug(0, "Creating a TCP listener socket on %s service %s", hostname, service);
 
  hints.ai_flags    = AI_PASSIVE;
  hints.ai_family   = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;

  memset(&hints, 0, sizeof(struct addrinfo));

  error = getaddrinfo(hostname, service, &hints, &res);
  if (error != 0) {
    debug(0, "getaddrinfo error: [%s]", gai_strerror(error));
    return -1;
  }
  ressave = res;

  /* Of all the results returned, the first successful wins */ 
  while(res) {
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(s >= 0) {
      if(setsockopt(s,  SOL_SOCKET, SO_REUSEADDR, &reuse_on, sizeof(reuse_on)) < 0) {
        debug(0, "setsockopt(SO_REUSEADDR) call failed, socket fd: %d", s);
          /* this is not a large disaster */
      } 
      error = set_nonblocking(s);
      if(error < 0) {
        debug(0, "Failed to make socket nonblocking");
      }
      
      if (bind(s, res->ai_addr, res->ai_addrlen) == 0) {
	break;
      }
      close(s);
      s = -1;
    }
    res = res->ai_next;
  }

  freeaddrinfo(ressave);

  if (s < 0) {
    debug(0, "Could not make a listening socket");
    return -1;
  } 

  listen(s, LISTEN_QUEUE);
  return s;
}


/***** libev main loop  *****/

struct ev_loop *mainloop = NULL;

/***** state stuff *****/

const char http_host_string[] = "\nhost:";

const char http_sxxis_string[] = "\nX-SXxis-Client: ";

enum {
  STATE_INBOUND_START = 0, /* MUST be zero! */
  /* intermediate states unnamed */
  STATE_HOST_MATCHED = sizeof(http_host_string)-1,
  STATE_INHOSTNAME,
  STATE_HOST_CAPTURED,
  STATE_OUTBOUND_CONNECTING,
  STATE_OUTBOUND_SHOWTIME,
  STATE_INBOUND_SHOWTIME,
  STATE_CLOSED,
  STATE_MAX, /* MUST be the last one */
};

/***** socket stuff *****/
#define BUFSZ 8192
#define BUFMINSZ 4096

typedef struct sock_buffer_t {
  struct sock_buffer_t *other;
  int fd;
  int state;
  int loop_detect_state;
  ev_io ev_read;
  ev_io ev_write;
  void *write_cb_ptr;

  struct dns_query *q;

  int findex; /* "fill" index - where to start if we pour into the buffer */
  int dindex; /* "drain" index - where to grab from the buffer. */
  int scindex; /* scan index  - when we're scanning for some pattern, where are we in the buffer */
  int hhindex; /* host header start index - immediately after line feed */
  int hsindex; /* hostname start index */
  int hfindex; /* hostname finish index (first char that is not hostname) */
  char savechar; /* save char to make null-terminated strings in buf */
  char buf[BUFSZ];
} sock_buffer_t;

static int num_sbs = 0;

sock_buffer_t *alloc_sb() {
  sock_buffer_t *sb = calloc(1, sizeof(*sb));
  if(sb) { num_sbs++; }
  return sb;
}

void free_sb(sock_buffer_t *sb) {
  if(sb) { num_sbs--; }
  free(sb);
}

void link2sb(sock_buffer_t *sb1, sock_buffer_t *sb2) {
  if(sb1->other) sb1->other->other = NULL;
  if(sb2->other) sb1->other->other = NULL;
  sb1->other = sb2;
  sb2->other = sb1;
}

void
delete_sock_buffer(struct ev_loop *loop, sock_buffer_t *sb) {
  sock_buffer_t *sbo = sb->other;
  ev_clear_pending(mainloop, &sb->ev_read);
  ev_clear_pending(mainloop, &sb->ev_write);
  ev_io_stop(EV_A_ &sb->ev_read);
  ev_io_stop(EV_A_ &sb->ev_write);
  if (sb->q) {
    dns_cancel(NULL, sb->q);
  }
  sb->q = NULL;
  close(sb->fd);
  sb->other = NULL;
  if(sbo) {
    /* Delete the coupled socket too, but do not let it try delete us again */
    sbo->other = NULL;
    delete_sock_buffer(loop, sbo);
  }
 // debug(2, "deleted socket %d", sb->fd);
  free_sb(sb);
}


/* 
 * send the unread data from the sds int sbd.
 * setup the events as needed.
 */

void send2sb(sock_buffer_t *sbs, sock_buffer_t *sbd) {
  int tosend = sbs->findex - sbs->dindex;
  int nsent = send(sbd->fd, &sbs->buf[sbs->dindex], tosend, 0);
  debug(2, "Sent from %d to %d: planned %d bytes, result %d", sbs->fd, sbd->fd, tosend, nsent);
  if(nsent > 0) {
    /* All sent successfully, no need to have onwrite monitor */
    ev_io_stop(mainloop, &sbd->ev_write);
    /* free up their buffer */
    sbs->findex = sbs->dindex = sbs->scindex = sbs->hhindex = sbs->hsindex = sbs->hfindex = 0;
    /* If we were sending from socket that was closed, we can close too */
    if(sbs->state == STATE_CLOSED) {
      debug(0, "Socket %d is closed now", sbs->fd);
      delete_sock_buffer(mainloop, sbs);
    }
  } else {
    switch(errno) {
      case EAGAIN:
      case EINTR:
        debug(0, "Could not send... callback.");
        /* setup the write callback */
	ev_io_init(&sbd->ev_write, sbd->write_cb_ptr, sbd->fd, EV_WRITE);
        ev_io_start(mainloop, &sbd->ev_write);
	break; /* will retry later in write callback */
      case EBADF:
      case ECONNRESET:
      case EPIPE:
        delete_sock_buffer(mainloop, sbs);
        break;
    }
  }
}



/***** libev stuff *****/

ev_io tcp80_watcher;
ev_io dns_watcher;
ev_timer timer_watcher;

int
ishostchar(char c) {
  // FIXME: got to be a less stupid way of doing this.
  return (isalpha(c) || (c=='.') || (c=='-'));
}

static void 
v4_read_cb (EV_P_ ev_io *w, int revents) {
  sock_buffer_t *sb = w->data;
  int nread;
  if (revents & EV_READ) {
    if(BUFSZ - sb->findex > BUFMINSZ) {
      nread = read(w->fd, &sb->buf[sb->findex], BUFMINSZ);
      debug(2, "Read from %d %d bytes", w->fd, nread);
      if(nread > 0) {
        sb->findex += nread;
      }
      if(nread == 0) {
        ev_io_stop(EV_A_ &sb->ev_read);
        debug(2, "Setting state to closed for %d", sb->fd);
        if(sb->findex == sb->dindex) { 
          if(sb->findex > sb->dindex) { 
            send2sb(sb, sb->other);
          }
          delete_sock_buffer(loop, sb); 
          return;
        } else {
          sb->state = STATE_CLOSED;
        }
      }
    }
  }
  if(sb->findex > sb->dindex) { 
    send2sb(sb, sb->other);
  }
}


static void
v4_write_cb (EV_P_ ev_io *w, int revents) {
  sock_buffer_t *sb = w->data;
  if(sb->state == STATE_OUTBOUND_CONNECTING) {
    debug(2, "Connected.");
    sb->state = STATE_OUTBOUND_SHOWTIME;
    sb->other->state = STATE_INBOUND_SHOWTIME;
    ev_io_init(&sb->ev_read, v4_read_cb, sb->fd, EV_READ);
    ev_io_start(mainloop, &sb->ev_read);
  }
  if(sb->state == STATE_OUTBOUND_SHOWTIME) {
    ev_io_stop(EV_A_ &sb->ev_write);
    send2sb(sb->other, sb);
  }
}

static void 
v6_write_cb (EV_P_ ev_io *w, int revents) {
  sock_buffer_t *sb = w->data;
  if(sb->state == STATE_INBOUND_SHOWTIME) {
    send2sb(sb->other, sb);
  }
}

/* 
 * Callback that gets called with the result of the lookup
 */
void
v6_dns_a4_rcvd(struct dns_ctx *ctx, struct dns_rr_a4 *result, void *data) {
  int cfd = -1;
  struct sockaddr_in sin;
  sock_buffer_t *sb;
  sock_buffer_t *sb0 = data;
  int retcode;
 

  if(result) {
    debug(2, "DNS resolution finished for '%s', number of results %d", result->dnsa4_qname, result->dnsa4_nrr);
    sb0->q = NULL;
    cfd = socket(AF_INET, SOCK_STREAM, 0);
    if(cfd < 0) {
      delete_sock_buffer(mainloop, data);
      return;
    }
    bzero(&sin, sizeof(sin));
    sin.sin_port = htons(TARGET_HTTP_PORT);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ((struct in_addr *) (result->dnsa4_addr))->s_addr;
    set_nonblocking(cfd);
    sb = alloc_sb();
    sb->fd = cfd;
    sb->other = NULL;
    link2sb(sb, data);
    sb->state = STATE_OUTBOUND_CONNECTING;
    sb->ev_read.data = sb;
    sb->ev_write.data = sb;
    sb->write_cb_ptr = v4_write_cb;
    sb->q = NULL;
    ev_io_init(&sb->ev_write, sb->write_cb_ptr, sb->fd, EV_WRITE);
    ev_io_start(mainloop, &sb->ev_write);

    retcode = connect(cfd, (struct sockaddr *) &sin, sizeof(struct sockaddr_in));
    if(retcode == 0) {
      // Connected right away
      debug(2, "Connection completed!");
    } else {
      if(errno == EINPROGRESS) {
        debug(2, "Connection in progress...");
      } else {
        delete_sock_buffer(mainloop, data);
      }
    }


  } else {
    debug(1, "DNS name does not exist");
    // FIXME: send them an error page or something ?
    sb0->q = NULL;
    delete_sock_buffer(mainloop, data);
  }
}

/*
 * Kick off the resolution request for this hostname;
 */

#define MAX_HOSTNAME_LEN 256

int
v6_act_on_hostname(EV_P_ ev_io *w, sock_buffer_t *sb, char *hostname, int hn_length) {
  char targethost[MAX_HOSTNAME_LEN] = REAL_TARGET_PREFIX;
  struct dns_query *q = NULL;

  if(hn_length + sizeof(REAL_TARGET_PREFIX) < MAX_HOSTNAME_LEN) {
    strcat(targethost, hostname);
    q = sb->q = dns_submit_a4(NULL, targethost, 0, v6_dns_a4_rcvd, sb);
    debug(2, "DNS query for '%s' submitted", targethost);
  }

  return (q != NULL);
}

int
looping_request(sock_buffer_t *sb) {
  if(sb->loop_detect_state < sizeof(http_sxxis_string) - 1) {
    int idx = sb->scindex;
    while ( (idx < sb->findex) && (sb->loop_detect_state < sizeof(http_sxxis_string) - 1) ) {
      if(tolower(sb->buf[idx++]) == tolower(http_sxxis_string[sb->loop_detect_state])) {
	sb->loop_detect_state++;
      } else {
	sb->loop_detect_state = 0;
      }
    }
    if (idx < sb->findex) {
      return 1;
    } else {
      return 0;
    }
  } else {
    return 1;
  }
}

#define INSERTION_MAX_SZ 128

/* 
 * Insert the header into the HTTP request with the real address of the remote
 * So the folks on the server side knew who is connecting to them.
 */
  
static void 
insert_sxxis_header(sock_buffer_t *sb) {
  char ipv6addr[64];
  struct sockaddr_in6 sa;
  int sa_len = sizeof(sa);
  int ipv6addr_len;
  int insert_len;
  char *buf_src = &sb->buf[sb->hhindex-1]; // Start copying with "\n"
  char *buf_dst = NULL;
  
  getpeername(sb->fd,  (struct sockaddr *)&sa, &sa_len);
  inet_ntop(AF_INET6, (void *)&sa.sin6_addr, ipv6addr, sizeof(ipv6addr));
  ipv6addr_len = strlen(ipv6addr);

  insert_len = sizeof(http_sxxis_string) + ipv6addr_len;
  buf_dst = buf_src + insert_len;
  memmove(buf_dst, buf_src, sb->findex - sb->hhindex + 1); /* All remaining data */
  memcpy(buf_src, http_sxxis_string, sizeof(http_sxxis_string)-1);
  buf_src += sizeof(http_sxxis_string)-1;
  memcpy(buf_src, ipv6addr, ipv6addr_len);
  buf_src += ipv6addr_len;
  *buf_src = '\r';
  sb->findex += insert_len;
}

static void
v6_read_cb (EV_P_ ev_io *w, int revents) {
  sock_buffer_t *sb = w->data;
  int nread;
  if (revents & EV_READ) {
    if(BUFSZ - sb->findex > BUFMINSZ + INSERTION_MAX_SZ) {
      nread = read(w->fd, &sb->buf[sb->findex], BUFMINSZ);
      if (nread > 0) {
        sb->findex += nread;
        debug(1, "fd %d read %d bytes, findex now %d", w->fd, nread, sb->findex);
        if(looping_request(sb)) {
          debug(0, "Looping request detected, disconnect it");
          delete_sock_buffer(mainloop, sb);
          return;
        }
        debug(1, "current state: %d", sb->state);
        if(sb->state < STATE_HOST_MATCHED) {
          while( (sb->scindex < sb->findex) && (sb->state < STATE_HOST_MATCHED) ) {
            debug(1, " '%c' : %d", sb->buf[sb->scindex], sb->state);
            if(tolower(sb->buf[sb->scindex++]) == http_host_string[sb->state]) {
              sb->state++;
            } else {
              sb->state = 0;
            }
            if(sb->state == 1) {
              sb->hhindex = sb->scindex;
              debug(1, "Host header start at %d", sb->hhindex);
            }
          }
        } 
        /* We do not put "else if" since in the loop above we could have reached this state */
        if(sb->state == STATE_HOST_MATCHED) {
          while( (sb->scindex < sb->findex) && (isspace(sb->buf[sb->scindex])) ) {
            sb->scindex++;
          }  
          sb->state = STATE_INHOSTNAME;
          sb->hsindex = sb->scindex;
          debug(1, "Hostname starting at index %d", sb->scindex);
        }
        if(sb->state == STATE_INHOSTNAME) {
          while( (sb->scindex < sb->findex) && (ishostchar(sb->buf[sb->scindex])) ) {
            sb->scindex++;
          }  
          if(sb->scindex < sb->findex) {
            sb->state = STATE_HOST_CAPTURED;
            sb->hfindex = sb->scindex;
            sb->savechar = sb->buf[sb->hfindex];
            sb->buf[sb->hfindex] = 0; // null-terminate
            debug(1, "Found finish of host header at index %d, hostname '%s'", sb->hfindex, &sb->buf[sb->hsindex]); 
            if(!v6_act_on_hostname(loop, w, sb, &sb->buf[sb->hsindex], sb->hfindex-sb->hsindex)) { 
              debug(0, "Error occured when trying to act on hostname");
              delete_sock_buffer(EV_A_ sb);
            } else {
              sb->buf[sb->hfindex] = sb->savechar; // restore
              /* We should sneak in the inserted header now, before it is too late */
              insert_sxxis_header(sb); 
            }
          } 
        }
        if(sb->state == STATE_INBOUND_SHOWTIME) {
          send2sb(sb, sb->other);
        }
      } else {
        /* Houston, we got a problem. Could not read anything - means the connection is gone */
        delete_sock_buffer(EV_A_ sb);
      }
    }
  }
}


static void
timeout_cb (EV_P_ ev_timer *w, int revents) {
  static int counter = 0;
  if(counter++ > 100) {
    debug(0, "... active DNS queries: %d, allocated sockets: %d", dns_active(NULL), num_sbs);
    counter = 0;
  }
  dns_timeouts(NULL, 0, 0);
}

static void
tcp80_accept_cb (EV_P_ ev_io *w, int revents) {
  sock_buffer_t *sb;
  struct sockaddr_in6 sa;
  int sa_len = sizeof(sa);
  int connfd = accept(w->fd, (struct sockaddr *)&sa, &sa_len);

  if (connfd < 0) {
    debug(0, "Error accepting new connection");
    return;
  }
  if(set_nonblocking(connfd) < 0) {
    debug(0, "Failed to set client socket non-blocking");
  }
  sb = alloc_sb();
  sb->fd = connfd;
  sb->state = STATE_INBOUND_START;
  sb->ev_read.data = sb;
  sb->ev_write.data = sb;
  sb->q = NULL;
  sb->write_cb_ptr = v6_write_cb;
  ev_io_init(&sb->ev_read, v6_read_cb, sb->fd, EV_READ);
  ev_io_start(loop, &sb->ev_read);
}

static void
dns_sock_cb (EV_P_ ev_io *w, int revents) {
  debug(1, "DNS event!");
  dns_ioevent(NULL, 0); // ev_now(loop));
  dns_timeouts(NULL, 0, 0);
}

int 
main(int argc, char *argv[]) {
  int s = new_listener_socket("::1", "80");
  if(s < 0) {
    exit(0);
  }
  mainloop = ev_default_loop (0);

  dns_init(NULL, 0);
  debug(0, "DNS sock: %d", dns_open(NULL));

  // makedaemon("/tmp/testlog.log");

  ev_io_init(&dns_watcher, dns_sock_cb, dns_sock(NULL), EV_READ);
  ev_io_start (mainloop, &dns_watcher);

  debug(0, "Socket: %d", s);

  ev_io_init(&tcp80_watcher, tcp80_accept_cb, s, EV_READ);
  ev_io_start (mainloop, &tcp80_watcher);


  ev_init(&timer_watcher, timeout_cb);
  timer_watcher.repeat = 0.01;
  ev_timer_again(mainloop, &timer_watcher); 
  
  ev_loop (mainloop, 0);

  debug(0, "Exiting...");
}

