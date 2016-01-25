#include "csiebox_server.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>

static int parse_arg(csiebox_server* server, int argc, char** argv);
static void handle_request(csiebox_server* server, int conn_fd);
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info);

static int sync_meta(csiebox_server *server, int conn_fd, csiebox_protocol_meta *meta);
static int sync_file(csiebox_server *server, int conn_fd, csiebox_protocol_file *file);
static int sync_hardlink(csiebox_server *server, int conn_fd, csiebox_protocol_hardlink *hardlink);
static int sync_rm(csiebox_server *server, int conn_fd, csiebox_protocol_rm *rm);

#define DIR_S_FLAG (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)//permission you can use to create new file
#define REG_S_FLAG (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)//permission you can use to create new directory

//read config file, and start to listen
void csiebox_server_init(/*{{{*/
  csiebox_server** server, int argc, char** argv) {
  csiebox_server* tmp = (csiebox_server*)malloc(sizeof(csiebox_server));
  if (!tmp) {
    fprintf(stderr, "server malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_server));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
    free(tmp);
    return;
  }
  int fd = server_start();
  if (fd < 0) {
    fprintf(stderr, "server fail\n");
    free(tmp);
    return;
  }
  tmp->client = (csiebox_client_info**)
      malloc(sizeof(csiebox_client_info*) * getdtablesize());
  if (!tmp->client) {
    fprintf(stderr, "client list malloc fail\n");
    close(fd);
    free(tmp);
    return;
  }
  memset(tmp->client, 0, sizeof(csiebox_client_info*) * getdtablesize());
  tmp->listen_fd = fd;
  *server = tmp;
}

//wait client to connect and handle requests from connected socket fd
int csiebox_server_run(csiebox_server* server) {
  int conn_fd, conn_len;
  struct sockaddr_in addr;
  while (1) {
    memset(&addr, 0, sizeof(addr));
    conn_len = 0;
    // waiting client connect
    conn_fd = accept(
      server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
    if (conn_fd < 0) {
      if (errno == ENFILE) {
          fprintf(stderr, "out of file descriptor table\n");
          continue;
        } else if (errno == EAGAIN || errno == EINTR) {
          continue;
        } else {
          fprintf(stderr, "accept err\n");
          fprintf(stderr, "code: %s\n", strerror(errno));
          break;
        }
    }
    // handle request from connected socket fd
    handle_request(server, conn_fd);
  }
  return 1;
}/*}}}*/

void csiebox_server_destroy(csiebox_server** server) {/*{{{*/
  csiebox_server* tmp = *server;
  *server = 0;
  if (!tmp) {
    return;
  }
  close(tmp->listen_fd);
  int i = getdtablesize() - 1;
  for (; i >= 0; --i) {
    if (tmp->client[i]) {
      free(tmp->client[i]);
    }
  }
  free(tmp->client);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_server* server, int argc, char** argv) {
  if (argc != 2) {
    return 0;
  }
  FILE* file = fopen(argv[1], "r");
  if (!file) {
    return 0;
  }
  fprintf(stderr, "reading config...\n");
  size_t keysize = 20, valsize = 20;
  char* key = (char*)malloc(sizeof(char) * keysize);
  char* val = (char*)malloc(sizeof(char) * valsize);
  ssize_t keylen, vallen;
  int accept_config_total = 2;
  int accept_config[2] = {0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
    if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(server->arg.path)) {
        strncpy(server->arg.path, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("account_path", key) == 0) {
      if (vallen <= sizeof(server->arg.account_path)) {
        strncpy(server->arg.account_path, val, vallen);
        accept_config[1] = 1;
      }
    }
  }
  free(key);
  free(val);
  fclose(file);
  int i, test = 1;
  for (i = 0; i < accept_config_total; ++i) {
    test = test & accept_config[i];
  }
  if (!test) {
    fprintf(stderr, "config error\n");
    return 0;
  }
  return 1;
}/*}}}*/

//this is where the server handle requests, you should write your code here
static void handle_request(csiebox_server* server, int conn_fd) {
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  while (recv_message(conn_fd, &header, sizeof(header))) {
    if (header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ) {
      continue;
    }
    switch (header.req.op) {
      case CSIEBOX_PROTOCOL_OP_LOGIN:
        fprintf(stderr, ">>>>>>>>>> login\n");
        csiebox_protocol_login req;
        if (complete_message_with_header(conn_fd, &header, &req)) {
			login(server, conn_fd, &req);
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_META:
        fprintf(stderr, ">>>>>>>>>> sync meta\n");
        csiebox_protocol_meta meta;
        if (complete_message_with_header(conn_fd, &header, &meta)) {
			sync_meta(server, conn_fd, &meta);
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_FILE:
        fprintf(stderr, ">>>>>>>>>> sync file\n");
        csiebox_protocol_file file;
        if (complete_message_with_header(conn_fd, &header, &file)) {
        	sync_file(server, conn_fd, &file);
		}
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK:
        fprintf(stderr, ">>>>>>>>>> sync hardlink\n");
        csiebox_protocol_hardlink hardlink;
        if (complete_message_with_header(conn_fd, &header, &hardlink)) {
			sync_hardlink(server, conn_fd, &hardlink);
		}
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_END:
        fprintf(stderr, "========== sync end\n");
        break;
      case CSIEBOX_PROTOCOL_OP_RM:
		fprintf(stderr, ">>>>>>>>>> sync rm\n");
        csiebox_protocol_rm rm;
        if (complete_message_with_header(conn_fd, &header, &rm)) {
        	sync_rm(server, conn_fd, &rm);
		}
        break;
      default:
		fprintf(stderr, ">>>>>>>>>> unknown op %x\n", header.req.op);
        break;
    }
  }
  fprintf(stderr, "========== end of connection\n");
  logout(server, conn_fd);
}

//open account file to get account information
static int get_account_info(/*{{{*/
  csiebox_server* server,  const char* user, csiebox_account_info* info) {
  FILE* file = fopen(server->arg.account_path, "r");
  if (!file) {
    return 0;
  }
  size_t buflen = 100;
  char* buf = (char*)malloc(sizeof(char) * buflen);
  memset(buf, 0, buflen);
  ssize_t len;
  int ret = 0;
  int line = 0;
  while ((len = getline(&buf, &buflen, file) - 1) > 0) {
    ++line;
    buf[len] = '\0';
    char* u = strtok(buf, ",");
    if (!u) {
      fprintf(stderr, "illegal form in account file, line %d\n", line);
      continue;
    }
    if (strcmp(user, u) == 0) {
      memcpy(info->user, user, strlen(user));
      char* passwd = strtok(NULL, ",");
      if (!passwd) {
        fprintf(stderr, "illegal form in account file, line %d\n", line);
        continue;
      }
      md5(passwd, strlen(passwd), info->passwd_hash);
      ret = 1;
      break;
    }
  }
  free(buf);
  fclose(file);
  return ret;
}/*}}}*/

//handle the login request from client
static void login(/*{{{*/
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login) {
  int succ = 1;
  csiebox_client_info* info =
    (csiebox_client_info*)malloc(sizeof(csiebox_client_info));
  memset(info, 0, sizeof(csiebox_client_info));
  if (!get_account_info(server, login->message.body.user, &(info->account))) {
    fprintf(stderr, "cannot find account\n");
    succ = 0;
  }
  if (succ &&
      memcmp(login->message.body.passwd_hash,
             info->account.passwd_hash,
             MD5_DIGEST_LENGTH) != 0) {
    fprintf(stderr, "passwd miss match\n");
    succ = 0;
  }

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  header.res.datalen = 0;
  if (succ) {
    if (server->client[conn_fd]) {
      free(server->client[conn_fd]);
    }
    info->conn_fd = conn_fd;
    server->client[conn_fd] = info;
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
    header.res.client_id = info->conn_fd;
    char* homedir = get_user_homedir(server, info);
    mkdir(homedir, DIR_S_FLAG);
    free(homedir);
  } else {
    header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
    free(info);
  }
  send_message(conn_fd, &header, sizeof(header));
}/*}}}*/

static void logout(csiebox_server* server, int conn_fd) {/*{{{*/
  free(server->client[conn_fd]);
  server->client[conn_fd] = 0;
  close(conn_fd);
}/*}}}*/

static char* get_user_homedir(/*{{{*/
  csiebox_server* server, csiebox_client_info* info) {
  char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(ret, 0, PATH_MAX);
  sprintf(ret, "%s/%s", server->arg.path, info->account.user);
  return ret;
}/*}}}*/

// make partial path at client
static char *make_path(char *path)/*{{{*/
{
	char *pch = strtok(path, "/");
	int start = 0;
	char *c_path = (char*)malloc(sizeof(char) * PATH_MAX);
	memset(c_path, 0, PATH_MAX);
	while(pch != NULL){
		if (start == 1) {
			strcat(c_path, "/");
			strcat(c_path, pch);
		}
		if (strcmp(pch, "cdir") == 0) start = 1;
		pch = strtok(NULL, "/");
	}
	return c_path;
}/*}}}*/

static int sync_meta(csiebox_server *server, int conn_fd, csiebox_protocol_meta *meta)/*{{{*/
{
	char full_path[PATH_MAX];
	recv_message(conn_fd, full_path, sizeof(full_path));
	// make a short path
	char *client_path = make_path(full_path);
	char *cur_dir = get_user_homedir(server, server->client[conn_fd]);
	if (chdir(cur_dir) == -1) {
		fprintf(stderr, "change to user directory error\n");
		return 0;
	}
	// start to traverse
	int file_check = 0;
	char *object = strtok(client_path, "/");
	while(object != NULL){
		strcat(cur_dir, "/");
		strcat(cur_dir, object);
		struct stat object_stat;
		memset(&object_stat, 0, sizeof(object_stat));
		int open_success = lstat(cur_dir, &object_stat);
		// if file not exist
		if (open_success == -1){
			if (S_ISDIR(meta->message.body.stat.st_mode)) {
				mkdir(cur_dir, meta->message.body.stat.st_mode);
				fprintf(stderr, "sync meta : create dir\n");
				// dir utime
				struct utimbuf meta_time;
				memset(&meta_time, 0, sizeof(meta_time));
				meta_time.actime = meta->message.body.stat.st_atime;
				meta_time.modtime = meta->message.body.stat.st_mtime;
				utime(cur_dir, &meta_time);
				fprintf(stderr, "create dir\n");
			}
			if (S_ISREG(meta->message.body.stat.st_mode)) {
				int fd = creat(cur_dir, meta->message.body.stat.st_mode);
				// file utime
				struct utimbuf meta_time;
				memset(&meta_time, 0, sizeof(meta_time));
				meta_time.actime = meta->message.body.stat.st_atime;
				meta_time.modtime = meta->message.body.stat.st_mtime;
				utime(cur_dir, &meta_time);
				fprintf(stderr, "sync meta : create file\n");
				close(fd);
				file_check = 1;
			}
			if (S_ISLNK(meta->message.body.stat.st_mode)) {
				fprintf(stderr, "sync meta : is symbolic link\n");
				file_check = 1;
			}
			object = strtok(NULL, "/");
		}
		// file exist
		else {
			// is directory
			if (S_ISDIR(object_stat.st_mode)){
				if (chdir(cur_dir) == -1) {
					fprintf(stderr, "chdir error\n");
					return 0;
				}
			}
			else {
			// is file
				// file chmod
				chmod(cur_dir, meta->message.body.stat.st_mode);
				chown(cur_dir, meta->message.body.stat.st_uid, meta->message.body.stat.st_gid);
				// check if is same
				uint8_t content_hash[MD5_DIGEST_LENGTH];
				memset(content_hash, 0, sizeof(content_hash));
				md5_file(cur_dir, content_hash);
				if (memcmp(content_hash, meta->message.body.hash, MD5_DIGEST_LENGTH) != 0) file_check = 1;
				// file utime
				struct utimbuf meta_time;
				memset(&meta_time, 0, sizeof(meta_time));
				meta_time.actime = meta->message.body.stat.st_atime;
				meta_time.modtime = meta->message.body.stat.st_mtime;
				utime(cur_dir, &meta_time);
			}
			object = strtok(NULL, "/");
			// dir chmod
			if (object == NULL) {
				chmod(cur_dir, meta->message.body.stat.st_mode);
				chown(cur_dir, meta->message.body.stat.st_uid, meta->message.body.stat.st_gid);
				struct utimbuf meta_time;
				// dir utime
				memset(&meta_time, 0, sizeof(meta_time));
				meta_time.actime = meta->message.body.stat.st_atime;
				meta_time.modtime = meta->message.body.stat.st_mtime;
				utime(cur_dir, &meta_time);
			}
		}
	}
	// send back message
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	header.res.status = (file_check == 1)? CSIEBOX_PROTOCOL_STATUS_MORE : CSIEBOX_PROTOCOL_STATUS_OK;
	header.res.datalen = 0;
	send_message(conn_fd, &header, sizeof(header));
	fprintf(stderr, "sync meta : success\n");

	return 1;
}/*}}}*/

static int sync_file(csiebox_server *server, int conn_fd, csiebox_protocol_file *file)/*{{{*/
{
	// receive path
	char full_path[PATH_MAX];
	recv_message(conn_fd, full_path, PATH_MAX);
	char target_path[PATH_MAX];
	sprintf(target_path, "%s%s", get_user_homedir(server, server->client[conn_fd]), make_path(full_path));
	fprintf(stderr, "sync file : target path : %s\n", target_path);
	// receive data
	struct stat fstatus;
	memset(&fstatus, 0, sizeof(fstatus));
	int open_success = lstat(target_path, &fstatus);
	if (S_ISREG(fstatus.st_mode)){
		int fd = open(target_path, O_WRONLY | O_CREAT | O_TRUNC);
		if (fd < 0) fprintf(stderr, "sync file : open fail\n");
		while(1){
			uint8_t buffer[1025];
			memset(buffer, 0, 1025);
			recv_message(conn_fd, buffer, 1024);
			write(fd, buffer, strlen(buffer));
			if (strlen(buffer) < 1024) break;
		}
		fsync(fd);
		close(fd);
		fprintf(stderr, "sync file : write success\n");
	}
	// symbolic link
	if (open_success == -1 || S_ISLNK(fstatus.st_mode)) {
		uint8_t actual_path[PATH_MAX];
		memset(actual_path, 0, PATH_MAX);
		recv_message(conn_fd, actual_path, PATH_MAX);
		if (symlink(actual_path, target_path) == 0) {
			fprintf(stderr, "sync file : symbolic link create/modify success\n");
		}
	}

	// resend message back to client for time
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	send_message(conn_fd, &header, sizeof(header));
	fprintf(stderr, "sync file : success\n");

	// utime
	struct utimbuf meta_time;
	memset(&meta_time, 0, sizeof(meta_time));
	recv_message(conn_fd, &meta_time, sizeof(meta_time));
	utime(target_path, &meta_time);
	fprintf(stderr, "sync file : utime\n");
	
	return 1;
}/*}}}*/

static int sync_hardlink(csiebox_server *server, int conn_fd, csiebox_protocol_hardlink *hardlink)/*{{{*/
{
	char client_src_path[PATH_MAX];
	char client_target_path[PATH_MAX];
	if (!recv_message(conn_fd, client_src_path, PATH_MAX) || 
		!recv_message(conn_fd, client_target_path, PATH_MAX)) {
		fprintf(stderr, "receive path error\n");
		return 0;
	}
	// sync hardlink
	fprintf(stderr, "sync hardlink : receive path :\n\t%s\n\t%s\n", client_src_path, client_target_path);
	char src_path[PATH_MAX], target_path[PATH_MAX];
	sprintf(src_path, "%s%s", get_user_homedir(server, server->client[conn_fd]), make_path(client_src_path));
	sprintf(target_path, "%s%s", get_user_homedir(server, server->client[conn_fd]), make_path(client_target_path));
	remove(target_path);
	fprintf(stderr, "sync hardlink : remove : %s\n", target_path);
	link(src_path, target_path);

	// send back message for time
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	send_message(conn_fd, &header, sizeof(header));
	fprintf(stderr, "sync hardlink : success\n");
	
	// utime
	struct utimbuf meta_time;
	memset(&meta_time, 0, sizeof(meta_time));
	recv_message(conn_fd, &meta_time, sizeof(meta_time));
	utime(src_path, &meta_time);

	fprintf(stderr, "sync hardlink : utime\n");
	return 1;
}/*}}}*/

static int sync_rm(csiebox_server *server, int conn_fd, csiebox_protocol_rm *rm)/*{{{*/
{
	char client_path[PATH_MAX];
	char target_path[PATH_MAX];
	if (recv_message(conn_fd, client_path, PATH_MAX)) {
		sprintf(target_path, "%s%s", get_user_homedir(server, server->client[conn_fd]), make_path(client_path));
		struct stat fstatus;
		memset(&fstatus, 0, sizeof(fstatus));
		lstat(target_path, &fstatus);
		if (S_ISDIR(fstatus.st_mode)) rmdir(target_path);
		else unlink(target_path);
		fprintf(stderr, "removed : %s\n", target_path);
	}
	// resend message back to client
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_RM;
	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	if (!send_message(conn_fd, &header, sizeof(header))) {
		fprintf(stderr, "send back message error\n");
		return 0;
	}
	return 1;
}/*}}}*/
