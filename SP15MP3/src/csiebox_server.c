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
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>
#include <sys/select.h>

static int parse_arg(csiebox_server* server, int argc, char** argv);
static int handle_request(csiebox_server* server, int conn_fd, int maxfd);
static int get_account_info(csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static char* sync_file(csiebox_server* server, int conn_fd, csiebox_protocol_meta* meta);
static char* get_user_homedir(csiebox_server* server, csiebox_client_info* info);
static char* rm_file(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm);

static void download(csiebox_server *server, int conn_fd);
static int traverse(csiebox_server *server, char *path, int conn_fd);
static void make_relative_path(csiebox_server *server, char *path, char *rpath, int conn_fd);
static int download_meta(csiebox_server *server, char *path, int conn_fd);
static int download_file(csiebox_server *server, char *path, int conn_fd);
static int download_rm(csiebox_server *server, char *path, int conn_fd);
static void download_end(csiebox_server *server, int conn_fd);

void csiebox_server_init(csiebox_server** server, int argc, char** argv) {
	csiebox_server* tmp = (csiebox_server*)malloc(sizeof(csiebox_server));
	if (!tmp) {
		fprintf(stderr, "server malloc fail\n");
		return;
	}
	memset(tmp, 0, sizeof(csiebox_server));
	if (!parse_arg(tmp, argc, argv)) {
		fprintf(stderr, "Usage: %s [config file] [-d]\n", argv[0]);
		free(tmp);
		return;
	}

	int fd = server_start();
	if (fd < 0) {
		fprintf(stderr, "server fail\n");
		free(tmp);
		return;
	}
	tmp->client = (csiebox_client_info**)malloc(sizeof(csiebox_client_info*) * getdtablesize());
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

int csiebox_server_run(csiebox_server* server) { 
	fprintf(stderr, "========== start run\n");
	int conn_fd, conn_len;
	struct sockaddr_in addr;
	fd_set fdset;
	fd_set tempfdset;
	FD_ZERO(&fdset);
	FD_ZERO(&tempfdset);
	FD_SET(server->listen_fd, &fdset);
	struct timeval t;
	t.tv_sec = 0; t.tv_usec = 100;
	int maxfd = server->listen_fd;
	while (1) {
		FD_ZERO(&tempfdset);
		memcpy(&tempfdset, &fdset, sizeof(fd_set));
		select(maxfd+1, &tempfdset, NULL, NULL, &t);
		for (int fd = 0 ; fd <= maxfd ; fd++) {
			// new user login
			if (FD_ISSET(fd, &tempfdset)==1 && fd == server->listen_fd) {
				memset(&addr, 0, sizeof(addr));
				conn_len = 0;
				conn_fd = accept(server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
				if (conn_fd < 0) {
					if (errno == ENFILE) {
						fprintf(stderr, "out of file descriptor table\n");
						continue;
					} 
					else if (errno == EAGAIN || errno == EINTR) {
						continue;
					} else {
						fprintf(stderr, "accept err\n");
						fprintf(stderr, "code: %s\n", strerror(errno));
						break;
					}
				} else {
					if (conn_fd > maxfd) maxfd = conn_fd;
					FD_SET(conn_fd, &fdset);
				}
			}
			// handle request from connected socket fd
			else if (FD_ISSET(fd, &tempfdset)) {
				int islogout = handle_request(server, fd, maxfd);
				if (islogout) {
					char buffer[1000];
					read(server->listen_fd, buffer, 1000);
					FD_CLR(fd, &fdset);
				}
			}
		}
	}
	return 1;
}

void csiebox_server_destroy(csiebox_server** server) {
	csiebox_server* tmp = *server;
	*server = 0;
	if (!tmp) {
		return;
	}
	close(tmp->listen_fd);
	free(tmp->client);
	free(tmp);
}

static int parse_arg(csiebox_server* server, int argc, char** argv) {
	if (argc < 2) {
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
		fprintf(stderr, "config (%zd, %s)=(%zd, %s)\n", keylen, key, vallen, val);
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
}

/*********************************/

static int handle_request(csiebox_server* server, int conn_fd, int maxfd) {
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	int connection = recv_message(conn_fd, &header, sizeof(header));
	if (connection > 0 && header.req.magic == CSIEBOX_PROTOCOL_MAGIC_REQ) {
		char *path;
		switch (header.req.op) {
			case CSIEBOX_PROTOCOL_OP_LOGIN:
				fprintf(stderr, "========== ");
				csiebox_protocol_login req;
				if (complete_message_with_header(conn_fd, &header, &req)) {
					login(server, conn_fd, &req);
					fprintf(stderr, "[%s] [fd = %d] login\n", 
						server->client[conn_fd]->account.user, conn_fd);
				}
				return 0;
			case CSIEBOX_PROTOCOL_OP_SYNC_META:
				fprintf(stderr, "sync meta\n");
				csiebox_protocol_meta meta;
				if (complete_message_with_header(conn_fd, &header, &meta)) {
					path = sync_file(server, conn_fd, &meta);
					for (int fd = 0 ; fd <= maxfd ; fd++) {
						if (fd == conn_fd) continue;
						if (server->client[fd] == NULL) continue;
						if (strcmp(server->client[conn_fd]->account.user,
							server->client[fd]->account.user) == 0) {
							download_meta(server, path, fd);
							download_end(server, fd);
						}
					}
					free(path);
				}
				return 0;
			case CSIEBOX_PROTOCOL_OP_SYNC_END:
				fprintf(stderr, "========== [%s] [fd = %d] sync end\nstart download...\n", 
					server->client[conn_fd]->account.user, conn_fd);
				download(server, conn_fd);
				fprintf(stderr, "========== [%s] [fd = %d] download success\n", 
					server->client[conn_fd]->account.user, conn_fd);
				return 0;
			case CSIEBOX_PROTOCOL_OP_RM:
				fprintf(stderr, "sync rm\n");
				csiebox_protocol_rm rm;
				if (complete_message_with_header(conn_fd, &header, &rm)) {
					path = rm_file(server, conn_fd, &rm);
					for (int fd = 0 ; fd <= maxfd ; fd++) {
						if (fd == conn_fd) continue;
						if (server->client[fd] == NULL) continue;
						if (strcmp(server->client[conn_fd]->account.user, 
							server->client[fd]->account.user) == 0) {
							download_rm(server, path, fd);
							download_end(server, fd);
						}
					}
					free(path);
				}
				return 0;
			default:
				fprintf(stderr, "unknow op %x\n", header.req.op);
				return 0;
		}
	} else if (connection <= 0) {
		fprintf(stderr, "========== [%s] [fd = %d] logout\n", 
			server->client[conn_fd]->account.user, conn_fd);
		logout(server, conn_fd);
		return 1;
	}
	return 0;
}

static void download(csiebox_server *server, int conn_fd)
{
	char *path = get_user_homedir(server, server->client[conn_fd]);
	traverse(server, path, conn_fd);
	free(path);
	// send download finish message
	download_end(server, conn_fd);
}

static int traverse(csiebox_server *server, char *path, int conn_fd)
{
	fprintf(stderr, "download traverse: path= %s\n", path);
	struct stat fs;
	memset(&fs, 0, sizeof(fs));
	lstat(path, &fs);
	if (S_ISREG(fs.st_mode)) {
		return download_meta(server, path, conn_fd);
	} else if (S_ISDIR(fs.st_mode)){
		// if client have no dir, create first
		download_meta(server, path, conn_fd);
		DIR *dir = opendir(path);
		struct dirent *content;
		while((content = readdir(dir)) != NULL) {
			if (strcmp(content->d_name, ".") == 0 || strcmp(content->d_name, "..") == 0) continue;
			char subpath[PATH_MAX];
			sprintf(subpath, "%s/%s", path, content->d_name);
			traverse(server, subpath, conn_fd);
		}
		closedir(dir);
		// sync dir time
		return download_meta(server, path, conn_fd);
	}
	return 0;
}

static void make_relative_path(csiebox_server *server, char *path, char *rpath, int conn_fd)
{
	memset(rpath, 0, PATH_MAX);
	char *rootpath = get_user_homedir(server, server->client[conn_fd]);
	int rootlen = strlen(rootpath);
	int pathlen = strlen(path);
	for (int i = 0 ; rootlen+i+1 < pathlen ; i++) {
		rpath[i] = path[rootlen+i+1];
	}
	free(rootpath);
}

static int download_meta(csiebox_server *server, char *path, int conn_fd)
{
	fprintf(stderr, "download meta\n");
	// send message
	csiebox_protocol_meta meta;
	memset(&meta, 0, sizeof(meta));
	meta.message.header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	meta.message.header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	meta.message.header.res.datalen = sizeof(meta) - sizeof(meta.message.header);
	lstat(path, &meta.message.body.stat);
	send_message(conn_fd, &meta, sizeof(meta));
	// send relative path
	char rpath[PATH_MAX];
	make_relative_path(server, path, rpath, conn_fd);
	send_message(conn_fd, rpath, PATH_MAX);
	int need_file = 0;
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	recv_message(conn_fd, &header, sizeof(header));
	if (header.req.magic == CSIEBOX_PROTOCOL_MAGIC_REQ &&
		header.req.op == CSIEBOX_PROTOCOL_OP_SYNC_META) {
		need_file = (header.req.status == CSIEBOX_PROTOCOL_STATUS_MORE)? 1 : 0;	
	} else {
		fprintf(stderr, "download meta fail\n");
		return 0;
	}

	if (need_file) {
		download_file(server, path, conn_fd);
	}
	return 1;
}

#define BUFSIZE 1025
static int download_file(csiebox_server *server, char *path, int conn_fd)
{
	fprintf(stderr, "download file\n");
	// send message
	csiebox_protocol_file file;
	memset(&file, 0, sizeof(file));
	file.message.header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	file.message.header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
	file.message.header.res.datalen = sizeof(file) - sizeof(file.message.header);
	send_message(conn_fd, &file, sizeof(file));
	// send path
	char rpath[PATH_MAX];
	make_relative_path(server, path, rpath, conn_fd);
	send_message(conn_fd, rpath, PATH_MAX);
	// send status
	struct stat fs;
	lstat(path, &fs);
	send_message(conn_fd, &fs, sizeof(fs));
	// send data if is reg file
	int fd = open(path, O_RDONLY);
	char buffer[BUFSIZE];
	if (fd >= 0 && S_ISREG(fs.st_mode)) do {
		memset(buffer, 0, BUFSIZE);
		read(fd, buffer, BUFSIZE-1);
		send_message(conn_fd, buffer, BUFSIZE-1);
	} while(strlen(buffer) == BUFSIZE-1);
	close(fd);
	// receive message from client
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	recv_message(conn_fd, &header, sizeof(header));
	if (header.req.magic == CSIEBOX_PROTOCOL_MAGIC_REQ &&
		header.req.op == CSIEBOX_PROTOCOL_OP_SYNC_FILE && 
		header.req.status == CSIEBOX_PROTOCOL_STATUS_OK) {
		return 1;
	} else {
		fprintf(stderr, "download file fail\n");
		return 0;
	}
}

static int download_rm(csiebox_server *server, char *path, int conn_fd) 
{
	fprintf(stderr, "download rm\n");
	// send message
	csiebox_protocol_rm rm;
	memset(&rm, 0, sizeof(rm));
	rm.message.header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	rm.message.header.res.op = CSIEBOX_PROTOCOL_OP_RM;
	rm.message.header.res.datalen = sizeof(rm) - sizeof(rm.message.header);
	send_message(conn_fd, &rm, sizeof(rm));
	// send path
	char rpath[PATH_MAX];
	make_relative_path(server, path, rpath, conn_fd);
	send_message(conn_fd, rpath, sizeof(rpath));
	// receive message from client
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	recv_message(conn_fd, &header, sizeof(header));
	if (header.req.magic == CSIEBOX_PROTOCOL_MAGIC_REQ &&
		header.req.op == CSIEBOX_PROTOCOL_OP_RM &&
		header.req.status == CSIEBOX_PROTOCOL_STATUS_OK) {
		return 1;
	} else {
		fprintf(stderr, "download rm fail\n");
		return 0;
	}
}

static void download_end(csiebox_server *server, int conn_fd)
{
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_END;
	send_message(conn_fd, &header, sizeof(header));
}

/****************************************/

static int get_account_info(
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
			fprintf(stderr, "ill form in account file, line %d\n", line);
			continue;
		}
		if (strcmp(user, u) == 0) {
			memcpy(info->user, user, strlen(user));
			char* passwd = strtok(NULL, ",");
			if (!passwd) {
				fprintf(stderr, "ill form in account file, line %d\n", line);
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
}

static void login(csiebox_server* server, int conn_fd, csiebox_protocol_login* login) {
	int succ = 1;
	csiebox_client_info* info = (csiebox_client_info*)malloc(sizeof(csiebox_client_info));
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
}

static void logout(csiebox_server* server, int conn_fd) {
	free(server->client[conn_fd]);
	server->client[conn_fd] = 0;
	close(conn_fd);
}

static char *sync_file(csiebox_server* server, int conn_fd, csiebox_protocol_meta* meta) {
	csiebox_client_info* info = server->client[conn_fd];
	char* homedir = get_user_homedir(server, info);
	printf("homedir = %s\n", homedir);
	char buf[PATH_MAX];
	char *req_path = malloc(sizeof(char) * PATH_MAX); // return path
	memset(buf, 0, PATH_MAX);
	memset(req_path, 0, PATH_MAX);
	recv_message(conn_fd, buf, meta->message.body.pathlen);
	sprintf(req_path, "%s%s", homedir, buf);
	free(homedir);
	fprintf(stderr, "req_path: %s\n", req_path);
	struct stat stat;
	memset(&stat, 0, sizeof(struct stat));
	int need_data = 0, change = 0;
	if (lstat(req_path, &stat) < 0) {
		need_data = 1;
		change = 1;
	} else { 					
		if(stat.st_mode != meta->message.body.stat.st_mode) { 
			chmod(req_path, meta->message.body.stat.st_mode);
		}				
		if(stat.st_atime != meta->message.body.stat.st_atime ||
				stat.st_mtime != meta->message.body.stat.st_mtime){
			struct utimbuf* buf = (struct utimbuf*)malloc(sizeof(struct utimbuf));
			buf->actime = meta->message.body.stat.st_atime;
			buf->modtime = meta->message.body.stat.st_mtime;
			if(utime(req_path, buf)!=0){
				printf("time fail\n");
			}
		}
		uint8_t hash[MD5_DIGEST_LENGTH];
		memset(hash, 0, MD5_DIGEST_LENGTH);
		if ((stat.st_mode & S_IFMT) == S_IFDIR) {
		} else {
			md5_file(req_path, hash);
		}
		if (memcmp(hash, meta->message.body.hash, MD5_DIGEST_LENGTH) != 0) {
			need_data = 1;
		}
	}

	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	header.res.datalen = 0;
	header.res.client_id = conn_fd;
	if (need_data) {
		header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
	} else {
		header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	}
	send_message(conn_fd, &header, sizeof(header));

	if (need_data) {
		csiebox_protocol_file file;
		memset(&file, 0, sizeof(file));
		recv_message(conn_fd, &file, sizeof(file));
		fprintf(stderr, "sync file: %zd\n", file.message.body.datalen);
		if ((meta->message.body.stat.st_mode & S_IFMT) == S_IFDIR) {
			fprintf(stderr, "dir\n");
			mkdir(req_path, DIR_S_FLAG);
		} else {
			fprintf(stderr, "regular file\n");
			int fd = open(req_path, O_CREAT | O_WRONLY | O_TRUNC, REG_S_FLAG);
			size_t total = 0, readlen = 0;;
			char buf[4096];
			memset(buf, 0, 4096);
			while (file.message.body.datalen > total) {
				if (file.message.body.datalen - total < 4096) {
					readlen = file.message.body.datalen - total;
				} else {
					readlen = 4096;
				}
				if (!recv_message(conn_fd, buf, readlen)) {
					fprintf(stderr, "file broken\n");
					break;
				}
				total += readlen;
				if (fd > 0) {
					write(fd, buf, readlen);
				}
			}
			if (fd > 0) {
				close(fd);
			}
		}
		if (change) {
			chmod(req_path, meta->message.body.stat.st_mode);
			struct utimbuf* buf = (struct utimbuf*)malloc(sizeof(struct utimbuf));
			buf->actime = meta->message.body.stat.st_atime;
			buf->modtime = meta->message.body.stat.st_mtime;
			utime(req_path, buf);
		}
		header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
		header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
		send_message(conn_fd, &header, sizeof(header));
	}
	return req_path;
}

static char* get_user_homedir(csiebox_server* server, csiebox_client_info* info) {
	char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
	memset(ret, 0, PATH_MAX);
	sprintf(ret, "%s/%s", server->arg.path, info->account.user);
	return ret;
}

static char *rm_file(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm) {
	csiebox_client_info* info = server->client[conn_fd];
	char* homedir = get_user_homedir(server, info);
	char buf[PATH_MAX];
	char *req_path = malloc(sizeof(char)*PATH_MAX);
	memset(req_path, 0, PATH_MAX);
	memset(buf, 0, PATH_MAX);
	recv_message(conn_fd, buf, rm->message.body.pathlen);
	sprintf(req_path, "%s%s", homedir, buf);
	free(homedir);
	fprintf(stderr, "rm (%zd, %s)\n", strlen(req_path), req_path);
	struct stat stat;
	memset(&stat, 0, sizeof(stat));
	lstat(req_path, &stat);
	if ((stat.st_mode & S_IFMT) == S_IFDIR) {
		rmdir(req_path);
	} else {
		unlink(req_path);
	}

	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_RM;
	header.res.datalen = 0;
	header.res.client_id = conn_fd;
	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	send_message(conn_fd, &header, sizeof(header));
	return req_path;
}
