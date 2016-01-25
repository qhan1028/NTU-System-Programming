#include "csiebox_client.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <linux/inotify.h>
#include <utime.h>
#include <sys/select.h>

static int parse_arg(csiebox_client* client, int argc, char** argv);
static int login(csiebox_client* client);
static int prepare_and_sync(csiebox_client* client);
static void sync_all(csiebox_client* client, char* longest_path, int level);

static char* check_walked_dir(csiebox_client* client);
static void sync_file(csiebox_client* client, char* path);
static csiebox_protocol_status sync_file_meta(csiebox_client* client, char* path);
static void sync_file_data(csiebox_client* client, char* path);
static char* convert_to_relative_path(csiebox_client* client, const char* path);
static void monitor_home(csiebox_client* client);
static void rm_file(csiebox_client* client, char* path, int is_dir);
static void add_inotify(csiebox_client* client, char* path);
static void handle_inotify(csiebox_client* client);

static int download(csiebox_client *client);
static int handle_download(csiebox_client *client);
static int download_meta(csiebox_client *client, csiebox_protocol_meta *meta);
static int download_file(csiebox_client *client, csiebox_protocol_file *file);
static int download_rm(csiebox_client *client, csiebox_protocol_rm *rm);

#define IN_FLAG (IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY)
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

int max_level = 0;

void csiebox_client_init(
		csiebox_client** client, int argc, char** argv) {
	csiebox_client* tmp = (csiebox_client*)malloc(sizeof(csiebox_client));
	if (!tmp) {
		fprintf(stderr, "client malloc fail\n");
		return;
	}
	memset(tmp, 0, sizeof(csiebox_client));
	if (!parse_arg(tmp, argc, argv)) {
		fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
		free(tmp);
		return;
	}
	int fd = client_start(tmp->arg.name, tmp->arg.server);
	if (fd < 0) {
		fprintf(stderr, "connect fail\n");
		free(tmp);
		return;
	}
	tmp->conn_fd = fd;
	fd = inotify_init();
	if (fd < 0) {
		fprintf(stderr, "inotify fail\n");
		close(tmp->conn_fd);
		free(tmp);
		return;
	}
	tmp->inotify_fd = fd;
	if (!init_hash(&(tmp->inotify_hash), 100)) {
		destroy_hash(&(tmp->inotify_hash));
		fprintf(stderr, "hash fail\n");
		close(tmp->conn_fd);
		close(tmp->inotify_fd);
		free(tmp);
	}
	memset(tmp->root, 0, PATH_MAX);
	realpath(tmp->arg.path, tmp->root);
	*client = tmp;
}

int csiebox_client_run(csiebox_client* client) {
	if (!login(client)) {
		fprintf(stderr, "login fail\n");
		return 0;
	}
	fprintf(stderr, "========== login success\nstart sync...\n");

	if (!prepare_and_sync(client)) {
		fprintf(stderr, "sync fail\n");
		return 0;
	}
	fprintf(stderr, "========== sync success\nstart download...\n");
	
	if (!download(client)) {
		fprintf(stderr, "download fail\n");
		return 0;
	}
	fprintf(stderr, "========== download success\n");

	fprintf(stderr, "========== monitor start\n");
	monitor_home(client);
	fprintf(stderr, "========== monitor end\n");
	return 1;
}

void csiebox_client_destroy(csiebox_client** client) {
	csiebox_client* tmp = *client;
	*client = 0;
	if (!tmp) {
		return;
	}
	close(tmp->conn_fd);
	close(tmp->inotify_fd);
	destroy_hash(&(tmp->inotify_hash));
	free(tmp);
}

/*************************************/

static int download(csiebox_client *client) 
{
	int finish = 0;
	while(!finish) {
		finish = handle_download(client);
	}
	return 1;
}

static int handle_download(csiebox_client *client)
{
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	recv_message(client->conn_fd, &header, sizeof(header));
	if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES) {
		switch (header.res.op) {
			case CSIEBOX_PROTOCOL_OP_SYNC_META: 
				fprintf(stderr, ">>> download meta: ");
				csiebox_protocol_meta meta;
				complete_message_with_header(client->conn_fd, &header, &meta);
				download_meta(client, &meta);
				return 0;
			case CSIEBOX_PROTOCOL_OP_SYNC_FILE:
				fprintf(stderr, ">>> download file\n");
				csiebox_protocol_file file;
				complete_message_with_header(client->conn_fd, &header, &file);
				download_file(client, &file);
				return 0;
			case CSIEBOX_PROTOCOL_OP_RM: 
				fprintf(stderr, ">>> download rm: ");
				csiebox_protocol_rm rm;
				complete_message_with_header(client->conn_fd, &header, &rm);
				download_rm(client, &rm);
				return 0;
			case CSIEBOX_PROTOCOL_OP_SYNC_END:
				fprintf(stderr, ">>> download end\n");
				char buffer[EVENT_BUF_LEN];
				while(read(client->inotify_fd, buffer, EVENT_BUF_LEN) == EVENT_BUF_LEN);
				return 1;
			default : 
				fprintf(stderr, "========== unknown op: %x\n", header.res.op);
				return 1;
		}
	}
	return 1;
}

static int download_meta(csiebox_client *client, csiebox_protocol_meta *meta)
{
	// receive relative path
	char rpath[PATH_MAX];
	recv_message(client->conn_fd, rpath, PATH_MAX);
	char path[PATH_MAX];
	sprintf(path, "%s/%s", client->arg.path, rpath);
	// check if exist
	struct stat fs;
	int exist = lstat(path, &fs);
	int need_data = 0;
	// if exist, sync time, chmod, chown
	if (exist != -1) {
		struct utimbuf stime;
		memset(&stime, 0, sizeof(stime));
		stime.actime = meta->message.body.stat.st_atime;
		stime.modtime = meta->message.body.stat.st_mtime;
		utime(path, &stime);
		fprintf(stderr, "file exist: path= %s\n", path);
		if (S_ISREG(fs.st_mode)) need_data = 1;
	} else {
		need_data = 1;
		fprintf(stderr, "file not exist: path= %s\n", path);
	}
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	header.req.status = (need_data)? CSIEBOX_PROTOCOL_STATUS_MORE : CSIEBOX_PROTOCOL_STATUS_OK;
	send_message(client->conn_fd, &header, sizeof(header));
	return 1;
}

#define BUFSIZE 1025
static int download_file(csiebox_client *client, csiebox_protocol_file *file)
{
	// receive path
	char rpath[PATH_MAX];
	recv_message(client->conn_fd, rpath, PATH_MAX);
	char path[PATH_MAX];
	sprintf(path, "%s/%s", client->arg.path, rpath);
	// receive status
	struct stat fs;
	memset(&fs, 0, sizeof(fs));
	recv_message(client->conn_fd, &fs, sizeof(fs));
	
	// is dir, need add inotify
	if (S_ISDIR(fs.st_mode)) {
		mkdir(path, fs.st_mode);
		add_inotify(client, path);
	}
	// if reg
	else if (S_ISREG(fs.st_mode)) { 
		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, fs.st_mode);
		int readlen = 0;
		char buffer[BUFSIZE];
		while (1) {
			memset(buffer, 0, BUFSIZE);
			recv_message(client->conn_fd, &buffer, BUFSIZE-1);
			write(fd, buffer, strlen(buffer));
			if (strlen(buffer) < BUFSIZE-1) break;
		}
		close(fd);
	} else {
		fprintf(stderr, "invalid file type\n");
		return 0;
	}
	// sync time, chmod, chown
	chmod(path, fs.st_mode);
	chown(path, fs.st_uid, fs.st_gid);
	struct utimbuf stime;
	memset(&stime, 0, sizeof(stime));
	stime.actime = fs.st_atime;
	stime.modtime = fs.st_mtime;
	utime(path, &stime);
	// send back message
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
	header.req.status = CSIEBOX_PROTOCOL_STATUS_OK;
	send_message(client->conn_fd, &header, sizeof(header));
	return 1;
}

static int download_rm(csiebox_client *client, csiebox_protocol_rm *rm)
{
	// receive relative path
	char rpath[PATH_MAX];
	recv_message(client->conn_fd, rpath, PATH_MAX);
	char path[PATH_MAX];
	sprintf(path, "%s/%s", client->arg.path, rpath);
	fprintf(stderr, "path= %s\n", path);
	// check is dir/reg
	struct stat fs;
	memset(&fs, 0, sizeof(fs));
	lstat(path, &fs);
	if (S_ISDIR(fs.st_mode)) {
		// remove inotify
		int wd = get_from_hash_by_path(&(client->inotify_hash), (void*)path, 0);
		inotify_rm_watch(client->inotify_fd, wd);
		char *tmp = NULL;
		del_from_hash(&(client->inotify_hash), (void**)&tmp, wd);
		free(tmp);
		rmdir(path);
	} else if (S_ISREG(fs.st_mode)) unlink(path);
	// send back message to server
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	header.req.op = CSIEBOX_PROTOCOL_OP_RM;
	header.req.status = CSIEBOX_PROTOCOL_STATUS_OK;
	send_message(client->conn_fd, &header, sizeof(header));
	return 1;
}

/*************************************/

static int parse_arg(csiebox_client* client, int argc, char** argv) {
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
	int accept_config_total = 5;
	int accept_config[5] = {0, 0, 0, 0, 0};
	while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
		key[keylen] = '\0';
		vallen = getline(&val, &valsize, file) - 1;
		val[vallen] = '\0';
		fprintf(stderr, "config (%zd, %s)=(%zd, %s)\n", keylen, key, vallen, val);
		if (strcmp("name", key) == 0) {
			if (vallen <= sizeof(client->arg.name)) {
				strncpy(client->arg.name, val, vallen);
				accept_config[0] = 1;
			}
		} else if (strcmp("server", key) == 0) {
			if (vallen <= sizeof(client->arg.server)) {
				strncpy(client->arg.server, val, vallen);
				accept_config[1] = 1;
			}
		} else if (strcmp("user", key) == 0) {
			if (vallen <= sizeof(client->arg.user)) {
				strncpy(client->arg.user, val, vallen);
				accept_config[2] = 1;
			}
		} else if (strcmp("passwd", key) == 0) {
			if (vallen <= sizeof(client->arg.passwd)) {
				strncpy(client->arg.passwd, val, vallen);
				accept_config[3] = 1;
			}
		} else if (strcmp("path", key) == 0) {
			if (vallen <= sizeof(client->arg.path)) {
				strncpy(client->arg.path, val, vallen);
				accept_config[4] = 1;
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

static int login(csiebox_client* client) {
	csiebox_protocol_login req;
	memset(&req, 0, sizeof(req));
	req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	req.message.header.req.op = CSIEBOX_PROTOCOL_OP_LOGIN;
	req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
	memcpy(req.message.body.user, client->arg.user, strlen(client->arg.user));
	md5(client->arg.passwd,
			strlen(client->arg.passwd),
			req.message.body.passwd_hash);
	if (!send_message(client->conn_fd, &req, sizeof(req))) {
		fprintf(stderr, "send fail\n");
		return 0;
	}
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	if (recv_message(client->conn_fd, &header, sizeof(header))) {
		if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
				header.res.op == CSIEBOX_PROTOCOL_OP_LOGIN &&
				header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) {
			client->client_id = header.res.client_id;
			return 1;
		} else {
			return 0;
		}
	}
	return 0;
}

static int prepare_and_sync(csiebox_client* client) {
	char* cwd = (char*)malloc(sizeof(char) * PATH_MAX);
	memset(cwd, 0, sizeof(cwd));
	if (getcwd(cwd, PATH_MAX) == 0) {
		fprintf(stderr, "getcwd fail\n");
		fprintf(stderr, "code: %s\n", strerror(errno));
		free(cwd);
		return 0;
	}
	if (chdir(client->arg.path) != 0) {
		fprintf(stderr, "invalid client path\n");
		free(cwd);
		return 0;
	}
	max_level = 0;
	char* longest_path = (char*)malloc(sizeof(char) * PATH_MAX);
	sync_all(client, longest_path, 0);
	// create longestPath.txt
	FILE *fp = fopen("longestPath.txt", "w+");
	int i = 0, len = strlen(longest_path);
	for (; i<len-1; i++) {
		longest_path[i] = longest_path[i+1]; 
	}
	longest_path[len-1] = 0;
	fwrite(longest_path, 1, strlen(longest_path), fp);
	fclose(fp);
	free(longest_path);
	handle_inotify(client);
	// send sync end message
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_END;
	header.req.client_id = client->client_id;
	send_message(client->conn_fd, &header, sizeof(header));
	chdir(cwd);
	free(cwd);
	return 1;
}

static void sync_all(csiebox_client* client, char* longest_path, int level) {
	char* cwd = (char*)malloc(sizeof(char) * PATH_MAX);
	memset(cwd, 0, sizeof(char) * PATH_MAX);
	if (getcwd(cwd, PATH_MAX) == 0) {
		fprintf(stderr, "getcwd fail\n");
	}
	add_inotify(client, cwd);
	DIR* dir;
	struct dirent* file;
	struct stat file_stat;
	dir = opendir(".");
	while ((file = readdir(dir)) != NULL) {
		if (strcmp(file->d_name, ".") == 0 ||
				strcmp(file->d_name, "..") == 0) {
			continue;
		}
		lstat(file->d_name, &file_stat); 
		sync_file(client, file->d_name);
		if ((file_stat.st_mode & S_IFMT) == S_IFDIR) {
			level++;
			if (level > max_level){
				max_level = level;
				strcpy(longest_path, convert_to_relative_path(client, file->d_name));
			}
			if (chdir(file->d_name) != 0) {
				fprintf(stderr, "bad dir %s\n", file->d_name);
				continue;
			}
			sync_all(client, longest_path, level);
			chdir(cwd);
		}
	}
	closedir(dir);
	free(cwd);
	return;
}

static void sync_file(csiebox_client* client, char* path) {
	csiebox_protocol_status status;
	status = sync_file_meta(client, path);
	if (status == CSIEBOX_PROTOCOL_STATUS_MORE) {
		sync_file_data(client, path);
	}
}

static csiebox_protocol_status sync_file_meta(csiebox_client* client, char* path) {
	char* relative = convert_to_relative_path(client, path);
	if (!relative) {
		fprintf(stderr, "convert relative fail: %s\n", path);
		return CSIEBOX_PROTOCOL_STATUS_FAIL;
	}
	csiebox_protocol_meta meta;
	memset(&meta, 0, sizeof(meta));
	meta.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	meta.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	meta.message.header.req.client_id = client->client_id;
	meta.message.header.req.datalen = sizeof(meta) - sizeof(csiebox_protocol_header);
	meta.message.body.pathlen = strlen(relative);
	lstat(path, &(meta.message.body.stat));
	if ((meta.message.body.stat.st_mode & S_IFMT) == S_IFDIR) {
	} else {
		md5_file(path, meta.message.body.hash);
	}
	send_message(client->conn_fd, &meta, sizeof(meta));
	send_message(client->conn_fd, relative, strlen(relative));
	free(relative);

	csiebox_protocol_header header;
	recv_message(client->conn_fd, &header, sizeof(header));
	if (header.res.status == CSIEBOX_PROTOCOL_STATUS_FAIL) {
		fprintf(stderr, "sync meta fail: %s\n", path);
		return;
	}
	return header.res.status;
}

static void sync_file_data(
		csiebox_client* client, char* path) {
	fprintf(stderr, "file_data: %s\t", path);
	struct stat stat;
	memset(&stat, 0, sizeof(stat));
	lstat(path, &stat);
	csiebox_protocol_file file;
	memset(&file, 0, sizeof(file));
	file.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	file.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
	file.message.header.req.client_id = client->client_id;
	file.message.header.req.datalen = sizeof(file) - sizeof(csiebox_protocol_header);
	if ((stat.st_mode & S_IFMT) == S_IFDIR) {
		file.message.body.datalen = 0;
		fprintf(stderr, "dir, datalen: %zu\n", file.message.body.datalen);
		send_message(client->conn_fd, &file, sizeof(file));
	} else {
		int fd = open(path, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "open fail\n");
			file.message.body.datalen = 0;
			send_message(client->conn_fd, &file, sizeof(file));
		} else {
			file.message.body.datalen = lseek(fd, 0, SEEK_END);
			fprintf(stderr, "reg, datalen: %zd\n", file.message.body.datalen);
			send_message(client->conn_fd, &file, sizeof(file));
			lseek(fd, 0, SEEK_SET);
			char buf[4096];
			memset(buf, 0, 4096);
			size_t readlen;
			while ((readlen = read(fd, buf, 4096)) > 0) {
				send_message(client->conn_fd, buf, readlen);
			}
			close(fd);
		}
	}

	csiebox_protocol_header header;
	recv_message(client->conn_fd, &header, sizeof(header));
	if (header.res.status != CSIEBOX_PROTOCOL_STATUS_OK) {
		fprintf(stderr, "sync data fail: %s\n", path);
	}
}

static char* convert_to_relative_path(csiebox_client* client, const char* path) {
	char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
	if (path[0] == '/') {
		strcpy(ret, path);
	} else {
		char dir[PATH_MAX];
		memset(dir, 0, PATH_MAX);
		getcwd(dir, PATH_MAX);
		sprintf(ret, "%s/%s", dir, path);
	}
	if (strncmp(client->root, ret, strlen(client->root)) != 0) {
		free(ret);
		return NULL;
	}
	size_t rootlen = strlen(client->root);
	size_t retlen = strlen(ret);
	size_t i;
	for (i = 0; i < retlen; ++i) {
		if (i < rootlen) {
			ret[i] = ret[i + rootlen];
		} else {
			ret[i] = 0;
		}
	}
	return ret;
}

static void monitor_home(csiebox_client* client) {
	fd_set master, readfds;
	FD_ZERO(&master); 
	FD_SET(client->conn_fd, &master);
	FD_SET(client->inotify_fd, &master);
	int maxfd = client->conn_fd;
	if (client->inotify_fd > maxfd) maxfd = client->inotify_fd;
	while (1) {
		memcpy(&readfds, &master, sizeof(fd_set));
		select(maxfd+1, &readfds, NULL, NULL, NULL);
		if (FD_ISSET(client->conn_fd, &readfds)) download(client);
		if (FD_ISSET(client->inotify_fd, &readfds)) handle_inotify(client);
	}
}

static void rm_file(csiebox_client* client, char* path, int is_dir) {
	char* relative = convert_to_relative_path(client, path);
	if (!relative) {
		fprintf(stderr, "conver relative fail\n");
		return;
	}
	if (is_dir) {
		int wd = get_from_hash_by_path(&(client->inotify_hash), (void*)path, 0);
		inotify_rm_watch(client->inotify_fd, wd);
		char* tmp = NULL;
		del_from_hash(&(client->inotify_hash), (void**)&tmp, wd);
		free(tmp);
	}
	csiebox_protocol_rm rm;
	memset(&rm, 0, sizeof(rm));
	rm.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	rm.message.header.req.op = CSIEBOX_PROTOCOL_OP_RM;
	rm.message.header.req.client_id = client->client_id;
	rm.message.header.req.datalen = sizeof(rm) - sizeof(csiebox_protocol_header);
	rm.message.body.pathlen = strlen(relative);
	send_message(client->conn_fd, &rm, sizeof(rm));
	send_message(client->conn_fd, relative, strlen(relative));
	csiebox_protocol_header header;
	recv_message(client->conn_fd, &header, sizeof(header));
	if (header.res.status != CSIEBOX_PROTOCOL_STATUS_OK) {
		fprintf(stderr, "rm fail: %s\n", path);
	}
	free(relative);
}

static void add_inotify(csiebox_client* client, char* path) {
	int wd = inotify_add_watch(client->inotify_fd, path, IN_FLAG);
	char* inotify_path = (char*)malloc(sizeof(char) * strlen(path)+1);
	memset(inotify_path, 0, strlen(path)+1);
	memcpy(inotify_path, path, strlen(path));
	put_into_hash(&(client->inotify_hash), (void*)inotify_path, wd);
}

static void handle_inotify(csiebox_client* client) {
	int len = 0, i = 0;
	char buffer[EVENT_BUF_LEN];
	memset(buffer, 0, EVENT_BUF_LEN);

	if ((len = read(client->inotify_fd, buffer, EVENT_BUF_LEN)) <= 0) {
		return;
	}

	i = 0;
	while (i < len) {
		struct inotify_event* event = (struct inotify_event*)&buffer[i];
		char path[PATH_MAX];
		memset(path, 0, PATH_MAX);
		char* wd_path;
		if (!get_from_hash(&(client->inotify_hash), (void**)&wd_path, event->wd)) {
			continue;
		}
		sprintf(path, "%s/", wd_path);
		strncat(path, event->name, event->len);
		fprintf(stderr, ">>> event wd = %d\n", event->wd);
		if (event->mask & IN_CREATE) {
			fprintf(stderr, "type: create\n");
			fprintf(stderr, "sync file: %s\n", path);
			sync_file(client, path);
			if (event->mask & IN_ISDIR) {
				add_inotify(client, path);
			}
		} else if (event->mask & IN_ATTRIB){
			fprintf(stderr, "type: attrib\n");
			fprintf(stderr, "sync file meta: %s\n", path);
			sync_file_meta(client, path);
		} else if (event->mask & IN_DELETE) {
			fprintf(stderr, "type: delete\n");
			fprintf(stderr, "rm file: %s\n", path);
			rm_file(client, path, event->mask & IN_ISDIR);
		} else {
			fprintf(stderr, "type: modify\n");
			fprintf(stderr, "sync file: %s\n", path);
			sync_file(client, path);
		}
		i += EVENT_SIZE + event->len;
	}
	memset(buffer, 0, EVENT_BUF_LEN);
}

