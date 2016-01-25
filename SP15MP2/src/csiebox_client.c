#include "csiebox_client.h"
#include "csiebox_common.h"
#include "connect.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>			// for traverse
#include <sys/stat.h>		// for lstat
#include <fcntl.h>			// for read, write
#include <sys/inotify.h>	// for inotify
#include <utime.h>

#define DIR_MAX 301
#define INOTIFY_ADD_FLAG ( IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY )
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

typedef struct monitor_structure {/*{{{*/
	int wd;
	char path[PATH_MAX];
} monitor_struct;/*}}}*/

static int parse_arg(csiebox_client* client, int argc, char** argv);
static int login(csiebox_client* client);
static int traverse_dir(csiebox_client *client, char *path, monitor_struct *monitor, int *monitor_no, int inotify_fd);
static int sync_meta(csiebox_client *client, char *path);
static int sync_file(csiebox_client *client, char *path);
static int sync_hardlink(csiebox_client *client, char *path);
static int traverse_hardlink(csiebox_client *client, char *cur_path, char *link_pathm, ino_t ino, nlink_t nlink);
static int sync_rm(csiebox_client *client, char *path);
static int sync_end(csiebox_client *client);
static int monitor_client(csiebox_client *client, monitor_struct *monitor, int inotify_fd, int max_no);
static int find_max_path(csiebox_client *client, monitor_struct *monitor, int *monitor_no);

//read config file, and connect to server
void csiebox_client_init(/*{{{*/
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
  *client = tmp;
}/*}}}*/

//this is where client sends request, you sould write your code here
int csiebox_client_run(csiebox_client* client) {
	// login
	if (!login(client)) {
		fprintf(stderr, "login fail\n");
		return 0;
	}
	fprintf(stderr, "========== login success\n"); 
	// init inotify
	monitor_struct monitor[DIR_MAX];
	memset(monitor, 0, sizeof(monitor_struct) * DIR_MAX);
	int inotify_fd = inotify_init();
	int monitor_no[1];	// count monitor
	monitor_no[0] = 0;
	// traverse directory and create inotify
	if (!traverse_dir(client, client->arg.path, monitor, monitor_no, inotify_fd)){
		fprintf(stderr, "traverse error\n");
		return 0;
	}
	fprintf(stderr, "========== traverse success\n");
	// find longest path
	if (!find_max_path(client, monitor, monitor_no)) {
		fprintf(stderr, "find max path error\n");
		return 0;
	}
	fprintf(stderr, "==========\n\n");
	// send sync end
	sync_end(client);
	// start inotify
	monitor_client(client, monitor, inotify_fd, monitor_no[0]);
	fprintf(stderr, "========== monitor terminate\n");
	return 1;
}

void csiebox_client_destroy(csiebox_client** client) {/*{{{*/
  csiebox_client* tmp = *client;
  *client = 0;
  if (!tmp) {
    return;
  }
  close(tmp->conn_fd);
  free(tmp);
}/*}}}*/

//read config file
static int parse_arg(csiebox_client* client, int argc, char** argv) {/*{{{*/
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
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
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
}/*}}}*/

static int login(csiebox_client* client) /*{{{*/
{
	fprintf(stderr, ">>>>> login\n");
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
}/*}}}*/

static int traverse_dir(csiebox_client *client, char *path, monitor_struct *monitor, int *monitor_no, int inotify_fd)/*{{{*/
{
	// open the directory
	DIR *dir = opendir(path);
	if (dir == NULL) {
		closedir(dir);
		return 0;	
		if (!sync_meta(client, path)){
			fprintf(stderr, "sync_meta fail\n");
			return 0;
		}
	}
	// create monitor
	if (monitor_no[0] <= 300) {
		monitor[monitor_no[0]].wd = inotify_add_watch(inotify_fd, path, INOTIFY_ADD_FLAG);
		strcpy(monitor[monitor_no[0]].path, path);
		fprintf(stderr, "--- add monitor at : %s\n--- monitor no : %d\n", path, monitor_no[0]);
		monitor_no[0]++;
	}
	// read directory
	struct dirent *dir_read;
	while((dir_read = readdir(dir)) != NULL) {
		fprintf(stderr, ">>>>>>>>>> %s\n", dir_read->d_name);
		if (!strcmp(dir_read->d_name, ".") || !strcmp(dir_read->d_name, "..")) continue;
		char sub_path[PATH_MAX];
		strcpy(sub_path, path);
		strcat(sub_path, "/");
		strcat(sub_path, dir_read->d_name);
		traverse_dir(client, sub_path, monitor, monitor_no, inotify_fd);
		if (!sync_meta(client, sub_path)){
			fprintf(stderr, "sync_meta fail\n");
			return 0;
		}
	}	
	closedir(dir);
	return 1;
}/*}}}*/

static int find_max_path(csiebox_client *client, monitor_struct *monitor, int *monitor_no)/*{{{*/
{	
	fprintf(stderr, "monitor list :\n");
	int max = 0;
	int max_no = 0;
	// use "/" to find max path
	for (int i = 0 ; i < monitor_no[0] ; i++) {
		fprintf(stderr, "monitor %d, wd %d, path %s\n", i, monitor[i].wd, monitor[i].path);
		char tmp[PATH_MAX];
		int count = 0;
		strcpy(tmp, monitor[i].path);
		char *pch = strtok(tmp, "/");
		while(pch != NULL) {
			count++;
			if(count > max) {
				max_no = i;
				max = count;
			}
			pch = strtok(NULL, "/");
		}
	}
	// start to create max path string
	int start = 0;
	char temp_max_path[PATH_MAX];
	strcpy(temp_max_path, monitor[max_no].path);
	char max_path[PATH_MAX];
	char *pch = strtok(temp_max_path, "/");
	while (pch != NULL) {
		if (start == 1 || start == 2) {
			strcat(max_path, pch);
			start = 2;
		}
		if (strcmp(pch, "cdir") == 0) start = 1;
		pch = strtok(NULL, "/");
		if (pch != NULL && start == 2) strcat(max_path, "/");
	}
	fprintf(stderr, "max path : %s\n", max_path);
	// create output path
	char lpath_name[PATH_MAX];
	strcpy(lpath_name, client->arg.path);
	strcat(lpath_name, "/");
	strcat(lpath_name, "longestPath.txt");
	// write into file
	int lpath = open(lpath_name, O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU);
	write(lpath, max_path, strlen(max_path));
	close(lpath);
	return 1;
}/*}}}*/

static int sync_meta(csiebox_client *client ,char *path)/*{{{*/
{
	fprintf(stderr, ">>> sync meta\n");
	csiebox_protocol_meta req;
	memset(&req, 0, sizeof(req));
	req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	req.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
	lstat(path, &req.message.body.stat);
	// if is file, hash the content
	if (!S_ISDIR(req.message.body.stat.st_mode)) {
		md5_file(path, req.message.body.hash);
	}
	if (!send_message(client->conn_fd, &req, sizeof(req)) || 
		!send_message(client->conn_fd, path, PATH_MAX)) {
		fprintf(stderr, "send fail\n");
		return 0;
	}

	// receive message from server
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	if (recv_message(client->conn_fd, &header, sizeof(header))) {
		if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES && 
			header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_META) {
			if (header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) {
				fprintf(stderr, "server return OK\n");
				return 1;
			}
			if (header.res.status == CSIEBOX_PROTOCOL_STATUS_MORE) {
				fprintf(stderr, "server return MORE \n");
				sync_file(client, path);
				return 1;
			}
		}
	}
	return 0;
}/*}}}*/

static int sync_file(csiebox_client *client, char *path)/*{{{*/
{
	fprintf(stderr, ">>> sync file\n");
	csiebox_protocol_file req;
	memset(&req, 0, sizeof(req));
	req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	req.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
	req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
	// send req and path
	if (!send_message(client->conn_fd, &req, sizeof(req)) || 
		!send_message(client->conn_fd, path, PATH_MAX)) {
		fprintf(stderr, "sync file : send message fail\n");
		return 0;
	}
	// catagorize file
	struct stat fstatus;
	memset(&fstatus, 0, sizeof(struct stat));
	lstat(path, &fstatus);
	if (S_ISREG(fstatus.st_mode)) {
		int fd = open(path, O_RDONLY);
		while (1) {
			uint8_t buffer[1025];
			memset(buffer, 0, 1025);
			read(fd, buffer, 1024);	
			send_message(client->conn_fd, buffer, 1024);
			if (strlen(buffer) < 1024) break; 
		}
		close(fd);
	}
	if (S_ISLNK(fstatus.st_mode)){
		char actual_path[PATH_MAX];
		memset(&actual_path, 0, PATH_MAX);
		readlink(path, actual_path, PATH_MAX);
		fprintf(stderr, "actual path : %s\n", actual_path);
		send_message(client->conn_fd, actual_path, PATH_MAX);
	}
	// receive message from server
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	if (recv_message(client->conn_fd, &header, sizeof(header))) {
		if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
			header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_FILE &&
			header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) {
			fprintf(stderr, "server return OK\n");
			struct utimbuf meta_time;
			memset(&meta_time, 0, sizeof(meta_time));
			meta_time.actime = fstatus.st_atime;
			meta_time.modtime = fstatus.st_mtime;
			send_message(client->conn_fd, &meta_time, sizeof(meta_time));
			fprintf(stderr, "sync time success\n");
			return 1;
		}
	}
	// check hardlink
	if (S_ISREG(fstatus.st_mode) && fstatus.st_nlink > 1) {
		sync_hardlink(client, path);
	}
	return 0;
}/*}}}*/

static int traverse_hardlink(csiebox_client *client, char *cur_path, char *link_path, ino_t ino, nlink_t nlink)/*{{{*/
{	
	if (nlink == 1) return 1;
	DIR *dir = opendir(cur_path);
	if (dir == NULL) return 0;	
	struct dirent *dir_read;
	while((dir_read = readdir(dir)) != NULL) {
		if (!strcmp(dir_read->d_name, ".") || !strcmp(dir_read->d_name, "..")) continue;
		char sub_path[PATH_MAX];
		strcpy(sub_path, cur_path);
		strcat(sub_path, "/");
		strcat(sub_path, dir_read->d_name);
		
		struct stat target_status;
		memset(&target_status, 0, sizeof(target_status));
		lstat(sub_path, &target_status);
		if (S_ISDIR(target_status.st_mode)) {
			traverse_hardlink(client, sub_path, link_path, ino, nlink);
		}
		if (S_ISREG(target_status.st_mode)) {
			if (ino == target_status.st_ino &&
				strcmp(sub_path, link_path) != 0 && nlink > 1) {
				csiebox_protocol_hardlink req;
				memset(&req, 0, sizeof(req));
				req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
				req.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
				req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
				req.message.body.srclen = strlen(link_path);
				req.message.body.targetlen = strlen(sub_path);
				if (!send_message(client->conn_fd, &req, sizeof(req)) ||
					!send_message(client->conn_fd, link_path, PATH_MAX) ||
					!send_message(client->conn_fd, sub_path, PATH_MAX)){
					fprintf(stderr, "sync hardlink : send error\n");
					return 0;
				}
				fprintf(stderr, "link path :\n\t%s\n\t%s\n", link_path, sub_path);
				// receive message from server
				csiebox_protocol_header header;
				memset(&header, 0, sizeof(header));
				recv_message(client->conn_fd, &header, sizeof(header));
				if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
					header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK &&
					header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) {
					fprintf(stderr, "sync hardlink success\n");
				}
				// utime
				struct stat src_status; memset(&src_status, 0, sizeof(src_status));
				struct utimbuf meta_time;
				memset(&meta_time, 0, sizeof(meta_time));
				meta_time.actime = src_status.st_atime;
				meta_time.modtime = src_status.st_mtime;
				send_message(client->conn_fd, &meta_time, sizeof(meta_time));
				fprintf(stderr, "sync time success\n");

				nlink--;
			}
		}
	}	
	closedir(dir);
	return 1;
}/*}}}*/

static int sync_hardlink(csiebox_client *client, char *path)/*{{{*/
{
	fprintf(stderr, ">>> sync hardlink\n");
	struct stat file_status;
	memset(&file_status, 0, sizeof(file_status));
	lstat(path, &file_status);
	traverse_hardlink(client, client->arg.path, path, file_status.st_ino, file_status.st_nlink);
}/*}}}*/

static int sync_rm(csiebox_client *client, char *path)/*{{{*/
{
	fprintf(stderr, ">>> sync rm\n");	
	csiebox_protocol_rm req;
	memset(&req, 0, sizeof(req));
	req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	req.message.header.req.op = CSIEBOX_PROTOCOL_OP_RM;
	req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
	req.message.body.pathlen = strlen(path);
	if (!send_message(client->conn_fd, &req, sizeof(req)) ||
		!send_message(client->conn_fd, path, PATH_MAX)) {
		fprintf(stderr, "send fail\n");
		return 0;
	}
	// receive message from server
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	if (recv_message(client->conn_fd, &header, sizeof(header))){
		if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
			header.res.op == CSIEBOX_PROTOCOL_OP_RM &&
			header.res.status == CSIEBOX_PROTOCOL_STATUS_OK){
			fprintf(stderr, "server return OK\n");
			return 1;
		}
	}
	return 0;
}/*}}}*/

static int sync_end(csiebox_client *client)/*{{{*/
{
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_END;
	header.req.datalen = 0;
	send_message(client->conn_fd, &header, sizeof(header));
	return 1;
}/*}}}*/

static int monitor_client(csiebox_client *client, monitor_struct *monitor, int inotify_fd, int max_no)/*{{{*/
{
	// init monitor	
	char buffer[BUF_LEN];
	memset(buffer, 0, BUF_LEN);
	int length = 0;
	// start monitor
	while ((length = read(inotify_fd, buffer, BUF_LEN)) > 0) {
		int offset = 0;
		while (offset < length) {
			struct inotify_event *event = (struct inotify_event*)&buffer[offset];
			int no = 0;
			char target_path[PATH_MAX];
			memset(target_path, 0, PATH_MAX);
			// find which monitor
			for (int i = 0 ; i < max_no ; i++) {
				if (monitor[i].wd == event->wd) {
					no = i;
					break;
				}
			}
			if (event->name[0] == '.' || strcmp(event->name, "4913") == 0) {
				offset += (EVENT_SIZE + event->len);
				continue;
			}
			fprintf(stderr, ">>>>>>>>>> event\n");
			fprintf(stderr, "--- monitor no : %d\n", no);
			fprintf(stderr, "--- wd : %d\n--- path : %s\n--- file : %s\n", event->wd, monitor[no].path, event->name);
			if (event->mask & IN_DELETE) {
				strcpy(target_path, monitor[no].path);
				strcat(target_path, "/");
				strcat(target_path, event->name);
				fprintf(stderr, "target path : %s\n", target_path);
				if (event->mask & IN_ISDIR) {
					fprintf(stderr, "delete directory\n");
					// remove monitor
					for (int i = 0 ; i < max_no ; i++) {
						if (strcmp((monitor[i].path), target_path) == 0) {
							inotify_rm_watch(inotify_fd, monitor[i].wd);
							monitor[i].wd = 0;
							memset(monitor[i].path, 0, PATH_MAX);
							fprintf(stderr, "remove monitor success\n");
							break;
						}
					}
				}
				else fprintf(stderr, "delete file\n");
				sync_rm(client, target_path);
			} else {
				if (event->mask & IN_CREATE) fprintf(stderr, "create ");
				if (event->mask & IN_ATTRIB) fprintf(stderr, "modify meta of ");
				if (event->mask & IN_MODIFY) fprintf(stderr, "modify content of ");
				strcpy(target_path, monitor[no].path);
				strcat(target_path, "/");
				strcat(target_path, event->name);
				// is create a new dir
				if ((event->mask & IN_ISDIR) && (event->mask & IN_CREATE)) {
					fprintf(stderr, "directory\n");
					int created = 0;
					for (int i = 0 ; i < max_no ; i++) {
						if (monitor[i].wd == 0) {
							monitor[i].wd = inotify_add_watch(inotify_fd, target_path, INOTIFY_ADD_FLAG);
							strcpy(monitor[i].path, target_path);
							fprintf(stderr, "--- add monitor at : %s\n", target_path);
							fprintf(stderr, "--- monitor no : %d\n", i);
							fprintf(stderr, "--- monitor wd : %d\n", monitor[i].wd);
							created = 1;
							break;
						}
					}
					if (!created && max_no <= 300) {
						monitor[max_no].wd = inotify_add_watch(inotify_fd, target_path, INOTIFY_ADD_FLAG);
						strcpy(monitor[max_no].path, target_path);
						fprintf(stderr, "--- add monitor at : %s\n", target_path);
						fprintf(stderr, "--- monitor no : %d\n", max_no);
						fprintf(stderr, "--- monitor wd : %d\n", monitor[max_no].wd);
						max_no++;
						created = 1;
					}
					if (!created) {
						fprintf(stderr, "--- can't create monitor\n");
						return 0;
					}
				}
				// is create a file, or modify/attrib a file/dir
				else fprintf(stderr, "file/dir\n");
				sync_meta(client, target_path);
			}
			offset += (EVENT_SIZE + event->len);
		}
		memset(buffer, 0, BUF_LEN);
	}
	return 1;
}/*}}}*/
