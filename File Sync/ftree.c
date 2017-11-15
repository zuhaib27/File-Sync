#include <stdio.h> //u
#include <stdlib.h> //u
#include <unistd.h>
#include <string.h> //u
#include <dirent.h> //u
#include <libgen.h> //u
#include <sys/types.h> //u
#include <sys/wait.h> //u
#include <errno.h>//u
#include <signal.h> //u
#include <sys/stat.h> //u
#include <sys/socket.h> //u
#include <netinet/in.h>
#include <arpa/inet.h> //u
#include "ftree.h" //u
#include <fcntl.h> //u


#define TYPE_DIRECTORY 0
#define TYPE_REGULAR 1
#define TYPE_UNREGULATED -1
#define MAX_BACKLOG 50

#define MAX_CONNECTIONS 500


struct sockID{
	size_t file_bytes_read;
	int sock_fd;
	int client_type;
	int read_stage;
	struct fileinfo file_info;
};

char *get_cd_fname(const char *file_path, ino_t file_ino){
	struct stat file_stat;
	if(lstat(file_path, &file_stat) == -1){
		perror("client: lstat @ get_cd_fname");
		return NULL;
	}
	char file_path_copy[MAXPATH];
    char *file_name, *relative_fname;

	file_name = NULL;
	strcpy(file_path_copy, file_path);
	relative_fname = basename(file_path_copy);

	if(strcmp(relative_fname, ".") == 0 || strcmp(relative_fname, "..") == 0){
		struct stat pfile_stat;
	    //get the parent directory of file
		char pfile_path[MAXPATH];
		strcpy(pfile_path, file_path);
		strncat(pfile_path, "/..", 3);

		if(lstat(pfile_path, &pfile_stat) == - 1){
			perror("client: lstat @ get_cd_fname");
	        return NULL;
		}

		DIR *pfile_directory;
		struct dirent *pfile_data;

		if((pfile_directory = opendir(pfile_path)) == NULL){
			perror("client: lstat @ get_cd_fname");
			return NULL;
		}
		int initial_errno = errno;
		//search the parent directory's files for the actual file name of source.
		while((pfile_data = readdir(pfile_directory)) != NULL){
			if(pfile_data->d_ino == file_ino){
				file_name = malloc(sizeof(pfile_data->d_name));
				strcpy(file_name, pfile_data->d_name);
			}
		}

		if(initial_errno != errno){
			perror("client: readdir @ get_cd_fname");
			return NULL;
		}

		if(closedir(pfile_directory) == -1){
			perror("client: closedir @ get_cd_fname");
	        return NULL;
	    }
	}
	else{
		file_name = malloc(strlen(relative_fname));
		strcpy(file_name, relative_fname);
	}
	return file_name;
}

int connect_to_server(int port, char *host_ip, int client_type){
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(sock_fd < 0){
		perror("client: socket @ connect_to_server");
		return -1;
	}

    struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	
	if (inet_pton(AF_INET, host_ip, &server.sin_addr) < 1){
		perror("client: inet_pton @ connect_to_server");
        return -1;
	}

	if (connect(sock_fd, (struct sockaddr *)&server, sizeof(server)) == -1) {
		perror("client: connect @ connect_to_server");
        return -1;
    }

    uint32_t conv_type = htonl(client_type);

    if(write(sock_fd, &conv_type, sizeof(conv_type)) != sizeof(conv_type)){
    	perror("client: write @ connect_to_server");
    	return -1;
    }

    return sock_fd;
}

int send_basic_fileinfo(int sock_fd, const char *destsrc, const char *proper_src_path, int file_type, int file_mode, int file_size){
	if(write(sock_fd, destsrc, MAXPATH) != MAXPATH){
		perror("client: write @ send_basic_fileinfo");
		return -1;
	}
	uint16_t conv_mode = htons(file_mode);
	if(write(sock_fd, &conv_mode, sizeof(uint16_t)) != sizeof(uint16_t)){
		perror("client: write @ send_basic_fileinfo");
		return -1;
	}

	if(file_type == TYPE_REGULAR){
		FILE *file_ptr;

		if((file_ptr = fopen(proper_src_path, "r")) == NULL){
			perror("client: fopen @ send_basic_fileinfo2");
			return -1;
		}
		char *file_hash;
		file_hash = hash(file_ptr);
		char hash_dup[BLOCKSIZE];
		strcpy(hash_dup, file_hash);
		free(file_hash);

		if(fclose(file_ptr) == EOF){
			perror("client: fclose @ send_basic_fileinfo3");
			return -1;
		}
		if(write(sock_fd, hash_dup, BLOCKSIZE) != BLOCKSIZE){
			perror("client: write @ send_basic_fileinfo4");
			return -1;
		}
	}
	else{
		char empty_hash[BLOCKSIZE] = "";
		if(write(sock_fd, empty_hash, BLOCKSIZE) != BLOCKSIZE){
			perror("client: write @ send_basic_fileinfo5");
			return -1;
		}
	}
	uint32_t conv_size = htonl(file_size);
	if(write(sock_fd, &conv_size, sizeof(conv_size)) != sizeof(conv_size)){
		perror("client: write @ send_basic_fileinfo");
		return -1;
	}
	return 0;
}

int receive_feedback(int sock_fd){
	uint32_t server_feedback;
	while(read(sock_fd, &server_feedback, sizeof(server_feedback)) == 0){
	}
	int feed_back = htonl(server_feedback);
	return feed_back;
}

int send_file(int sock_fd, int port, const char *file_path, const char *destsrc, int file_type, char *host_ip){
	struct stat file_stat;
	if(lstat(file_path, &file_stat) == -1){
		perror("client: lstat @ send_file");
		return -1;
	}
	if(file_type == TYPE_REGULAR){
		if(send_basic_fileinfo(sock_fd, destsrc, file_path, TYPE_REGULAR, file_stat.st_mode, (int)file_stat.st_size) == -1){
			return -1;
		}
	}
	else{//DIRECTORY
		if(send_basic_fileinfo(sock_fd, destsrc, file_path, TYPE_DIRECTORY, file_stat.st_mode, (int)file_stat.st_size) == -1){
			return -1;
		}
	}
	int server_feedback = receive_feedback(sock_fd);
	if(server_feedback == -1){
		perror("client: unable to read server feedback");
		return -1;
	}
	if(server_feedback == MISMATCH){
		pid_t pid_result;
		if((pid_result = fork()) == -1){
			perror("client: fork");
			return -1;
		}
		else if(pid_result == 0){
			//close connection of parent in child.
			close(sock_fd);
			//establish a new connection
			int sock_fd = connect_to_server(port, host_ip, SENDER_CLIENT);
			if(send_basic_fileinfo(sock_fd, destsrc, file_path, file_type, file_stat.st_mode, (int)file_stat.st_size) == -1){
				close(sock_fd);
				exit(1);
			}	
			
			if(file_type == TYPE_REGULAR){
				FILE *src_fp;

				if((src_fp = fopen(file_path,"rb")) == NULL){
			        perror("client: fopen on src\n");
			        close(sock_fd);
			        exit(1);
				}

				char src_content[MAXDATA + 1];
				int initial_errno = errno;
				int elements_read;
				while((elements_read = fread(src_content, sizeof(char), MAXDATA, src_fp)) > 0){
					//maybe wait until the data transfered is the size of the file? in the server?
					src_content[elements_read] = '\0';
					if(write(sock_fd, src_content, MAXDATA) < 0){
						perror("client: fwrite on src");
						fclose(src_fp);
						close(sock_fd);
						exit(1);
					}

				}
				if(initial_errno != errno){
					perror("client: fread on src\n");
					close(sock_fd);
					exit(1);
				}
			}
			server_feedback = receive_feedback(sock_fd); //will receive feedback once server reads the whole file, x bytes
			if(server_feedback == -1){
				perror("client: unable to read server feedback");
				close(sock_fd);
				exit(1);
			}
			if(server_feedback == TRANSMIT_OK){
				close(sock_fd);
				exit(0);
			}
			else{
				fprintf(stderr, "client: error occured when sending %s", file_path);
				close(sock_fd);
				exit(1);
			}
		}
		else{
			//wait for children? check the status. if status results in an error, return -1
			int status;
			if(wait(&status) == -1){
				perror("client: wait @ send_file");
				return -1;
			}

			if(WIFEXITED(status)){
				int exit_status = WEXITSTATUS(status);
				if(exit_status == 1){
					return -1;
				}
			}
			else{
				fprintf(stderr, "client: WIFEXITED @ send_file");
				return -1;
			}

		}
	}
	else if(server_feedback == MATCH_ERROR){
		fprintf(stderr, "client: match error");
		return -1;
	}
	return 0;
}

int send_ftree(int sock_fd, int port, const char *proper_src_path, const char *destsrc, char *host_ip){
	struct stat file_stat;

	int error_result = 0;
	if(lstat(proper_src_path, &file_stat) == -1){
		perror("client: lstat");
		return 1;
	}

	if(S_ISREG(file_stat.st_mode)){
		if(send_file(sock_fd, port, proper_src_path, destsrc, TYPE_REGULAR, host_ip) == -1){
			return 1;
		}
	}
	else if(S_ISDIR(file_stat.st_mode)){
		if(send_file(sock_fd, port, proper_src_path, destsrc, TYPE_DIRECTORY, host_ip) == -1){
			return 1;
		}
		DIR *file_directory;
		struct dirent *file_data;
		if((file_directory = opendir(proper_src_path)) == NULL){
			perror("client: opendir");
			return 1;
		}

		int initial_errno = errno;
		char proper_ssrc_path[MAXPATH], new_destsrc[MAXPATH];

		while((file_data = readdir(file_directory)) != NULL){
			if((file_data->d_name)[0] != '.'){
				strcpy(proper_ssrc_path, proper_src_path);
				strncat(proper_ssrc_path, "/", 1);
				strncat(proper_ssrc_path, file_data->d_name, strlen(file_data->d_name));

				strcpy(new_destsrc, destsrc);
				strncat(new_destsrc, "/", 1);
				strncat(new_destsrc, file_data->d_name, strlen(file_data->d_name));
				
				if(send_ftree(sock_fd, port, proper_ssrc_path, new_destsrc, host_ip) == 1){
					error_result = 1;
				} //recurse on every sub file regardless of type (excluding ".*")
			}
		}
		if(initial_errno != errno){
			perror("client: readdir");
			return 1;
		}
		if(closedir(file_directory) == -1){
			perror("client: closedir");
			return 1;
		}
	}
	return error_result;
}

int rcopy_client(char *src_path, char *dest_path, char *host_ip, int port){
	//identify as main client. CHECKER_CLIENT

	if(strcmp(src_path, "") == 0 || strcmp(dest_path, "") == 0){
		return 1;
	}
	struct stat file_stat;
	if(lstat(src_path, &file_stat) == -1){;
		return 1;
	}
	char *file_name, *dir_fname;	

	if((file_name = get_cd_fname(src_path, file_stat.st_ino)) == NULL){
		return 1;
	}

	if((dir_fname = basename(dest_path)) == NULL){
		return 1;
	}

	int sock_fd = connect_to_server(port, host_ip, CHECKER_CLIENT);

	int copy_success = 0;
	char destsrc[MAXPATH];
	strcpy(destsrc, dest_path);
	strncat(destsrc, "/", 1);
	strncat(destsrc, file_name, strlen(file_name));
	if(file_name[0] != '.' && dir_fname[0] != '.'){
    	copy_success = send_ftree(sock_fd, port, src_path, destsrc, host_ip);
    }
   	free(file_name);
   	char dummy_value[] = ".";
   	if(write(sock_fd, dummy_value, sizeof(dummy_value)) == -1){
   		copy_success = 1;
   	}
    close(sock_fd); // how do you know the server closed?
    return copy_success;
}

int accept_connection(int fd, struct sockID *clients){
	int client_index = 0;
	//find the available spot in the possible server clients.
	while(client_index < MAX_CONNECTIONS && clients[client_index].sock_fd != -1){
		client_index++;
	}

    int client_fd = accept(fd, NULL, NULL);
    if (client_fd < 0) {
        perror("server: accept");
        close(fd);
        return client_fd;
    }

    if(client_index == MAX_CONNECTIONS){
    	fprintf(stderr, "server: max concurrent connections");
    	close(client_fd);
    	return client_fd;
    }

    uint32_t client_type;

    if(read(client_fd, &client_type, sizeof(client_type)) == -1){
    	fprintf(stderr, "server: unable to read client type");
    	close(client_fd);
    	return client_fd;
    }

    int conv_type = htonl(client_type);
 
    clients[client_index].sock_fd = client_fd;
    clients[client_index].client_type = conv_type;    
    clients[client_index].read_stage = 0;
    clients[client_index].file_bytes_read = 0;
    return client_fd;
}

int read_from(int index, struct sockID *clients){
	int fd = clients[index].sock_fd;
	int read_stage = clients[index].read_stage;

	struct fileinfo *file_info;
	file_info = &(clients[index].file_info);

	if(read_stage == 0){
		if(read(fd, &(file_info->path), MAXPATH) == -1 || (file_info->path)[0] == '.'){
			clients[index].sock_fd = -1;
			return fd;
		}
		clients[index].read_stage++;
	}
	else if(read_stage == 1){
		uint16_t mode;
		if(read(fd, &mode, sizeof(mode)) == -1){
			clients[index].sock_fd = -1;
			return fd;
		}
		file_info->mode = (mode_t) ntohs(mode);
		clients[index].read_stage++;
	}
	else if(read_stage == 2){
		if(read(fd, &(file_info->hash), BLOCKSIZE) == -1){
			clients[index].sock_fd = -1;
			return fd;
 		}
		clients[index].read_stage++;
	}
	else if(read_stage == 3){
		uint32_t size;
		if(read(fd, &size, sizeof(size)) == -1){
			clients[index].sock_fd = -1;
			return fd;
		}
		file_info->size = (size_t) ntohl(size);

		clients[index].read_stage++;

		int client_type = clients[index].client_type;
		mode_t file_mode = file_info->mode;

		if(client_type == CHECKER_CLIENT){
			struct stat server_file_stat;
			uint32_t match;
			int initial_errno = errno;
			if(lstat(file_info->path, &server_file_stat) == 0){
				if(S_ISREG(file_mode) && S_ISREG(server_file_stat.st_mode)){
					if(file_info->size == server_file_stat.st_size){
						FILE *file_ptr;
						if((file_ptr = fopen(file_info->path, "r")) == NULL){
							match = ntohl(MATCH_ERROR);
							if(write(fd, &match, sizeof(match)) == -1){
								clients[index].sock_fd = -1;
								return fd;
							}
							fprintf(stderr, "server: unable to open file @ read_from");
							clients[index].sock_fd = -1;
							return fd;
						}
						char *file_hash;
						file_hash = hash(file_ptr);

						if(fclose(file_ptr) == EOF){
							match = ntohl(MATCH_ERROR);
							if(write(fd, &match, sizeof(match)) == -1){
								clients[index].sock_fd = -1;
								return fd;
							}
							fprintf(stderr, "server: Unable to close file @ read_from");
							clients[index].sock_fd = -1;
							return fd;
						}

						if(strncmp(file_info->hash, file_hash, BLOCKSIZE) == 0){
							match = ntohl(MATCH);
							if(write(fd, &match, sizeof(match)) == -1){
								clients[index].sock_fd = -1;
								return fd;
							}
							chmod(file_info->path, file_info->mode);
						}
						else{
							match = ntohl(MISMATCH);
							if(write(fd, &match, sizeof(match)) == -1){
								clients[index].sock_fd = -1;
								return fd;
							}
						}
						free(file_hash);
					}
					else{
						match = ntohl(MISMATCH);
						if(write(fd, &match, sizeof(match)) == -1){
							clients[index].sock_fd = -1;
							return fd;
						}
					}
				}
				else if(S_ISDIR(file_mode) && S_ISDIR(server_file_stat.st_mode)){
					match = ntohl(MATCH);
					if(write(fd, &match, sizeof(match)) == -1){
						clients[index].sock_fd = -1;
						return fd;
					}
					chmod(file_info->path, file_info->mode);
				}
				else{
					match = ntohl(MATCH_ERROR);
					if(write(fd, &match, sizeof(match)) == -1){
						clients[index].sock_fd = -1;
						return fd;
					}
					fprintf(stderr, "server: incompatible file types @ read_from");
					clients[index].sock_fd = -1;
					return fd;
				}
			}
			else if(errno == ENOENT){
				char *fpath, *parent_path;
				fpath = strdup(file_info->path);
				parent_path = dirname(fpath);

				struct stat parent_stat;
				errno = initial_errno; // restore errno
				if(lstat(parent_path, &parent_stat) == 0){
					if(S_ISDIR(parent_stat.st_mode)){
						match = ntohl(MISMATCH);
						if(write(fd, &match, sizeof(match)) == -1){
							clients[index].sock_fd = -1;
							return fd;
						} // file doesn't exist
					}
					else{
						match = ntohl(MATCH_ERROR);
						if(write(fd, &match, sizeof(match)) == -1){
							clients[index].sock_fd = -1;
							return fd;
						}
						fprintf(stderr, "server: parent is not a folder");
						clients[index].sock_fd = -1;
						return fd;
					}
				}
				else{
					match = ntohl(MATCH_ERROR);
					if(write(fd, &match, sizeof(match)) == -1){
						clients[index].sock_fd = -1;
						return fd;
					}
					fprintf(stderr, "server: parent folder doesn't exist");
					clients[index].sock_fd = -1;
					return fd;
				}

			}
			else{
				match = ntohl(MATCH_ERROR);
				if(write(fd, &match, sizeof(match)) == -1){
					clients[index].sock_fd = -1;
					return fd;
				}
				perror("server: lstat @ read_from");
				clients[index].sock_fd = -1;
				return fd;
			}
			clients[index].read_stage = 0; //restart
		}
		else{
			uint32_t transmit_result;
			if(S_ISDIR(file_mode)){
				//make directory?
				if(mkdir(file_info->path, file_mode) == -1){
					//transmir error
					transmit_result = ntohl(TRANSMIT_ERROR);
					write(fd, &transmit_result, sizeof(transmit_result));
					clients[index].sock_fd = -1;
					return fd;
				}
				else{
					transmit_result = ntohl(TRANSMIT_OK);
					write(fd, &transmit_result, sizeof(transmit_result));
					clients[index].sock_fd = -1;
					return fd;
				}
			}
			else if(S_ISREG(file_mode)){

				
				FILE *server_file_ptr;

				if((server_file_ptr = fopen(file_info->path, "wb")) == NULL){
					transmit_result = ntohl(TRANSMIT_ERROR);
					write(fd, &transmit_result, sizeof(transmit_result));
					clients[index].sock_fd = -1;
					return fd;
				}
				char file_contents[MAXDATA];
				int bytes_read;
				while(clients[index].file_bytes_read < file_info->size){
					
					if((bytes_read = read(fd, &file_contents, MAXDATA)) == -1){
						transmit_result = ntohl(TRANSMIT_ERROR);
						write(fd, &transmit_result, sizeof(transmit_result));
						clients[index].sock_fd = -1;
						fclose(server_file_ptr);
						return fd;
					}
					clients[index].file_bytes_read += bytes_read;
					
					if(clients[index].file_bytes_read > file_info->size){
						bytes_read -= clients[index].file_bytes_read - file_info->size;
					}
					if(fwrite(file_contents, 1, bytes_read, server_file_ptr) != bytes_read){
						transmit_result = ntohl(TRANSMIT_ERROR);
						write(fd, &transmit_result, sizeof(transmit_result));
						clients[index].sock_fd = -1;
						fclose(server_file_ptr);
						return fd;
					}
				

				}
				if(chmod(file_info->path, file_mode) == -1){
					transmit_result = ntohl(TRANSMIT_ERROR);
					write(fd, &transmit_result, sizeof(transmit_result));
					clients[index].sock_fd = -1;
					fclose(server_file_ptr);
					return fd;
				}
				if(fclose(server_file_ptr) == EOF){
					transmit_result = ntohl(TRANSMIT_ERROR);
					write(fd, &transmit_result, sizeof(transmit_result));
					clients[index].sock_fd = -1;
					return fd;
				}

				transmit_result = ntohl(TRANSMIT_OK);
				write(fd, &transmit_result, sizeof(transmit_result));
				clients[index].sock_fd = - 1;
				return fd;
			}
			else{
				//shouldn't get here
			}

		}
	}

	return 0;
}

void rcopy_server(int port) {
	if(signal(SIGPIPE, SIG_IGN) == SIG_ERR){
		perror("server: signal");
		exit(1);
	}

    struct sockID clientIDs[MAX_CONNECTIONS];
    for (int index = 0; index < MAX_CONNECTIONS; index++) {
    	//initialize future connections
        clientIDs[index].sock_fd = -1;
        clientIDs[index].client_type = -1;
        clientIDs[index].read_stage = 0;
    }

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("server: socket");
        exit(1);
    }

    // Set information about the port (and IP) we want to be connected to.
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = INADDR_ANY;

    // This should always be zero. On some systems, it won't error if you
    // forget, but on others, you'll get mysterious errors. So zero it.
    memset(&server.sin_zero, 0, 8);

    // Bind the selected port to the socket.
    if (bind(sock_fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("server: bind");
        close(sock_fd);
        exit(1);
    }

    // Announce willingness to accept connections on this socket.
    if (listen(sock_fd, MAX_BACKLOG) < 0) {
        perror("server: listen");
        close(sock_fd);
        exit(1);
    }

  	int max_fd = sock_fd;
    fd_set all_fds, listen_fds;
    FD_ZERO(&all_fds);
    FD_SET(sock_fd, &all_fds);

    while (1) {
        // select updates the fd_set it receives, so we always use a copy and retain the original.
        listen_fds = all_fds;
        int nready = select(max_fd + 1, &listen_fds, NULL, NULL, NULL);
        if (nready == -1) {
            perror("server: select");
            exit(1);
        }

        // Is it the original socket? Create a new connection ...
        if (FD_ISSET(sock_fd, &listen_fds)) {
            int client_fd = accept_connection(sock_fd, clientIDs);
            if (client_fd > max_fd) {
                max_fd = client_fd;
            }
            FD_SET(client_fd, &all_fds);
            printf("Accepted connection\n");
        }
        // Next, check the clients.
        // NOTE: We could do some tricks with nready to terminate this loop early.
        for (int index = 0; index < MAX_CONNECTIONS; index++) {
            if (clientIDs[index].sock_fd > -1 && FD_ISSET(clientIDs[index].sock_fd, &listen_fds)) {
                // Note: never reduces max_fd
                int client_closed = read_from(index, clientIDs);
                if (client_closed > 0) {
                	//Free struct fileinfo @ clientsIDs[index].file_info? set to null?
                    FD_CLR(client_closed, &all_fds);
                    close(client_closed);
                    printf("Client %d disconnected\n", client_closed);
                    clientIDs[index].sock_fd = -1;
                
                } 
            }
        }
    }
    exit(1);
}
