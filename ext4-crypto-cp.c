/*
 * ext4-crypto-cp-md.c
 *
 * Test program to test the new crypto metadata backup/restore ioctl's
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

typedef unsigned long u32;
typedef signed long s32;

struct ext4_encrypted_metadata {
	s32 fd;			/* Only used by EXT4_IOC_SET_ENCRYPTED_FILENAME */
	u32 len;
	unsigned char *data;
};

#ifndef EXT4_IOC_GET_ENCRYPTION_METADATA
#define EXT4_IOC_GET_ENCRYPTION_METADATA _IOWR('f', 22, struct ext4_encrypted_metadata)
#endif
#ifndef EXT4_IOC_SET_ENCRYPTION_METADATA
#define EXT4_IOC_SET_ENCRYPTION_METADATA _IOR('f', 23, struct ext4_encrypted_metadata)
#endif
#ifndef EXT4_IOC_GET_ENCRYPTED_FILENAME
#define EXT4_IOC_GET_ENCRYPTED_FILENAME	_IOWR('f', 24, struct ext4_encrypted_metadata)
#endif
#ifndef EXT4_IOC_SET_ENCRYPTED_FILENAME
#define EXT4_IOC_SET_ENCRYPTED_FILENAME	_IOR('f', 25, struct ext4_encrypted_metadata)
#endif
#ifndef EXT4_ENCRYPT_FL
#define EXT4_ENCRYPT_FL			0x00000800 /* encrypted file */
#endif

#define DEFAULT_BLOCK_SIZE 4096
#define BUFFER_SIZE 32768
#define MDATA_BUFSIZE 512

/* Assumes b is a power of two */
#define ROUND_UP(a, b) (((a) + (b) - 1) & ~((b) - 1))

const char *progname;

void print_mdata(const char *s, struct ext4_encrypted_metadata *mdata)
{
	int i;

	printf("%s len %lu: \n", s, mdata->len);
	for (i = 0; i < mdata->len; i++)
		printf("%02x ", mdata->data[i] & 0xFF);
	printf("\n");
}

static void copy_data(int src, int dest)
{
	off_t start_data, start_hole, cur = 0;
	off_t len, full_len, actual;
	void *ptr, *buf;

	printf("Copying data...\n");
	if (posix_memalign(&buf, BUFFER_SIZE, DEFAULT_BLOCK_SIZE) != 0) {
		printf("posix_memalign failed!\n");
		exit(1);
	}

	while (1) {
		start_data = lseek(src, cur, SEEK_DATA);
		if (start_data == (off_t) -1) {
			if (errno == ENXIO)
				break;
			perror("SEEK_DATA");
			break;
		}
		start_hole = lseek(src, start_data, SEEK_HOLE);
		if (start_hole == (off_t) -1) {
			perror("SEEK_DATA");
			break;
		}
		len = start_hole - start_data;
		full_len = ROUND_UP(len, DEFAULT_BLOCK_SIZE);
		printf("start_data %d start_hole %d len %d full len %d\n",
		       (int) start_data, (int) start_hole, (int) len,
		       (int) full_len);
		if (len > BUFFER_SIZE)
			len = BUFFER_SIZE;
		if (lseek(src, start_data, SEEK_SET) == (off_t) -1) {
			perror("SEEK_SET src");
			break;
		}
		for (actual = 0, ptr = buf; actual < len;) {
			int n;

			printf("doing read(len %lu)\n", full_len - actual);
			n = read(src, ptr, full_len - actual);
			if (n < 0) {
				if ((errno == EAGAIN) || (errno == EINTR))
					continue;
				perror("read");
				break;
			}
			actual += n;
		}
		if (lseek(dest, start_data, SEEK_SET) == (off_t) -1) {
			perror("SEEK_SET dest");
			break;
		}
		for (actual = 0, ptr = buf; actual < full_len;) {
			int n;

			printf("doing write(len %lu)\n", full_len - actual);
			n = write(dest, ptr, full_len - actual);
			if (n < 0) {
				if ((errno == EAGAIN) || (errno == EINTR))
					continue;
				perror("write");
				break;
			}
			actual += n;
		}
		cur = start_hole;
	}
}

int is_directory(const char *file)
{
	struct stat st;

	if (stat(file, &st) < 0)
		return (errno == ENOENT) ? 0 : -1;
	return S_ISDIR(st.st_mode) ? 1 : 0;
}

/*
 * Return the absolute pathname of the parent directory.  The last
 * component in the pathname does not need to exist.  This function
 * requires the POSIX.1-2008 behavior of realpath().
 */
char *get_parent(const char *file)
{
	char *cp, *tmp, *ret;

	ret = realpath(file, NULL);
	if (ret) {
		cp = strrchr(ret, '/');
		if (cp && cp != ret)
			*cp = '\0';
		return ret;
	}
	if (!ret && errno != ENOENT)
		return NULL;

	cp = strrchr(file, '/');
	if (!cp)
		return realpath(".", NULL);

	tmp = strdup(file);
	if (!tmp)
		return NULL;

	cp = strrchr(tmp, '/');
	if (!cp)
		abort();	/* Should never happen */
	if (cp == tmp)
		cp++;
	*cp = 0;

	ret = realpath(tmp, NULL);
	free(tmp);
	return ret;
}

#if 0
int is_parent_encrypted(const char *file)
{
	int ret = -1;
	char *parent;

	parent = get_parent(file);
	if (parent)
		ret = is_encrypted(parent);
	else
		errno = ENOMEM;
	free(parent);
	return ret;
}
#endif

int is_encrypted(const char *file)
{
	int	fd, ret, f;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return fd;
	ret = ioctl(fd, FS_IOC_GETFLAGS, &f);
	if (ret >= 0)
		ret = (f & EXT4_ENCRYPT_FL) ? 1 : 0;
	close(fd);
	return ret;
}

char *get_cwd(void)
{
	char *ret;
	int len = PATH_MAX;

retry:
	ret = malloc(len);
	errno = ENOMEM;
	if (!ret)
		return NULL;
	getcwd(ret, len);
	if (!ret && (errno = ERANGE)) {
		len = len << 1;
		goto retry;
	}
	return ret;
}

/*
 * Return the first parent directory that is unencrypted.  With any
 * luck this should be in the same file system as the given file,
 * since we don't allow for encrypted root directories (yet).
 */
char *get_unencrypted_topdir(const char *file)
{
	char *parent = NULL, *cp;

	if (strchr(file, '/')) {
		parent = malloc(strlen(file) + 1);
		if (!parent) {
			errno = ENOMEM;
			return NULL;
		}
		strcpy(parent, file);
	}
	while (1) {
		if (!parent || ((cp = strrchr(parent, '/')) == NULL)) {
			free(parent);
			parent = get_cwd();
			cp = strrchr(parent, '/');
			if (cp == NULL) {
				fprintf(stderr,
					"get_cwd returned %s w/o slash?!?\n",
					parent);
				abort();
			}
		}
		if (cp == parent)
			return parent;
		if (!is_encrypted(parent))
			break;
		*cp = '\0';
	}
	return parent;
}

#define GET_FD_INFO_DIRECTORY		0x0001
#define GET_FD_INFO_ENCRYPTED		0x0002
#define GET_FD_INFO_PARENT_ENCRYPTED	0x0004

/*
 * Open the requested file, doing the appropriate error checking
 */
static int get_fd(const char *filename, int open_flags, int perms,
		  int *ret_info)
{
	int ret, isdir, fd, f = 0, info = 0;
	char *parent;

	isdir = is_directory(filename);
	if (isdir) {
		info = GET_FD_INFO_DIRECTORY;
		open_flags = O_DIRECTORY;
	}
	fd = open(filename, open_flags, perms);
	if (fd < 0) {
		perror("filename");
		exit(1);
	}
	ret = ioctl(fd, FS_IOC_GETFLAGS, &f);
	if (ret >= 0 && (f & EXT4_ENCRYPT_FL))
		info |= GET_FD_INFO_ENCRYPTED;
	parent = get_parent(filename);
	if (is_encrypted(parent))
		info |= GET_FD_INFO_PARENT_ENCRYPTED;
	free(parent);
	if (ret_info)
		*ret_info = info;
	return fd;
}
		  
static void usage(void)
{
	fprintf(stderr, "Usage: %s source [destination] [destdir]\n",
		progname);
	exit(1);
}

int main(int argc, char **argv)
{
	struct ext4_encrypted_metadata	f_mdata, fn_mdata;
	unsigned char			f_mdata_buf[MDATA_BUFSIZE];
	unsigned char			fn_mdata_buf[MDATA_BUFSIZE];
	char				*topdir, *tmpfn;
	int				s_fd, d_fd = -1, tmp_fd = -1;
	int				s_info, d_info, f;
	progname = argv[0];
	
#if 0
	char *parent, *topdir;
	parent = get_parent(argv[1]);
	if (parent)
		printf("parent: %s\n", parent);
	else
		perror(argv[1]);
	topdir = get_unencrypted_topdir(argv[1]);
	if (topdir)
		printf("topdir: %s\n", topdir);
	else
		perror(argv[1]);
	s_fd = get_fd(argv[1], O_RDONLY, 0, &s_info);
	printf("get_fd %d %d\n", s_fd, s_info);
	exit(0);
#endif

	if (argc < 2 || argc > 4) {
		usage();
	}
	s_fd = get_fd(argv[1], O_RDONLY | O_DIRECT, 0, &s_info);
	if (!(s_info & GET_FD_INFO_ENCRYPTED)) {
		fprintf(stderr, "source file/directory %s not encrypted!\n",
			argv[1]);
		exit(1);
	}
	f_mdata.len = MDATA_BUFSIZE;
	f_mdata.fd = -1;
	f_mdata.data = f_mdata_buf;
	if (ioctl(s_fd, EXT4_IOC_GET_ENCRYPTION_METADATA, &f_mdata)) {
		perror("EXT4_IOC_GET_ENCRYPTION_METADATA");
		exit(1);
	}
	print_mdata("source file", &f_mdata);

	if (s_info & GET_FD_INFO_PARENT_ENCRYPTED) {
		fn_mdata.len = MDATA_BUFSIZE;
		fn_mdata.fd = -1;
		fn_mdata.data = fn_mdata_buf;
		if (ioctl(s_fd, EXT4_IOC_GET_ENCRYPTED_FILENAME, &fn_mdata)) {
			perror("EXT4_IOC_GET_ENCRYPTED_FILENAME");
			exit(1);
		}
		print_mdata("source filename", &fn_mdata);
	} else
		fn_mdata.len = 0;
	if (argc == 2)
		exit(0);
	
	d_fd = get_fd(argv[2],
		      O_CREAT | O_TRUNC | O_DIRECT | O_WRONLY | O_DIRECT,
		      0644, &d_info);
	if ((d_info & GET_FD_INFO_DIRECTORY) == 0) {
		if (s_info & GET_FD_INFO_DIRECTORY) {
			fprintf(stderr, "Source is a directory, destination "
				"must also be a directory\n");
			exit(1);
		}
		copy_data(s_fd, d_fd);
	copy_encryption_metadata:
		if (ioctl(d_fd, EXT4_IOC_SET_ENCRYPTION_METADATA, &f_mdata)) {
			perror("EXT4_IOC_SET_ENCRYPTION_METADATA");
			exit(1);
		}
		exit(0);
	}
	/* destination is a directory */
	if (s_info & GET_FD_INFO_DIRECTORY) {
		/* source is a directory */
		if (fn_mdata.len == 0)
			/*
			 * source's parent is not encrypted, so copy
			 * encryption metadata to destination directory
			 */
			goto copy_encryption_metadata;
		/* 
		 * source's parent is encrypted -- this means source's
		 * filename is encrypted
		 */
		if (d_info & GET_FD_INFO_PARENT_ENCRYPTED) {
			fprintf(stderr, "Destination directory is not "
				"encrypted but source's filename is "
				"encrypted\n");
			exit(1);
		}
		if (ioctl(d_fd, EXT4_IOC_SET_ENCRYPTED_FILENAME, &fn_mdata)) {
			perror("EXT4_IOC_SET_ENCRYPTED_FILENAME");
			exit(1);
		}
		exit(0);
	}
	/* source is a regular file */
	topdir = get_unencrypted_topdir(argv[1]);
	tmpfn = malloc(strlen(topdir)+12);
	if (!tmpfn) {
		fprintf(stderr, "malloc failed for tmpfn!\n");
		exit(1);
	}
	sprintf(tmpfn, "%s/tmp.XXXXXX", topdir);
	tmp_fd = mkstemp(tmpfn);
	if (tmp_fd < 0) {
		perror("mkstemp");
		exit(1);
	}
	f = fcntl(tmp_fd, F_GETFL);
	if (f == -1) {
		perror("fcntl F_GETFL");
		exit(1);
	}
	f = fcntl(tmp_fd, F_SETFL, f | O_DIRECT);
	if (f == -1) {
		perror("fcntl F_SETFL");
		exit(1);
	}
	copy_data(s_fd, tmp_fd);
	if (ioctl(tmp_fd, EXT4_IOC_SET_ENCRYPTION_METADATA, &f_mdata)) {
		perror("EXT4_IOC_SET_ENCRYPTION_METADATA");
		exit(1);
	}
	fn_mdata.fd = tmp_fd;
	if (ioctl(d_fd, EXT4_IOC_SET_ENCRYPTED_FILENAME, &fn_mdata)) {
		perror("EXT4_IOC_SET_ENCRYPTED_FILENAME");
	}
	if (unlink(tmpfn) < 0) {
		perror("unlink");
		exit(1);
	}
	close(tmp_fd);
	return 0;
}
