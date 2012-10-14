/*
	diskonion - a layered deniable disk encryption scheme
	Copyright (C) 2012 Edward Cree
	
	This library is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this library.  If not, see <http://www.gnu.org/licenses/>.
	
	In addition, as a special exception, the copyright holders give
	permission to link the code of portions of this program with the
	OpenSSL library under certain conditions as described in each
	individual source file, and distribute linked combinations
	including the two.
	
	You must obey the GNU General Public License in all respects
	for all of the code used other than OpenSSL.  If you modify
	file(s) with this exception, you may extend this exception to your
	version of the file(s), but you are not obligated to do so.  If you
	do not wish to do so, delete this exception statement from your
	version.  If you delete this exception statement from all source
	files in the program, then also delete it here.
	
	onionmount.c: mount an onion image with FUSE, presenting data and keystream
*/

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include "crypto.h"
#include "onion.h"

pthread_rwlock_t mx; // image mutex
char *im=NULL; // image map
size_t i_sz; // image size
size_t nblk; // number of blocks (excl. header)
uid_t uid;
gid_t gid;

static int onion_getattr(const char *path, struct stat *st)
{
	memset(st, 0, sizeof(struct stat));
	st->st_uid=uid;
	st->st_gid=gid;
	if(strcmp(path, "/")==0)
	{
		pthread_rwlock_rdlock(&mx);
		st->st_mode=S_IFDIR | S_IRWXU;
		st->st_nlink=2;
		st->st_size=SECTOR_LENGTH;
		pthread_rwlock_unlock(&mx);
		return(0);
	}
	if(strcmp(path, "/data")==0)
	{
		pthread_rwlock_rdlock(&mx);
		st->st_mode=S_IFREG | S_IRUSR | S_IWUSR;
		st->st_nlink=1;
		st->st_size=nblk*SECTOR_LENGTH;
		st->st_blocks=(st->st_size+511)/512;
		st->st_blksize=SECTOR_LENGTH;
		pthread_rwlock_unlock(&mx);
		return(0);
	}
	if(strcmp(path, "/keystream")==0)
	{
		pthread_rwlock_rdlock(&mx);
		st->st_mode=S_IFREG | S_IRUSR | S_IWUSR;
		st->st_nlink=1;
		st->st_size=nblk*IV_LENGTH;
		st->st_blocks=(st->st_size+511)/512;
		st->st_blksize=IV_LENGTH;
		pthread_rwlock_unlock(&mx);
		return(0);
	}
	return(-ENOENT);
}

static int onion_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	if(strcmp(path, "/")==0)
	{
		filler(buf, ".", NULL, 0);
		filler(buf, "..", NULL, 0);
		filler(buf, "data", NULL, 0);
		filler(buf, "keystream", NULL, 0);
		return(0);
	}
	if(strcmp(path, "/data")==0)
		return(-ENOTDIR);
	if(strcmp(path, "/keystream")==0)
		return(-ENOTDIR);
	return(-ENOENT);
}

static int onion_open(const char *path, struct fuse_file_info *fi)
{
	if(fi->flags&O_SYNC) return(-ENOSYS);
	if(fi->flags&O_TRUNC) return(-EACCES);
	if(fi->flags&O_CREAT) return(-EACCES);
	if(strcmp(path, "/")==0)
		return(-EISDIR);
	if(strcmp(path, "/data")==0)
	{
		fi->fh=1;
		return(0);
	}
	if(strcmp(path, "/keystream")==0)
	{
		fi->fh=2;
		return(0);
	}
	return(-ENOENT);
}

static int onion_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	switch(fi->fh)
	{
		case 1: // data
			return(-ENOSYS);
		case 2: // keystream
			return(-ENOSYS);
		default:
			return(-EBADF);
	}
}

static int onion_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	return(-ENOSYS);
}

static struct fuse_operations onion_oper = {
	.getattr	= onion_getattr,
	/*.access		= onion_access,
	.readlink	= onion_readlink,*/
	.readdir	= onion_readdir,
	/*.mknod		= onion_mknod,
	.mkdir		= onion_mkdir,
	.symlink	= onion_symlink,
	.unlink		= onion_unlink,
	.rmdir		= onion_rmdir,
	.rename		= onion_rename,
	.link		= onion_link,
	.chmod		= onion_chmod,
	.chown		= onion_chown,
	.truncate	= onion_truncate,
	.utimens	= onion_utimens,*/
	.open		= onion_open,
	.read		= onion_read,
	.write		= onion_write,
	/*.statfs		= onion_statfs,
	.release	= onion_release,
	.fsync		= onion_fsync,
	.setxattr	= onion_setxattr,
	.getxattr	= onion_getxattr,
	.listxattr	= onion_listxattr,
	.removexattr= onion_removexattr,*/
};

int main(int argc, char *argv[])
{
	if(argc<3)
	{
		fprintf(stderr, "Usage: onionmount <onion-image> <mountpoint> [options]\n");
		return(1);
	}
	uid=geteuid();
	gid=getegid();
	if(pthread_rwlock_init(&mx, NULL))
	{
		perror("onionmount: pthread_rwlock_init");
		return(1);
	}
	const char *img=argv[1];
	struct stat st;
	if(stat(img, &st))
	{
		fprintf(stderr, "onionmount: Failed to stat '%s'\n", img);
		perror("\tstat");
		pthread_rwlock_destroy(&mx);
		return(1);
	}
	i_sz=st.st_size;
	nblk=i_sz/BLOCK_LENGTH-1;
	int fd=open(img, O_RDWR);
	if(fd<0)
	{
		perror("onionmount: open");
		pthread_rwlock_destroy(&mx);
		return(1);
	}
	if(flock(fd, LOCK_EX|LOCK_NB))
	{
		if(errno==EWOULDBLOCK)
		{
			fprintf(stderr, "onionmount: '%s' is locked by another process (flock: EWOULDBLOCK)\n", img);
		}
		else
			perror("onionmount: flock");
		pthread_rwlock_destroy(&mx);
		return(1);
	}
	im=mmap(NULL, i_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, fd, 0);
	if(!im)
	{
		perror("onionmount: mmap");
		flock(fd, LOCK_UN);
		close(fd);
		pthread_rwlock_destroy(&mx);
		return(1);
	}
	fprintf(stderr, "onionmount: '%s' mmap()ed in\n", img);
	
	int rv=EXIT_FAILURE;
	int fargc=argc-1;
	char **fargv=(char **)malloc(fargc*sizeof(char *));
	fargv[0]=argv[0];
	for(int i=1;i<fargc;i++)
		fargv[i]=argv[i+1];
	
	rv=fuse_main(fargc, fargv, &onion_oper, NULL);
	pthread_rwlock_wrlock(&mx);
	munmap(im, i_sz);
	flock(fd, LOCK_UN);
	close(fd);
	pthread_rwlock_unlock(&mx);
	pthread_rwlock_destroy(&mx);
	return(rv);
}
