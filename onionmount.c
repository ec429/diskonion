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
#include <stdbool.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include "crypto.h"
#include "onion.h"
#include "bits.h"

pthread_rwlock_t mx; // image mutex
unsigned char *im=NULL; // image map
size_t i_sz; // image size
size_t nblk; // number of blocks (excl. header)
uid_t uid;
gid_t gid;

struct
{
	size_t key_size, key_len, key_stride;
	unsigned char *key_data; // this is a pointer into im, so reads must acquire rdlock on mx
}
header;

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

static int onion_truncate(const char *path, off_t offset)
{
	return(0); // do nothing, because you can't truncate either file.  But we lie about it, because otherwise editing the files is impossible
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
		{
			size_t blk=offset/SECTOR_LENGTH;
			size_t rb=0;
			pthread_rwlock_rdlock(&mx);
			unsigned char derivedkey[header.key_size];
			unsigned char decodedblk[SECTOR_LENGTH];
			while(rb<size)
			{
				if(blk>=nblk)
					break;
				int e;
				if((e=derive_key(header.key_len, header.key_data, header.key_size, derivedkey, header.key_stride, blk)))
				{
					fprintf(stderr, "Error on block %zu:\n", blk);
					if(e<0) perror("derive_key");
					else fprintf(stderr, "derive_key failed with code %d\n", e);
					pthread_rwlock_unlock(&mx);
					return(-EIO);
				}
				unsigned char *block=im+(blk+1)*BLOCK_LENGTH;
				if((e=decrypt_sector(header.key_size, derivedkey, block, block+IV_LENGTH, decodedblk)))
				{
					fprintf(stderr, "Error on block %zu:\n", blk);
					if(e<0) perror("decrypt_sector");
					else fprintf(stderr, "decrypt_sector failed with code %d\n", e);
					pthread_rwlock_unlock(&mx);
					return(-EIO);
				}
				if(rb)
				{
					size_t left=size-rb;
					if(left>SECTOR_LENGTH) left=SECTOR_LENGTH;
					memcpy(buf+rb, decodedblk, left);
					rb+=left;
				}
				else
				{
					size_t off=offset%SECTOR_LENGTH;
					memcpy(buf, decodedblk+off, SECTOR_LENGTH-off);
					rb=SECTOR_LENGTH-off;
				}
				blk++;
			}
			pthread_rwlock_unlock(&mx);
			return(rb);
		}
		case 2: // keystream
		{
			size_t blk=offset/KS_BLKLEN;
			size_t rb=0;
			unsigned char ks[KS_BLKLEN];
			pthread_rwlock_rdlock(&mx);
			while(rb<size)
			{
				if(blk>=nblk)
					break;
				unsigned char *block=im+(blk+1)*BLOCK_LENGTH;
				int e;
				if((e=decode_keystream(block, ks)))
				{
					fprintf(stderr, "Error on block %zu:\n", blk);
					if(e<0) perror("decode_keystream");
					else fprintf(stderr, "decode_keystream failed with code %d\n", e);
					pthread_rwlock_unlock(&mx);
					return(-EIO);
				}
				if(rb)
				{
					size_t left=size-rb;
					if(left>KS_BLKLEN) left=KS_BLKLEN;
					memcpy(buf+rb, ks, left);
					rb+=left;
				}
				else
				{
					size_t off=offset%KS_BLKLEN;
					memcpy(buf, ks+off, KS_BLKLEN-off);
					rb=KS_BLKLEN-off;
				}
				blk++;
			}
			pthread_rwlock_unlock(&mx);
			return(rb);
		}
		default:
			return(-EBADF);
	}
}

static int onion_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	switch(fi->fh)
	{
		case 1: // data
		{
			size_t blk=offset/SECTOR_LENGTH;
			size_t rb=0;
			pthread_rwlock_wrlock(&mx);
			unsigned char derivedkey[header.key_size];
			unsigned char decodedblk[SECTOR_LENGTH];
			while(rb<size)
			{
				if(blk>=nblk)
					break;
				size_t left=size-rb;
				if(left>SECTOR_LENGTH) left=SECTOR_LENGTH;
				size_t off=offset%SECTOR_LENGTH;
				bool partial_write;
				partial_write=(left<SECTOR_LENGTH)||(off&&!rb);
				unsigned char *block=im+(blk+1)*BLOCK_LENGTH;
				if(partial_write)
				{
					int e;
					if((e=derive_key(header.key_len, header.key_data, header.key_size, derivedkey, header.key_stride, blk)))
					{
						fprintf(stderr, "Error on block %zu:\n", blk);
						if(e<0) perror("derive_key");
						else fprintf(stderr, "derive_key failed with code %d\n", e);
						pthread_rwlock_unlock(&mx);
						return(-EIO);
					}
					if((e=decrypt_sector(header.key_size, derivedkey, block, block+IV_LENGTH, decodedblk)))
					{
						fprintf(stderr, "Error on block %zu:\n", blk);
						if(e<0) perror("decrypt_sector");
						else fprintf(stderr, "decrypt_sector failed with code %d\n", e);
						pthread_rwlock_unlock(&mx);
						return(-EIO);
					}
				}
				if(rb)
				{
					memcpy(decodedblk, buf+rb, left);
					rb+=left;
				}
				else
				{
					size_t bytes=SECTOR_LENGTH-off;
					if(left<bytes) bytes=left;
					memcpy(decodedblk+off, buf, bytes);
					rb=bytes;
				}
				int e;
				if((e=derive_key(header.key_len, header.key_data, header.key_size, derivedkey, header.key_stride, blk)))
				{
					fprintf(stderr, "Error on block %zu:\n", blk);
					if(e<0) perror("derive_key");
					else fprintf(stderr, "derive_key failed with code %d\n", e);
					pthread_rwlock_unlock(&mx);
					return(-EIO);
				}
				if((e=generate_newiv(block, block)))
				{
					fprintf(stderr, "Error on block %zu:\n", blk);
					if(e<0) perror("generate_newiv");
					else fprintf(stderr, "generate_newiv failed with code %d\n", e);
					pthread_rwlock_unlock(&mx);
					return(-EIO);
				}
				if((e=encrypt_sector(header.key_size, derivedkey, block, decodedblk, block+IV_LENGTH)))
				{
					fprintf(stderr, "Error on block %zu:\n", blk);
					if(e<0) perror("encrypt_sector");
					else fprintf(stderr, "encrypt_sector failed with code %d\n", e);
					pthread_rwlock_unlock(&mx);
					return(-EIO);
				}
				blk++;
			}
			pthread_rwlock_unlock(&mx);
			return(rb);
		}
		case 2: // keystream
		{
			size_t blk=offset/KS_BLKLEN;
			size_t rb=0;
			pthread_rwlock_wrlock(&mx);
			unsigned char derivedkey[header.key_size];
			unsigned char decodedblk[SECTOR_LENGTH];
			unsigned char keyblk[KS_BLKLEN];
			while(rb<size)
			{
				if(blk>=nblk)
					break;
				size_t left=size-rb;
				if(left>KS_BLKLEN) left=KS_BLKLEN;
				size_t off=offset%KS_BLKLEN;
				unsigned char *block=im+(blk+1)*BLOCK_LENGTH;
				int e;
				if((e=derive_key(header.key_len, header.key_data, header.key_size, derivedkey, header.key_stride, blk)))
				{
					fprintf(stderr, "Error on block %zu:\n", blk);
					if(e<0) perror("derive_key");
					else fprintf(stderr, "derive_key failed with code %d\n", e);
					pthread_rwlock_unlock(&mx);
					return(-EIO);
				}
				if((e=decrypt_sector(header.key_size, derivedkey, block, block+IV_LENGTH, decodedblk)))
				{
					fprintf(stderr, "Error on block %zu:\n", blk);
					if(e<0) perror("decrypt_sector");
					else fprintf(stderr, "decrypt_sector failed with code %d\n", e);
					pthread_rwlock_unlock(&mx);
					return(-EIO);
				}
				if((e=decode_keystream(block, keyblk)))
				{
					fprintf(stderr, "Error on block %zu:\n", blk);
					if(e<0) perror("decode_keystream");
					else fprintf(stderr, "decode_keystream failed with code %d\n", e);
					pthread_rwlock_unlock(&mx);
					return(-EIO);
				}
				if(rb)
				{
					memcpy(keyblk, buf+rb, left);
					rb+=left;
				}
				else
				{
					size_t bytes=KS_BLKLEN-off;
					if(left<bytes) bytes=left;
					memcpy(keyblk+off, buf, bytes);
					rb=bytes;
				}
				if((e=encode_keystream(keyblk, block)))
				{
					fprintf(stderr, "Error on block %zu:\n", blk);
					if(e<0) perror("encode_keystream");
					else fprintf(stderr, "encode_keystream failed with code %d\n", e);
					pthread_rwlock_unlock(&mx);
					return(-EIO);
				}
				if((e=encrypt_sector(header.key_size, derivedkey, block, decodedblk, block+IV_LENGTH)))
				{
					fprintf(stderr, "Error on block %zu:\n", blk);
					if(e<0) perror("encrypt_sector");
					else fprintf(stderr, "encrypt_sector failed with code %d\n", e);
					pthread_rwlock_unlock(&mx);
					return(-EIO);
				}
				blk++;
			}
			pthread_rwlock_unlock(&mx);
			return(rb);
		}
		default:
			return(-EBADF);
	}
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
	.chown		= onion_chown,*/
	.truncate	= onion_truncate,
	/*.utimens	= onion_utimens,*/
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
	fprintf(stderr, "Image has %zu blocks\n", nblk);
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
	unsigned char headersector[SECTOR_LENGTH];
	fprintf(stderr, "Enter your layer master passphrase (at most %u bytes will be used)\n", KEY_LENGTH_HIGH);
	unsigned char passphrase[KEY_LENGTH_HIGH+1];
	memset(passphrase, 0, KEY_LENGTH_HIGH); // make sure it's initialised to all 0s
	if(!fgets((char *)passphrase, KEY_LENGTH_HIGH+1, stdin))
	{
		perror("Failed to read passphrase: fgets");
		goto shutdown;
	}
	int e;
	if((e=decrypt_sector(KEY_LENGTH_HIGH, passphrase, im, im+IV_LENGTH, headersector)))
	{
		if(e<0) perror("decrypt_sector");
		else fprintf(stderr, "decrypt_sector failed with code %d\n", e);
		goto shutdown;
	}
	size_t blocklength=read32be(headersector);
	if(blocklength!=BLOCK_LENGTH)
	{
		fprintf(stderr, "Bad image: blocklength is %zu, expected %zu\n", blocklength, BLOCK_LENGTH);
		goto shutdown;
	}
	header.key_size=read32be(headersector+0x4);
	header.key_len=read32be(headersector+0x8);
	header.key_stride=read32be(headersector+0xC);
	header.key_data=headersector+0x10;
	
	int rv=EXIT_FAILURE;
	int fargc=argc-1;
	char **fargv=(char **)malloc(fargc*sizeof(char *));
	fargv[0]=argv[0];
	for(int i=1;i<fargc;i++)
		fargv[i]=argv[i+1];
	
	rv=fuse_main(fargc, fargv, &onion_oper, NULL);
	shutdown:
	pthread_rwlock_wrlock(&mx);
	munmap(im, i_sz);
	flock(fd, LOCK_UN);
	close(fd);
	pthread_rwlock_unlock(&mx);
	pthread_rwlock_destroy(&mx);
	return(rv);
}
