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
	
	bits.c: general common functions
*/

#include "bits.h"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

void write32be(uint32_t val, unsigned char *buf)
{
	buf[0]=(val>>24)&0xFF;
	buf[1]=(val>>16)&0xFF;
	buf[2]=(val>>8)&0xFF;
	buf[3]=(val)&0xFF;
}

uint32_t read32be(const unsigned char *buf)
{
	uint32_t rv=buf[3]&0xFF;
	rv|=(buf[2]&0xFF)<<8;
	rv|=(buf[1]&0xFF)<<16;
	rv|=(buf[0]&0xFF)<<24;
	return(rv);
}

ssize_t writeall(int fd, const unsigned char *buf, size_t count)
{
	size_t i=0;
	ssize_t b;
	while(i<count)
	{
		b=write(fd, buf+i, count-i);
		if(b<=0) return(b);
		i+=b;
	}
	return(i);
}

ssize_t readall(int fd, unsigned char *buf, size_t count)
{
	size_t i=0;
	ssize_t b;
	while(i<count)
	{
		b=read(fd, buf+i, count-i);
		if(b<=0) return(b);
		i+=b;
	}
	return(b);
}
