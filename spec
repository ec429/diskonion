diskonion: A layered deniable disk encryption scheme

Rationale:
It is desired to create a layered disk encryption scheme in which the existence of further layers beyond those already decrypted is deniable.  Current methods of doing this (TrueCrypt, etc.) store the inner volume data in the free space of the outer volume, thereby risking data loss if the outer volume is used normally.  While this property (data destruction of unacknowledged layers) can sometimes be desirable, it does tend to prevent the use of a kind of rôle-based security wherein the user only mounts volumes up to the desired one (more sensitive data remaining unmounted) which protects the most sensitive data in at least some 'hot disk' scenarios.  The method described below provides such a scheme, the innermost layer being indistinguishable from any other.
The threat model envisaged is that of law-enforcement in a jurisdiction with key disclosure laws (such as the UK's Regulation of Investigatory Powers Act (RIPA)), where penalties for non-disclosure require proof beyond reasonable doubt that encrypted data is present (and that the defendant possesses or had previously possessed the decryption key).  Given the cluefulness exhibited by the average judge, it seems likely that the presence of encryption software and a random-looking binary blob will be taken as such evidence; however, if three layers of data have already been decrypted and there is nothing to show that the third is not the last, it is the author's belief that judges will consider there to be insufficient evidence of a fourth layer.
With regard to another threat model (that of physical coercion, so-called "rubber-hose" or "lead-pipe" cryptanalysis), the argument in <http://embeddedsw.net/doc/physical_coercion.txt> suggests that under certain circumstances, it may be preferable to be unable to prove that one has disclosed all keys, which is the case with the scheme described here.

Description of the Scheme:
A layer stores a separate IV for each sector (then using AES CBC to encrypt the sector with the relevant part of the layer's sector key).
Each layer's sector IVs contain the data for the next layer (though they don't consist purely of it).  For instance, the data could be the XOR of paired bits of the sector IV.  That way we can do regeneration-on-write with changed IVs, doing so in a way which preserves the data (if indeed there is any).

The layer (which is generic, ie. all the layers are provided by the same program) provides both a "data file" (for this layer) and a "keystream file" (for use by an upper layer if one exists).  This file exposes the sector IVs; writing to it should transparently update the relevant sectors.  Obviously this will be slow, since as well as updating the IV, it is also necessary to update the sector data encrypted using that IV.  Of course the keystream should be randomly initialised (otherwise the presence of data in the keystream would give away the existence of a further layer) - this is provided by generating the initial IVs randomly (though there is a subtlety in that the keystream decoding must not distinguish the IVs from true random; for a strong CSPRNG this should not be a problem.  A really bad PRNG might however produce patterns in the keystream which would indicate the absence of a further layer).

Finally note that there is no reason for the layer to provide filesystem primitives, when it can simply present a filesystem image as the data file, which can then be mounted by eg. a loop device.  However, a reasonable means of implementation is by a userspace filesystem (eg. with FUSE) which presents two files under its mountpoint, say /data and /keystream.

Description of the Implementation Format:
The data file is partitioned into /sectors/ of 4080 bytes (4096 bytes - 128 bits).  Then, for each sector, a random 128-bit IV is generated, and used with the derived sector key to encrypt the sector with AES in CBC mode.  The IV is prepended to the ciphertext to produce a 4096 byte block.
The image as a whole consists of a header block followed by these cipher blocks in order.  The header block is 4096 bytes, and contains the header sector, encrypted in the same way as any other sector (so the header sector is only 4080 bytes) except that the layer master key (rather than the layer sector key) is used to encrypt it.  The header sector contains the following information (all encoded big-endian):
Offset	Length	Meaning
0x0000	4		Block length in bytes (currently fixed at 4096, 0x1000)
0x0004	4		Sector key size in bytes (typically 16/24/32, for 128/192/256 bit AES) (B)
0x0008	4		Sector key length in bytes (maximum 4064) (L)
0x000C	4		Sector key stride in bytes (S)
0x0010	L		Sector key data
The derived sector key is produced by taking the sector index (i) and computing R=i*S mod L; then the key is B bytes from the sector key data starting at offset R and wrapping around if necessary.  This extra obfuscatory step is included in an attempt to offset the reduction in security resulting from constraining the IVs (which constraint increases the chance of related or even colliding sector IVs), since an IV collision isn't a problem if the keys are different.  Typically L and S should be chosen to be coprime to ensure that all the possible derived sector keys are used.  However, an implementation is permitted to set L:=B and S:=0 thereby allowing it to ignore sector key derivation and precompute the AES round keys just once, using them for the life of the mount (this isn't advised, though, as AES key expansion isn't particularly expensive).
The keystream consists of a 64-bit block for each 4096-byte block in the image (including the header block), produced from the sector IV as follows: the nth byte of the keystream block is the XOR of the (2n)th and (2n+1)th bytes of the IV (where byte indices start from zero).
An important feature of the format is that the image is indistinguishable from random data; thus, without a key to decrypt it (or a practical attack on the underlying cryptosystem AES), a keystream file cannot be determined to carry (or not carry) an image.  It is for this reason that the image does not have any kind of header 'in the clear'.

Implementation notes:
Given a sector IV, a new IV can be generated as follows: generate a 64-bit nonce, then double its bytes (so eg. 0xdeadbeef... becomes 0xdedeadadbebeefef...); now XOR this with the old sector IV.  This preserves the keystream block, since XOR is commutative (so (a^1)^(b^1) = (a^b)^(1^1) = (a^b) ^ 0 = a^b).
