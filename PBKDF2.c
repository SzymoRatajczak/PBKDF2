#include <stdio.h>
#include <stdlib.h>
#include<openssl/evp.h>
#include<openssl/hmac.h>
/* run this program using the console pauser or add your own getch, system("pause") or input loop */


#define HLEN (20)

int pbkdf2(unsigned char *pw,unsigned int pwlen,char *salt,unsigned long long saltlen,unsigned int ic,unsigned char *dk,unsigned long long dklen)
{
	
	unsigned long l,r,i,j;
	unsigned char txt[4],hash[HLEN*2],tmp[HLEN],*p=dk;
	unsigned char *lhix,*hix,*swap;
	short k;
	int outlen;
	
	if(dklen>((((unsigned long long)1)<<32)-1)*HLEN)
	abort();
	l=dklen/HLEN;
	r=dklen%HLEN;
	
	for (i=1;i<=l;i++)
	{
		sprintf(txt,"%04u",(unsigned int)i);
		HMAC(EVP_sha1(),pw,pwlen,txt,4,has,&outlen);
		lhix=hash;
		hix=hash+HLEN;
		for(k=0;k<HLEN;k++)
		{
			
			tmp[k]=hash[k];
		}
		
		for(j=1;j<ic;j++)
		{
			HMAC(EVP_sha1(),pw,pwlen,lhix,HLEN,hix,&outlen);
			for(k=0;k<HLEN;k++)
			{
				tmp[k]^=hix[k];
			}
			
			swap=hix;
			hix=lhix;
			lhix=swap;
		}
		for(k=0;k<HLEN;k++)
		{
			*p++=tmp[k];
			
		}
	}
		if(r)
		{
			sprintf(txt,"%04u",(unsigned int)i);
			HMAC(EVP_sha1(),pw,pwlen,txt,4,hash,&outlen);
			lhix=hash;
			hix=hash+HLEN;
			for(k=0;k<HLEN;k++)
			{
				tmp[k]=hash[k];
			}
			for(j=1;j<ic;j++)
			{
			HMAC(EVP_sha1(),pw,pwlen,lhix,HLEN,hix,&outlen);
			for(k=0;k<HLEN;k++)
			{
				tmp[k]^=hix[k];
			}
			swap=hix;
			hix=lhix;
			lhix=swap;
			}
			for(k=0;k<r;k++)
			{
				*p++=tmp[k];
			}
		}
	
	return 0;
}

int main(int argc, char *argv[]) {
	return 0;
}
