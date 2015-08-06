#include <stdio.h>
#include <time.h>
#include<iostream>
using namespace std;
int main ()
{
	 
	//vector< pcap_pkthdr > header_vector;
	double MAX_TIME=5.00,diff;
	struct timespec startTime,countTime;
	int dump=clock_gettime(CLOCK_REALTIME,&startTime);
	while ( 1 ) 
	{
		cout<<"CAPTURE"<<endl;
		dump=clock_gettime(CLOCK_REALTIME,&countTime);
		diff=countTime.tv_sec - startTime.tv_sec;
		if(diff > MAX_TIME)
		{
			break;
		}
		
	}
	//return header_vector;
 
return 0;
}
