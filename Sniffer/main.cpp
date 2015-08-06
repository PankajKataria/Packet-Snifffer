#include <pcap.h>
#include <stdio.h>
#include <vector>
#include <time.h>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <cstring>
#include <string>
#include <bits/stdc++.h>

using namespace std;

map< string, int > MAC_ID_COUNT;
double CHANNEL_TIME[12],total_time = 12.0;
int NUM_PACKET[12];
int channel_iterator(0);
pcap_t *handle;							
char *dev;					
char errbuf[PCAP_ERRBUF_SIZE];			
bpf_u_int32 mask;				
bpf_u_int32 net;						
struct pcap_pkthdr header;
const u_char *packet;
bool flag=false;



struct ieee80211_radiotap_header 
{

        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */

};


/*prism value */
struct prism_value
{
	u_int32_t did;
	u_int16_t status;
	u_int16_t len;
	u_int32_t data;

};


/*prism header for traditional wireless card*/
struct prism_header
{

	u_int32_t msgcode;
	u_int32_t msglen;
	struct prism_value hosttime;
	struct prism_value mactime;
	struct prism_value channel;
	struct prism_value rssi;
	struct prism_value sq;
	struct prism_value signal;
	struct prism_value noise;
	struct prism_value rate;
	struct prism_value istx;
	struct prism_value frmlen;
};
void handlePacket(const u_char* packet, int len) {
	
	int type =pcap_datalink(handle);
	if(type==127)														//LINKTYPE_IEEE802_11_RADIOTAP
	{
			string macid;
			int i;
			struct ieee80211_radiotap_header* rth1 = (struct ieee80211_radiotap_header*)(packet);
			i = rth1->it_len;		
			int j = i;
			i = j = rth1->it_len + 4;
			//printf("Addr1: ");
			for(; (i < j + 6) && (i < len); i++) 
			{
			//	printf("%02X", packet[i]);
				char temp[3];
				sprintf(temp,"%02X",packet[i]);
				macid+=temp;
			}
			MAC_ID_COUNT[macid]++;
			macid="";
			
			j = i;
			// printf("  Addr2: ");
			for(; (i < j + 6) && (i < len); i++) 
			{
			//	printf("%02X", packet[i]);
				char temp[3];
				sprintf(temp,"%02X",packet[i]);
				macid+=temp;
			}
			MAC_ID_COUNT[macid]++;
			macid="";
			
			j = i;			
			//printf("  Addr3: ");
			for(; (i < j + 6) && (i < len); i++) 
			{
			//	printf("%02X", packet[i]);
				char temp[3];
				sprintf(temp,"%02X",packet[i]);
				macid+=temp;
			}
			MAC_ID_COUNT[macid]++;
			
			macid="";
			i++;
			i++;
			j = i;    
			//printf("  Addr4: ");
			for(; (i < j + 6) && (i < len); i++) {

			//	printf("%02X", packet[i]);
				char temp[3];
				sprintf(temp,"%02X",packet[i]);
				macid+=temp;
			}
			MAC_ID_COUNT[macid]++;
			
			macid="";
	}
}


void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	handlePacket(packet, pkthdr->len);
}

void show_mac_table()
{
	printf("\n\n\n\n");
	for(auto it =MAC_ID_COUNT.begin();it!=MAC_ID_COUNT.end(); it++  )
	{
		cout<<it->first<<"\t"<<it->second<<endl;
	}
	printf("\n\n\n\n");
		
}


						
int   packet_capture(double Max_T)
{
		int no_of_packets(0);
		double diff;
		struct timespec startTime,countTime;
		int dump=clock_gettime(CLOCK_REALTIME,&startTime);
		while ( 1 ) 
		{
			pcap_loop(handle,1, callback, NULL);
			//cout<<"yo"<<endl;
			no_of_packets++;
			dump=clock_gettime(CLOCK_REALTIME,&countTime);
			diff=countTime.tv_sec - startTime.tv_sec;
			if(diff > Max_T)
			{
				break;
			}
		}
		cout<<no_of_packets<<endl;
		return  no_of_packets;
}

void update_channel_time()
{	
	double sum = 0.0;
	for(int i = 0; i < 12; i++)
	{
		if(CHANNEL_TIME[i] != 0)
			sum = sum + (double)NUM_PACKET[i]/CHANNEL_TIME[i];
			cout<<"sum :"<<sum<<endl;
		
	}
	for(int i = 0; i < 12; i++)
	{
		
		CHANNEL_TIME[i] = (((double)NUM_PACKET[i]/CHANNEL_TIME[i])/sum) * (double)total_time;
	}
}




int main(int argc, char *argv[])
{
	dev = argv[1];
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n",dev, errbuf);
		return(2);
	}
	
	for(int i =0;i<12;i++)
	{
		NUM_PACKET[i]=0;
		CHANNEL_TIME[i]=1.0;
		cout<<i<<"	"<<CHANNEL_TIME[i]<<endl;
	}
	
	int temp = 0;
	while(1)
	{
		temp++;
		
		string command = "iwconfig wlan0 channel ";
		stringstream ss;
		ss<<(channel_iterator+1);
		command += ss.str();
		cout<<command<<endl;
		const char* final_command=command.c_str();
		system(final_command);
		
			cout<<"time	"<<CHANNEL_TIME[channel_iterator]<<endl;
		NUM_PACKET[channel_iterator]=packet_capture((double)CHANNEL_TIME[channel_iterator]);
		cout<<"CHANNEL : "<<channel_iterator+1 <<"	"<<NUM_PACKET[channel_iterator]<<endl;
		channel_iterator=(channel_iterator+1)%12;
		if(channel_iterator==0)
		{
			update_channel_time();
			show_mac_table();
		}
		cout<<"\n"<<"\n"<<"\n";
	}
	pcap_close(handle);
	
	return(0);
 }
