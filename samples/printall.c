/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
See the file COPYING for license details.
*/


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../src/util.h"
#include "nids.h"

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
char *
adres (struct tuple4 addr)
{
  static char buf[256];
  strcpy (buf, int_ntoa (addr.saddr));
  sprintf (buf + strlen (buf), ",%i,", addr.source);
  strcat (buf, int_ntoa (addr.daddr));
  sprintf (buf + strlen (buf), ",%i", addr.dest);
  return buf;
}

void print_state(char nids_state)
{
  printcat("\n------a_tcp->nids_state = ");

  switch (nids_state)
  {
    case NIDS_JUST_EST:
      printcat("NIDS_JUST_EST");
      break;
    
    case NIDS_DATA:
      printcat("NIDS_DATA");
      break;

    case NIDS_CLOSE:
      printcat("NIDS_CLOSE");
      break;

    case NIDS_RESET:
      printcat("NIDS_RESET");
      break;

    case NIDS_TIMED_OUT:
      printcat("NIDS_TIMED_OUT");
      break;

    case NIDS_EXITING:
      print("NIDS_EXITING");
      break;

    default:
      fprintf(stderr,"%d", (int)nids_state);
      break;
  }

  print("------");
}

void
tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed)
{
  static int callback_count = 0;
  fprintf(stderr, "\n\n------New tcp_callback No. %d----------------\n", ++callback_count);

  char buf[1024];
  strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf

  print_state(a_tcp->nids_state);

  switch (a_tcp->nids_state)
  {
    case NIDS_JUST_EST:
      {
        // connection described by a_tcp is established
        // here we decide, if we wish to follow this stream
        // sample condition: if (a_tcp->addr.dest!=23) return;
        // in this simple app we follow each stream, so..
        a_tcp->client.collect++; // we want data received by a client
        a_tcp->server.collect++; // and by a server, too
        a_tcp->server.collect_urg++; // we want urgent data received by a
                                      // server
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
        a_tcp->client.collect_urg++; // if we don't increase this value,
                                      // we won't be notified of urgent data
                                      // arrival
#endif
        fprintf (stderr, "%s established\n", buf);
      }
      break;

    case NIDS_CLOSE:
      // connection has been closed normally
      fprintf (stderr, "%s closing\n", buf);
      break;

    case NIDS_RESET:
      // connection has been closed by RST
      fprintf (stderr, "%s reset\n", buf);
      break;

    case NIDS_DATA:
      {
        static int data_count = 0;
        fprintf(stderr,"------NIDS_DATA No. %d------\n",++data_count);
        fprintf(stderr,"------a_tcp->client.collect = %d, collect_urg = %d------\n", a_tcp->client.collect, a_tcp->client.collect_urg);
        fprintf(stderr,"------a_tcp->server.collect = %d, collect_urg = %d------\n", a_tcp->server.collect, a_tcp->server.collect_urg);


        // new data has arrived; gotta determine in what direction
        // and if it's urgent or not

        if (a_tcp->server.count_new_urg)
        {
          // new byte of urgent data has arrived 
          strcat(buf,"(urgent->)");
          buf[strlen(buf)+1]=0;
          buf[strlen(buf)]=a_tcp->server.urgdata;
          write(1,buf,strlen(buf));
          return;
        }

        // We don't have to check if urgent data to client has arrived,
        // because we haven't increased a_tcp->client.collect_urg variable.
        // So, we have some normal data to take care of.
        
        struct half_stream *hlf;

        if (a_tcp->client.count_new)
        {
          // new data for client
          hlf = &a_tcp->client; // from now on, we will deal with hlf var,
                                // which will point to client side of conn
          strcat (buf, "(<-)"); // symbolic direction of data
        }
        else
        {
          hlf = &a_tcp->server; // analogical
          strcat (buf, "(->)");
        }

        fprintf(stderr,"%s\n",buf); // we print the connection parameters
                                  // (saddr, daddr, sport, dport) accompanied
                                  // by data flow direction (-> or <-)

        fprintf(stderr,"\n------hlf->count_new = %d-------\n",(int)hlf->count_new);
        print("\n------Begin hex hlf->data------");

        for(int i = 0; i < hlf->count_new; ++i)
        {
          fprintf(stderr,"%02x ",(unsigned char)hlf->data[i]);
        }

        print("\n------End hex hlf->data hex------\n\n------Begin char hlf->data------");

        write(2,hlf->data,hlf->count_new); // we print the newly arrived data  

        print("\n------End char hlf->data------");


        
        // print other parts of the tcp_stream
        fprintf(stderr, "\n------hash_index: %d------read: %d------", a_tcp->hash_index, a_tcp->read);
        
        fprintf(stderr, "\n------bufsize: %d------", hlf->bufsize);



      }
      break;

    default:
      break;
  }

  print("\n------End tcp_callback------\n\n\n\n\n");

  return;
}

//   if (a_tcp->nids_state == NIDS_JUST_EST)
//   {
//     // connection described by a_tcp is established
//     // here we decide, if we wish to follow this stream
//     // sample condition: if (a_tcp->addr.dest!=23) return;
//     // in this simple app we follow each stream, so..
//     a_tcp->client.collect++; // we want data received by a client
//     a_tcp->server.collect++; // and by a server, too
//     a_tcp->server.collect_urg++; // we want urgent data received by a
//                                   // server
// #ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
//     a_tcp->client.collect_urg++; // if we don't increase this value,
//                                   // we won't be notified of urgent data
//                                   // arrival
// #endif
//     fprintf (stderr, "%s established\n", buf);
//     return;
//   }

//   if (a_tcp->nids_state == NIDS_CLOSE)
//   {
//     // connection has been closed normally
//     fprintf (stderr, "%s closing\n", buf);
//     return;
//   }

//   if (a_tcp->nids_state == NIDS_RESET)
//   {
//     // connection has been closed by RST
//     fprintf (stderr, "%s reset\n", buf);
//     return;
//   }

//   if (a_tcp->nids_state == NIDS_DATA)
//   {
//     // new data has arrived; gotta determine in what direction
//     // and if it's urgent or not

//     struct half_stream *hlf;

//     fprintf (stderr, "\n------a_tcp->server.count_new_urg = %d-----\n", (int)a_tcp->server.count_new_urg);

//     if (a_tcp->server.count_new_urg)
//     {
//       // new byte of urgent data has arrived 
//       strcat(buf,"(urgent->)");
//       buf[strlen(buf)+1]=0;
//       buf[strlen(buf)]=a_tcp->server.urgdata;
//       write(1,buf,strlen(buf));
//       return;
//     }
//     // We don't have to check if urgent data to client has arrived,
//     // because we haven't increased a_tcp->client.collect_urg variable.
//     // So, we have some normal data to take care of.
//     if (a_tcp->client.count_new)
//     {
//             // new data for client
//       hlf = &a_tcp->client; // from now on, we will deal with hlf var,
//                                   // which will point to client side of conn
//       strcat (buf, "(<-)"); // symbolic direction of data
//     }
//     else
//     {
//       hlf = &a_tcp->server; // analogical
//       strcat (buf, "(->)");
//     }

//     fprintf(stderr,"%s\n",buf); // we print the connection parameters
//                               // (saddr, daddr, sport, dport) accompanied
//                               // by data flow direction (-> or <-)

//     fprintf(stderr,"\n------strlen(buf)=%d-------\n",(int)strlen(buf));

//     for(int i = 0; i < strlen(buf); ++i)
//     {
//       fprintf(stderr,"%x ",*(buf + i));
//     }

//     static int print_count = 0;
//     fprintf(stderr,"\n\n------No. %d",++print_count);
//     print("-------by pdliu-------------------\n\n\n\n\n\n");

//     write(2,hlf->data,hlf->count_new); // we print the newly arrived data      
//   }
  
//   return ;
// }

int 
main ()
{
  // here we can alter libnids params, for instance:
  // nids_params.n_hosts=256;

  print("enter printall main");


// fix the bug of not able to capture packets
struct nids_chksum_ctl temp;
temp.netaddr = 0;
temp.mask = 0;
temp.action = 1;
nids_register_chksum_ctl(&temp,1);


  if (!nids_init ())
  {
  	fprintf(stderr,"%s\n",nids_errbuf);
  	exit(1);
  }

  nids_register_tcp (tcp_callback);
  nids_run ();
  return 0;
}

