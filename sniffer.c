#include <winsock2.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tpcshrd.h>

#pragma comment(lib, "ws2_32.lib")

#define LS_HI_PART(x)  ((x>>4) & 0x0F)
#define LS_LO_PART(x)  ((x) & 0x0F)

typedef struct _IP_HEADER_ {
    BYTE ver_ihl;
    BYTE type;
    WORD length;
    WORD packet_id;
    WORD flags_foof;
    BYTE ttl;
    BYTE protocol;
    WORD cheksum;
    DWORD srcip;
    DWORD destip;
} IPHEADER;

typedef struct _TCP_HEADER_ {
    WORD srcport;
    WORD destport;
    DWORD seq_number;
    DWORD ack;
    WORD info_ctrl;
    WORD window;
    WORD checksum;
    WORD urg;
} TCPHEADER;

char *GetLastErrorAsString() {

    // Error Buffer
    char *error[256];
    // Obtener Id del ultimo error
    DWORD errorMsgId = GetLastError();

    if(errorMsgId == 0) {
        return *error;
    }

    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL, errorMsgId, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char *)&error, 0, NULL);
    
    return *error;
    
}

#define MAX_PACKET_SIZE 65535

void get_this_machine_ip(char *_retIP);
void translate_ip(DWORD _ip, char *_cip);

int main() {

    int optval = 1;
    IPHEADER *ip_header = NULL;
    int ip_header_size = 0;
    char ipSrc[20], ipDest[20];

    WSADATA netdata;

    char thisIp[20];

    int check = WSAStartup(MAKEWORD(2, 2), &netdata);
    if(check !=  0) {
        printf("Error enm la verificacion");
        exit(-1);
    }

    // Crear el socket sin procesar
    int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

    if(socketfd == INVALID_SOCKET) {
        printf("Socket fallo al abrir");
        exit(-1);
    }

    char buffer[MAX_PACKET_SIZE]; // datos

    memset(thisIp, 0x00, sizeof(thisIp));
    get_this_machine_ip(thisIp);

    struct sockaddr_in socksniff;

    socksniff.sin_family = AF_INET;
    socksniff.sin_addr.s_addr = inet_addr(thisIp);
    socksniff.sin_port = htons(0);

    if(bind(socketfd, (struct sockaddr *)&socksniff, sizeof(socksniff)) == SOCKET_ERROR) {
        printf("Error en el bindeo");
    }

    // Poner en modo promiscuo el socket para coger todos los paquetes que pasan a travez de la red
    // Normalmente el socket esta en modo no promiscuo, es decir solo presta atencion a los paquetes que estan dirigidos hacia ella, a su ip
    DWORD dwlen = 0;
    if(WSAIoctl(socketfd, 
                SIO_RCVALL, 
                &optval,
                sizeof(optval),
                NULL,
                0,
                &dwlen,
                NULL,
                NULL) == SOCKET_ERROR) {
                    printf("Error con WsaIoctl");
                    printf("%s", GetLastErrorAsString());
                }

    
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    while(1) {

        /*Limpiar el paquete cada que entre en el bucle para recibir*/
        (void) memset(buffer, 0x00, sizeof(buffer));

        int recived = recv(socketfd, buffer, MAX_PACKET_SIZE, 0);
        
        if(recived < 0) {
            printf("packete no recibido");
        }else{
            printf("\nPackete recvido\n");
        }

        if(recived < sizeof(IPHEADER))
            continue; // Ignora el paquete

        ip_header = (IPHEADER *) buffer;

        //if(ip_header->destip == inet_addr(thisIp))
        //    continue;

        if(LS_HI_PART(ip_header->ver_ihl) != 4) // Si no es ipv4
            continue; // Ignora el paquete

        ip_header_size = LS_LO_PART(ip_header->ver_ihl);
        ip_header_size *= sizeof(DWORD); // Tamaño en 32 bits

        memset(ipSrc, 0x00, sizeof(ipSrc));
        memset(ipDest, 0x00, sizeof(ipDest));

        translate_ip(ip_header->srcip, ipSrc);
        translate_ip(ip_header->destip, ipDest);

        //printf("\n EXTRA Source IP: %s", ipSrc);
        //printf("\n EXTRA Destination IP: %s", ipDest);
        //printf("\n%d\n", ip_header->protocol);
        
        switch(ip_header->protocol) {
            case 6:  // TCP case
                printf("\n ------------------ // -------------------- ");
                printf("\n IP header:");
                printf("\n Source IP: %s", ipSrc);
                printf("\n Destination IP: %s", ipDest);
                printf("\n TCP header: ");
                break;
            default:
                //printf("\nNo pertenece a la red\n");
                //printf("%d\n", ip_header->protocol);
                break;
        };

        Sleep(100);

    }

    close(socketfd);
    WSACleanup();

    return 0;
}

void translate_ip(DWORD _ip, char *_cip) {
    struct in_addr in;

    in.S_un.S_addr = _ip;
    strcpy(_cip, inet_ntoa(in));
}

void get_this_machine_ip(char *_retIP)
{
    char host_name[128];
    struct hostent *hs;
    struct in_addr in;
  
    memset( host_name, 0x00, sizeof(host_name) );
    gethostname(host_name,128);
    hs = gethostbyname(host_name);
  
    memcpy( &in, hs->h_addr, hs->h_length );
    strcpy( _retIP, inet_ntoa(in) );
}

