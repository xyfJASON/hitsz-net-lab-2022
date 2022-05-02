#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

int send_id = 0;

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // 长度检测
    if(buf->len < sizeof(ip_hdr_t)) return;
    // 报头检测
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    if(hdr->version != IP_VERSION_4)   return;
    if(swap16(hdr->total_len16) > buf->len)    return;
    // 校验和检测
    uint16_t checksum = hdr->hdr_checksum16;
    hdr->hdr_checksum16 = 0;
    uint16_t checksum_tmp = checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t));
    if(swap16(checksum) != checksum_tmp)   return;
    hdr->hdr_checksum16 = checksum;
    // 检查目的ip是否是本机ip
    if(memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0)    return;
    // 去除填充的0
    if(swap16(hdr->total_len16) < buf->len)
        buf_remove_padding(buf, buf->len - swap16(hdr->total_len16));
    // 协议不可达
    if(!(hdr->protocol == NET_PROTOCOL_UDP ||
         hdr->protocol == NET_PROTOCOL_ICMP))
        icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    // 去除报头
    buf_remove_header(buf, sizeof(ip_hdr_t));
    // 向上传递数据包
    net_in(buf, hdr->protocol, hdr->src_ip);
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    // 增加头部，填写头部字段
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    hdr->version = IP_VERSION_4;
    hdr->tos = 0;
    hdr->total_len16 = swap16(buf->len);
    hdr->id16 = swap16(id);
    uint16_t flags_fragment = (offset & 0x1FFFFFFF);
    if(mf == 1) flags_fragment |= IP_MORE_FRAGMENT;
    hdr->flags_fragment16 = swap16(flags_fragment);
    hdr->ttl = 64;
    hdr->protocol = protocol;
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);
    // 计算校验和
    hdr->hdr_checksum16 = 0;
    hdr->hdr_checksum16 = swap16(checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t)));
    // 发送
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    size_t eachlen = 1500 - sizeof(ip_hdr_t);
    if(eachlen != 1480) printf("ERROR!");
    // 分片发送
    int i = 0;
    for(i = 0; (i + 1) * eachlen < buf->len; i++){
        buf_t ip_buf;
        buf_init(&ip_buf, eachlen);
        memcpy(ip_buf.data, buf->data + i * eachlen, eachlen);
        ip_fragment_out(&ip_buf, ip, protocol, send_id, i * (eachlen >> 3), 1);
    }
    if(buf->len - i * eachlen <= 0)  printf("ERROR");
    buf_t ip_buf;
    buf_init(&ip_buf, buf->len - i * eachlen);
    memcpy(ip_buf.data, buf->data + i * eachlen, buf->len - i * eachlen);
    ip_fragment_out(&ip_buf, ip, protocol, send_id, i * (eachlen >> 3), 0);
    send_id++;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}