#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // TO-DO
    buf_init(&txbuf, req_buf->len);
    // 拷贝数据
    memcpy(txbuf.data, req_buf->data, req_buf->len);
    // 填写报头
    icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr_t *req_hdr = (icmp_hdr_t *)req_buf->data;
    hdr->type = ICMP_TYPE_ECHO_REPLY;
    hdr->code = 0;
    hdr->id16 = req_hdr->id16;
    hdr->seq16 = req_hdr->seq16;
    hdr->checksum16 = 0;
    hdr->checksum16 = swap16(checksum16((uint16_t *)txbuf.data, txbuf.len));
    // 发送出去
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    // 报头检测
    if(buf->len < sizeof(icmp_hdr_t))   return;
    // 回显请求发送回显应答
    icmp_hdr_t *hdr = (icmp_hdr_t *)buf->data;
    if(hdr->type == ICMP_TYPE_ECHO_REQUEST)
        icmp_resp(buf, src_ip);
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // TO-DO
    int total_size = sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8;
    buf_init(&txbuf, total_size);
    // 填写首部
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->id16 = 0; // unused, must be 0
    icmp_hdr->seq16 = 0; // unused, must be 0
    // 填写 icmp 数据中 ip 首部
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(icmp_hdr + 1);
    ip_hdr_t *recv_ip_hdr = (ip_hdr_t *)recv_buf->data;
    memcpy(ip_hdr, recv_ip_hdr, sizeof(ip_hdr_t));
    // 填写 icmp 数据中 ip 前8个字节
    uint8_t *data = (uint8_t *)(ip_hdr + 1);
    uint8_t *recv_ip_data = (uint8_t *)(recv_ip_hdr + 1);
    memcpy(data, recv_ip_data, 8);
    // 计算校验和
    icmp_hdr->checksum16 = 0;
    icmp_hdr->checksum16 = swap16(checksum16((uint16_t *)txbuf.data, total_size));
    // 发送出去
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}