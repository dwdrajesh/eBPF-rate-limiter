#include <time.h>
#include "xdp_lb_kern.h"

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))

#define BACKEND_A 2
#define BACKEND_B 3
#define CLIENT 4
#define LB 5

typedef struct slidingwindow_t {
	int window_size;
	int bucket_id = 0;
	int prev_counter = 0, curr_counter = 0;
	unsigned time_st = 0;
	int capacity;
} slidingwindow;

int throttle (struct slidingwindow_t* sw, int requests)
{
	unsigned time_now = (unsigned) time(NULL);
	int bucket_id = time_now/(st->window_size);

	// 1. first time
	if (sw->bucket_id == 0)
	{
		sw->bucket_id = bucket_id;
	} // 2. 1 bucket ahead
	else if (bucket_id == sw->bucket_id+1)
	{
		sw->prev_counter = sw->curr_counter;
		sw->prev_counter = 0;
	} // much ahead
	else
	{
		sw->prev_counter = 0;
		sw->curr_counter = 0;
	}

	// note down new values now
	sw->time_st = time_now;
	sw->bucket_id = bucket_id;

	double prev_window_weight = 1 - (time_now % sw->window_size) / sw->window_size;
	double prev_window_count = prev_window_weight * sw->prev_counter;
	
	// check rate reached or not now
	if (prev_window_count + sw->curr_counter+requests > (sw->capacity)/sw->window_size)
	{
                bpf_printk("Rejecting request");
		return 0;
	}
	else
	{
                bpf_printk("Allowing request");
	        sw->curr_counter += requests;
		return 1;
	}
}

SEC("xdp_lb")
int xdp_load_balancer(struct xdp_md *ctx)
{
    slidingwindow sd;
    sd.window_size = 60;
    sd.capacity = 1;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_printk("got something");

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    bpf_printk("Got TCP packet from %x", iph->saddr);

    if (iph->saddr == IP_ADDRESS(CLIENT))
    {
        char be = BACKEND_A;
	if (!throttle(&sd, 1))
	{
            bpf_printk("Rejected by Load Balancer for too many requests");
	}

        if (bpf_ktime_get_ns() % 2)
            be = BACKEND_B;

        iph->daddr = IP_ADDRESS(be);
        eth->h_dest[5] = be;
    }
    else
    {
        iph->daddr = IP_ADDRESS(CLIENT);
        eth->h_dest[5] = CLIENT;
    }
    iph->saddr = IP_ADDRESS(LB);
    eth->h_source[5] = LB;

    iph->check = iph_csum(iph);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
