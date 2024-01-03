/*
 *
 * kretprobe to trace netfilter ingress skb processing
 * The objective is to find where an ingress packet gets dropped
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#include <linux/skbuff.h>
#include <net/ip.h>
#include <linux/netfilter/x_tables.h>

#define NAME_LEN 50

static char func_name[NAME_LEN] = "ipt_do_table";

/* Per-instance private data struct */
struct steph {
	struct sk_buff *skb;
	struct nf_hook_state *state;
	struct xt_table *table;
};

/*
 * Grabbing the registers/arguments before we move on into the function
 */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct steph *data;

	data = (struct steph *)ri->data;

	data->skb = (struct sk_buff *) regs_get_kernel_argument(regs, 0);
	if (IS_ERR_OR_NULL(data->skb)) {
		pr_err("%s found NULL skb pointer", func_name);
		return 1;
	}

	data->state = (struct nf_hook_state *) regs_get_kernel_argument(regs, 1);
	if (!data->state) {
		pr_err("%s found NULL nf_hook_state pointer", func_name);
		return 1;
	}

	data->table = (struct xt_table *) regs_get_kernel_argument(regs, 2);
	if (!data->table) {
		pr_err("%s found NULL xt_table pointer", func_name);
		return 1;
	}

	return 0;
}

/*
 * The packet and netfilter verdict inspection
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int verdict;
	struct steph *data;
	struct nf_hook_state *state;
	struct xt_table *table;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	__u32 saddr, daddr;
	__u16 src, dst;
	unsigned int proto;
	const char *devin, *devout;
	int devidxin, devidxout;

	verdict = regs_return_value(regs);

	/* We don't care about accepted ingress packets */
	if (verdict == NF_ACCEPT)
		return 0;

	data = (struct steph *)ri->data;
	if (!data) {
		pr_err("%s: NULL private data", __func__);
		return 1;
	}

	iph = ip_hdr(data->skb);
	if (!iph) {
		pr_err("%s: failed to find the iphdr structure", __func__);
		return 1;
	}

	saddr = ntohl(iph->saddr);
	daddr = ntohl(iph->daddr);

	switch(iph->protocol) {
		case IPPROTO_TCP:
		       	tcph = tcp_hdr(data->skb);

			if (!tcph) {
				pr_err("%s: failed to find the tcphdr structure", __func__);
				return 1;
			}

			proto = 0x000000ff & IPPROTO_TCP;
			src = ntohs(tcph->source);
			dst = ntohs(tcph->dest);

			break;
		case IPPROTO_UDP:
			udph = udp_hdr(data->skb);

			if (!udph) {
				pr_err("%s: failed to find the udph structure", __func__);
				return 1;
			}

			proto = 0x000000ff & IPPROTO_UDP;
			src = ntohs(udph->source);
			dst = ntohs(udph->dest);

			break;
		default:
			pr_warn("%s: unsupported L4 protocol; only TCP and UDP are supported", func_name);
			return 0;
	}

	state = data->state;
	if (state) {
		if (state->in) {
			devin = state->in->name;
			devidxin = state->in->ifindex;
		} else {
			devin = NULL;
			devidxin = 0;
		}

		if (state->out) {
			devout = state->out->name;
			devidxout = state->out->ifindex;
		} else {
			devout = NULL;
			devidxout = 0;
		}
	} else {
		devin = NULL;
		devidxin = 0;
		devout = NULL;
		devidxout = 0;
	}

	table = data->table;

	pr_info("%s(%s) - devin=%s/%d, devout=%s/%d, saddr=%x, daddr=%x, proto=%d, "
		"spt=%x, dpt=%x, verdict=%d\n", func_name, table->name, devin, devidxin,
						devout, devidxout, saddr, daddr, proto,
						src, dst, verdict);

	return 0;
}

static struct kretprobe my_kretprobe = {
	.entry_handler		= entry_handler,
	.handler		= ret_handler,
	/* Probe up to 20 instances concurrently. */
	.maxactive		= 20,
};

static int __init kretprobe_init(void)
{
	int ret;

	my_kretprobe.kp.symbol_name = func_name;

	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		pr_err("register_kretprobe failed, returned %d\n", ret);
		return -1;
	}
	pr_info("Planted return probe at %s: 0x%lx\n",
			my_kretprobe.kp.symbol_name, (unsigned long) my_kretprobe.kp.addr);
	return 0;
}

static void __exit kretprobe_exit(void)
{
	unregister_kretprobe(&my_kretprobe);
	pr_info("kretprobe at 0x%lx unregistered\n", (unsigned long) my_kretprobe.kp.addr);

	/* nmissed > 0 suggests that maxactive was set too low. */
	pr_info("Missed probing %d instances of %s\n",
		my_kretprobe.nmissed, my_kretprobe.kp.symbol_name);
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");
