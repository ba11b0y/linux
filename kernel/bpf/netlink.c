#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

struct sock *nl_sk = NULL;
int client_pid;

void nl_verifier_handler(struct sk_buff *skb) {
	struct nlmsghdr *nlh = (struct nlmsghdr *) skb->data;
	client_pid = nlh->nlmsg_pid;
	printk(KERN_INFO "PONG from kernel: msg -> %s, from pid -> %d \n", (char*) nlmsg_data(nlh), client_pid);
}

static int __init netlink_bpf_init(void)
{
	struct netlink_kernel_cfg cfg = {
        .input = nl_verifier_handler,
    	};

    	nl_sk = netlink_kernel_create(&init_net, NETLINK_BPF, &cfg);
	printk("Entering: %s, protocol family = %d \n",__FUNCTION__, NETLINK_BPF);
	if(nl_sk==NULL)
	{
		printk(KERN_ALERT "Error creating NETLINK_BPF socket.\n");
		return -10;
	}

	return 0;
}

static int send_msg_netlink_sock(int verifier_id)
{
	struct nlmsghdr *nlhead;
	struct sk_buff *skb_out;
	int res, msg_size;
	char msg[32]; // Buffer to hold the string representation of verifier_id

	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

	snprintf(msg, sizeof(msg), "%d", verifier_id); // Convert verifier_id to string
	msg_size = strlen(msg);

	skb_out = nlmsg_new(msg_size, 0); // Allocate a new netlink message

	if (!skb_out)
	{
	printk(KERN_ERR "Failed to allocate new skb\n");
	return -1;
	}

	nlhead = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0); // Add a new netlink message to an skb
	NETLINK_CB(skb_out).dst_group = 0;
	strncpy(nlmsg_data(nlhead), msg, msg_size); // Copy the message

	res = nlmsg_unicast(nl_sk, skb_out, client_pid);

	if (res < 0)
	printk(KERN_INFO "Error while sending back to user\n");

	return 0;
};


static void __exit netlink_bpf_exit(void)
{
	printk(KERN_INFO "exiting netlink_bpf module\n");
	netlink_kernel_release(nl_sk);
}

module_init(netlink_bpf_init);
module_exit(netlink_bpf_exit);
MODULE_LICENSE("GPL");
