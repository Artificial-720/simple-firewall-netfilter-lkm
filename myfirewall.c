#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h> // ip_hdr
#include <linux/tcp.h>

static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;
//static char *machine_b_ip = "10.0.2.5";
static uint32_t machine_b_ip = 0x0A000205;
//One of github.com ips
//static char *website_ip = "192.30.255.113";
static uint32_t webpage_ip = 0xC01EFF71;

unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
  struct iphdr *iph;
  struct tcphdr *tcph;
  if(!skb) // Socket buffer is empty just accept
    return NF_ACCEPT;
  iph = ip_hdr(skb);  // Get the ip header from buffer
  if (iph->protocol == IPPROTO_TCP){
    // TCP protocol
    tcph = tcp_hdr(skb); // Get the tcp header from the buffer
    printk(KERN_INFO "Inbound Packet Info: Source IP=%pI4, Destination IP=%pI4, Source Port=%u, Destination Port=%u\n", 
          &iph->saddr, &iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));


    // Block Inbound telnet traffic to Machine A from Machine B.
    if (ntohl(iph->saddr) == machine_b_ip && ntohs(tcph->dest) == 23){
      printk(KERN_INFO "Dropping inbound telnet packet\n");
      return NF_DROP;
    }
    // Block Inbound SSH traffic to Machine A from Machine B.
    if (ntohl(iph->saddr) == machine_b_ip && ntohs(tcph->dest) == 22){
      printk(KERN_INFO "Dropping inbound SSH packet\n");
      return NF_DROP;
    }
  }

  // Defaulting to Accept, meaning rules are a black list
  return NF_ACCEPT;
}

unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
  struct iphdr *iph;
  struct tcphdr *tcph;
  if (!skb)
    return NF_ACCEPT;
  iph = ip_hdr(skb);
  if (iph->protocol == IPPROTO_TCP) {
    tcph = tcp_hdr(skb);
    printk(KERN_INFO "Outbound Packet Info: Source IP=%pI4, Destination IP=%pI4, Source Port=%u, Destination Port=%u\n", 
          &iph->saddr, &iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));


    // Block Outbound telnet traffic from Machine A to Machine B.
    if (ntohl(iph->daddr) == machine_b_ip && ntohs(tcph->dest) == 23){
      printk(KERN_INFO "Dropping outbound telnet packet\n");
      return NF_DROP;
    }
    // Block Outbound SSH traffic from Machine A to Machine B.
    if (ntohl(iph->daddr) == machine_b_ip && ntohs(tcph->dest) == 22){
      printk(KERN_INFO "Dropping outbound SSH packet\n");
      return NF_DROP;
    }
    // Block Access to specific eternal website from Machine A.
    if (ntohl(iph->daddr) == webpage_ip && ntohs(tcph->dest) == 443){
      printk(KERN_INFO "Dropping outbound webpage packet\n");
      return NF_DROP;
    }
  }
  return NF_ACCEPT;
}


static int __init myfirewall_init(void){
  printk(KERN_INFO "Loaded myfirewall\n");

  // setup hook for inbound traffic
  nfho_in.hook = hook_func_in;
  nfho_in.hooknum = NF_INET_PRE_ROUTING;
  nfho_in.pf = PF_INET;
  nfho_in.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &nfho_in);

  // Set up hook for outbound traffic
  nfho_out.hook = hook_func_out;
  nfho_out.hooknum = NF_INET_POST_ROUTING;
  nfho_out.pf = PF_INET;
  nfho_out.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &nfho_out);

  return 0;
}

static void __exit myfirewall_exit(void){
  printk(KERN_INFO "Unloaded myfirewall\n");
  nf_unregister_net_hook(&init_net, &nfho_in);
  nf_unregister_net_hook(&init_net, &nfho_out);
}

module_init(myfirewall_init);
module_exit(myfirewall_exit);

MODULE_LICENSE("GPL");