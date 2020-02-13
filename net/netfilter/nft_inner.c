/*
 * Copyright (c) 2020 David R. Bild <david@davidbild.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Xaptum (http://www.xaptum.com/)
 */

#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <net/netfilter/nf_tables_core.h>
#include <net/netfilter/nf_tables.h>
#include <net/ip.h>
#include <net/ipv6.h>

struct nft_inner {
	u8	family;
};

static int nft_inner_init(const struct nft_ctx *ctx,
			  const struct nft_expr *expr,
			  const struct nlattr * const tb[])
{
	struct nft_inner *priv = nft_expr_priv(expr);
	u32 family;

	if (tb[NFTA_INNER_FAMILY] == NULL)
		return -EINVAL;

	family = ntohl(nla_get_be32(tb[NFTA_INNER_FAMILY]));
	switch (family) {
	case NFPROTO_IPV4:
	case NFPROTO_IPV6:
	case NFPROTO_INET:
		priv->family = family;
		break;
	default:
		return -EAFNOSUPPORT;
	}

	return 0;
}

int nft_inner_dump(struct sk_buff *skb, const struct nft_expr *expr)
{
	const struct nft_inner *priv = nft_expr_priv(expr);

	if (nla_put_be32(skb, NFTA_INNER_FAMILY, htonl(priv->family)))
		goto nla_put_failure;
	return 0;

 nla_put_failure:
	return -1;
}

static int update_active_ipv4_validate(struct nft_pktinfo *pkt)
{
	struct sk_buff *skb = pkt->active_skb;
	struct iphdr *iph, _iph;
	u32 thoff, len;

	if (!pskb_pull(skb, pkt->xt.thoff))
		return -1;
	skb_postpull_rcsum(skb, skb_network_header(skb), pkt->xt.thoff);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	iph = skb_header_pointer(skb, skb_network_offset(skb), sizeof(*iph),
				 &_iph);
	if (!iph)
		return -1;

	if (iph->ihl < 5 || iph->version != 4)
		return -1;

	len = ntohs(iph->tot_len);
	thoff = iph->ihl * 4;
	if (skb->len < len)
		return -1;
	else if (len < thoff)
		return -1;

	skb_set_transport_header(skb, thoff);

	pkt->tprot_set = true;
	pkt->tprot = iph->protocol;
	pkt->xt.thoff = thoff;
	pkt->xt.fragoff = ntohs(iph->frag_off) & IP_OFFSET;

	return 0;
}

static int update_active_ipv6_validate(struct nft_pktinfo *pkt)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct sk_buff *skb = pkt->active_skb;
	unsigned int flags = IP6_FH_F_AUTH;
	struct ipv6hdr *ip6h, _ip6h;
	unsigned int thoff = 0;
	unsigned short frag_off;
	int protohdr;
	u32 pkt_len;

	if (!pskb_pull(skb, pkt->xt.thoff))
		return -1;
	skb_postpull_rcsum(skb, skb_network_header(skb), pkt->xt.thoff);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	ip6h = skb_header_pointer(skb, skb_network_offset(skb), sizeof(*ip6h),
				  &_ip6h);
	if (!ip6h)
		return -1;

	if (ip6h->version != 6)
		return -1;

	pkt_len = ntohs(ip6h->payload_len);
	if (pkt_len + sizeof(*ip6h) > skb->len)
		return -1;

	protohdr = ipv6_find_hdr(skb, &thoff, -1, &frag_off, &flags);
	if (protohdr < 0)
		return -1;
	skb_set_transport_header(skb, thoff);

	pkt->tprot_set = true;
	pkt->tprot = protohdr;
	pkt->xt.thoff = thoff;
	pkt->xt.fragoff = frag_off;

	return 0;
#else
	return -1;
#endif
}

void nft_inner_eval(const struct nft_expr *expr,
		    struct nft_regs *regs,
		    const struct nft_pktinfo *cpkt)
{
	const struct nft_inner *priv = nft_expr_priv(expr);
	struct nft_pktinfo *pkt = (struct nft_pktinfo*) cpkt;

	// Currently only support introspecting on one inner packet
	if (pkt->active_skb != pkt->skb)
		goto err;

	if (!pkt->tprot_set)
		goto err;

	pkt->active_skb = skb_clone(pkt->skb, GFP_ATOMIC);
	if (!pkt->active_skb)
		goto err;

	switch (pkt->tprot) {
	case IPPROTO_IPIP:
		if (priv->family != NFPROTO_IPV4 &&
		    priv->family != NFPROTO_INET)
			goto err;

		if (update_active_ipv4_validate(pkt))
			goto err;

		break;
	case IPPROTO_IPV6:
		if (priv->family != NFPROTO_IPV6 &&
		    priv->family != NFPROTO_INET)
			goto err;

		if (update_active_ipv6_validate(pkt))
			goto err;

		break;
	default:
		goto err;
	}

	return;

 err:
    regs->verdict.code = NFT_BREAK;
}

static const struct nft_expr_ops nft_inner_ops = {
	.type		= &nft_inner_type,
	.size		= NFT_EXPR_SIZE(sizeof(struct nft_inner)),
	.eval		= nft_inner_eval,
	.init		= nft_inner_init,
	.dump		= nft_inner_dump,
};

struct nft_expr_type nft_inner_type __read_mostly = {
	.name		= "inner",
	.ops		= &nft_inner_ops,
	.maxattr	= NFTA_INNER_MAX,
	.owner		= THIS_MODULE,
};
