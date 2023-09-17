#include "ACL.hpp"
#include "PacketParser.hpp"
#include "api/Packet.hpp"
#include <runos/core/logging.hpp>

#include "Recovery.hpp"
#include <boost/lexical_cast.hpp>
#include <../../../core/lib/ipv4addr.cc>

#include <sstream>

namespace runos {

REGISTER_APPLICATION(ACL, {"controller", "switch-manager", ""}) //"host-manager", "link-discovery", 

std::string InvertIP(std::string ip) 
{
    std::vector<std::string> fragms;
    std::string fragm = "";
    for (char c : ip) 
    {
        if (c == '.') 
        {
            fragms.push_back(fragm);
            fragm = "";
        } 
        else 
        {
            fragm += c;
        }
    }
    fragms.push_back(fragm);
    std::string res = "";
    for (int i = 3; i > 0; i--) 
    {
        res += fragms[i] + '.';
    }
    return res + fragms[0];
}


void ACL::init(Loader *loader, const Config &config) 
{
    sender_ = OFMsgSender::get(loader);

    switch_manager_ = SwitchManager::get(loader);
    connect(switch_manager_, &SwitchManager::switchUp,
            this, &ACL::onSwitchUp);

    auto data_base = std::make_shared<HostDatabase>();

    make_politics();

    handler_ = Controller::get(loader)->register_handler(
    [=](of13::PacketIn& pi, OFConnectionPtr ofconn) -> bool
    {
	PacketParser pp(pi);
	runos::Packet& pkt(pp);

        const auto ofb_eth_type = oxm::eth_type();
        const auto ofb_arp_spa = oxm::arp_spa();
        const auto ofb_arp_tpa = oxm::arp_tpa();

        const auto ofb_ipv4_src = oxm::ipv4_src();
        const auto ofb_ipv4_dst = oxm::ipv4_dst();

        src_mac_ = pkt.load(ofb_l2::eth_src);
        dst_mac_ = pkt.load(ofb_l2::eth_dst);
        in_port_ = pkt.load(ofb_l2::in_port);
        dpid_ = ofconn->dpid();

        if (not data_base->setPort(dpid_, src_mac_, in_port_))
        {
            return false;
	}
	
        auto target_port = data_base->getPort(dpid_, dst_mac_);

        ipv4addr src_ip(convert("0.0.0.0").first);
        ipv4addr dst_ip(convert("0.0.0.0").first);

        if (pkt.test(ofb_eth_type == 0x0800)) 
        {
            src_ip = ipv4addr(pkt.load(ofb_ipv4_src));
            dst_ip = ipv4addr(pkt.load(ofb_ipv4_dst));
        } 
        else if (pkt.test(ofb_eth_type == 0x0806)) 
        {
            src_ip = ipv4addr(pkt.load(ofb_arp_spa));
            dst_ip = ipv4addr(pkt.load(ofb_arp_tpa));
        }

        std::string str_src_ip = InvertIP(boost::lexical_cast<std::string>(src_ip));
        std::string str_dst_ip = InvertIP(boost::lexical_cast<std::string>(dst_ip));

        if ((str_dst_ip != std::string("0.0.0.0")) && (str_src_ip != std::string("0.0.0.0"))) 
        {
            if (politics[str_src_ip].find(str_dst_ip) != politics[str_src_ip].end())
            {
                //LOG(INFO) << "No violation: packet from IP " << str_src_ip << " to " << str_dst_ip;
                LOG(INFO) << "No violation: packet from IP " << str_src_ip << " to " << str_dst_ip << " on switch " << dpid_;
                if (target_port != boost::none)
                {
                	send_unicast(*target_port, pi, str_src_ip, str_dst_ip);
                }
                else
                {
                	send_broadcast(pi);
                }
            }
            else
            {
                //LOG(WARNING) << "Politics violation: packet from IP " << str_src_ip << " to " << str_dst_ip;
                LOG(WARNING) << "Politics violation: packet from IP " << str_src_ip << " to " << str_dst_ip << " on switch " << dpid_;
            }
        }

        return true;
    }, -1000);
}

void ACL::send_unicast(uint32_t target_port, const of13::PacketIn& pi, std::string str_src_ip, std::string str_dst_ip)
{
    { // Send PacketOut.
        of13::PacketOut po;
        po.data(pi.data(), pi.data_len());
        of13::OutputAction output_action(target_port, of13::OFPCML_NO_BUFFER);
        po.add_action(output_action);
        switch_manager_->switch_(dpid_)->connection()->send(po);

    } // Send PacketOut.

    { // Create FlowMod.

        of13::FlowMod fm;
        fm.command(of13::OFPFC_ADD);
        fm.table_id(0);
        fm.priority(2);
        std::stringstream ss;
        fm.idle_timeout(uint64_t(60));
        fm.hard_timeout(uint64_t(1800));

        ss.str(std::string());
        ss.clear();
        ss << src_mac_;
        fm.add_oxm_field(new of13::EthSrc{
                fluid_msg::EthAddress(ss.str())});

        ss.str(std::string());
        ss.clear();
        ss << dst_mac_;
        fm.add_oxm_field(new of13::EthDst{
                fluid_msg::EthAddress(ss.str())});

        if (str_src_ip != "0.0.0.0") 
        {
            ipv4addr ipv4_src(convert(str_src_ip).first);
            ss.str(std::string());
            ss.clear();
            ss << ipv4_src;
            fm.add_oxm_field(new of13::EthType(0x0800));
            fm.add_oxm_field(new of13::IPv4Src{fluid_msg::IPAddress(ss.str())});
        }

        if (str_dst_ip != "0.0.0.0") 
        {
            ipv4addr ipv4_dst(convert(str_dst_ip).first);
            ss.str(std::string());
            ss.clear();
            ss << ipv4_dst;
            //LOG(INFO) << "dst " << ipv4_dst;
            //LOG(INFO) << "dst " << ss.str();
            fm.add_oxm_field(new of13::IPv4Dst{fluid_msg::IPAddress(ss.str())});
        }

        of13::ApplyActions applyActions;
        of13::OutputAction output_action(target_port, of13::OFPCML_NO_BUFFER);
        applyActions.add_action(output_action);
        fm.add_instruction(applyActions);
        switch_manager_->switch_(dpid_)->connection()->send(fm);

    } // Create FlowMod.
}

void ACL::send_broadcast(const of13::PacketIn& pi)
{
    of13::PacketOut po;
    po.data(pi.data(), pi.data_len());
    po.in_port(in_port_);
    of13::OutputAction output_action(of13::OFPP_ALL, of13::OFPCML_NO_BUFFER);
    po.add_action(output_action);
    switch_manager_->switch_(dpid_)->connection()->send(po);
}

void ACL::onSwitchUp(SwitchPtr sw)
{
    of13::FlowMod fm;
    fm.command(of13::OFPFC_ADD);
    fm.table_id(0);
    fm.priority(1);
    of13::ApplyActions applyActions;
    of13::OutputAction output_action(of13::OFPP_CONTROLLER, 0xFFFF);
    applyActions.add_action(output_action);
    fm.add_instruction(applyActions);
    sw->connection()->send(fm);
}

void ACL::make_politics()
{
    std::set<std::string> ip1 = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"};
    std::set<std::string> ip2 = {"10.0.0.2", "10.0.0.3", "10.0.0.4"};
    std::set<std::string> ip3 = {"10.0.0.3", "10.0.0.4", "10.0.0.5"};
    std::set<std::string> ip4 = {"10.0.0.3", "10.0.0.4"};
    std::set<std::string> ip5 = {"10.0.0.3", "10.0.0.4", "10.0.0.5"};

    politics["10.0.0.1"] = ip1;
    politics["10.0.0.2"] = ip2;
    politics["10.0.0.3"] = ip3;
    politics["10.0.0.4"] = ip4;
    politics["10.0.0.5"] = ip5;
}

bool HostDatabase::setPort(uint64_t dpid, ethaddr mac, uint32_t in_port)
{
    if (is_broadcast(mac)) 
    {
        LOG(WARNING) << "Broadcast source address, dropping";
        return false;
    }

    boost::unique_lock<boost::shared_mutex> lock(mutex_);
    seen_ports_[dpid][mac] = in_port;
    return true;
}

boost::optional<uint32_t> HostDatabase::getPort(uint64_t dpid, ethaddr mac)
{
    boost::shared_lock<boost::shared_mutex> lock(mutex_);
    auto it = seen_ports_[dpid].find(mac);

    if (it != seen_ports_[dpid].end())
    {
        return it->second;
    }
    else 
    {
    	return boost::none;
    }
}

} //namespace runos
