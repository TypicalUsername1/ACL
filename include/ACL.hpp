#pragma once

#include "Application.hpp"
#include "Loader.hpp"
#include "SwitchManager.hpp"
#include "api/SwitchFwd.hpp"
#include "oxm/openflow_basic.hh"

#include <boost/optional.hpp>
#include <boost/thread.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <tins/icmp.h>
#include <tins/ip.h>
#include <tins/ethernetII.h>

#include <unordered_map>

//#include "Controller.hpp"
//#include "api/Switch.hpp"

//#include "HostManager.hpp"
//#include "LinkDiscovery.hpp"
//#include "oxm/field_set.hh"

#include "OFMsgSender.hpp"
#include <string>
#include <iostream>
#include <algorithm>

namespace runos {

using SwitchPtr = safe::shared_ptr<Switch>;
namespace of13 = fluid_msg::of13;
namespace pt = boost::property_tree;

namespace ofb_l2 
{
    constexpr auto in_port = oxm::in_port();
    constexpr auto eth_src = oxm::eth_src();
    constexpr auto eth_dst = oxm::eth_dst();
}

class ACL : public Application 
{
    Q_OBJECT SIMPLE_APPLICATION(ACL, "ACL")

public:
    void init(Loader* loader, const Config& config) override;
    struct t_politics
    {
        std::string ip_src;
        std::vector<std::string> v_destIp;
        std::vector<std::string> v_ports;
    } ;
protected slots:
    void onSwitchUp(SwitchPtr sw);

private:
    OFMessageHandlerPtr handler_;
    SwitchManager* switch_manager_;
    OFMsgSender* sender_;

    ethaddr src_mac_;
    ethaddr dst_mac_;
    uint64_t dpid_;
    uint32_t in_port_;
    
    void send_unicast(uint32_t target_switch_and_port,
                      const of13::PacketIn& pi,
                      std::string str_src_ip,
                      std::string str_dst_ip);
    void send_broadcast(const of13::PacketIn& pi);
    void del(void);
    bool readConfig(bool printConfig);
    void sortPolitics();
    void addRule(std::string ipSrc, std::string ipDst, uint32_t port, std::string MAC, uint32_t priority, uint32_t action);
};

class HostDatabase
{
public:
    bool setPort(uint64_t dpid, ethaddr mac, uint32_t in_port);
    boost::optional<uint32_t> getPort(uint64_t dpid, ethaddr mac);

private:
    boost::shared_mutex mutex_;
    std::unordered_map<uint64_t, std::unordered_map<ethaddr, uint32_t>> seen_ports_;
};

}//runos namespace
