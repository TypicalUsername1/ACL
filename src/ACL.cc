#include "ACL.hpp"
#include "PacketParser.hpp"
#include "api/Packet.hpp"
#include <runos/core/logging.hpp>

#include "Recovery.hpp"
#include <boost/lexical_cast.hpp>
#include <../../../core/lib/ipv4addr.cc>

#include <sstream>
#include <filesystem>

namespace protocols {
    constexpr uint16_t ip = 0x0800;
    constexpr uint16_t arp = 0x0806;
    constexpr uint8_t tcp = IPPROTO_TCP;
}

namespace runos {

REGISTER_APPLICATION(ACL, {"controller", "switch-manager", ""}) //"host-manager", "link-discovery", 

static constexpr uint64_t COOKIE = 0xBEAF;

struct Node {
  std::string data;
  Node *parent;
  Node *left;
  Node *right;
  int color;
};

typedef Node *NodePtr;

class RedBlackTree {
   private:
  NodePtr root;
  NodePtr TNULL;

  NodePtr searchTreeHelper(NodePtr node, std::string key) {
    if (node == TNULL)
        return nullptr;
    if (key.compare(node->data) == 0) {
      return node;
    }

    if (key.compare(node->data) < 0) {
      return searchTreeHelper(node->left, key);
    }
    return searchTreeHelper(node->right, key);
  }

  // For balancing the tree after insertion
  void insertFix(NodePtr k) {
    NodePtr u;
    while (k->parent->color == 1) {
      if (k->parent == k->parent->parent->right) {
        u = k->parent->parent->left;
        if (u->color == 1) {
          u->color = 0;
          k->parent->color = 0;
          k->parent->parent->color = 1;
          k = k->parent->parent;
        } else {
          if (k == k->parent->left) {
            k = k->parent;
            rightRotate(k);
          }
          k->parent->color = 0;
          k->parent->parent->color = 1;
          leftRotate(k->parent->parent);
        }
      } else {
        u = k->parent->parent->right;

        if (u->color == 1) {
          u->color = 0;
          k->parent->color = 0;
          k->parent->parent->color = 1;
          k = k->parent->parent;
        } else {
          if (k == k->parent->right) {
            k = k->parent;
            leftRotate(k);
          }
          k->parent->color = 0;
          k->parent->parent->color = 1;
          rightRotate(k->parent->parent);
        }
      }
      if (k == root) {
        break;
      }
    }
    root->color = 0;
  }

  void printHelper(NodePtr root, std::string indent, bool last) {
    if (root != TNULL) {
      LOG(INFO) << indent;
      if (last) {
        LOG(INFO) << "R----";
        indent += "   ";
      } else {
        LOG(INFO) << "L----";
        indent += "|  ";
      }

      std::string sColor = root->color ? "RED" : "BLACK";
      LOG(INFO) << root->data << "(" << sColor << ")";
      printHelper(root->left, indent, false);
      printHelper(root->right, indent, true);
    }
  }

   public:
  RedBlackTree() {
    TNULL = new Node;
    TNULL->color = 0;
    TNULL->left = nullptr;
    TNULL->right = nullptr;
    root = TNULL;
  }

  NodePtr searchTree(std::string k) {
    return searchTreeHelper(this->root, k);
  }

  NodePtr minimum(NodePtr node) {
    while (node->left != TNULL) {
      node = node->left;
    }
    return node;
  }

  void leftRotate(NodePtr x) {
    NodePtr y = x->right;
    x->right = y->left;
    if (y->left != TNULL) {
      y->left->parent = x;
    }
    y->parent = x->parent;
    if (x->parent == nullptr) {
      this->root = y;
    } else if (x == x->parent->left) {
      x->parent->left = y;
    } else {
      x->parent->right = y;
    }
    y->left = x;
    x->parent = y;
  }

  void rightRotate(NodePtr x) {
    NodePtr y = x->left;
    x->left = y->right;
    if (y->right != TNULL) {
      y->right->parent = x;
    }
    y->parent = x->parent;
    if (x->parent == nullptr) {
      this->root = y;
    } else if (x == x->parent->right) {
      x->parent->right = y;
    } else {
      x->parent->left = y;
    }
    y->right = x;
    x->parent = y;
  }

  // Inserting a node
  void insert(std::string key) {
    NodePtr node = new Node;
    node->parent = nullptr;
    node->data = key;
    node->left = TNULL;
    node->right = TNULL;
    node->color = 1;

    NodePtr y = nullptr;
    NodePtr x = this->root;

    while (x != TNULL) {
      y = x;
      if (node->data.compare(x->data) < 0){
        x = x->left;
      } else {
        x = x->right;
      }
    }

    node->parent = y;
    if (y == nullptr) {
      root = node;
    } else if (node->data.compare(y->data) < 0) {
      y->left = node;
    } else {
      y->right = node;
    }

    if (node->parent == nullptr) {
      node->color = 0;
      return;
    }

    if (node->parent->parent == nullptr) {
      return;
    }

    insertFix(node);
  }

  void printTree() {
    if (root) {
      printHelper(this->root, "", true);
    }
  }
};

struct Btrees
{
  RedBlackTree binaryDstTree;
  RedBlackTree binaryPortTree;
};

std::unordered_map<std::string, Btrees> umap;

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

    if(readConfig(true))
    {
        LOG(ERROR) << "ACL readConfig failed";
    }
    
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
            std::string str_mac = boost::lexical_cast<std::string>(src_mac_);

            LOG(INFO) << " str_src_ip = " << str_src_ip  << " str_dst_ip = " << str_dst_ip << " target_port = " << target_port;

            del();

            if (umap.find(str_src_ip) != umap.end())
            {
                if( umap[str_src_ip].binaryDstTree.searchTree(str_dst_ip) )
                {
                    if (target_port != boost::none)
                    {
                        // std::string target_port_str = boost::lexical_cast<std::string>(target_port); 

                        // if( umap[str_src_ip].binaryPortTree.searchTree(target_port_str) )
                        // {
                            addRule(str_src_ip, str_dst_ip, 0, "", 1, of13::OFPP_CONTROLLER);
                            LOG(INFO) << "No violation: packet from IP " << str_src_ip << " to " << str_dst_ip << " on switch " << dpid_;
                            send_unicast(*target_port, pi, str_src_ip, str_dst_ip);
                        // }
                        // else
                        // {
                        //     addRule(str_src_ip, str_dst_ip, 0, "", 2, 0);
                        //     LOG(WARNING) << "Politics violation: packet from IP " << str_src_ip << " to " << str_dst_ip << " on switch " << dpid_;
                        // }
                
                    }
                    else
                    {
                        addRule(str_src_ip, str_dst_ip, 0, "", 1, of13::OFPP_CONTROLLER);
                        LOG(INFO) << "No violation: packet from IP " << str_src_ip << " to " << str_dst_ip << " on switch " << dpid_;
                        send_broadcast(pi);
                    }
                }
                else
                {
                    addRule(str_src_ip, str_dst_ip, 0, "", 2, 0);
                    LOG(WARNING) << "Politics violation: packet from IP " << str_src_ip << " to " << str_dst_ip << " on switch " << dpid_;
                }
            }
        }

        return true;
    }, -1000);
}

void ACL::send_unicast(uint32_t target_port, const of13::PacketIn& pi, std::string str_src_ip, std::string str_dst_ip)
{
    LOG(INFO) << __func__;
    { // Send PacketOut.
        of13::PacketOut po;
        po.data(pi.data(), pi.data_len());
        of13::OutputAction output_action(target_port, of13::OFPCML_NO_BUFFER);
        po.add_action(output_action);
        switch_manager_->switch_(dpid_)->connection()->send(po);

    } // Send PacketOut.
}

void ACL::send_broadcast(const of13::PacketIn& pi)
{
    LOG(INFO) << __func__;
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

void ACL::addRule(std::string ipSrc, std::string ipDst, uint32_t port, std::string MAC, uint32_t priority, uint32_t action)
{
    uint16_t types[2] = {protocols::ip, protocols::arp};

    for( int i =0; i < 2; ++i)
    {
        of13::FlowMod fm;
        fm.command(of13::OFPFC_ADD);
        fm.xid(0);
        fm.buffer_id(OFP_NO_BUFFER);
        fm.table_id(0);
        fm.priority(priority);
        fm.cookie(COOKIE);
        fm.idle_timeout(0);
        fm.hard_timeout(0);
        fm.flags( of13::OFPFF_SEND_FLOW_REM );
        fm.add_oxm_field(new of13::EthType(types[i]));
        // fm.add_oxm_field(new of13::IPProto(protocols::tcp));
        if (!ipSrc.empty() && !ipSrc.compare("0.0.0.0"))
        {
            std::stringstream ss;
            ipv4addr ipv4_src(convert(ipSrc).first);
            ss.str(std::string());
            ss.clear();
            ss << ipv4_src;
            fm.add_oxm_field(new of13::IPv4Src{fluid_msg::IPAddress(ss.str())});
        }

        if (!ipDst.empty() && !ipDst.compare("0.0.0.0"))
        {
            std::stringstream ss;
            ipv4addr ipv4_dst(convert(ipDst).first);
            ss.str(std::string());
            ss.clear();
            ss << ipv4_dst;
            fm.add_oxm_field(new of13::IPv4Dst{fluid_msg::IPAddress(ss.str())});
        }
        
        if (!MAC.empty())
        {
            std::stringstream ss;
            ethaddr eth_src(MAC);
            ss.str(std::string());
            ss.clear();
            ss << eth_src;
            fm.add_oxm_field(new of13::EthSrc{fluid_msg::EthAddress(ss.str())});
        }
        
        if (port)
        {
            fm.add_oxm_field(new of13::InPort(port));
        }
        
        if (action)
        {
            of13::ApplyActions actions;
            actions.add_action(new of13::OutputAction(action, of13::OFPCML_NO_BUFFER));
            fm.add_instruction(actions);
        }

        sender_->send(dpid_, fm);
    }
}

void ACL::del(void) {
    LOG(INFO) << __func__;
	of13::FlowMod fm;
	fm.command(of13::OFPFC_DELETE);
	fm.table_id(of13::OFPTT_ALL);
	fm.priority(2);
	fm.cookie(COOKIE);
	fm.cookie_mask(0);
	fm.out_port(of13::OFPP_ANY);
	fm.out_group(of13::OFPP_ANY);
	sender_->send(dpid_, fm);
}

bool ACL::readConfig(bool printConfig)
{
    // Create a root
    pt::ptree root;
    
    std::string path = std::filesystem::current_path();    
    path.append("/runos-settings.json");

    if (! std::filesystem::exists(path))
    {
        LOG(WARNING) << "File not found" << path.c_str();
        return 1;
    }

    // Load the json file in this ptree
    pt::read_json(path.c_str(), root);

    auto aclConfig = root.get_child("ACL");
    // Iterator over all source
    auto sourceIpList = aclConfig.get_child("SourceIpList");

    for (pt::ptree::value_type &src : sourceIpList)
    {
        std::string ip = src.second.get<std::string>("ipSrc");
        RedBlackTree binDstTree;
        for (pt::ptree::value_type &dst : src.second.get_child("DestIpList"))
        {
            // dst.first contain the string ""
            binDstTree.insert(dst.second.data());
        }
        RedBlackTree binPortTree;
        for (pt::ptree::value_type &port : src.second.get_child("PortList"))
        {
            // port.first contain the string ""
            binPortTree.insert(port.second.data());
        }
        umap.insert({ip, {binDstTree, binPortTree}});
    }

    if(printConfig)
    {
        for (auto itr = umap.begin(); itr != umap.end(); itr++)
        { 
            std::cout << "ip = " << itr->first << '\n'; 
            std::cout << "destinations:" << '\n';
            itr->second.binaryDstTree.printTree();
            std::cout << "ports:" << '\n';
            itr->second.binaryPortTree.printTree();
        } 
    }

    return 0;
}

} //namespace runos
