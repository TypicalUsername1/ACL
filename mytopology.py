from mininet.topo import Topo
class MyTopo(Topo):
    def __init__(self):
        "Create custom topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        Host1 = self.addHost('h1')
        Host2 = self.addHost('h2')
        Host3 = self.addHost('h3')
        Host4 = self.addHost('h4')
        Host5 = self.addHost('h5')

        Switch1 = self.addSwitch('s1')
        Switch2 = self.addSwitch('s2')
        Switch3 = self.addSwitch('s3')

        # Add links
        self.addLink(Host1, Switch1)
        self.addLink(Host2, Switch1)
        self.addLink(Host3, Switch2)
        self.addLink(Host4, Switch3)
        self.addLink(Host5, Switch3)
        self.addLink(Switch1, Switch2)
        self.addLink(Switch2, Switch3)
topos = {'mytopo': (lambda: MyTopo())}

#to start:
#cd runos
#nix-shell
#cd build
#cmake ..
#make
#cd ..
#./build/runos

#в другом терминале:
#sudo mn --custom ./mytopology.py --topo=mytopo --switch ovsk,protocols=OpenFlow13 --controller remote,ip=127.0.0.1,port=6653



