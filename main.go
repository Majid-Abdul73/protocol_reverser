package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Configuration struct to hold program settings
type Config struct {
	device      string
	snapLen     int32
	promiscuous bool
	filter      string
	listInterfaces bool
}

func main() {
	// Parse command line flags
	config := parseFlags()

	// List interfaces if requested
	if config.listInterfaces {
		if err := listAvailableInterfaces(); err != nil {
			log.Fatal("Error listing interfaces: ", err)
		}
		return
	}

	// Initialize packet capture
	handle, err := initializeCapture(config)
	if err != nil {
		log.Fatal("Error initializing capture: ", err)
	}
	defer handle.Close()

	// Start packet processing
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	processPackets(packetSource)
}

func parseFlags() *Config {
	config := &Config{}
	
	// Create a temporary int variable for flag parsing
	var snapLenInt int = 1024
	
	flag.StringVar(&config.device, "i", "", "Interface to capture packets from")
	flag.IntVar(&snapLenInt, "s", 1024, "Snapshot length for packet capture")
	flag.BoolVar(&config.promiscuous, "promisc", true, "Enable promiscuous mode")
	flag.StringVar(&config.filter, "f", "", "BPF filter string")
	flag.BoolVar(&config.listInterfaces, "l", false, "List available interfaces")
	
	flag.Parse()
	
	// Convert int to int32 after parsing
	config.snapLen = int32(snapLenInt)
	return config
}

func listAvailableInterfaces() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("error finding devices: %v", err)
	}

	fmt.Println("Available interfaces:")
	for _, device := range devices {
		fmt.Printf("\nName: %s\n", device.Name)
		fmt.Printf("Description: %s\n", device.Description)
		fmt.Printf("Addresses:\n")
		for _, address := range device.Addresses {
			fmt.Printf("- IP: %s, Netmask: %s\n", address.IP, address.Netmask)
		}
	}
	return nil
}

func initializeCapture(config *Config) (*pcap.Handle, error) {
	// Open device for capturing
	handle, err := pcap.OpenLive(config.device, config.snapLen, config.promiscuous, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("error opening device %s: %v", config.device, err)
	}

	// Set BPF filter if specified
	if config.filter != "" {
		if err := handle.SetBPFFilter(config.filter); err != nil {
			return nil, fmt.Errorf("error setting BPF filter: %v", err)
		}
	}

	return handle, nil
}

func processPackets(packetSource *gopacket.PacketSource) {
	for packet := range packetSource.Packets() {
		analyzePacket(packet)
	}
}

func analyzePacket(packet gopacket.Packet) {
	// Extract network layer info
	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		fmt.Printf("Network layer: %v\n", networkLayer.LayerType())
		fmt.Printf("Source IP: %s\n", networkLayer.NetworkFlow().Src())
		fmt.Printf("Destination IP: %s\n", networkLayer.NetworkFlow().Dst())
	}

	// Extract transport layer info
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		fmt.Printf("Transport layer: %v\n", transportLayer.LayerType())
		fmt.Printf("Source port: %s\n", transportLayer.TransportFlow().Src())
		fmt.Printf("Destination port: %s\n", transportLayer.TransportFlow().Dst())
	}

	// Extract application layer payload
	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		payload := applicationLayer.Payload()
		fmt.Printf("Payload length: %d bytes\n", len(payload))
		// TODO: Add protocol-specific payload analysis
	}

	fmt.Println("-------------------")
}