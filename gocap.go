package main

import (
	"fmt"
	//"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/urfave/cli"
	"os"
	"time"
)

var (
	ethLayer layers.Ethernet
	ipLayer  layers.IPv4
	tcpLayer layers.TCP
	udpLayer layers.UDP
)

var (
	VERSION = "1.0.0"
)

func main() {

	app := cli.NewApp()
	app.Name = "capture"
	app.Usage = "capture the net data"
	app.Version = VERSION
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "protocol, p",
			Value: "udp",
			Usage: "capture protocol",
		},

		cli.IntFlag{
			Name:  "port",
			Value: 0000, // 0000 means not designation port
			Usage: "capture port",
		},

		cli.StringFlag{
			Name:  "filename, f",
			Value: "test.pcap",
			Usage: "generate file name",
		},
	}

	app.Action = func(c *cli.Context) error {
		f, _ := os.Create(c.String("filename"))
		w := pcapgo.NewWriter(f)
		w.WriteFileHeader(65535, layers.LinkTypeEthernet)
		defer f.Close()

		handle, err := pcap.OpenLive("lo", 65535, false, time.Duration(30)*time.Second)
		if err != nil {
			panic(err)
		}

		defer handle.Close()

		// filter
		var filter string
		if c.Int("port") != 0000 {
			filter = fmt.Sprintf("%s and port %d", c.String("protocol"), c.Int("port"))
			if err = handle.SetBPFFilter(filter); err != nil {
				panic(err)
			}
		}

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			parser := gopacket.NewDecodingLayerParser(
				layers.LayerTypeEthernet,
				&ethLayer,
				&ipLayer,
				&tcpLayer,
				&udpLayer,
			)
			foundLayerTypes := []gopacket.LayerType{}

			if err := parser.DecodeLayers(packet.Data(), &foundLayerTypes); err != nil {
				fmt.Println("Trouble decoding layers :", err)
			}

			for _, layerType := range foundLayerTypes {
				if layerType == layers.LayerTypeIPv4 {
					//fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
				}

				if layerType == layers.LayerTypeTCP && c.String("protocol") == "tcp" {
					w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				}

				if layerType == layers.LayerTypeUDP && c.String("protocol") == "udp" {
					w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				}
			}
		}
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}

}
